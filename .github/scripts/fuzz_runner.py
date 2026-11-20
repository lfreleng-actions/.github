# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The fuzz side of fuzz_publish.py: run harnesses and write a handover."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, cast

from fuzz_common import (
    COMMIT,
    EXIT_REFUSED,
    FAILURE_PREFIXES,
    FUZZ_SLACK,
    HARNESS_ERROR,
    INPUT_TIMEOUT,
    MAX_CORPUS_BYTES,
    MAX_CORPUS_FILES,
    MAX_FAILURES,
    MAX_IDENTITIES,
    MAX_INPUT_BYTES,
    MERGE_WALL,
    PENDING,
    PLACEHOLDER,
    PROBE_WALL,
    REPLAY_WALL,
    REPRODUCIBLE,
    RSS_LIMIT_MB,
    SCHEMA,
    STATE_MARKER,
    TOTAL_SECONDS,
    classify,
    inside,
    locate,
    parse_harnesses,
    read_log,
    read_regular,
)
from fuzz_evidence import hand_over_binding
from fuzz_sarif import Checkout
from fuzz_state import (
    cap_failures,
    executed_units,
    fuzz_budget,
    harness_key,
    load_evidence,
    prepare_state,
    save_evidence,
    saved_inputs,
    sha1_hex,
    tree_size,
    truncate_log,
)

if TYPE_CHECKING:
    import argparse


@dataclass
class Process:
    """One harness process the fuzz side ran."""

    phase: str
    log: str
    exit_code: int | None
    timed_out: bool
    input: str | None = None
    fixed: list[list[str]] | None = None
    held: list[list[str]] | None = None

    def as_json(self) -> dict[str, object]:
        """Return the process as the run record holds it."""
        return {
            "phase": self.phase,
            "log": self.log,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "input": self.input,
            "fixed": self.fixed,
            "held": self.held,
        }


@dataclass
class HarnessRun:
    """What the fuzz side did for one harness."""

    path: str
    seconds: int
    processes: list[Process] = field(default_factory=list)
    executed: int = 0
    fixed: int = 0
    unretained: bool = False

    def as_json(self) -> dict[str, object]:
        """Return the harness as the run record holds it."""
        return {
            "path": self.path,
            "seconds": self.seconds,
            "executed": self.executed,
            "fixed": self.fixed,
            "processes": [process.as_json() for process in self.processes],
        }


Signature = tuple[str, str, str, str]


@dataclass(frozen=True)
class Located:
    """How a process failed, and the line its result points at."""

    signature: Signature
    line: int

    def identity(self) -> list[str]:
        """Return the failure as an evidence identity."""
        return [*self.signature, str(self.line)]


class Fuzzer:
    """Replay, fuzz and bound the state of one repository's harnesses."""

    def __init__(
        self, root: Path, python: Path, output: Path, scratch: Path, source: Path
    ) -> None:
        """Remember where the repository, interpreter and handover live.

        source is a pristine checkout of the commit, which installing
        and fuzzing never write to. Failure locations are validated
        against it as the publish job validates them, so the evidence
        saved for an input names the alert that was published.
        """
        self.root: Path = root
        self.python: Path = python
        self.output: Path = output
        self.scratch: Path = scratch
        self.checkout: Checkout = Checkout(source)

    def environment(self) -> dict[str, str]:
        """Return the minimal environment a harness runs under."""
        return {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": str(self.scratch),
            "TMPDIR": str(self.scratch),
            "LANG": "C.UTF-8",
            "PYTHONHASHSEED": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def run(
        self, run: HarnessRun, phase: str, args: list[str], wall: int
    ) -> tuple[Process, str]:
        """Run the harness once under a wall-clock limit; return it and its log."""
        key = harness_key(run.path)
        name = f"logs/{key}/{len(run.processes):03d}-{phase}.log"
        log = self.output / name
        log.parent.mkdir(parents=True, exist_ok=True)
        argv = [str(self.python), run.path, *args]
        timed_out = False
        with log.open("wb") as handle:
            proc = subprocess.Popen(
                argv,
                cwd=self.root,
                env=self.environment(),
                stdin=subprocess.DEVNULL,
                stdout=handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                code: int | None = proc.wait(timeout=wall)
            except subprocess.TimeoutExpired:
                code = None
                timed_out = True
            # Kill the whole session, so no child the harness started
            # outlives its process or its wall-clock limit.
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            if timed_out:
                _ = proc.wait()
        truncate_log(log)
        process = Process(phase, name, code, timed_out)
        run.processes.append(process)
        return process, read_log(log)

    def signature(self, run: HarnessRun, text: str, process: Process) -> Located | None:
        """Return how a process failed, or None when it passed."""
        failure = classify(text, process.exit_code, timed_out=process.timed_out)
        if failure is None:
            return None
        file, line, function = locate(
            failure, str(self.root), run.path, self.checkout.accepts
        )
        return Located((failure.rule, failure.exception, file, function), line)

    def hand_over(self, run: HarnessRun, process: Process, data: bytes) -> None:
        """Copy a failing input into the handover and name it on the process.

        The file takes its process's log name, not a hash of the input,
        so two inputs that collide cannot overwrite each other's bytes.
        """
        name = f"inputs/{harness_key(run.path)}/{Path(process.log).stem}"
        target = self.output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        _ = target.write_bytes(data)
        process.input = name

    def replay(
        self, run: HarnessRun, failures: Path, evidence: dict[str, list[list[str]]]
    ) -> set[Signature]:
        """Run each saved failing input once; set aside those that now pass.

        A passing input names, from the evidence, every way it has
        failed, so the publish job can let those alerts close, and moves
        with that evidence to the harness's PENDING directory until a
        publication acknowledges it (prepare_state). A failing
        input that now fails another way holds the ways it no longer
        fails, so their alerts stay open until it passes.
        """
        known: set[Signature] = set()
        pending = failures.parent / PENDING
        limits = [f"-timeout={INPUT_TIMEOUT}", f"-rss_limit_mb={RSS_LIMIT_MB}"]
        for path in sorted(failures.iterdir()):
            data = read_regular(path, MAX_INPUT_BYTES)
            process, text = self.run(run, "replay", [*limits, str(path)], REPLAY_WALL)
            run.executed += 1
            found = self.signature(run, text, process)
            prior = evidence.pop(path.name, [])
            if found is None:
                run.fixed += 1
                process.fixed = prior or None
                if prior:
                    # The builder hashes the input itself, and the
                    # publish job checks that hash against its binding.
                    self.hand_over(run, process, data)
                    pending.mkdir(exist_ok=True)
                    _ = path.replace(pending / path.name)
                    evidence[path.name] = prior
                else:
                    path.unlink()
                continue
            known.add(found.signature)
            self.hand_over(run, process, data)
            if found.signature[0] not in REPRODUCIBLE:
                evidence[path.name] = prior
                continue
            held = [item for item in prior if tuple(item[:-1]) != found.signature]
            process.held = held or None
            evidence[path.name] = [*held, found.identity()]
            if len(held) >= MAX_IDENTITIES:
                run.unretained = True
        return known

    def fuzz(
        self,
        run: HarnessRun,
        state: Path,
        known: set[Signature],
        evidence: dict[str, list[list[str]]],
    ) -> None:
        """Fuzz from the saved corpus and save each new kind of failure.

        A new kind of failure whose input cannot be saved, because the
        harness is at its cap, the input is over the size cap or its
        name is already a saved input's, marks
        the run as unretained: publishing it would open an alert that a
        later run could close without a replay.
        """
        prefix = Path(tempfile.mkdtemp(prefix="artifacts-", dir=self.scratch))
        args = [
            f"-max_total_time={run.seconds}",
            f"-timeout={INPUT_TIMEOUT}",
            f"-rss_limit_mb={RSS_LIMIT_MB}",
            "-print_final_stats=1",
            f"-artifact_prefix={prefix}/",
            str(state / "corpus"),
        ]
        process, text = self.run(run, "fuzz", args, run.seconds + FUZZ_SLACK)
        run.executed += executed_units(text)
        found = self.signature(run, text, process)
        failures = state / "failures"
        retained = (
            found is None
            or found.signature in known
            or found.signature[0] == HARNESS_ERROR
        )
        for path in sorted(prefix.iterdir()):
            if not path.name.startswith(FAILURE_PREFIXES):
                continue
            try:
                data = read_regular(path, MAX_INPUT_BYTES)
            except OSError:
                continue
            if process.input is None:
                self.hand_over(run, process, data)
            room = saved_inputs(state) < MAX_FAILURES
            name = sha1_hex(data)
            # A taken name belongs to a saved input whose bytes and
            # evidence a colliding input must not replace.
            free = name not in evidence and not any(
                (state / part / name).exists() for part in ("failures", PENDING)
            )
            if not retained and room and free and found is not None:
                _ = (failures / name).write_bytes(data)
                evidence[name] = [found.identity()]
                known.add(found.signature)
                retained = True
        run.unretained = run.unretained or not retained

    def bound_corpus(self, run: HarnessRun, corpus: Path) -> None:
        """Minimise a corpus past its bound with libFuzzer's merge, or reset it."""
        files, size = tree_size(corpus)
        if files <= MAX_CORPUS_FILES and size <= MAX_CORPUS_BYTES:
            return
        merged = Path(tempfile.mkdtemp(prefix="merge-", dir=self.scratch))
        limits = [f"-timeout={INPUT_TIMEOUT}", f"-rss_limit_mb={RSS_LIMIT_MB}"]
        args = ["-merge=1", *limits, str(merged), str(corpus)]
        process, _ = self.run(run, "merge", args, MERGE_WALL)
        shutil.rmtree(corpus)
        files, size = tree_size(merged)
        fits = files <= MAX_CORPUS_FILES and size <= MAX_CORPUS_BYTES
        if process.exit_code == 0 and fits:
            _ = shutil.move(merged, corpus)
        else:
            corpus.mkdir()

    def harness(self, path: str, seconds: int, state: Path) -> HarnessRun:
        """Replay, fuzz and bound one harness's state."""
        run = HarnessRun(path, seconds)
        failures = state / "failures"
        corpus = state / "corpus"
        failures.mkdir(parents=True, exist_ok=True)
        corpus.mkdir(parents=True, exist_ok=True)
        _ = cap_failures(failures)
        evidence = load_evidence(state)
        known = self.replay(run, failures, evidence)
        self.fuzz(run, state, known, evidence)
        save_evidence(state, evidence)
        self.bound_corpus(run, corpus)
        return run

    def probe(self, code: str) -> str:
        """Return what a one-line program prints under the interpreter."""
        try:
            proc = subprocess.run(
                [str(self.python), "-c", code],
                capture_output=True,
                text=True,
                timeout=PROBE_WALL,
                check=False,
                env=self.environment(),
            )
        except (OSError, subprocess.SubprocessError):
            return PLACEHOLDER
        value = proc.stdout.strip()
        return value if proc.returncode == 0 and value else PLACEHOLDER


def fuzz_main(args: argparse.Namespace) -> int:
    """Run the fuzz side and write the handover."""
    root = Path(cast("str", args.root)).resolve()
    source = Path(cast("str", args.source_root)).resolve()
    python = Path(cast("str", args.python))
    state = Path(cast("str", args.state))
    output = Path(cast("str", args.output))
    commit = cast("str", args.commit)
    seconds = cast("int", args.fuzz_seconds)
    try:
        harnesses = parse_harnesses(cast("str", args.harnesses))
    except ValueError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return EXIT_REFUSED
    missing = [path for path in harnesses if inside(root, path) is None]
    if not COMMIT.fullmatch(commit) or not 1 <= seconds <= TOTAL_SECONDS or missing:
        print("::error::bad commit, fuzz seconds or harness paths", file=sys.stderr)
        return EXIT_REFUSED
    if output.exists() and any(output.iterdir()):
        print(f"::error::handover directory {output} is not empty", file=sys.stderr)
        return EXIT_REFUSED
    output.mkdir(parents=True, exist_ok=True)
    hand_over_binding(cast("str", args.binding), output)
    keys = {harness_key(path) for path in harnesses}
    restored = prepare_state(
        state,
        keys,
        cast("str", args.restored_key),
        published=cast("str", args.published) == "true",
    )
    share = fuzz_budget(len(harnesses), seconds)
    runs: list[HarnessRun] = []
    with tempfile.TemporaryDirectory(prefix="fuzz-scratch-") as scratch:
        fuzzer = Fuzzer(root, python, output, Path(scratch), source)
        for path in harnesses:
            print(f"Fuzzing {path} for {share}s")
            runs.append(fuzzer.harness(path, share, state / harness_key(path)))
        version = fuzzer.probe("import sys; print(sys.version.split()[0])")
        atheris = fuzzer.probe(
            "import importlib.metadata as m; print(m.version('atheris'))"
        )
    unretained = [run.path for run in runs if run.unretained]
    if unretained:
        print(
            "::error::a failure's input could not be saved (at the cap of"
            f" {MAX_FAILURES} saved inputs, over {MAX_INPUT_BYTES} bytes,"
            " named as a saved input already is, or failing in more than"
            f" {MAX_IDENTITIES} ways) for"
            f" {', '.join(unretained)}; handing nothing over, since no later run"
            " could replay it",
            file=sys.stderr,
        )
        return EXIT_REFUSED
    record = {
        "schema": SCHEMA,
        "commit": commit,
        "root": str(root),
        "restored": restored,
        "python": version,
        "atheris": atheris,
        "harnesses": [run.as_json() for run in runs],
    }
    _ = (output / "record.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8"
    )
    _ = (state / STATE_MARKER).write_text(
        json.dumps({"schema": SCHEMA}), encoding="utf-8"
    )
    print(f"Handed over {len(runs)} harness run(s); state restored: {restored}")
    return 0
