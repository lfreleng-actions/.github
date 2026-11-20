# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Unit tests for the fuzz side of .github/scripts/fuzz_publish.py and its modules.

A stand-in harness plays Atheris: it prints the banners, frames and
final stats Atheris 3.1.0 prints, and writes failing inputs under the
artifact prefix, so these tests run on any interpreter. The suite
imports nothing from pytest, so the pre-commit type checkers resolve
it without a test environment.
"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path
from typing import cast
from unittest import mock

import fuzz_common as fc
import fuzz_publish as fp
import fuzz_runner as fr
import fuzz_state as fs

HARNESS = "fuzz/fuzz_fake.py"
CORE = "def check(data):\n    raise ValueError(data)\n\ndef spin():\n    pass\n"
FAKE = textwrap.dedent(
    """\
    import hashlib
    import sys
    import time
    from pathlib import Path

    ROOT = Path.cwd()


    def crash():
        print(" === Uncaught Python exception: ===")
        print("ValueError: the input quoted here")
        print("Traceback (most recent call last):")
        print(f'  File "{ROOT}/fuzz/fuzz_fake.py", line 3, in TestOneInput')
        print(f'  File "{ROOT}/pkg/core.py", line 2, in check')
        print("==1== ERROR: libFuzzer: fuzz target exited")
        return 77


    def slow():
        print(" === Timeout: 11s elapsed, timeout=10s ===")
        print("Current thread 0x1 (most recent call first):")
        print(f'  File "{ROOT}/pkg/core.py", line 4 in spin')
        print("==1== ERROR: libFuzzer: timeout after 11 seconds")
        return 70


    def verdict(data):
        if data.startswith(b"crash"):
            return crash()
        if data.startswith(b"slow"):
            return slow()
        if data.startswith(b"hang"):
            time.sleep(60)
        return 0


    args = sys.argv[1:]
    options = dict(a[1:].split("=", 1) for a in args if a.startswith("-"))
    paths = [a for a in args if not a.startswith("-")]
    files = [p for p in paths if Path(p).is_file()]
    if files:
        sys.exit(verdict(Path(files[0]).read_bytes()))
    if "merge" in options:
        out, *sources = paths
        kept = sorted(p for d in sources for p in Path(d).iterdir())[:2]
        for path in kept:
            (Path(out) / path.name).write_bytes(path.read_bytes())
        sys.exit(0)
    plan = Path("fuzz-plan")
    data = plan.read_bytes() if plan.exists() else b""
    print("stat::number_of_executed_units: 42")
    if data:
        kind = "timeout-" if data.startswith(b"slow") else "crash-"
        name = options["artifact_prefix"] + kind + hashlib.sha1(data).hexdigest()
        Path(name).write_bytes(data)
        sys.exit(verdict(data))
    """
)


def repository(root: Path, plan: bytes = b"") -> Path:
    """Write a fixture repository holding the stand-in harness."""
    (root / "fuzz").mkdir(parents=True)
    (root / "pkg").mkdir()
    _ = (root / HARNESS).write_text(FAKE, encoding="utf-8")
    _ = (root / "pkg" / "core.py").write_text(CORE, encoding="utf-8")
    if plan:
        _ = (root / "fuzz-plan").write_bytes(plan)
    return root


def fuzzer(tmp_path: Path, plan: bytes = b"", source: Path | None = None) -> fr.Fuzzer:
    """Return a Fuzzer over a fresh fixture repository, pristine unless source."""
    root = repository(tmp_path / "repo", plan)
    for name in ("out", "scratch"):
        (tmp_path / name).mkdir()
    return fr.Fuzzer(
        root,
        Path(sys.executable),
        tmp_path / "out",
        tmp_path / "scratch",
        source or root,
    )


def saved(state: Path, *inputs: bytes) -> Path:
    """Write saved failing inputs into a harness state directory."""
    failures = state / "failures"
    failures.mkdir(parents=True)
    for data in inputs:
        _ = (failures / fs.sha1_hex(data)).write_bytes(data)
    return failures


def test_budget_is_divided_only_past_the_total() -> None:
    """Harnesses keep fuzz_seconds until the total would pass 45 minutes."""
    assert fs.fuzz_budget(9, 300) == 300
    assert fs.fuzz_budget(10, 300) == 270
    assert fs.fuzz_budget(3, 1200) == 900
    assert fs.fuzz_budget(10_000, 300) == 1


def test_replayed_input_that_passes_is_dropped(tmp_path: Path) -> None:
    """A saved input that now passes is deleted and counted as fixed."""
    runner = fuzzer(tmp_path)
    failures = saved(tmp_path / "state", b"fine now")
    run = fr.HarnessRun(HARNESS, 1)
    assert runner.replay(run, failures, {}) == set()
    assert list(failures.iterdir()) == []
    assert run.fixed == 1
    assert run.processes[0].input is None
    assert run.processes[0].fixed is None


def test_replayed_input_that_passes_names_how_it_failed(tmp_path: Path) -> None:
    """A passing replay names every way it failed and keeps its evidence."""
    runner = fuzzer(tmp_path)
    state = tmp_path / "state"
    failures = saved(state, b"fine now")
    prior = [
        [fc.UNCAUGHT, "ValueError", "pkg/core.py", "check", "2"],
        [fc.TIMEOUT, "", "pkg/core.py", "spin", "4"],
    ]
    name = fs.sha1_hex(b"fine now")
    evidence = {name: prior}
    run = fr.HarnessRun(HARNESS, 1)
    _ = runner.replay(run, failures, evidence)
    assert run.processes[0].fixed == prior
    assert run.processes[0].as_json()["fixed"] == prior
    handed = run.processes[0].input
    assert handed is not None
    assert (tmp_path / "out" / handed).read_bytes() == b"fine now"
    assert list(failures.iterdir()) == []
    assert (state / fc.PENDING / name).read_bytes() == b"fine now"
    fs.save_evidence(state, evidence)
    assert fs.load_evidence(state) == {name: prior}


def test_passing_input_waits_for_a_publication(tmp_path: Path) -> None:
    """A passing input replays again until a published state drops it."""
    state = tmp_path / "state"
    harness = state / "abc"
    _ = saved(harness, b"crash")
    (harness / fc.PENDING).mkdir()
    _ = (harness / fc.PENDING / "passed").write_bytes(b"fine now")
    _ = (state / fc.STATE_MARKER).write_text("{}", encoding="utf-8")
    assert fs.prepare_state(state, {"abc"}, "fuzz-state/o/r/1-1")
    assert sorted(path.name for path in (harness / "failures").iterdir()) == sorted(
        [fs.sha1_hex(b"crash"), "passed"]
    )
    assert not (harness / fc.PENDING).exists()
    (harness / fc.PENDING).mkdir()
    _ = (harness / "failures" / "passed").replace(harness / fc.PENDING / "passed")
    assert fs.prepare_state(state, {"abc"}, "fuzz-state/o/r/2-1", published=True)
    assert [path.name for path in (harness / "failures").iterdir()] == [
        fs.sha1_hex(b"crash")
    ]
    assert not (harness / fc.PENDING).exists()


def test_passing_inputs_count_against_the_cap(tmp_path: Path) -> None:
    """An input awaiting publication keeps its room from a new failure."""
    runner = fuzzer(tmp_path, b"slow down")
    state = tmp_path / "state"
    _ = saved(state, *(f"crash {n:02d}".encode() for n in range(fc.MAX_FAILURES - 1)))
    (state / fc.PENDING).mkdir()
    _ = (state / fc.PENDING / "passed").write_bytes(b"fine now")
    run = runner.harness(HARNESS, 1, state)
    assert run.unretained


def test_replayed_input_that_fails_is_kept(tmp_path: Path) -> None:
    """A saved input that still fails is kept and handed over."""
    runner = fuzzer(tmp_path)
    failures = saved(tmp_path / "state", b"crash me")
    run = fr.HarnessRun(HARNESS, 1)
    evidence: dict[str, list[list[str]]] = {}
    known = runner.replay(run, failures, evidence)
    assert known == {(fc.UNCAUGHT, "ValueError", "pkg/core.py", "check")}
    assert evidence == {
        fs.sha1_hex(b"crash me"): [
            [fc.UNCAUGHT, "ValueError", "pkg/core.py", "check", "2"]
        ]
    }
    assert len(list(failures.iterdir())) == 1
    assert run.fixed == 0
    assert run.processes[0].held is None
    handed = run.processes[0].input
    assert handed is not None
    assert (runner.output / handed).read_bytes() == b"crash me"


def test_colliding_inputs_keep_their_own_handover_bytes(tmp_path: Path) -> None:
    """Two replays whose inputs share a SHA-1 hand over distinct files."""
    runner = fuzzer(tmp_path)
    failures = tmp_path / "state" / "failures"
    failures.mkdir(parents=True)
    _ = (failures / "a").write_bytes(b"crash me")
    _ = (failures / "b").write_bytes(b"fine now")
    prior = [[fc.UNCAUGHT, "KeyError", "pkg/core.py", "check", "2"]]
    run = fr.HarnessRun(HARNESS, 1)
    with mock.patch.object(fr, "sha1_hex", return_value="0" * 40):
        _ = runner.replay(run, failures, {"b": prior})
    handed = [process.input for process in run.processes]
    assert None not in handed
    assert len(set(handed)) == 2
    assert [(runner.output / cast("str", name)).read_bytes() for name in handed] == [
        b"crash me",
        b"fine now",
    ]


def test_replay_that_fails_another_way_holds_the_old_way(tmp_path: Path) -> None:
    """A changed failure keeps the identity it was published under."""
    runner = fuzzer(tmp_path)
    failures = saved(tmp_path / "state", b"crash me")
    old = [fc.UNCAUGHT, "KeyError", "pkg/core.py", "check", "2"]
    moved = [fc.UNCAUGHT, "ValueError", "pkg/core.py", "check", "1"]
    name = fs.sha1_hex(b"crash me")
    evidence = {name: [old, moved]}
    run = fr.HarnessRun(HARNESS, 1)
    _ = runner.replay(run, failures, evidence)
    assert run.processes[0].held == [old]
    assert run.processes[0].as_json()["held"] == [old]
    assert evidence == {name: [old, [*moved[:4], "2"]]}
    assert not run.unretained


def test_input_failing_in_too_many_ways_is_unretained(tmp_path: Path) -> None:
    """Past MAX_IDENTITIES ways, the evidence cannot keep every alert open."""
    runner = fuzzer(tmp_path)
    failures = saved(tmp_path / "state", b"crash me")
    prior = [
        [fc.UNCAUGHT, f"Error{n}", "pkg/core.py", "check", "2"]
        for n in range(fc.MAX_IDENTITIES)
    ]
    run = fr.HarnessRun(HARNESS, 1)
    _ = runner.replay(run, failures, {fs.sha1_hex(b"crash me"): prior})
    assert run.unretained


def test_replay_over_the_wall_clock_is_a_harness_error(tmp_path: Path) -> None:
    """A process that overruns its wall-clock limit did not run."""
    runner = fuzzer(tmp_path)
    failures = saved(tmp_path / "state", b"hang")
    run = fr.HarnessRun(HARNESS, 1)
    with mock.patch.object(fr, "REPLAY_WALL", 1):
        known = runner.replay(run, failures, {})
    assert run.processes[0].timed_out
    assert known == {(fc.HARNESS_ERROR, "", HARNESS, fc.PLACEHOLDER)}


def test_new_failure_is_saved(tmp_path: Path) -> None:
    """A failing input the fuzzer finds is saved and handed over."""
    runner = fuzzer(tmp_path, b"crash new")
    state = tmp_path / "state"
    run = runner.harness(HARNESS, 1, state)
    assert [path.read_bytes() for path in (state / "failures").iterdir()] == [
        b"crash new"
    ]
    assert run.executed == 42
    assert run.processes[-1].phase == "fuzz"
    assert run.processes[-1].input is not None
    assert fs.load_evidence(state) == {
        fs.sha1_hex(b"crash new"): [
            [fc.UNCAUGHT, "ValueError", "pkg/core.py", "check", "2"]
        ]
    }


def test_evidence_locates_a_failure_as_the_publish_job_does(tmp_path: Path) -> None:
    """A frame in a file the pristine checkout lacks falls back to the harness."""
    source = tmp_path / "source"
    (source / "fuzz").mkdir(parents=True)
    _ = (source / HARNESS).write_text(FAKE, encoding="utf-8")
    runner = fuzzer(tmp_path, b"crash new", source)
    state = tmp_path / "state"
    _ = runner.harness(HARNESS, 1, state)
    assert fs.load_evidence(state) == {
        fs.sha1_hex(b"crash new"): [
            [fc.UNCAUGHT, "ValueError", HARNESS, "TestOneInput", "3"]
        ]
    }


def test_failure_that_already_fails_the_same_way_is_not_saved(
    tmp_path: Path,
) -> None:
    """A new input reaching a defect a saved input reaches is not saved."""
    runner = fuzzer(tmp_path, b"crash again")
    state = tmp_path / "state"
    _ = saved(state, b"crash first")
    _ = runner.harness(HARNESS, 1, state)
    assert [path.read_bytes() for path in (state / "failures").iterdir()] == [
        b"crash first"
    ]


def test_failure_that_fails_another_way_is_saved(tmp_path: Path) -> None:
    """A new input reaching a different defect is saved beside the old."""
    runner = fuzzer(tmp_path, b"slow down")
    state = tmp_path / "state"
    _ = saved(state, b"crash first")
    _ = runner.harness(HARNESS, 1, state)
    kept = sorted(path.read_bytes() for path in (state / "failures").iterdir())
    assert kept == [b"crash first", b"slow down"]


def test_saved_failures_are_capped(tmp_path: Path) -> None:
    """At most 20 saved inputs survive, none over 1 MiB."""
    failures = saved(tmp_path, *(f"crash {n:02d}".encode() for n in range(25)))
    _ = (failures / "big").write_bytes(b"x" * (fc.MAX_INPUT_BYTES + 1))
    assert fs.cap_failures(failures) == 6
    kept = list(failures.iterdir())
    assert len(kept) == fc.MAX_FAILURES
    assert all(path.stat().st_size <= fc.MAX_INPUT_BYTES for path in kept)


def test_no_room_for_a_new_failure_marks_it_unretained(tmp_path: Path) -> None:
    """A harness at the cap cannot save a new kind of failure."""
    runner = fuzzer(tmp_path, b"slow down")
    state = tmp_path / "state"
    inputs = [f"crash {n:02d}".encode() for n in range(fc.MAX_FAILURES)]
    failures = saved(state, *inputs)
    run = runner.harness(HARNESS, 1, state)
    assert b"slow down" not in [path.read_bytes() for path in failures.iterdir()]
    assert run.unretained


def test_oversized_new_failure_is_unretained(tmp_path: Path) -> None:
    """A new failing input over the size cap cannot be saved."""
    runner = fuzzer(tmp_path, b"crash" + b"x" * fc.MAX_INPUT_BYTES)
    state = tmp_path / "state"
    run = runner.harness(HARNESS, 1, state)
    assert list((state / "failures").iterdir()) == []
    assert run.unretained


def test_colliding_new_failure_keeps_the_saved_input(tmp_path: Path) -> None:
    """A new input whose SHA-1 names a saved input replaces nothing of it."""
    runner = fuzzer(tmp_path, b"slow down")
    state = tmp_path / "state"
    failures = saved(state, b"crash me")
    name = fs.sha1_hex(b"crash me")
    with mock.patch.object(fr, "sha1_hex", return_value=name):
        run = runner.harness(HARNESS, 1, state)
    assert [path.read_bytes() for path in failures.iterdir()] == [b"crash me"]
    assert fs.load_evidence(state) == {
        name: [[fc.UNCAUGHT, "ValueError", "pkg/core.py", "check", "2"]]
    }
    assert run.unretained


def test_known_failure_at_the_cap_is_retained(tmp_path: Path) -> None:
    """At the cap, a failure a saved input already reaches needs no room."""
    runner = fuzzer(tmp_path, b"crash again")
    state = tmp_path / "state"
    _ = saved(state, *(f"crash {n:02d}".encode() for n in range(fc.MAX_FAILURES)))
    run = runner.harness(HARNESS, 1, state)
    assert not run.unretained


def test_fuzz_side_refuses_an_unretained_failure(tmp_path: Path) -> None:
    """The fuzz side hands nothing over when a new input cannot be saved."""
    root = repository(tmp_path / "repo", b"crash" + b"x" * fc.MAX_INPUT_BYTES)
    output = tmp_path / "out"
    code = fp.main(
        [
            "fuzz",
            f"--root={root}",
            f"--source-root={root}",
            f"--python={sys.executable}",
            f"--harnesses={json.dumps([HARNESS])}",
            f"--state={tmp_path / 'state'}",
            f"--output={output}",
            f"--commit={'a' * 40}",
            "--fuzz-seconds=7",
        ]
    )
    assert code == fc.EXIT_REFUSED
    assert not (output / "record.json").exists()
    assert not (tmp_path / "state" / fc.STATE_MARKER).exists()


def test_corpus_past_its_bound_is_merged(tmp_path: Path) -> None:
    """A corpus over the bound is minimised with libFuzzer's merge."""
    runner = fuzzer(tmp_path)
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for n in range(5):
        _ = (corpus / str(n)).write_bytes(b"seed")
    run = fr.HarnessRun(HARNESS, 1)
    with mock.patch.object(fr, "MAX_CORPUS_FILES", 3):
        runner.bound_corpus(run, corpus)
    assert sorted(path.name for path in corpus.iterdir()) == ["0", "1"]
    assert run.processes[0].phase == "merge"


def test_state_without_its_marker_is_not_restored(tmp_path: Path) -> None:
    """State a run did not save is discarded and counts as not restored."""
    state = tmp_path / "state"
    _ = saved(state / "abc", b"crash")
    assert not fs.prepare_state(state, {"abc"}, "fuzz-state/o/r/1-1")
    assert list(state.iterdir()) == []


def test_state_is_bounded_and_pruned(tmp_path: Path) -> None:
    """Restored state keeps only known harnesses; oversized state is reset."""
    state = tmp_path / "state"
    _ = saved(state / "abc", b"crash")
    _ = saved(state / "gone", b"crash")
    (state / "abc" / "link").symlink_to("/etc/passwd")
    _ = (state / fc.STATE_MARKER).write_text("{}", encoding="utf-8")
    assert fs.prepare_state(state, {"abc"}, "fuzz-state/o/r/1-1")
    assert sorted(path.name for path in state.iterdir()) == ["abc", fc.STATE_MARKER]
    assert sorted(path.name for path in (state / "abc").iterdir()) == ["failures"]
    with mock.patch.object(fs, "MAX_STATE_FILES", 1):
        assert not fs.prepare_state(state, {"abc"}, "fuzz-state/o/r/1-1")
    assert list(state.iterdir()) == []


def test_fuzz_side_writes_the_run_record(tmp_path: Path) -> None:
    """The fuzz side records commit, harnesses, seconds and versions.

    It hands the restored evidence binding over as it found it.
    """
    root = repository(tmp_path / "repo", b"crash new")
    output = tmp_path / "out"
    binding = tmp_path / "binding.json"
    _ = binding.write_bytes(b'{"unchecked": true}')
    code = fp.main(
        [
            "fuzz",
            f"--root={root}",
            f"--source-root={root}",
            f"--python={sys.executable}",
            f"--harnesses={json.dumps([HARNESS])}",
            f"--state={tmp_path / 'state'}",
            f"--output={output}",
            f"--commit={'a' * 40}",
            "--fuzz-seconds=7",
            f"--binding={binding}",
        ]
    )
    assert code == 0
    assert (output / "binding.json").read_bytes() == b'{"unchecked": true}'
    record = cast(
        "dict[str, object]",
        json.loads((output / "record.json").read_text(encoding="utf-8")),
    )
    assert record["commit"] == "a" * 40
    assert record["restored"] is False
    assert record["python"] == sys.version.split()[0]
    harnesses = cast("list[dict[str, object]]", record["harnesses"])
    assert [(item["path"], item["seconds"]) for item in harnesses] == [(HARNESS, 7)]
    assert (tmp_path / "state" / fc.STATE_MARKER).is_file()


def test_fuzz_side_refuses_a_harness_that_is_not_a_file(tmp_path: Path) -> None:
    """A harness path that names no regular file stops the run."""
    root = repository(tmp_path / "repo")
    code = fp.main(
        [
            "fuzz",
            f"--root={root}",
            f"--source-root={root}",
            f"--python={sys.executable}",
            '--harnesses=["fuzz/missing.py"]',
            f"--state={tmp_path / 'state'}",
            f"--output={tmp_path / 'out'}",
            f"--commit={'a' * 40}",
        ]
    )
    assert code == fc.EXIT_REFUSED
