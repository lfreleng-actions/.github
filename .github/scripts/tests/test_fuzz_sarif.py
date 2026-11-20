# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Unit tests for the SARIF side of .github/scripts/fuzz_publish.py and its modules.

Each test writes a handover by hand, as a hostile fuzz job could, and
a checkout to validate it against, then runs the builder the way the
publish job does. The suite imports nothing from pytest, so the
pre-commit type checkers resolve it without a test environment.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from typing import cast

import fuzz_common as fc
import fuzz_publish as fp
import fuzz_state as fs

HARNESS = "fuzz/fuzz_parse.py"
COMMIT = "c" * 40
ROOT = "/home/runner/work/fuzz/target"
FINGERPRINT = Path(__file__).resolve().parent.parent / "sarif_fingerprint.py"
PUBLISH = Path(__file__).resolve().parent.parent / "fuzz_publish.py"
SOURCE = "".join(f"line {n}\n" for n in range(1, 11))
MESSAGES = re.compile(
    r"Uncaught [\w.<>]+ in [\w.<>]+, reached from fuzz harness \S+"
    r"|Input exceeds the time limit in [\w.<>]+, reached from fuzz harness \S+"
    r"|Input exceeds the memory limit, reached from fuzz harness \S+"
    r"|Fuzz harness \S+ did not run"
)
Result = dict[str, object]


def uncaught(
    exception: str = "ValueError",
    frames: tuple[tuple[str, int, str], ...] = (
        (f"{ROOT}/{HARNESS}", 4, "TestOneInput"),
        (f"{ROOT}/pkg/core.py", 7, "check"),
    ),
) -> str:
    """Return an Atheris uncaught-exception log."""
    lines = [
        "INFO: Seed: 1",
        " === Uncaught Python exception: ===",
        f"{exception}: the input b'\\x00secret' quoted here",
        "Traceback (most recent call last):",
        *(f'  File "{p}", line {n}, in {f}' for p, n, f in frames),
        "",
        "==9== ERROR: libFuzzer: fuzz target exited",
    ]
    return "\n".join(lines) + "\n"


def timeout() -> str:
    """Return an Atheris timeout log, most recent call first."""
    return (
        " === Timeout: 11s elapsed, timeout=10s ===\n"
        "Current thread 0x7f (most recent call first):\n"
        f'  File "{ROOT}/pkg/core.py", line 9 in spin\n'
        f'  File "{ROOT}/pkg/core.py", line 3 in check\n'
        f'  File "{ROOT}/{HARNESS}", line 4 in TestOneInput\n'
        "==9== ERROR: libFuzzer: timeout after 11 seconds\n"
    )


class Handover:
    """A handover directory and checkout written by a test."""

    def __init__(self, base: Path) -> None:
        """Create the checkout and an empty handover under base."""
        self.base: Path = base
        self.checkout: Path = base / "checkout"
        self.handover: Path = base / "handover"
        for relative in (HARNESS, "pkg/core.py"):
            path = self.checkout / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            _ = path.write_text(SOURCE, encoding="utf-8")
        self.handover.mkdir()
        self.processes: list[dict[str, object]] = []
        self.record: dict[str, object] = {}
        self.summary_file: Path = base / "summary.json"

    def summary(self) -> dict[str, object]:
        """Return the summary the last build wrote."""
        return cast("dict[str, object]", json.loads(self.summary_file.read_text()))

    def process(
        self,
        log: str | bytes,
        exit_code: int | None,
        *,
        phase: str = "fuzz",
        data: bytes | bool = True,
        timed_out: bool = False,
    ) -> None:
        """Add one process with its log and optional failing input.

        A failing process gets an input of its own, as the fuzz side
        hands one over, unless data names one or is False.
        """
        name = f"logs/k/{len(self.processes):03d}-{phase}.log"
        failing = exit_code not in {0, None} and phase != "merge"
        if data is True:
            data = f"input {len(self.processes)}".encode() if failing else False
        path = self.handover / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(log, str):
            _ = path.write_text(log, encoding="utf-8")
        else:
            _ = path.write_bytes(log)
        entry: dict[str, object] = {
            "phase": phase,
            "log": name,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "input": None,
        }
        if isinstance(data, bytes):
            input_name = f"inputs/k/{fs.sha1_hex(data)}"
            target = self.handover / input_name
            target.parent.mkdir(parents=True, exist_ok=True)
            _ = target.write_bytes(data)
            entry["input"] = input_name
        self.processes.append(entry)

    def write(self, **changes: object) -> None:
        """Write the run record, with any top-level fields replaced."""
        if not any(item["phase"] == "fuzz" for item in self.processes):
            self.process("stat::number_of_executed_units: 5\n", 0)
        record: dict[str, object] = {
            "schema": fc.SCHEMA,
            "commit": COMMIT,
            "root": ROOT,
            "restored": True,
            "python": "3.13.0",
            "atheris": "3.1.0",
            "harnesses": [
                {
                    "path": HARNESS,
                    "seconds": 300,
                    "executed": 5,
                    "fixed": 0,
                    "processes": self.processes,
                }
            ],
        }
        record.update(changes)
        _ = (self.handover / "record.json").write_text(
            json.dumps(record), encoding="utf-8"
        )

    def build(self, harnesses: list[str] | None = None) -> tuple[int, list[Result]]:
        """Run the builder; return its exit code and the results written."""
        output = self.base / "fuzz.sarif"
        output.unlink(missing_ok=True)
        self.summary_file.unlink(missing_ok=True)
        code = fp.main(
            [
                "sarif",
                f"--handover={self.handover}",
                f"--source-root={self.checkout}",
                f"--commit={COMMIT}",
                f"--harnesses={json.dumps(harnesses or [HARNESS])}",
                f"--output={output}",
                f"--summary={self.summary_file}",
            ]
        )
        if not output.exists():
            return code, []
        log = cast("dict[str, list[dict[str, object]]]", json.loads(output.read_text()))
        return code, cast("list[Result]", log["runs"][0]["results"])

    def built(self) -> list[Result]:
        """Write the record, build, and return results checked for form."""
        self.write()
        code, results = self.build()
        assert code == 0
        for result in results:
            assert MESSAGES.fullmatch(message(result)), message(result)
            assert result["level"] == "error"
        return results


def message(result: Result) -> str:
    """Return a result's message text."""
    return cast("dict[str, str]", result["message"])["text"]


def where(result: Result) -> tuple[str, int]:
    """Return a result's file and line."""
    locations = cast(
        "list[dict[str, dict[str, dict[str, object]]]]", result["locations"]
    )
    physical = locations[0]["physicalLocation"]
    uri = cast("str", physical["artifactLocation"]["uri"])
    return uri, cast("int", physical["region"]["startLine"])


def test_uncaught_exception(tmp_path: Path) -> None:
    """An uncaught exception points at the deepest repository frame."""
    case = Handover(tmp_path)
    case.process(uncaught(), 77, data=b"\x00secret")
    [result] = case.built()
    assert result["ruleId"] == fc.UNCAUGHT
    assert message(result) == (
        f"Uncaught ValueError in check, reached from fuzz harness {HARNESS}"
    )
    assert where(result) == ("pkg/core.py", 7)
    assert result["properties"] == {
        "harness": HARNESS,
        "exceptionType": "ValueError",
        "inputSha1": fs.sha1_hex(b"\x00secret"),
        "inputSha256": fs.sha256_hex(b"\x00secret"),
    }


def test_timeout(tmp_path: Path) -> None:
    """A timeout points at the most recent repository frame."""
    case = Handover(tmp_path)
    case.process(timeout(), 70, data=b"slow")
    [result] = case.built()
    assert result["ruleId"] == fc.TIMEOUT
    assert message(result) == (
        f"Input exceeds the time limit in spin, reached from fuzz harness {HARNESS}"
    )
    assert where(result) == ("pkg/core.py", 9)


def test_out_of_memory(tmp_path: Path) -> None:
    """An out-of-memory input points at the harness file."""
    case = Handover(tmp_path)
    case.process("==9== ERROR: libFuzzer: out-of-memory (used: 2100Mb)\n", 71)
    [result] = case.built()
    assert result["ruleId"] == fc.OUT_OF_MEMORY
    assert message(result) == (
        f"Input exceeds the memory limit, reached from fuzz harness {HARNESS}"
    )
    assert where(result) == (HARNESS, 1)


def test_harness_error(tmp_path: Path) -> None:
    """A harness that cannot start, or overran its wall clock, did not run."""
    case = Handover(tmp_path)
    case.process("Traceback (most recent call last):\nImportError: no\n", 1)
    case.process("", None, timed_out=True)
    [result] = case.built()
    assert result["ruleId"] == fc.HARNESS_ERROR
    assert message(result) == f"Fuzz harness {HARNESS} did not run"
    assert where(result) == (HARNESS, 1)


def test_replay_without_a_verdict_is_refused(tmp_path: Path) -> None:
    """A saved input that could not be replayed blocks the upload."""
    for log, code, timed_out in (
        ("Traceback (most recent call last):\nImportError: no\n", 1, False),
        ("", None, True),
    ):
        case = Handover(tmp_path / str(len(list(tmp_path.iterdir()))))
        case.process(log, code, phase="replay", data=b"saved", timed_out=timed_out)
        case.write()
        assert case.build() == (fc.EXIT_REFUSED, []), log


def test_defect_without_a_reproducer_is_refused(tmp_path: Path) -> None:
    """Each defect but a harness error needs a handed-over input."""
    for log, code in (
        (uncaught(), 77),
        (timeout(), 70),
        ("==9== ERROR: libFuzzer: out-of-memory\n", 71),
    ):
        case = Handover(tmp_path / str(len(list(tmp_path.iterdir()))))
        case.process(log, code, data=False)
        case.write()
        assert case.build() == (fc.EXIT_REFUSED, []), log


def test_duplicate_defect_relies_on_another_reproducer(tmp_path: Path) -> None:
    """A process with no input may reach a defect another input reproduces."""
    case = Handover(tmp_path)
    case.process(uncaught(), 77, data=False)
    case.process(uncaught(), 77, phase="replay", data=b"saved")
    [result] = case.built()
    properties = cast("dict[str, str]", result["properties"])
    assert properties["inputSha1"] == fs.sha1_hex(b"saved")


def test_fingerprint_is_the_alert_identity(tmp_path: Path) -> None:
    """An edit to the failing line keeps the fingerprint; another defect differs."""
    fingerprints: list[str] = []
    for source in (SOURCE, SOURCE.replace("line 7", "edited")):
        case = Handover(tmp_path / str(len(fingerprints)))
        _ = (case.checkout / "pkg" / "core.py").write_text(source, encoding="utf-8")
        case.process(uncaught(), 77)
        case.process(uncaught("KeyError"), 77)
        first, second = case.built()
        held = [
            cast("dict[str, str]", item["partialFingerprints"])[fc.FINGERPRINT_KEY]
            for item in (first, second)
        ]
        assert held[0] != held[1]
        fingerprints.append(held[0])
    assert fingerprints[0] == fingerprints[1]


def test_path_is_uri_encoded_and_reported_decoded(tmp_path: Path) -> None:
    """A '%' or space in a file name is escaped in the URI, not in the summary."""
    case = Handover(tmp_path)
    name = "pkg/a%20b c.py"
    _ = (case.checkout / name).write_text(SOURCE, encoding="utf-8")
    frames = ((f"{ROOT}/{HARNESS}", 4, "TestOneInput"), (f"{ROOT}/{name}", 7, "check"))
    case.process(uncaught(frames=frames), 77)
    [result] = case.built()
    assert where(result) == ("pkg/a%2520b%20c.py", 7)
    assert case.summary()["reported"] == [
        {
            "rule": fc.UNCAUGHT,
            "path": name,
            "message": message(result),
            "input": fs.sha256_hex(b"input 0"),
        }
    ]


def test_passing_replay_names_the_alerts_it_fixes(tmp_path: Path) -> None:
    """The summary lists each identity of each passing input, with its SHA-256."""
    case = Handover(tmp_path)
    fixed: list[list[list[str]]] = [
        [
            [fc.UNCAUGHT, "ValueError", "pkg/core.py", "check", "7"],
            [fc.UNCAUGHT, "KeyError", "pkg/gone.py", "check", "3"],
        ],
        [[fc.TIMEOUT, "", "pkg/core.py", "spin; rm -rf /", "9"]],
        [[fc.UNCAUGHT, "ValueError", "../outside.py", "check", "1"]],
        [[fc.HARNESS_ERROR, "", HARNESS, fc.PLACEHOLDER, "1"]],
    ]
    for index, item in enumerate(fixed):
        case.process("Running: x\n", 0, phase="replay", data=f"saved {index}".encode())
        case.processes[-1]["fixed"] = item
    assert case.built() == []
    first = fs.sha256_hex(b"saved 0")
    assert case.summary()["fixed"] == [
        {
            "rule": fc.UNCAUGHT,
            "path": "pkg/core.py",
            "message": f"Uncaught ValueError in check, reached from fuzz harness {HARNESS}",
            "input": first,
        },
        {
            "rule": fc.UNCAUGHT,
            "path": "pkg/gone.py",
            "message": f"Uncaught KeyError in check, reached from fuzz harness {HARNESS}",
            "input": first,
        },
        {
            "rule": fc.TIMEOUT,
            "path": "pkg/core.py",
            "message": (
                f"Input exceeds the time limit in {fc.PLACEHOLDER},"
                f" reached from fuzz harness {HARNESS}"
            ),
            "input": fs.sha256_hex(b"saved 1"),
        },
    ]


def test_passing_replay_without_its_input_is_refused(tmp_path: Path) -> None:
    """A fixed claim needs the input that passed, for the binding to check."""
    case = Handover(tmp_path)
    case.process("Running: x\n", 0, phase="replay", data=False)
    case.processes[-1]["fixed"] = [[fc.UNCAUGHT, "ValueError", "pkg/core.py", "f", "7"]]
    case.write()
    assert case.build() == (fc.EXIT_REFUSED, [])


def test_failing_replay_keeps_reporting_how_it_failed_before(
    tmp_path: Path,
) -> None:
    """A saved input that now fails another way keeps its old alerts open."""
    case = Handover(tmp_path)
    case.process(uncaught("KeyError"), 77, phase="replay", data=b"saved")
    case.processes[-1]["held"] = [
        [fc.UNCAUGHT, "ValueError", "pkg/core.py", "check", "7"],
        [fc.TIMEOUT, "", "pkg/core.py", "spin", "99"],
        [fc.UNCAUGHT, "ValueError", "pkg/gone.py", "check", "2"],
        [fc.HARNESS_ERROR, "", HARNESS, fc.PLACEHOLDER, "1"],
    ]
    results = case.built()
    assert [(message(r), where(r)) for r in results] == [
        (
            f"Uncaught KeyError in check, reached from fuzz harness {HARNESS}",
            ("pkg/core.py", 7),
        ),
        (
            f"Uncaught ValueError in check, reached from fuzz harness {HARNESS}",
            ("pkg/core.py", 7),
        ),
        (
            f"Input exceeds the time limit in spin, reached from fuzz harness {HARNESS}",
            ("pkg/core.py", 1),
        ),
    ]
    sha = fs.sha1_hex(b"saved")
    assert all(
        cast("dict[str, str]", r["properties"])["inputSha1"] == sha for r in results
    )
    bound = fs.sha256_hex(b"saved")
    reported = cast("list[dict[str, str]]", case.summary()["reported"])
    assert [item.get("input") for item in reported] == [bound, None, None]
    held = [{**item, "input": bound} for item in reported[1:]]
    assert case.summary()["held"] == held


def test_observed_input_wins_over_a_held_one(tmp_path: Path) -> None:
    """A defect an input reproduces takes that input, not one the state pairs it with."""
    case = Handover(tmp_path)
    case.process(uncaught("KeyError"), 77, phase="replay", data=b"other")
    case.processes[-1]["held"] = [
        [fc.UNCAUGHT, "ValueError", "pkg/core.py", "check", "7"],
    ]
    case.process(uncaught(), 77, phase="replay", data=b"real")
    _, result = case.built()
    properties = cast("dict[str, str]", result["properties"])
    assert properties["inputSha1"] == fs.sha1_hex(b"real")
    assert properties["inputSha256"] == fs.sha256_hex(b"real")
    reported = cast("list[dict[str, str]]", case.summary()["reported"])
    assert reported[1]["input"] == fs.sha256_hex(b"real")
    held = cast("list[dict[str, str]]", case.summary()["held"])
    assert [item["input"] for item in held] == [fs.sha256_hex(b"other")]


def test_identities_off_their_replay_are_refused(tmp_path: Path) -> None:
    """Fixed off a passing replay, held off a failing one, or malformed, write nothing."""
    last = [fc.UNCAUGHT, "ValueError", "pkg/core.py", "check", "7"]
    cases: list[tuple[str, str, int, object]] = [
        ("fixed", "fuzz", 0, [last]),
        ("fixed", "replay", 77, [last]),
        ("held", "replay", 0, [last]),
        ("held", "fuzz", 77, [last]),
        ("fixed", "replay", 0, last),
        ("fixed", "replay", 0, []),
        ("fixed", "replay", 0, [last[:4]]),
        ("held", "replay", 77, [[*last[:4], "0"]]),
        ("held", "replay", 77, [[*last[:4], 7]]),
        ("held", "replay", 77, [last] * (fc.MAX_IDENTITIES + 1)),
    ]
    for key, phase, code, identities in cases:
        case = Handover(tmp_path / str(len(list(tmp_path.iterdir()))))
        log = uncaught() if code else "Running: x\n"
        case.process(log, code, phase=phase)
        case.processes[-1][key] = identities
        case.write()
        assert case.build() == (fc.EXIT_REFUSED, []), (key, phase, code, identities)


def test_two_inputs_reaching_one_defect_give_one_result(tmp_path: Path) -> None:
    """Results are unique on rule, harness, file, function and exception."""
    case = Handover(tmp_path)
    case.process(uncaught(), 77, phase="replay", data=b"one")
    case.process(uncaught(), 77, data=b"two")
    case.process(uncaught("KeyError"), 77, phase="replay", data=b"three")
    results = case.built()
    assert [
        cast("dict[str, str]", r["properties"])["exceptionType"] for r in results
    ] == [
        "ValueError",
        "KeyError",
    ]


def test_clean_run_still_uploads(tmp_path: Path) -> None:
    """A clean repository gets a fuzz run with no results."""
    case = Handover(tmp_path)
    case.process("stat::number_of_executed_units: 99\n", 0)
    case.process("Running: x\n", 0, phase="replay")
    case.process("merge noise", 1, phase="merge")
    assert case.built() == []


def test_frame_outside_the_checkout_falls_back(tmp_path: Path) -> None:
    """A frame outside the checkout is skipped for the harness frame."""
    case = Handover(tmp_path)
    frames = (
        (f"{ROOT}/{HARNESS}", 4, "TestOneInput"),
        ("/usr/lib/python3.13/json/decoder.py", 3, "decode"),
        (f"{ROOT}/../../etc/passwd", 1, "x"),
        ("../outside.py", 1, "y"),
    )
    case.process(uncaught(frames=frames), 77)
    [result] = case.built()
    assert where(result) == (HARNESS, 4)
    assert message(result).endswith(
        f"in TestOneInput, reached from fuzz harness {HARNESS}"
    )


def test_frame_through_a_symlink_falls_back(tmp_path: Path) -> None:
    """A checkout path through a symlink is not a file inside the checkout."""
    case = Handover(tmp_path)
    (case.checkout / "link").symlink_to(case.base)
    frames = ((f"{ROOT}/link/checkout/pkg/core.py", 2, "check"),)
    case.process(uncaught(frames=frames), 77)
    [result] = case.built()
    assert where(result) == (HARNESS, 1)


def test_line_past_the_end_falls_back(tmp_path: Path) -> None:
    """A line the file does not have falls back to the harness file."""
    case = Handover(tmp_path)
    frames = ((f"{ROOT}/pkg/core.py", 11, "check"), (f"{ROOT}/pkg/core.py", 0, "x"))
    case.process(uncaught(frames=frames), 77)
    [result] = case.built()
    assert where(result) == (HARNESS, 1)
    assert fc.PLACEHOLDER in message(result)


def test_names_that_are_not_identifiers_become_placeholders(tmp_path: Path) -> None:
    """Exception and function names are plain dotted identifiers or a placeholder."""
    case = Handover(tmp_path)
    frames = ((f"{ROOT}/pkg/core.py", 2, "check; rm -rf /"),)
    case.process(uncaught("Evil Error`$(x)`", frames), 77)
    case.process(
        uncaught("pkg.errors.Bad", ((f"{ROOT}/pkg/core.py", 3, "<module>"),)), 77
    )
    first, second = case.built()
    assert message(first) == (
        f"Uncaught {fc.PLACEHOLDER} in {fc.PLACEHOLDER}, reached from fuzz harness {HARNESS}"
    )
    assert message(second) == (
        f"Uncaught pkg.errors.Bad in <module>, reached from fuzz harness {HARNESS}"
    )


def test_log_too_large_to_read_whole_is_read_from_its_tail(tmp_path: Path) -> None:
    """Only the last LOG_LIMIT bytes of a log are read."""
    case = Handover(tmp_path)
    noise = "INFO: noise ValueError: quoted\n" * (fc.LOG_LIMIT // 16)
    case.process(noise + uncaught(), 77)
    [result] = case.built()
    assert result["ruleId"] == fc.UNCAUGHT
    assert where(result) == ("pkg/core.py", 7)


def test_binary_noise_is_a_harness_error(tmp_path: Path) -> None:
    """A log of binary noise yields the fixed harness-error result."""
    case = Handover(tmp_path)
    case.process(bytes(range(256)) * 64, 77)
    [result] = case.built()
    assert result["ruleId"] == fc.HARNESS_ERROR


def test_record_that_omits_a_harness_is_refused(tmp_path: Path) -> None:
    """A record that does not cover every discovered harness is refused."""
    case = Handover(tmp_path)
    case.write()
    code, results = case.build([HARNESS, "fuzz/fuzz_other.py"])
    assert code == fc.EXIT_REFUSED
    assert results == []
    assert not (tmp_path / "fuzz.sarif").exists()


def test_hostile_records_are_refused(tmp_path: Path) -> None:
    """A malformed record, or one naming files outside it, writes nothing."""
    hostile: list[dict[str, object]] = [
        {"commit": "d" * 40},
        {"schema": 2},
        {"restored": "yes"},
        {"root": "relative"},
        {"harnesses": "fuzz/fuzz_parse.py"},
    ]
    for changes in hostile:
        case = Handover(tmp_path / str(len(list(tmp_path.iterdir()))))
        case.write(**changes)
        assert case.build() == (fc.EXIT_REFUSED, []), changes
    for log in ("../../checkout/pkg/core.py", "/etc/passwd", "logs/missing"):
        case = Handover(tmp_path / str(len(list(tmp_path.iterdir()))))
        case.process("", 0)
        case.processes[0]["log"] = log
        case.write()
        assert case.build() == (fc.EXIT_REFUSED, []), log


def test_symlinked_log_and_missing_record_are_refused(tmp_path: Path) -> None:
    """A log that is a symlink, or no record at all, writes nothing."""
    case = Handover(tmp_path / "link")
    case.process("", 0)
    log = case.handover / cast("str", case.processes[0]["log"])
    log.unlink()
    log.symlink_to(case.checkout / "pkg" / "core.py")
    case.write()
    assert case.build() == (fc.EXIT_REFUSED, [])
    empty = Handover(tmp_path / "empty")
    assert empty.build() == (fc.EXIT_REFUSED, [])


def test_isolated_launch_finds_the_sibling_modules(tmp_path: Path) -> None:
    """Under python -I, as the workflow runs it, the entry point still imports."""
    case = Handover(tmp_path)
    case.process(uncaught(), 77, data=b"boom")
    case.write()
    output = tmp_path / "isolated.sarif"
    _ = subprocess.run(
        [
            sys.executable,
            "-I",
            str(PUBLISH),
            "sarif",
            f"--handover={case.handover}",
            f"--source-root={case.checkout}",
            f"--commit={COMMIT}",
            f"--harnesses={json.dumps([HARNESS])}",
            f"--output={output}",
        ],
        check=True,
        cwd=tmp_path,
        capture_output=True,
    )
    log = cast(
        "dict[str, list[dict[str, list[object]]]]", json.loads(output.read_text())
    )
    assert len(log["runs"][0]["results"]) == 1


def test_output_passes_fingerprint_and_upload_guards(tmp_path: Path) -> None:
    """The builder's SARIF survives sarif_fingerprint.py and both jq guards."""
    jq = shutil.which("jq")
    if jq is None:
        reason = "jq is not installed"
        raise unittest.SkipTest(reason)
    case = Handover(tmp_path)
    case.process(uncaught(), 77, data=b"boom")
    case.process(timeout(), 70, data=b"slow")
    case.write()
    assert case.build()[0] == 0
    printed = tmp_path / "printed.sarif"
    _ = subprocess.run(
        [
            sys.executable,
            "-I",
            str(FINGERPRINT),
            f"--input={tmp_path / 'fuzz.sarif'}",
            f"--output={printed}",
            f"--source-root={case.checkout}",
        ],
        check=True,
    )
    stamped = subprocess.run(
        [jq, '.runs[].automationDetails.id = "fuzz/"', str(printed)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    category = (
        '(.runs | type == "array" and length > 0)'
        ' and all(.runs[]; .automationDetails.id == "fuzz/")'
    )
    fingerprinted = (
        'all(.runs[].results[]?; .partialFingerprints["lfrelengContentHash/v1"]'
        ' | type == "string" and length > 0)'
    )
    for guard in (category, fingerprinted):
        _ = subprocess.run(
            [jq, "-e", guard], input=stamped, check=True, capture_output=True, text=True
        )
    log = cast(
        "dict[str, list[dict[str, dict[str, dict[str, str]]]]]", json.loads(stamped)
    )
    assert log["runs"][0]["tool"]["driver"]["name"] == "fuzz"
    built = cast(
        "dict[str, list[dict[str, list[dict[str, object]]]]]",
        json.loads((tmp_path / "fuzz.sarif").read_text()),
    )
    printed_results = cast("list[dict[str, object]]", log["runs"][0]["results"])
    assert [r["partialFingerprints"] for r in printed_results] == [
        r["partialFingerprints"] for r in built["runs"][0]["results"]
    ]
