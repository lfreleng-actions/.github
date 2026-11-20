# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Unit tests for the evidence side of .github/scripts/fuzz_publish.py.

The publish job counts the open alerts an upload would close without
evidence, and after each processed upload signs which input reproduced
each result. These tests drive both subcommands as the workflow does,
with a binding a fuzz job could have forged. The suite imports nothing
from pytest, so the pre-commit type checkers resolve it without a test
environment.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import io
import json
import os
from typing import TYPE_CHECKING, cast
from unittest import mock

import fuzz_common as fc
import fuzz_evidence as fe
import fuzz_publish as fp

if TYPE_CHECKING:
    from pathlib import Path

KEY = "k" * 32
REPOSITORY = "org/victim"
SARIF_ID = "6f1c1e0a-0000-4000-8000-000000000001"
ALERT = {"rule": fc.UNCAUGHT, "path": "pkg/core.py", "message": "Uncaught KeyError"}
REAL = "1" * 64
HARMLESS = "2" * 64


def run(argv: list[str], key: str = KEY) -> tuple[int, str]:
    """Run a subcommand under the given key; return its code and stdout."""
    out = io.StringIO()
    with (
        mock.patch.dict(os.environ, {fe.KEY_ENV: key}),
        contextlib.redirect_stdout(out),
    ):
        code = fp.main(argv)
    return code, out.getvalue()


class Case:
    """A summary, open alerts and handover written by a test."""

    def __init__(self, base: Path) -> None:
        """Lay out the files under base."""
        self.base: Path = base
        self.handover: Path = base / "handover"
        self.handover.mkdir()

    def summary(self, path: str, summary: dict[str, object]) -> str:
        """Write a summary and return its path."""
        target = self.base / path
        _ = target.write_text(json.dumps(summary), encoding="utf-8")
        return str(target)

    def bind(
        self,
        reported: list[dict[str, str]],
        held: list[dict[str, str]] | None = None,
        /,
        **changes: str,
    ) -> None:
        """Sign a binding for an upload that reported these results.

        The binding already in the handover is the previous one, for
        the analysis SARIF_ID names, unless changes name another.
        """
        summary = self.summary(
            "published.json", {"reported": reported, "held": held or []}
        )
        options = {
            "repository": REPOSITORY,
            "sarif_id": SARIF_ID,
            "previous": SARIF_ID,
            "key": KEY,
        }
        options.update(changes)
        code, _ = run(
            [
                "bind",
                f"--summary={summary}",
                f"--handover={self.handover}",
                f"--repository={options['repository']}",
                f"--sarif-id={options['sarif_id']}",
                f"--previous-sarif-id={options['previous']}",
                f"--output={self.handover / fe.BINDING}",
            ],
            options["key"],
        )
        assert code == 0

    def unproven(self, alerts: list[dict[str, str]], summary: dict[str, object]) -> int:
        """Run the evidence check for the latest analysis; return its count."""
        feed = self.base / "alerts.jsonl"
        _ = feed.write_text("".join(json.dumps(item) + "\n" for item in alerts))
        code, out = run(
            [
                "evidence",
                f"--summary={self.summary('summary.json', summary)}",
                f"--alerts={feed}",
                f"--handover={self.handover}",
                f"--repository={REPOSITORY}",
                f"--sarif-id={SARIF_ID}",
            ]
        )
        assert code == 0
        return int(out)


def fixed_by(digest: str) -> dict[str, object]:
    """Return a summary in which a passing replay of digest names ALERT fixed."""
    return {"restored": True, "reported": [], "fixed": [{**ALERT, "input": digest}]}


def test_open_alert_without_evidence_blocks_the_upload(tmp_path: Path) -> None:
    """An alert neither reported nor proven fixed, as after a stale restore, blocks."""
    case = Case(tmp_path)
    fixed = {**ALERT, "message": "Uncaught ValueError"}
    stale = {**ALERT, "message": "Uncaught TypeError"}
    harness = {"rule": fc.HARNESS_ERROR, "path": "fuzz/f.py", "message": "m"}
    case.bind([{**fixed, "input": REAL}])
    restored: dict[str, object] = {
        "restored": True,
        "reported": [ALERT],
        "fixed": [{**fixed, "input": REAL}],
    }
    assert case.unproven([ALERT, fixed, harness], restored) == 0
    assert case.unproven([ALERT, stale], restored) == 1
    lost: dict[str, object] = {"restored": False, "reported": [ALERT], "fixed": []}
    assert case.unproven([ALERT, harness], lost) == 1


def test_evidence_check_compares_decoded_paths(tmp_path: Path) -> None:
    """A reported path matches its alert decoded, not as its SARIF URI."""
    case = Case(tmp_path)
    alert = {"rule": fc.TIMEOUT, "path": "pkg/a%20b.py", "message": "m"}
    decoded: dict[str, object] = {"restored": True, "reported": [alert], "fixed": []}
    assert case.unproven([alert], decoded) == 0
    encoded = {**alert, "path": "pkg/a%2520b.py"}
    wrong: dict[str, object] = {"restored": True, "reported": [encoded], "fixed": []}
    assert case.unproven([alert], wrong) == 1


def test_fixed_claim_needs_the_input_the_binding_ties_to_the_alert(
    tmp_path: Path,
) -> None:
    """A forged state pairing a harmless input with the alert closes nothing."""
    case = Case(tmp_path)
    case.bind([{**ALERT, "input": REAL}])
    assert case.unproven([ALERT], fixed_by(HARMLESS)) == 1
    assert case.unproven([ALERT], fixed_by(REAL)) == 0


def test_forged_or_stale_bindings_prove_nothing(tmp_path: Path) -> None:
    """Only a binding this key signed, for this repository and analysis, counts."""
    case = Case(tmp_path)
    assert case.unproven([ALERT], fixed_by(REAL)) == 1
    for changes in (
        {"key": "x" * 32},
        {"repository": "org/attacker"},
        {"sarif_id": "6f1c1e0a-0000-4000-8000-000000000000"},
    ):
        case.bind([{**ALERT, "input": REAL}], **changes)
        assert case.unproven([ALERT], fixed_by(REAL)) == 1, changes
    case.bind([{**ALERT, "input": HARMLESS}])
    path = case.handover / fe.BINDING
    binding = cast("dict[str, object]", json.loads(path.read_text()))
    binding["entries"] = [[*ALERT.values(), REAL]]
    _ = path.write_text(json.dumps(binding))
    assert case.unproven([ALERT], fixed_by(REAL)) == 1
    for junk in ("[]", "{", '{"schema": 1, "entries": [[1, 2, 3, 4]], "mac": ""}'):
        _ = path.write_text(junk)
        assert case.unproven([ALERT], fixed_by(REAL)) == 1, junk


def test_sha1_or_v1_bindings_prove_nothing(tmp_path: Path) -> None:
    """A binding of SHA-1 digests, or one signed as v1, closes nothing."""
    case = Case(tmp_path)
    path = case.handover / fe.BINDING
    sha1 = "1" * 40
    rule, file, text = ALERT.values()
    v1 = ["lfrelengFuzzBinding/v1", REPOSITORY, SARIF_ID, [[*ALERT.values(), REAL]]]
    signed = (
        fe.sign(KEY.encode(), REPOSITORY, SARIF_ID, [(rule, file, text, sha1)]),
        hmac.new(
            KEY.encode(),
            json.dumps(v1, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).hexdigest(),
    )
    for digest, mac in zip((sha1, REAL), signed, strict=True):
        binding = {
            "schema": fc.SCHEMA,
            "repository": REPOSITORY,
            "sarif_id": SARIF_ID,
            "entries": [[*ALERT.values(), digest]],
            "mac": mac,
        }
        _ = path.write_text(json.dumps(binding))
        assert case.unproven([ALERT], fixed_by(digest)) == 1, digest


def test_bind_signs_only_results_with_an_input(tmp_path: Path) -> None:
    """A harness error has no input, so the binding holds nothing for it."""
    case = Case(tmp_path)
    harness = {"rule": fc.HARNESS_ERROR, "path": "fuzz/f.py", "message": "m"}
    case.bind([{**ALERT, "input": REAL}, harness])
    binding = json.loads((case.handover / fe.BINDING).read_text())
    assert binding["entries"] == [[*ALERT.values(), REAL]]


def test_held_failure_is_bound_only_when_the_previous_binding_holds_it(
    tmp_path: Path,
) -> None:
    """A poisoned state pairing an alert with another failing input signs nothing."""
    case = Case(tmp_path)
    other = {**ALERT, "message": "Uncaught ValueError"}
    case.bind([{**other, "input": HARMLESS}], [{**ALERT, "input": HARMLESS}])
    binding = json.loads((case.handover / fe.BINDING).read_text())
    assert binding["entries"] == [[*other.values(), HARMLESS]]
    assert case.unproven([ALERT], fixed_by(HARMLESS)) == 1
    case.bind([{**ALERT, "input": REAL}])
    case.bind([{**other, "input": REAL}], [{**ALERT, "input": REAL}])
    assert case.unproven([ALERT], fixed_by(REAL)) == 0
    case.bind([], [{**ALERT, "input": REAL}], previous="0" * 8)
    assert case.unproven([ALERT], fixed_by(REAL)) == 1


def test_a_short_or_missing_key_is_refused(tmp_path: Path) -> None:
    """Without the key nothing is checked or signed, so the job fails."""
    case = Case(tmp_path)
    summary = case.summary("summary.json", {"reported": []})
    feed = tmp_path / "alerts.jsonl"
    _ = feed.write_text("")
    common = [f"--summary={summary}", f"--repository={REPOSITORY}"]
    for key in ("", "short"):
        evidence = ["evidence", *common, f"--alerts={feed}", f"--handover={tmp_path}"]
        assert run(evidence, key)[0] == fc.EXIT_REFUSED
        bind = ["bind", *common, f"--handover={tmp_path}", f"--sarif-id={SARIF_ID}"]
        assert run([*bind, f"--output={tmp_path}/b"], key)[0] == fc.EXIT_REFUSED
    empty = ["bind", *common, f"--handover={tmp_path}", "--sarif-id="]
    assert run([*empty, f"--output={tmp_path}/b"])[0] == fc.EXIT_REFUSED
