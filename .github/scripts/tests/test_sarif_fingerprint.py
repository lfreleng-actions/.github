# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Contract tests for .github/scripts/sarif_fingerprint.py.

Each test runs the script as a subprocess, as the SARIF publishers do,
against a throwaway checkout and a hand-written SARIF log, then reads
back the fingerprints it wrote. The suite imports nothing from pytest,
so the pre-commit type checkers resolve it without a test environment.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import cast

SCRIPT = Path(__file__).resolve().parent.parent / "sarif_fingerprint.py"
KEY = "lfrelengContentHash/v1"
EXIT_USAGE = 2
CSS = "a { color: red; }\n.unused { margin: 0; }\nb { color: blue; }\n"
Log = dict[str, list[dict[str, list[dict[str, dict[str, str]]]]]]


def result(
    rule: str = "ai-slop/unused-css",
    uri: str | None = "style.css",
    *,
    line: int | None = 2,
    message: str = "unused selector",
) -> dict[str, object]:
    """Build one SARIF result with an optional primary location."""
    body: dict[str, object] = {"ruleId": rule, "message": {"text": message}}
    if uri is not None:
        physical: dict[str, object] = {"artifactLocation": {"uri": uri}}
        if line is not None:
            physical["region"] = {"startLine": line}
        body["locations"] = [{"physicalLocation": physical}]
    return body


def run_script(root: Path, log: object) -> subprocess.CompletedProcess[str]:
    """Write log beside root, run the script over it and return the process."""
    source = root.parent / "in.sarif"
    _ = source.write_text(json.dumps(log), encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            "-I",
            str(SCRIPT),
            f"--input={source}",
            f"--output={root.parent / 'out.sarif'}",
            f"--source-root={root}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def read_output(root: Path) -> Log:
    """Return the SARIF log the script wrote beside root."""
    text = (root.parent / "out.sarif").read_text(encoding="utf-8")
    return cast("Log", json.loads(text))


def fingerprints(root: Path, results: list[dict[str, object]]) -> list[str]:
    """Return the new fingerprint of each result, in order."""
    proc = run_script(root, {"version": "2.1.0", "runs": [{"results": results}]})
    assert proc.returncode == 0, proc.stderr
    out = read_output(root)
    return [item["partialFingerprints"][KEY] for item in out["runs"][0]["results"]]


def checkout(tmp_path: Path, files: dict[str, str]) -> Path:
    """Create a checkout directory holding the given files."""
    root = tmp_path / "repo"
    root.mkdir(parents=True)
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        _ = path.write_text(text, encoding="utf-8")
    return root


def test_moving_the_line_keeps_the_fingerprint(tmp_path: Path) -> None:
    """Lines added or removed above a finding leave it unchanged."""
    before = fingerprints(checkout(tmp_path / "a", {"style.css": CSS}), [result()])
    down = fingerprints(
        checkout(tmp_path / "b", {"style.css": "x {}\ny {}\n" + CSS}),
        [result(line=4)],
    )
    up = fingerprints(
        checkout(tmp_path / "c", {"style.css": CSS.split("\n", 1)[1]}),
        [result(line=1)],
    )
    assert before == down == up


def test_surrounding_whitespace_is_ignored(tmp_path: Path) -> None:
    """Re-indenting the flagged line keeps the fingerprint."""
    plain = fingerprints(checkout(tmp_path / "a", {"style.css": CSS}), [result()])
    spaced = CSS.replace(".unused { margin: 0; }", "\t  .unused  {\tmargin: 0; }  ")
    indented = fingerprints(checkout(tmp_path / "b", {"style.css": spaced}), [result()])
    assert plain == indented


def test_changing_the_flagged_text_changes_the_fingerprint(tmp_path: Path) -> None:
    """A different flagged line yields a new fingerprint."""
    before = fingerprints(checkout(tmp_path / "a", {"style.css": CSS}), [result()])
    edited = CSS.replace("margin: 0", "margin: 1px")
    after = fingerprints(checkout(tmp_path / "b", {"style.css": edited}), [result()])
    assert before != after


def test_rule_and_file_are_part_of_the_fingerprint(tmp_path: Path) -> None:
    """The same line under another rule or file is a different finding."""
    root = checkout(tmp_path, {"style.css": CSS, "other.css": CSS})
    prints = fingerprints(
        root,
        [result(), result(rule="ai-slop/other"), result(uri="other.css")],
    )
    assert len(set(prints)) == len(prints)


def test_identical_lines_get_distinct_ordinals(tmp_path: Path) -> None:
    """Repeated identical lines stay distinct, ordered by line."""
    text = "a {}\n.x { }\n.x { }\n"
    root = checkout(tmp_path / "a", {"style.css": text})
    first, second = fingerprints(root, [result(line=3), result(line=2)])
    assert first != second
    moved = checkout(tmp_path / "b", {"style.css": "z {}\n" + text})
    assert fingerprints(moved, [result(line=3), result(line=4)]) == [second, first]


def test_distinct_findings_on_one_line_keep_their_identity(tmp_path: Path) -> None:
    """Reordering or removing a same-line finding moves no fingerprint."""
    root = checkout(tmp_path, {"style.css": CSS})
    pairs = [("unused .a", "unused .b"), ("unused .a1", "unused .a2")]
    for one_text, two_text in pairs:
        one, two = result(message=one_text), result(message=two_text)
        first, second = fingerprints(root, [one, two])
        assert first != second, pairs
        assert fingerprints(root, [two, one]) == [second, first]
        assert fingerprints(root, [two]) == [second]


def test_digits_in_names_are_kept(tmp_path: Path) -> None:
    """Digits that are part of a name stay in the subject."""
    root = checkout(tmp_path, {"style.css": CSS})
    names = [
        "CSS class '.col1' is defined but never referenced",
        "CSS class '.col2' is defined but never referenced",
        "Unused export: handler1",
        "Unused export: handler2",
        "Go vulnerability: GO-2024-1234",
        "Go vulnerability: GO-2024-1235",
        "Unused value '42'",
        "Unused value '43'",
    ]
    prints = [fingerprints(root, [result(message=text)])[0] for text in names]
    assert len(set(prints)) == len(prints)


def test_dependency_findings_are_told_apart_by_package(tmp_path: Path) -> None:
    """Packages sharing a manifest line keep identities across advice changes."""
    root = checkout(tmp_path, {"package.json": '{"dependencies": {}}\n'})
    rule = "security/vulnerable-dependency"

    def dep(message: str) -> dict[str, object]:
        """Build a dependency result on the manifest's first line."""
        return result(rule, "package.json", line=1, message=message)

    glob, minimatch = fingerprints(
        root,
        [
            dep("glob (moderate) — upgrade to 10.4.5"),
            dep("minimatch (moderate) — upgrade to 9.0.5"),
        ],
    )
    assert glob != minimatch
    later = fingerprints(
        root,
        [
            dep("minimatch (high) — upgrade to 10.0.1"),
            dep("glob (moderate) — upgrade to 11.0.0"),
        ],
    )
    assert later == [minimatch, glob]
    assert fingerprints(root, [dep("minimatch (high)")]) == [minimatch]


def test_numbers_in_messages_do_not_rekey_a_finding(tmp_path: Path) -> None:
    """A count, limit or line number quoted in a message leaves the hash alone."""
    root = checkout(tmp_path, {"style.css": CSS})
    pairs = [
        ("complexity 12, see line 40", "complexity 15, see line 7"),
        (
            "Function too long (limit: 80, flagged above 100 lines)",
            "Function too long (limit: 60, flagged above 75 lines)",
        ),
        (
            '"os" is also imported on line 3. Merge into one.',
            '"os" is also imported on line 9. Merge into one.',
        ),
    ]
    for before_text, after_text in pairs:
        before = fingerprints(root, [result(message=before_text)])
        after = fingerprints(root, [result(message=after_text)])
        assert before == after, before_text


def test_absolute_and_file_uris_match_relative_ones(tmp_path: Path) -> None:
    """URI spelling does not change the fingerprint."""
    root = checkout(tmp_path, {"style.css": CSS})
    absolute = str(root / "style.css")
    spellings = ["style.css", "./style.css", absolute, "file://" + absolute]
    prints = {fingerprints(root, [result(uri=uri)])[0] for uri in spellings}
    assert len(prints) == 1


def test_symlinked_artifacts_keep_their_own_identity(tmp_path: Path) -> None:
    """Two links to one file fingerprint apart, and neither shifts the other."""
    root = checkout(tmp_path, {"style.css": CSS})
    (root / "a.css").symlink_to("style.css")
    (root / "b.css").symlink_to("style.css")
    both = fingerprints(root, [result(uri="a.css"), result(uri="b.css")])
    assert both[0] != both[1]
    assert fingerprints(root, [result(uri="b.css")]) == [both[1]]
    assert fingerprints(root, [result(uri="style.css")])[0] not in both


def test_links_leaving_the_checkout_are_not_read(tmp_path: Path) -> None:
    """A link whose target lies outside the checkout is never read."""
    root = checkout(tmp_path / "repo", {"style.css": CSS})
    outside = tmp_path / "outside.css"
    (root / "leak.css").symlink_to(outside)
    prints: list[str] = []
    for text in (CSS, CSS.replace("margin: 0", "margin: 1px")):
        _ = outside.write_text(text, encoding="utf-8")
        prints += fingerprints(root, [result(uri="leak.css")])
    assert prints[0] == prints[1]


def test_unreadable_lines_fall_back_to_the_message(tmp_path: Path) -> None:
    """No location, a missing file or a line past EOF still fingerprint."""
    root = checkout(tmp_path, {"style.css": CSS})
    results = [
        result(uri=None),
        result(uri="missing.css"),
        result(line=99),
        result(line=None),
        result(uri="../outside.css"),
    ]
    first = fingerprints(root, results)
    assert all(first)
    assert first == fingerprints(root, results)
    other = fingerprints(root, [result(uri=None, message="another")])
    assert other[0] != first[0]


def test_a_final_line_break_opens_no_line(tmp_path: Path) -> None:
    """The line after a final line break hashes as a missing line."""
    root = checkout(tmp_path, {"style.css": CSS, "empty.css": ""})
    for uri, line in (("style.css", 4), ("empty.css", 1)):
        (phantom,) = fingerprints(root, [result(uri=uri, line=line)])
        (missing,) = fingerprints(root, [result(uri=uri, line=99)])
        assert phantom == missing, uri


def test_preserved_fingerprints_count_towards_ordinals(tmp_path: Path) -> None:
    """A re-run over a partly fingerprinted log matches a fresh run."""
    root = checkout(tmp_path, {"style.css": "a {}\n.x { }\n.x { }\n"})
    first, second = fingerprints(root, [result(line=2), result(line=3)])
    kept = result(line=2)
    kept["partialFingerprints"] = {KEY: first}
    assert fingerprints(root, [kept, result(line=3)]) == [first, second]


def test_new_findings_never_reuse_a_preserved_fingerprint(tmp_path: Path) -> None:
    """A new identical finding gets a hash distinct from a preserved one."""
    root = checkout(tmp_path, {"style.css": "a {}\n.x { }\n.x { }\n"})
    (alone,) = fingerprints(root, [result(line=3)])
    kept = result(line=3)
    kept["partialFingerprints"] = {KEY: alone}
    new, old = fingerprints(root, [result(line=2), kept])
    assert old == alone
    assert new != alone


def test_existing_fingerprints_are_left_untouched(tmp_path: Path) -> None:
    """A tool's own fingerprints survive alongside the new key."""
    root = checkout(tmp_path, {"style.css": CSS})
    tagged = result()
    tagged["partialFingerprints"] = {"toolHash/v1": "abc"}
    kept = result(line=1)
    kept["partialFingerprints"] = {KEY: "preset"}
    log = {"version": "2.1.0", "runs": [{"results": [tagged, kept]}]}
    proc = run_script(root, log)
    assert proc.returncode == 0, proc.stderr
    first, second = read_output(root)["runs"][0]["results"]
    assert first["partialFingerprints"]["toolHash/v1"] == "abc"
    assert len(first["partialFingerprints"][KEY]) == len("0" * 64)
    assert second["partialFingerprints"] == {KEY: "preset"}


def test_rule_index_resolves_the_rule(tmp_path: Path) -> None:
    """A result naming its rule by index hashes as one naming it by ID."""
    root = checkout(tmp_path, {"style.css": CSS})
    by_id = fingerprints(root, [result()])
    indexed = result()
    del indexed["ruleId"]
    indexed["ruleIndex"] = 0
    log = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"rules": [{"id": "ai-slop/unused-css"}]}},
                "results": [indexed],
            }
        ],
    }
    proc = run_script(root, log)
    assert proc.returncode == 0, proc.stderr
    out = read_output(root)
    assert out["runs"][0]["results"][0]["partialFingerprints"][KEY] == by_id[0]


def test_runs_without_results_pass(tmp_path: Path) -> None:
    """A clean scan succeeds and fingerprints nothing."""
    root = checkout(tmp_path, {})
    proc = run_script(root, {"version": "2.1.0", "runs": [{"tool": {}}]})
    assert proc.returncode == 0, proc.stderr
    assert "to 0 result(s)" in proc.stdout


def test_malformed_logs_fail_closed(tmp_path: Path) -> None:
    """Logs the script cannot read exit 2 and write nothing."""
    root = checkout(tmp_path, {})
    bad: list[object] = [
        {"version": "2.1.0"},
        {"runs": []},
        {"runs": [{"results": {}}]},
        {"runs": [{"results": ["text"]}]},
        {"runs": [{"results": [{"partialFingerprints": []}]}]},
    ]
    for log in bad:
        proc = run_script(root, log)
        assert proc.returncode == EXIT_USAGE, log
        assert "::error::" in proc.stderr
        assert not (tmp_path / "out.sarif").exists()
