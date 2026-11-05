# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Compare two SARIF reports and fail only on findings a change adds.

Findings are counted per (ruleId, path, subject) key rather than matched
one to one, since neither aislop nor zizmor sets SARIF fingerprints.
README.md documents the inputs, outputs, matching and the fail-closed
rules; sarif_log.py, beside this script, reads and validates the logs.
Exits 0 on pass, 1 on fail and 2 on a usage error.
"""

from __future__ import annotations

import argparse
import os
import posixpath
import secrets
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast
from urllib.parse import unquote

from sarif_log import (
    LEVELS,
    SarifError,
    as_dict,
    as_list,
    as_str,
    load_sarif,
    result_location,
    result_rule,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

TOOLS = ("aislop", "zizmor", "generic")
MODES = ("ratchet", "absolute")
DEFAULT_LEVEL = "warning"
AISLOP_DEPENDENCY_RULE = "security/vulnerable-dependency"
TITLE = "findings-ratchet"

COUNTS = ("base-count", "head-count", "new-count", "fixed-count")
EXIT_PASS = 0
EXIT_FAIL = 1
WF_DATA = str.maketrans({"%": "%25", "\r": "%0D", "\n": "%0A"})
WF_PROPERTY = WF_DATA | str.maketrans({":": "%3A", ",": "%2C"})
MD_CELL = str.maketrans(
    {"&": "&amp;", "<": "&lt;", ">": "&gt;", "|": "\\|", "`": "\\`"}
)

Key = tuple[str, str, str]


@dataclass(frozen=True)
class Finding:
    """One counted SARIF result."""

    rule: str
    path: str
    subject: str
    line: int | None
    message: str

    @property
    def key(self) -> Key:
        """Return the matching key: rule, path and subject."""
        return (self.rule, self.path, self.subject)


@dataclass(frozen=True)
class KeyRow:
    """Counts for one key, with the head findings reported as new."""

    key: Key
    base: int
    head: int
    new_findings: tuple[Finding, ...]

    @property
    def new(self) -> int:
        """Return the number of findings the head adds for this key."""
        return max(0, self.head - self.base)

    @property
    def fixed(self) -> int:
        """Return the number of findings the head removes for this key."""
        return max(0, self.base - self.head)


@dataclass(frozen=True)
class Options:
    """Settings shared by both sides of the comparison."""

    tool: str
    levels: frozenset[str]
    exclude: frozenset[str]


def wf_escape(text: str) -> str:
    """Escape workflow-command data, as aislop.yaml's wf_escape does."""
    return text.translate(WF_DATA)


def text_property(text: str) -> str:
    """Escape a workflow-command property value."""
    return text.translate(WF_PROPERTY)


def md_cell(text: str) -> str:
    """Render text safely inside one Markdown table cell."""
    return " ".join(text.split()).translate(MD_CELL)


def split_list(raw: str) -> list[str]:
    """Split a comma-separated input into trimmed, non-empty items."""
    return [item.strip() for item in raw.split(",") if item.strip()]


def normalise_path(uri: str, root: str) -> str:
    """Turn an artifact URI into a normalised path relative to the checkout.

    Raises SarifError when the path climbs out of the checkout.
    """
    path = unquote(uri.removeprefix("file://")).replace("\\", "/")
    if not path:
        return ""
    path = posixpath.normpath(path)
    if root:
        if path == root:
            return ""
        if path.startswith(root + "/"):
            path = path[len(root) + 1 :]
    if path == ".." or path.startswith("../"):
        msg = f"artifact URI {uri!r} resolves outside the checkout"
        raise SarifError(msg)
    return path


def subject_for(tool: str, rule: str, message: str) -> str:
    """Return the per-tool subject that refines a rule and path.

    Raises SarifError when an aislop dependency result names no package,
    since an empty subject would merge every package into one key.
    """
    if tool == "aislop" and rule == AISLOP_DEPENDENCY_RULE:
        package = message.strip().split(" ", 1)[0]
        if not package:
            msg = f"a {rule!r} result has no literal 'message.text' naming a package"
            raise SarifError(msg)
        return package
    return ""


def extract(log: dict[str, object], root: str, options: Options) -> list[Finding]:
    """Return the counted findings of a SARIF log.

    Raises SarifError when a result's path climbs out of the checkout,
    or a counted aislop dependency result names no package.
    """
    root = root.removeprefix("file://").replace("\\", "/")
    root = posixpath.normpath(root).rstrip("/") if root else ""
    findings: list[Finding] = []
    for run_obj in as_list(log.get("runs")):
        run = as_dict(run_obj)
        rules = as_list(as_dict(as_dict(run.get("tool")).get("driver")).get("rules"))
        defaults: dict[str, str] = {}
        for rule_obj in rules:
            rule = as_dict(rule_obj)
            config = as_dict(rule.get("defaultConfiguration"))
            defaults[as_str(rule.get("id"))] = (
                as_str(config.get("level")) or DEFAULT_LEVEL
            )
        for result_obj in as_list(run.get("results")):
            result = as_dict(result_obj)
            uri, line = result_location(result)
            path = normalise_path(uri, root)
            rule_id = result_rule(result, rules)
            level = as_str(result.get("level")) or defaults.get(rule_id, DEFAULT_LEVEL)
            if level not in options.levels or rule_id in options.exclude:
                continue
            message = as_str(as_dict(result.get("message")).get("text"))
            subject = subject_for(options.tool, rule_id, message)
            findings.append(Finding(rule_id, path, subject, line, message))
    return findings


def read_findings(path_text: str, root: str, options: Options) -> list[Finding]:
    """Load a SARIF log and return its counted findings.

    Raises SarifError when the file cannot be used.
    """
    log = load_sarif(path_text)
    try:
        return extract(log, root, options)
    except SarifError as exc:
        msg = f"{path_text} is not a usable SARIF log: {exc}"
        raise SarifError(msg) from exc


def pick_new(
    head: list[Finding], base: list[Finding], count: int
) -> tuple[Finding, ...]:
    """Choose which head findings of one key to report as new.

    Counting decides the verdict; this only picks what to annotate,
    putting first the head findings whose line and message match none
    in the base.
    """
    if count <= 0:
        return ()
    unmatched = Counter((finding.line, finding.message) for finding in base)
    fresh: list[Finding] = []
    carried: list[Finding] = []
    for finding in head:
        signature = (finding.line, finding.message)
        if unmatched[signature] > 0:
            unmatched[signature] -= 1
            carried.append(finding)
        else:
            fresh.append(finding)
    return tuple((fresh + carried[::-1])[:count])


def compare(head: list[Finding], base: list[Finding]) -> list[KeyRow]:
    """Count findings per key and return rows, new findings first."""
    head_by_key: dict[Key, list[Finding]] = {}
    base_by_key: dict[Key, list[Finding]] = {}
    for finding in head:
        head_by_key.setdefault(finding.key, []).append(finding)
    for finding in base:
        base_by_key.setdefault(finding.key, []).append(finding)
    rows: list[KeyRow] = []
    for key in head_by_key.keys() | base_by_key.keys():
        head_items = head_by_key.get(key, [])
        base_items = base_by_key.get(key, [])
        new = pick_new(head_items, base_items, len(head_items) - len(base_items))
        rows.append(KeyRow(key, len(base_items), len(head_items), new))
    rows.sort(key=lambda row: (-row.new, -row.fixed, row.key))
    return rows


def location_text(finding: Finding) -> str:
    """Render a finding's location as path:line."""
    if finding.line is None:
        return finding.path
    return f"{finding.path}:{finding.line}"


def annotation(finding: Finding) -> str:
    """Build the ::error workflow command for one new finding."""
    properties: list[str] = []
    if finding.path:
        properties.append(f"file={text_property(finding.path)}")
        if finding.line is not None:
            properties.append(f"line={finding.line}")
    properties.append(f"title={text_property(f'{TITLE}: {finding.rule}')}")
    text = f"New finding {finding.rule}: {finding.message}"
    return f"::error {','.join(properties)}::{wf_escape(text)}"


def counts_text(outputs: dict[str, str]) -> str:
    """Render the four counts on one line."""
    names = ("base", "head", "new", "fixed")
    return ", ".join(f"{name} {outputs[f'{name}-count']}" for name in names)


def summary_markdown(rows: Sequence[KeyRow], outputs: dict[str, str]) -> str:
    """Render the step summary."""
    verdict = f"Verdict: **{outputs['verdict']}** (mode: {outputs['effective-mode']})"
    lines = ["## Findings ratchet", "", verdict, "", counts_text(outputs), ""]
    if not rows:
        return "\n".join([*lines, "No counted findings on either side.", ""])
    lines += [
        "| Rule | Path | Subject | Base | Head | New | Fixed | New findings |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        rule, path, subject = row.key
        detail = "<br>".join(
            f"{md_cell(location_text(finding))}: {md_cell(finding.message)}"
            for finding in row.new_findings
        )
        cells = [md_cell(rule), md_cell(path), md_cell(subject)]
        cells += [str(row.base), str(row.head), str(row.new), str(row.fixed), detail]
        lines.append(f"| {' | '.join(cells)} |")
    return "\n".join(lines) + "\n"


def append_file(variable: str, text: str) -> None:
    """Append text to the file a GitHub Actions variable names."""
    target = os.environ.get(variable, "")
    if target:
        with Path(target).open("a", encoding="utf-8") as handle:
            _ = handle.write(text)


def write_outputs(outputs: dict[str, str]) -> None:
    """Write step outputs to GITHUB_OUTPUT."""
    append_file(
        "GITHUB_OUTPUT", "".join(f"{name}={value}\n" for name, value in outputs.items())
    )


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    """Parse the command line, exiting 2 on a usage error."""
    parser = argparse.ArgumentParser(
        description="Compare two SARIF reports by counted findings."
    )
    _ = parser.add_argument("--head-sarif", required=True)
    for name in ("--base-sarif", "--head-root", "--base-root", "--exclude-rules"):
        _ = parser.add_argument(name, default="")
    _ = parser.add_argument("--tool", required=True, choices=TOOLS)
    _ = parser.add_argument("--mode", default="ratchet", choices=MODES)
    _ = parser.add_argument("--levels", default=",".join(LEVELS))
    _ = parser.add_argument("--annotate", default="true", choices=("true", "false"))
    args = parser.parse_args(argv)
    levels = split_list(cast("str", args.levels))
    if not levels or not set(levels) <= set(LEVELS):
        parser.error(f"--levels takes a comma-separated subset of {','.join(LEVELS)}")
    return args


def fail_unusable_head(mode: str, error: SarifError) -> int:
    """Report an unusable head SARIF and fail closed."""
    write_outputs(
        {"verdict": "fail", "effective-mode": mode} | dict.fromkeys(COUNTS, "")
    )
    text = f"Head SARIF unusable, failing closed: {error}"
    print(f"::error title={TITLE}::{wf_escape(text)}")
    return EXIT_FAIL


def print_report(mode: str, rows: Sequence[KeyRow], outputs: dict[str, str]) -> None:
    """Print the result line and, with commands suspended, the key table."""
    print(f"findings-ratchet ({mode}): {counts_text(outputs)}: {outputs['verdict']}")
    report = [
        f"base {row.base} head {row.head} new {row.new} fixed {row.fixed}: {' | '.join(row.key)}"
        for row in rows
    ]
    report += [
        f"new: {location_text(finding)}: {' '.join(finding.message.split())}"
        for row in rows
        for finding in row.new_findings
    ]
    if report:
        token = secrets.token_hex(16)
        print("\n".join([f"::stop-commands::{token}", *report, f"::{token}::"]))


def main(argv: Sequence[str]) -> int:
    """Run the comparison and return the exit code."""
    args = parse_args(argv)
    options = Options(
        tool=cast("str", args.tool),
        levels=frozenset(split_list(cast("str", args.levels))),
        exclude=frozenset(split_list(cast("str", args.exclude_rules))),
    )
    mode = cast("str", args.mode)

    try:
        head = read_findings(
            cast("str", args.head_sarif), cast("str", args.head_root), options
        )
    except SarifError as exc:
        return fail_unusable_head(mode, exc)

    base: list[Finding] = []
    if mode == "ratchet":
        try:
            base = read_findings(
                cast("str", args.base_sarif), cast("str", args.base_root), options
            )
        except SarifError as exc:
            mode = "absolute"
            text = f"Base SARIF unusable ({exc}); using absolute mode"
            print(f"::warning title={TITLE}::{wf_escape(text)}")

    rows = compare(head, base)
    new_total = sum(row.new for row in rows)
    failed = new_total > 0 if mode == "ratchet" else bool(head)
    counts = (len(base), len(head), new_total, sum(row.fixed for row in rows))
    outputs = {"verdict": "fail" if failed else "pass", "effective-mode": mode}
    outputs |= {name: str(count) for name, count in zip(COUNTS, counts, strict=True)}
    write_outputs(outputs)
    append_file("GITHUB_STEP_SUMMARY", summary_markdown(rows, outputs))
    print_report(mode, rows, outputs)
    if cast("str", args.annotate) == "true":
        for row in rows:
            for finding in row.new_findings:
                print(annotation(finding))
    return EXIT_FAIL if failed else EXIT_PASS


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
