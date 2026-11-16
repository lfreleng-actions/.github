# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Add content-based partialFingerprints to every result in a SARIF log.

The organisation SARIF publishers post to the code-scanning REST API,
which, unlike github/codeql-action/upload-sarif, computes no
fingerprints. Without one, code scanning matches an alert only by file
and line, so an edit that moves a finding closes its alert and opens a
new one, losing any dismissal.

Each result that lacks the FINGERPRINT_KEY entry gets one, hashed from:

- the rule ID;
- the primary location's artifact URI, relative to the checkout;
- the flagged source line read from the checkout, with whitespace
  collapsed, when the result has a location and the line can be read;
- the finding's subject, so distinct findings of one rule on one line
  keep their own identity whatever their order: for aislop's
  DEPENDENCY_RULE the package name, the message text up to the first
  space, as the findings ratchet counts it; for every other rule the
  message text with whitespace collapsed and each standalone numeral
  masked, so a count, limit or line number quoted in a message never
  re-keys the finding, while digits inside a name (a selector such as
  .a1, a symbol, an advisory ID) still tell findings apart;
- an ordinal among results sharing those values, ordered by line and
  column, so repeated identical findings stay distinct. Results that
  already carry the key count towards the ordinals, and no new
  fingerprint repeats one they hold.

Line numbers never enter the hash. Fingerprints a tool already emits,
under any key, are left untouched.

Usage: sarif_fingerprint.py --input=IN --output=OUT --source-root=DIR

Exit codes: 0 written; 2 bad arguments, or an input that is not a
SARIF log this script can read (nothing is written).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import cast
from urllib.parse import unquote

FINGERPRINT_KEY = "lfrelengContentHash/v1"
DEPENDENCY_RULE = "security/vulnerable-dependency"
EXIT_USAGE = 2
LINE_BREAK = re.compile(r"\r\n|\r|\n")
# A standalone numeral in prose: a count, limit or line number. Digits
# inside a name (.a1, h2, GO-2024-1234, pkg@1.2, '42') never match.
NUMERAL = re.compile(r"(?<![\w.@$#/\\'\"`-])[0-9]+(?:\.[0-9]+)*(?![\w@$#/\\'\"`-])")


class SarifError(Exception):
    """The input is not a SARIF log this script can fingerprint."""


def as_dict(value: object) -> dict[str, object]:
    """Return value as a JSON object, or an empty one."""
    return cast("dict[str, object]", value) if isinstance(value, dict) else {}


def as_list(value: object) -> list[object]:
    """Return value as a JSON array, or an empty one."""
    return cast("list[object]", value) if isinstance(value, list) else []


def as_str(value: object) -> str:
    """Return value as a string, or an empty one."""
    return value if isinstance(value, str) else ""


def as_int(value: object) -> int:
    """Return value as a positive integer, or 0."""
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return 0


class SourceTree:
    """Read source lines from the checkout, never outside it."""

    def __init__(self, root: Path) -> None:
        """Remember the checkout root, as given and resolved."""
        self.given: Path = Path(os.path.normpath(root.absolute()))
        self.root: Path = root.resolve()
        self._cache: dict[Path, list[str] | None] = {}

    def relative(self, uri: str) -> str:
        """Return uri as a normalised path relative to the root.

        The path is normalised without following symlinks, so distinct
        links to one file stay distinct; the link's target must still
        resolve inside the root. Returns '' when the URI is empty or
        does not name a path inside the root; the caller then hashes
        the raw URI instead.
        """
        text = unquote(uri.removeprefix("file://")).replace("\\", "/")
        if not text:
            return ""
        name = self._name(Path(text))
        if not name or name in {".", ".."} or name.startswith("../"):
            return ""
        try:
            resolved = (self.root / name).resolve()
        except (OSError, RuntimeError):
            return ""
        if not resolved.is_relative_to(self.root) or resolved == self.root:
            return ""
        return name

    def _name(self, candidate: Path) -> str:
        """Return candidate relative to the root, symlinks unresolved."""
        if not candidate.is_absolute():
            return posixpath.normpath(candidate.as_posix())
        absolute = Path(os.path.normpath(candidate))
        for base in (self.given, self.root):
            if absolute.is_relative_to(base):
                return absolute.relative_to(base).as_posix()
        try:
            resolved = candidate.resolve()
        except (OSError, RuntimeError):
            return ""
        if resolved.is_relative_to(self.root):
            return resolved.relative_to(self.root).as_posix()
        return ""

    def line(self, relative: str, number: int) -> str | None:
        """Return line number (1-based) of a file, whitespace collapsed."""
        if not relative or number < 1:
            return None
        lines = self._lines(self.root / relative)
        if lines is None or number > len(lines):
            return None
        return " ".join(lines[number - 1].split())

    def _lines(self, path: Path) -> list[str] | None:
        if path not in self._cache:
            try:
                data = path.read_bytes()
            except OSError:
                self._cache[path] = None
            else:
                text = data.decode("utf-8", errors="replace")
                lines = LINE_BREAK.split(text)
                # A final line break ends the last line; it opens no new one.
                if lines[-1] == "":
                    _ = lines.pop()
                self._cache[path] = lines
        return self._cache[path]


def rule_id(result: dict[str, object], rules: list[object]) -> str:
    """Return the result's rule ID from ruleId, rule.id or ruleIndex."""
    direct = as_str(result.get("ruleId"))
    if direct:
        return direct
    rule = as_dict(result.get("rule"))
    if as_str(rule.get("id")):
        return as_str(rule.get("id"))
    index = rule.get("index", result.get("ruleIndex"))
    valid = isinstance(index, int) and not isinstance(index, bool)
    if valid and 0 <= cast("int", index) < len(rules):
        return as_str(as_dict(rules[cast("int", index)]).get("id"))
    return ""


def primary_location(result: dict[str, object]) -> tuple[str, int, int]:
    """Return the primary location's URI, start line and start column."""
    locations = as_list(result.get("locations"))
    if not locations:
        return "", 0, 0
    physical = as_dict(as_dict(locations[0]).get("physicalLocation"))
    uri = as_str(as_dict(physical.get("artifactLocation")).get("uri"))
    region = as_dict(physical.get("region"))
    return uri, as_int(region.get("startLine")), as_int(region.get("startColumn"))


def message_text(result: dict[str, object]) -> str:
    """Return the result's message text, or its message ID."""
    message = as_dict(result.get("message"))
    text = as_str(message.get("text")) or as_str(message.get("id"))
    return " ".join(text.split())


def subject(rule: str, result: dict[str, object]) -> str:
    """Return what tells this finding apart from others on its line."""
    text = message_text(result)
    if rule == DEPENDENCY_RULE:
        return text.split(" ", 1)[0]
    return NUMERAL.sub("#", text)


def digest(parts: list[str | int]) -> str:
    """Return the SHA-256 hex digest of a JSON-encoded list."""
    encoded = json.dumps(parts, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def as_result(item: object) -> dict[str, object]:
    """Return item as a SARIF result, or raise SarifError."""
    if not isinstance(item, dict):
        msg = "a result is not an object"
        raise SarifError(msg)
    result = cast("dict[str, object]", item)
    existing = result.get("partialFingerprints")
    if existing is not None and not isinstance(existing, dict):
        msg = "a result's 'partialFingerprints' is not an object"
        raise SarifError(msg)
    return result


def result_basis(
    result: dict[str, object], rules: list[object], tree: SourceTree
) -> tuple[tuple[str, ...], int, int]:
    """Return the values a result's fingerprint hashes, and its position."""
    uri, line, column = primary_location(result)
    relative = tree.relative(uri)
    text = tree.line(relative, line)
    rule = rule_id(result, rules)
    about = subject(rule, result)
    if text is not None:
        return ("line", rule, relative, text, about), line, column
    return ("message", rule, relative or uri, about), line, column


def fingerprint_run(run: dict[str, object], tree: SourceTree) -> int:
    """Fingerprint one run's results in place; return how many gained one."""
    driver = as_dict(as_dict(run.get("tool")).get("driver"))
    rules = as_list(driver.get("rules"))
    results = run.get("results")
    if results is None:
        return 0
    if not isinstance(results, list):
        msg = "a run's 'results' is not an array"
        raise SarifError(msg)
    items = [as_result(item) for item in cast("list[object]", results)]
    groups: defaultdict[tuple[str, ...], list[tuple[int, int, int]]]
    groups = defaultdict(list)
    taken: set[str] = set()
    for index, result in enumerate(items):
        held = as_dict(result.get("partialFingerprints")).get(FINGERPRINT_KEY)
        if held is not None:
            taken.add(as_str(held))
        basis, line, column = result_basis(result, rules, tree)
        groups[basis].append((line, column, index))
    added = 0
    for basis, members in groups.items():
        spare = len(members)
        for ordinal, (_, _, index) in enumerate(sorted(members)):
            fingerprints = as_dict(items[index].get("partialFingerprints"))
            if FINGERPRINT_KEY in fingerprints:
                continue
            value = digest([FINGERPRINT_KEY, *basis, ordinal])
            # Never hand a new finding a hash a preserved one already holds.
            while value in taken:
                value = digest([FINGERPRINT_KEY, *basis, spare])
                spare += 1
            taken.add(value)
            fingerprints[FINGERPRINT_KEY] = value
            items[index]["partialFingerprints"] = fingerprints
            added += 1
    return added


def fingerprint_log(log: object, tree: SourceTree) -> int:
    """Fingerprint every run of a SARIF log in place; return the count."""
    runs = as_dict(log).get("runs")
    if not isinstance(runs, list) or not runs:
        msg = "the SARIF log has no 'runs' array"
        raise SarifError(msg)
    added = 0
    for run in cast("list[object]", runs):
        if not isinstance(run, dict):
            msg = "a run is not an object"
            raise SarifError(msg)
        added += fingerprint_run(cast("dict[str, object]", run), tree)
    return added


def main(argv: list[str] | None = None) -> int:
    """Read, fingerprint and write one SARIF log."""
    parser = argparse.ArgumentParser(
        description="Add content-based partialFingerprints to a SARIF log."
    )
    _ = parser.add_argument("--input", required=True, help="SARIF to read")
    _ = parser.add_argument("--output", required=True, help="SARIF to write")
    _ = parser.add_argument(
        "--source-root", required=True, help="checkout the SARIF describes"
    )
    args = parser.parse_args(argv)
    source = Path(cast("str", args.input))
    target = Path(cast("str", args.output))
    root = Path(cast("str", args.source_root))
    if not root.is_dir():
        print(f"::error::source root {root} is not a directory", file=sys.stderr)
        return EXIT_USAGE
    try:
        log = cast("object", json.loads(source.read_text(encoding="utf-8")))
        added = fingerprint_log(log, SourceTree(root))
    except (OSError, ValueError, SarifError) as exc:
        print(f"::error::cannot fingerprint {source}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    _ = target.write_text(json.dumps(log, ensure_ascii=False), encoding="utf-8")
    print(f"Added {FINGERPRINT_KEY} to {added} result(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
