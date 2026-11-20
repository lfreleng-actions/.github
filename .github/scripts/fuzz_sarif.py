# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The sarif side of fuzz_publish.py: build SARIF from a handover."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, cast
from urllib.parse import quote, unquote

from fuzz_common import (
    EXIT_REFUSED,
    FINGERPRINT_KEY,
    HARNESS_ERROR,
    LINE_BREAK,
    MAX_INPUT_BYTES,
    MAX_SOURCE_BYTES,
    OUT_OF_MEMORY,
    REPRODUCIBLE,
    RULES,
    TIMEOUT,
    TOOL_NAME,
    UNCAUGHT,
    Failure,
    RefusalError,
    classify,
    clean_relative,
    inside,
    locate,
    parse_harnesses,
    plain_name,
    read_log,
    read_regular,
)
from fuzz_record import (
    Identity,
    Record,
    RecordedHarness,
    RecordedProcess,
    load_record,
)
from fuzz_state import sha1_hex, sha256_hex

if TYPE_CHECKING:
    import argparse


class Checkout:
    """Validate file and line references against the checkout."""

    def __init__(self, root: Path) -> None:
        """Remember the checkout root."""
        self.root: Path = root
        self._lines: dict[str, int | None] = {}

    def line_count(self, relative: str) -> int | None:
        """Return the number of lines in a checkout file, or None."""
        if relative not in self._lines:
            count: int | None = None
            path = inside(self.root, relative)
            if path is not None and relative.split("/", 1)[0] != ".git":
                try:
                    data = read_regular(path, MAX_SOURCE_BYTES)
                except OSError:
                    data = None
                if data is not None:
                    lines = LINE_BREAK.split(data.decode("utf-8", errors="replace"))
                    if lines[-1] == "":
                        _ = lines.pop()
                    count = len(lines)
            self._lines[relative] = count
        return self._lines[relative]

    def accepts(self, relative: str, line: int) -> bool:
        """Return whether line exists in a file of the checkout."""
        count = self.line_count(relative)
        return count is not None and 1 <= line <= count


def message(rule: str, harness: str, exception: str, function: str) -> str:
    """Return a result's fixed message wording with its validated fields."""
    if rule == UNCAUGHT:
        return (
            f"Uncaught {exception} in {function}, reached from fuzz harness {harness}"
        )
    if rule == TIMEOUT:
        return f"Input exceeds the time limit in {function}, reached from fuzz harness {harness}"
    if rule == OUT_OF_MEMORY:
        return f"Input exceeds the memory limit, reached from fuzz harness {harness}"
    return f"Fuzz harness {harness} did not run"


def require_verdict(
    harness: RecordedHarness, process: RecordedProcess, failure: Failure
) -> None:
    """Refuse a replay that could not say whether its saved input fails.

    Reporting only that the harness did not run would close the alert
    the saved input keeps open, though that input never passed.
    """
    if process.phase == "replay" and failure.rule == HARNESS_ERROR:
        msg = (
            f"a saved input of harness {harness.path} could not be"
            " replayed, so whether it still fails is unknown"
        )
        raise RefusalError(msg)


def fingerprint(rule: str, file: str, text: str) -> str:
    """Return a result's fingerprint, from what the evidence check compares.

    An alert is the same alert exactly when its rule, file and message
    are the same, whatever the text of its line.
    """
    encoded = json.dumps(
        [FINGERPRINT_KEY, TOOL_NAME, rule, file, text],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def new_result(
    failure: Failure, harness: str, file: str, line: int, function: str
) -> dict[str, object]:
    """Return the SARIF result for a defect, with no input yet."""
    fields: dict[str, object] = {"harness": harness}
    if failure.exception:
        fields["exceptionType"] = failure.exception
    text = message(failure.rule, harness, failure.exception, function)
    # A URI, so a name holding '%' or a space decodes back to itself
    # (sarif_fingerprint.py and code scanning both decode it).
    location = {
        "artifactLocation": {"uri": quote(file, safe="/")},
        "region": {"startLine": line},
    }
    return {
        "ruleId": failure.rule,
        "ruleIndex": list(RULES).index(failure.rule),
        "level": "error",
        "message": {"text": text},
        "locations": [{"physicalLocation": location}],
        "partialFingerprints": {FINGERPRINT_KEY: fingerprint(failure.rule, file, text)},
        "properties": fields,
    }


def process_failure(
    harness: RecordedHarness, process: RecordedProcess
) -> Failure | None:
    """Return how a process failed, or None when it passed or merged."""
    if process.phase == "merge":
        return None
    try:
        text = read_log(process.log)
    except OSError as exc:
        msg = f"cannot read a log of harness {harness.path}"
        raise RefusalError(msg) from exc
    failure = classify(text, process.exit_code, timed_out=process.timed_out)
    if failure is not None:
        require_verdict(harness, process, failure)
    return failure


def require_reproducers(results: list[dict[str, object]]) -> None:
    """Refuse a defect but a harness error that no handed-over input reproduces."""
    for result in results:
        rule = cast("str", result["ruleId"])
        properties = cast("dict[str, object]", result["properties"])
        if rule in REPRODUCIBLE and "inputSha1" not in properties:
            msg = (
                f"a {rule} result of harness {properties['harness']} has no"
                " handed-over input that reproduces it"
            )
            raise RefusalError(msg)


def recorded_identity(identity: Identity) -> tuple[Failure, str, int, str] | None:
    """Return a recorded identity's failure, file, line and function, or None.

    A name is validated as a result's is; a rule but a reproducible one,
    or a file that is not a plain relative path, gives None.
    """
    rule, exception, file, function, line = identity
    relative = clean_relative(file)
    if rule not in REPRODUCIBLE or relative is None:
        return None
    exception = plain_name(exception) if rule == UNCAUGHT else ""
    return Failure(rule, exception), relative, int(line), plain_name(function)


def held_location(
    identity: Identity, checkout: Checkout
) -> tuple[Failure, str, int, str] | None:
    """Return where a held identity's result points, or None to report none.

    A held identity whose file is gone from the checkout gives no
    result, which leaves its alert to the publish job's evidence check
    rather than open one at another place; a line the file no longer
    has falls back to its first.
    """
    held = recorded_identity(identity)
    if held is None:
        return None
    failure, file, line, function = held
    if not checkout.accepts(file, line):
        line = 1
    if not checkout.accepts(file, line):
        return None
    return failure, file, line, function


class Built(NamedTuple):
    """The results a handover shows, and where each one's input came from.

    observed holds the index of each result whose input a process of
    this run reproduced; held lists each alert identity a failing replay
    kept from an earlier way its input failed, with that input's SHA-256.
    """

    results: list[dict[str, object]]
    observed: set[int]
    held: list[dict[str, str]]


class Collector:
    """Gather one result per defect, and where each one's input came from."""

    def __init__(self) -> None:
        """Start with no results."""
        self.found: dict[tuple[str, str, str, str, str], dict[str, object]] = {}
        self.observed: set[tuple[str, str, str, str, str]] = set()
        self.held: list[dict[str, str]] = []

    def add(
        self,
        harness: str,
        process: RecordedProcess,
        located: tuple[Failure, str, int, str],
        *,
        inherited: bool,
    ) -> None:
        """Record a defect a process reached, observed or held from the state."""
        failure, file, line, function = located
        key = (failure.rule, harness, file, function, failure.exception)
        result = self.found.setdefault(
            key, new_result(failure, harness, file, line, function)
        )
        if process.input is None:
            return
        data = read_regular(process.input, MAX_INPUT_BYTES)
        digests = {"inputSha1": sha1_hex(data), "inputSha256": sha256_hex(data)}
        properties = cast("dict[str, object]", result["properties"])
        if inherited:
            text = cast("dict[str, str]", result["message"])["text"]
            link = {"rule": failure.rule, "path": file, "message": text}
            link["input"] = digests["inputSha256"]
            if link not in self.held:
                self.held.append(link)
            if "inputSha1" not in properties:
                properties.update(digests)
        elif key not in self.observed:
            self.observed.add(key)
            properties.update(digests)

    def built(self) -> Built:
        """Return what was gathered."""
        results = list(self.found.values())
        require_reproducers(results)
        keys = enumerate(self.found)
        observed = {index for index, key in keys if key in self.observed}
        return Built(results, observed, self.held)


def build_results(record: Record, checkout: Checkout) -> Built:
    """Return one SARIF result per defect the record's processes show.

    Every defect but a harness error needs a handed-over input that
    reproduces it; one process with no input may rely on another that
    reached the same defect with one. A replayed input that now fails
    another way still reports each way it failed before, so those
    alerts close only once it passes. That earlier way comes from the
    restored state, which any fuzz job can write, so a result takes its
    input from an observed failure in preference, and the publish job
    signs a held association only when its previous binding holds it.
    """
    collector = Collector()
    for harness in record.harnesses:
        if checkout.line_count(harness.path) is None:
            msg = f"harness {harness.path} is not a file in the checkout"
            raise RefusalError(msg)
        for process in harness.processes:
            failure = process_failure(harness, process)
            if failure is None:
                continue
            file, line, function = locate(
                failure, record.root, harness.path, checkout.accepts
            )
            located = (failure, file, line, function)
            collector.add(harness.path, process, located, inherited=False)
            for identity in process.held or ():
                held = held_location(identity, checkout)
                if held is not None:
                    collector.add(harness.path, process, held, inherited=True)
    return collector.built()


def build_fixed(record: Record) -> list[dict[str, str]]:
    """Return the alert identities a passing replay shows fixed.

    Each is the rule, file and message a result had when its saved
    input failed that way, with the SHA-256 of the handed-over input that
    now passes: the publish job lets the alert close only when its
    signed binding ties that input to it. It compares them against open
    alerts alone, so a file need not still be in the checkout: a fix
    that deletes it closes the alert too.
    """
    fixed: list[dict[str, str]] = []
    for harness in record.harnesses:
        for process in harness.processes:
            if not process.fixed:
                continue
            if process.input is None:
                msg = (
                    f"a passing replay of harness {harness.path} names fixed"
                    " failures but hands over no input"
                )
                raise RefusalError(msg)
            digest = sha256_hex(read_regular(process.input, MAX_INPUT_BYTES))
            for identity in process.fixed:
                located = recorded_identity(identity)
                if located is None:
                    continue
                failure, file, _, function = located
                text = message(failure.rule, harness.path, failure.exception, function)
                entry = {
                    "rule": failure.rule,
                    "path": file,
                    "message": text,
                    "input": digest,
                }
                if entry not in fixed:
                    fixed.append(entry)
    return fixed


def build_reported(built: Built) -> list[dict[str, str]]:
    """Return each result's alert identity: its rule, decoded path and message.

    The publish job compares these, as it compares build_fixed's,
    against the open alerts, whose paths code scanning reports decoded,
    and binds each that an observed failure reproduced to that input's
    SHA-256.
    """
    reported: list[dict[str, str]] = []
    for index, result in enumerate(built.results):
        [location] = cast(
            "list[dict[str, dict[str, dict[str, str]]]]", result["locations"]
        )
        uri = location["physicalLocation"]["artifactLocation"]["uri"]
        text = cast("dict[str, str]", result["message"])["text"]
        rule = cast("str", result["ruleId"])
        entry = {"rule": rule, "path": unquote(uri), "message": text}
        properties = cast("dict[str, object]", result["properties"])
        if index in built.observed:
            entry["input"] = cast("str", properties["inputSha256"])
        reported.append(entry)
    return reported


def build_sarif(results: list[dict[str, object]]) -> dict[str, object]:
    """Return a SARIF log holding one fuzz run."""
    rules = [
        {
            "id": rule,
            "name": rule.removeprefix("fuzz/"),
            "shortDescription": {"text": short},
            "fullDescription": {"text": full},
            "defaultConfiguration": {"level": "error"},
        }
        for rule, (short, full) in RULES.items()
    ]
    driver = {
        "name": TOOL_NAME,
        "informationUri": "https://github.com/lfreleng-actions/.github",
        "rules": rules,
    }
    run = {
        "tool": {"driver": driver},
        "automationDetails": {"id": "fuzz/"},
        "results": results,
    }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def sarif_main(args: argparse.Namespace) -> int:
    """Build SARIF from a handover, or refuse it and write nothing."""
    handover = Path(cast("str", args.handover))
    root = Path(cast("str", args.source_root))
    commit = cast("str", args.commit)
    try:
        harnesses = parse_harnesses(cast("str", args.harnesses))
        record = load_record(handover, commit, harnesses)
        checkout = Checkout(root)
        built = build_results(record, checkout)
        fixed = build_fixed(record)
    except (ValueError, OSError, RefusalError) as exc:
        print(f"::error::refusing the fuzz handover: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    results = built.results
    output = Path(cast("str", args.output))
    _ = output.write_text(json.dumps(build_sarif(results), indent=2), encoding="utf-8")
    if args.summary:
        counts = dict.fromkeys(RULES, 0)
        for result in results:
            counts[cast("str", result["ruleId"])] += 1
        summary = {
            "restored": record.restored,
            "harnesses": len(record.harnesses),
            "executed": sum(harness.executed for harness in record.harnesses),
            "results": len(results),
            "rules": counts,
            "reported": build_reported(built),
            "held": built.held,
            "fixed": fixed,
        }
        _ = Path(cast("str", args.summary)).write_text(
            json.dumps(summary), encoding="utf-8"
        )
    print(f"Built fuzz SARIF with {len(results)} result(s)")
    return 0
