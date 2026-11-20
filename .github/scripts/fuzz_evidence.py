# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""The evidence side of fuzz_publish.py: decide which open alerts may close.

A passing replay names, in the summary's 'fixed', each alert its input
failed as. The state that says so lives in the Actions cache, which any
fuzz job of the run can write, so a compromised fuzz job could pair a
harmless input with another repository's alert identity. Once code
scanning processes an upload, the publish job therefore signs a
binding, under FUZZ_EVIDENCE_KEY, which no fuzz job holds: the
repository, the upload's SARIF ID, and each reported result's rule,
path and message with the SHA-256 of the input that reproduced it.
SHA-1, which libFuzzer names inputs by, admits chosen collisions, so
the binding never relies on it. The next fuzz job restores the binding
and hands it over as data.

A failing replay also reports each earlier way its input failed, which
only the state records. Such a held association enters the binding
only when the previous binding, verified for the analysis the evidence
check read, already held it, so a poisoned state cannot tie an alert
to an input that never failed that way.

An open alert this run does not report is proven fixed only when a
passing replay names it with the input the binding holds for it, and
the binding is for the repository's latest fuzz analysis, so neither a
forged nor a stale binding can close it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, cast

from fuzz_common import (
    EXIT_REFUSED,
    HARNESS_ERROR,
    SCHEMA,
    RefusalError,
    inside,
    read_regular,
)

if TYPE_CHECKING:
    import argparse

KEY_ENV = "FUZZ_EVIDENCE_KEY"


# The binding's name in the fuzz job's evidence directory and in the
# handover.
BINDING = "binding.json"


MAX_BINDING_BYTES = 1 << 20


MAX_ALERTS_BYTES = 16 << 20


MIN_KEY_LENGTH = 32


# v2 binds SHA-256 input digests; a v1 binding, of SHA-1 digests, no
# longer verifies.
BINDING_TAG = "lfrelengFuzzBinding/v2"


SHA256 = re.compile(r"[0-9a-f]{64}")


SARIF_ID = re.compile(r"[0-9A-Za-z-]{1,100}")


# An alert identity: its rule, decoded path and message.
Alert = tuple[str, str, str]


# An alert identity and the SHA-256 of the input bound to it.
Bound = tuple[str, str, str, str]


def evidence_key() -> bytes:
    """Return the binding key from the environment, or refuse."""
    value = os.environ.get(KEY_ENV, "")
    if len(value) < MIN_KEY_LENGTH:
        msg = f"{KEY_ENV} is unset or shorter than {MIN_KEY_LENGTH} characters"
        raise RefusalError(msg)
    return value.encode("utf-8")


def sign(key: bytes, repository: str, sarif_id: str, entries: list[Bound]) -> str:
    """Return the binding's MAC over the repository, SARIF ID and entries."""
    payload = json.dumps(
        [BINDING_TAG, repository, sarif_id, [list(entry) for entry in entries]],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def strings(value: object, size: int) -> tuple[str, ...] | None:
    """Return value as a tuple of size strings, or None."""
    if not isinstance(value, list):
        return None
    items = cast("list[object]", value)
    if len(items) != size or not all(isinstance(item, str) for item in items):
        return None
    return tuple(cast("list[str]", items))


def summary_entries(summary: dict[str, object], key: str) -> list[dict[str, str]]:
    """Return the summary's identity entries under key."""
    return cast("list[dict[str, str]]", summary.get(key) or [])


def bound_entries(summary: dict[str, object], previous: set[Bound]) -> list[Bound]:
    """Return the input associations the next binding may hold.

    Each reported result an observed failure reproduced counts, with
    its input's SHA-256; a held association counts only when the previous
    binding holds it.
    """
    entries = {
        (item["rule"], item["path"], item["message"], item["input"])
        for item in summary_entries(summary, "reported")
        if "input" in item
    }
    held = {
        (item["rule"], item["path"], item["message"], item["input"])
        for item in summary_entries(summary, "held")
    }
    return sorted(entries | (held & previous))


def make_binding(
    key: bytes,
    repository: str,
    sarif_id: str,
    summary: dict[str, object],
    previous: set[Bound],
) -> dict[str, object]:
    """Return the signed binding for an upload the summary describes."""
    if not SARIF_ID.fullmatch(sarif_id):
        msg = "the upload reported no SARIF ID"
        raise RefusalError(msg)
    entries = bound_entries(summary, previous)
    return {
        "schema": SCHEMA,
        "repository": repository,
        "sarif_id": sarif_id,
        "entries": [list(entry) for entry in entries],
        "mac": sign(key, repository, sarif_id, entries),
    }


class BindingError(Exception):
    """A handed-over binding that cannot be read as one."""


def parse_binding(path: Path) -> tuple[dict[str, object], list[Bound], str]:
    """Return a binding file's fields, entries and MAC, or raise BindingError."""
    try:
        raw = cast("object", json.loads(read_regular(path, MAX_BINDING_BYTES)))
    except (OSError, ValueError, RecursionError) as exc:
        msg = "the evidence binding is unreadable"
        raise BindingError(msg) from exc
    malformed = "the evidence binding is malformed"
    if not isinstance(raw, dict):
        raise BindingError(malformed)
    binding = cast("dict[str, object]", raw)
    items = binding.get("entries")
    mac = binding.get("mac")
    if not isinstance(items, list) or not isinstance(mac, str):
        raise BindingError(malformed)
    found = [strings(item, 4) for item in cast("list[object]", items)]
    if binding.get("schema") != SCHEMA or None in found:
        raise BindingError(malformed)
    entries = [cast("Bound", item) for item in found]
    if not all(SHA256.fullmatch(entry[3]) for entry in entries):
        raise BindingError(malformed)
    return binding, entries, mac


def load_binding(
    handover: Path, key: bytes, repository: str, sarif_id: str
) -> tuple[set[Bound], str]:
    """Return the handed-over binding's entries, or none and the reason.

    Only a binding this key signed, for this repository and for the
    latest fuzz analysis, counts; anything else proves nothing.
    """
    path = inside(handover, BINDING)
    if path is None:
        return set(), "the handover holds no evidence binding"
    try:
        binding, entries, mac = parse_binding(path)
    except BindingError as exc:
        return set(), str(exc)
    if binding.get("repository") != repository or binding.get("sarif_id") != sarif_id:
        return set(), "the evidence binding is for another repository or analysis"
    if not hmac.compare_digest(mac, sign(key, repository, sarif_id, entries)):
        return set(), "the evidence binding's signature does not match"
    return set(entries), ""


def hand_over_binding(binding: str, output: Path) -> None:
    """Copy the restored evidence binding, if any, into the handover.

    The fuzz side cannot check its signature and need not: the publish
    job does, and a binding that is missing or forged only keeps alerts
    open.
    """
    if not binding:
        return
    try:
        data = read_regular(Path(binding), MAX_BINDING_BYTES)
    except FileNotFoundError:
        return
    except OSError as exc:
        print(f"::warning::not handing over the evidence binding: {exc}")
        return
    _ = (output / BINDING).write_bytes(data)


def load_alerts(path: Path) -> list[Alert]:
    """Read the open alerts, one JSON object per line, as the API gave them."""
    alerts: list[Alert] = []
    for line in read_regular(path, MAX_ALERTS_BYTES).decode("utf-8").splitlines():
        if not line.strip():
            continue
        item = cast("dict[str, object]", json.loads(line))
        # A missing field reads as 'None', which nothing proves.
        rule, file, text = (str(item.get(name)) for name in ("rule", "path", "message"))
        alerts.append((rule, file, text))
    return alerts


def unproven(
    alerts: list[Alert], summary: dict[str, object], bound: set[Bound]
) -> tuple[list[Alert], list[Alert]]:
    """Return the open alerts an upload would close without evidence.

    The second list holds those a passing replay names fixed with an
    input the binding does not tie to them.
    """
    reported = {
        (item["rule"], item["path"], item["message"])
        for item in summary_entries(summary, "reported")
    }
    claimed = {
        (item["rule"], item["path"], item["message"], item["input"])
        for item in summary_entries(summary, "fixed")
    }
    fixed = {entry[:3] for entry in claimed & bound}
    exempt = summary.get("restored") is True
    left = [
        alert
        for alert in alerts
        if not (exempt and alert[0] == HARNESS_ERROR)
        and alert not in reported
        and alert not in fixed
    ]
    unbound = [alert for alert in left if alert in {entry[:3] for entry in claimed}]
    return left, unbound


def load_summary(path: Path) -> dict[str, object]:
    """Read the summary the sarif side wrote in this job."""
    return cast("dict[str, object]", json.loads(path.read_text(encoding="utf-8")))


def evidence_main(args: argparse.Namespace) -> int:
    """Print how many open alerts an upload would close without evidence."""
    repository = cast("str", args.repository)
    sarif_id = cast("str", args.sarif_id)
    try:
        key = evidence_key()
        summary = load_summary(Path(cast("str", args.summary)))
        alerts = load_alerts(Path(cast("str", args.alerts)))
    except (OSError, ValueError, RefusalError) as exc:
        print(f"::error::cannot check the evidence: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    bound, reason = load_binding(
        Path(cast("str", args.handover)), key, repository, sarif_id
    )
    left, unbound = unproven(alerts, summary, bound)
    if unbound:
        print(
            f"::warning::{repository}: {len(unbound)} open alert(s) a passing"
            " replay names fixed are not bound to the input that passed"
            f"{f' ({reason})' if reason else ''}",
            file=sys.stderr,
        )
    print(len(left))
    return 0


def bind_main(args: argparse.Namespace) -> int:
    """Write the signed binding for an upload code scanning processed."""
    repository = cast("str", args.repository)
    try:
        key = evidence_key()
        summary = load_summary(Path(cast("str", args.summary)))
        previous, reason = load_binding(
            Path(cast("str", args.handover)),
            key,
            repository,
            cast("str", args.previous_sarif_id),
        )
        if reason and summary_entries(summary, "held"):
            print(f"::notice::{repository}: signing no held failure: {reason}")
        binding = make_binding(
            key, repository, cast("str", args.sarif_id), summary, previous
        )
    except (OSError, ValueError, RefusalError) as exc:
        print(f"::error::cannot bind the evidence: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    output = Path(cast("str", args.output))
    output.parent.mkdir(parents=True, exist_ok=True)
    _ = output.write_text(json.dumps(binding), encoding="utf-8")
    print(f"Bound {len(cast('list[object]', binding['entries']))} result(s)")
    return 0
