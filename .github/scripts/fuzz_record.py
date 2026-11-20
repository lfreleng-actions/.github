# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Load and validate the fuzz side's run record for the sarif side."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from fuzz_common import (
    MAX_INPUT_BYTES,
    MAX_RECORD_BYTES,
    PHASES,
    SCHEMA,
    RefusalError,
    inside,
    parse_identities,
    read_regular,
)

if TYPE_CHECKING:
    from pathlib import Path


Identity = tuple[str, ...]


@dataclass(frozen=True)
class RecordedProcess:
    """A validated process entry from the run record."""

    phase: str
    log: Path
    exit_code: int | None
    timed_out: bool
    input: Path | None
    fixed: tuple[Identity, ...] | None = None
    held: tuple[Identity, ...] | None = None


@dataclass(frozen=True)
class RecordedHarness:
    """A validated harness entry from the run record."""

    path: str
    executed: int
    processes: tuple[RecordedProcess, ...]


@dataclass(frozen=True)
class Record:
    """A validated run record."""

    root: str
    restored: bool
    harnesses: tuple[RecordedHarness, ...]


def as_dict(value: object, what: str) -> dict[str, object]:
    """Return value as a JSON object, or refuse."""
    if not isinstance(value, dict):
        msg = f"{what} is not an object"
        raise RefusalError(msg)
    return cast("dict[str, object]", value)


def as_list(value: object, what: str) -> list[object]:
    """Return value as a JSON array, or refuse."""
    if not isinstance(value, list):
        msg = f"{what} is not an array"
        raise RefusalError(msg)
    return cast("list[object]", value)


def as_count(value: object, what: str) -> int:
    """Return value as a non-negative integer, or refuse."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        msg = f"{what} is not a count"
        raise RefusalError(msg)
    return value


def handover_file(handover: Path, value: object, what: str) -> Path:
    """Return the handover file a record entry names, or refuse."""
    path = inside(handover, value) if isinstance(value, str) else None
    if path is None:
        msg = f"{what} does not name a file in the handover"
        raise RefusalError(msg)
    return path


def load_process(handover: Path, value: object) -> RecordedProcess:
    """Validate one process entry."""
    entry = as_dict(value, "a process")
    phase = entry.get("phase")
    code = entry.get("exit_code")
    timed_out = entry.get("timed_out")
    if not isinstance(phase, str) or phase not in PHASES:
        msg = "a process has no known phase"
        raise RefusalError(msg)
    if code is not None and (isinstance(code, bool) or not isinstance(code, int)):
        msg = "a process exit code is not an integer"
        raise RefusalError(msg)
    if not isinstance(timed_out, bool):
        msg = "a process has no timed_out flag"
        raise RefusalError(msg)
    log = handover_file(handover, entry.get("log"), "a process log")
    raw_input = entry.get("input")
    data = None if raw_input is None else handover_file(handover, raw_input, "an input")
    if data is not None and data.stat().st_size > MAX_INPUT_BYTES:
        msg = "a failing input is over the size cap"
        raise RefusalError(msg)
    fixed = load_identities(entry, "fixed", passing=True)
    held = load_identities(entry, "held", passing=False)
    if (fixed is not None or held is not None) and phase != "replay":
        msg = "a process names fixed or held failures but is not a replay"
        raise RefusalError(msg)
    if (fixed is not None and code != 0) or (held is not None and code == 0):
        msg = "a replay names fixed failures but failed, or held ones but passed"
        raise RefusalError(msg)
    return RecordedProcess(phase, log, code, timed_out, data, fixed, held)


def load_identities(
    entry: dict[str, object], key: str, *, passing: bool
) -> tuple[Identity, ...] | None:
    """Return the failure identities a replay names under key, or None.

    A passing replay names, as fixed, every way its input has failed; a
    failing one names, as held, the ways it failed before and no longer
    does.
    """
    raw = entry.get(key)
    if raw is None:
        return None
    identities = parse_identities(raw)
    if identities is None:
        state = "passing" if passing else "failing"
        msg = f"a {state} replay names malformed {key} failures"
        raise RefusalError(msg)
    return tuple(tuple(identity) for identity in identities)


def load_record(handover: Path, commit: str, harnesses: list[str]) -> Record:
    """Read and validate the run record against what discovery recorded."""
    try:
        raw = read_regular(handover / "record.json", MAX_RECORD_BYTES)
        record = as_dict(cast("object", json.loads(raw)), "the run record")
    except (OSError, ValueError, RecursionError) as exc:
        msg = f"cannot read the run record: {exc}"
        raise RefusalError(msg) from exc
    if record.get("schema") != SCHEMA or record.get("commit") != commit:
        msg = "the run record is for another schema or commit"
        raise RefusalError(msg)
    root = record.get("root")
    restored = record.get("restored")
    if not isinstance(root, str) or not root.startswith("/") or "\x00" in root:
        msg = "the run record names no checkout root"
        raise RefusalError(msg)
    if not isinstance(restored, bool):
        msg = "the run record does not say whether state was restored"
        raise RefusalError(msg)
    entries = [
        as_dict(item, "a harness")
        for item in as_list(record.get("harnesses"), "harnesses")
    ]
    paths = [entry.get("path") for entry in entries]
    if sorted(str(path) for path in paths) != harnesses or len(paths) != len(harnesses):
        msg = "the run record's harnesses differ from the ones discovered"
        raise RefusalError(msg)
    loaded: list[RecordedHarness] = []
    for entry in entries:
        processes = tuple(
            load_process(handover, item)
            for item in as_list(entry.get("processes"), "processes")
        )
        if not any(process.phase == "fuzz" for process in processes):
            msg = f"harness {entry.get('path')} has no fuzz process"
            raise RefusalError(msg)
        executed = as_count(entry.get("executed"), "executed")
        loaded.append(RecordedHarness(cast("str", entry["path"]), executed, processes))
    loaded.sort(key=lambda item: item.path)
    return Record(root, restored, tuple(loaded))
