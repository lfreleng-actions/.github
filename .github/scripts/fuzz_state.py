# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Budget, saved-state and handover helpers for the fuzz side of fuzz_publish.py."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from pathlib import Path
from typing import cast

from fuzz_common import (
    EVIDENCE,
    EXECUTED,
    LOG_LIMIT,
    MAX_EVIDENCE_BYTES,
    MAX_FAILURES,
    MAX_INPUT_BYTES,
    MAX_STATE_BYTES,
    MAX_STATE_FILES,
    PENDING,
    STATE_MARKER,
    TOTAL_SECONDS,
    parse_identities,
    read_regular,
)


def fuzz_budget(count: int, seconds: int, total: int = TOTAL_SECONDS) -> int:
    """Return each harness's fuzzing seconds, sharing total when exceeded."""
    if count <= 0 or count * seconds <= total:
        return seconds
    return max(1, total // count)


def harness_key(path: str) -> str:
    """Return the state directory name for a harness path."""
    return hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]


def sha1_hex(data: bytes) -> str:
    """Return the SHA-1 hex digest of data, as libFuzzer names inputs."""
    return hashlib.sha1(data, usedforsecurity=False).hexdigest()


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 hex digest of data, as the evidence binding names inputs."""
    return hashlib.sha256(data).hexdigest()


def tree_size(root: Path) -> tuple[int, int]:
    """Return the number and total size of regular files under root."""
    files = 0
    size = 0
    for directory, _, names in os.walk(root):
        for name in names:
            info = (Path(directory) / name).lstat()
            if stat.S_ISREG(info.st_mode):
                files += 1
                size += info.st_size
    return files, size


def remove(path: Path) -> None:
    """Remove a file, link or directory tree."""
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


def prune(root: Path) -> None:
    """Remove everything under root that is not a directory or regular file."""
    for directory, dirnames, names in os.walk(root):
        for name in [*dirnames, *names]:
            path = Path(directory) / name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                path.unlink()


def prepare_state(
    state: Path, keys: set[str], restored_key: str, *, published: bool = False
) -> bool:
    """Bound the restored state in place; return whether it was restored.

    State over the file or byte bound, or without the marker a saved
    state carries, is discarded and counts as nothing restored. The
    state of a harness no longer found is dropped, and saved inputs
    over the caps with it; the publish job's evidence check keeps the
    alerts those inputs held from closing without a replay.

    Inputs whose replay passed are dropped when the run that saved the
    state published it, which closed their alerts; otherwise they go
    back to be replayed, and name their alerts fixed, again.
    """
    if state.is_symlink() or (state.exists() and not state.is_dir()):
        state.unlink()
    state.mkdir(parents=True, exist_ok=True)
    prune(state)
    files, size = tree_size(state)
    marker = state / STATE_MARKER
    restored = bool(restored_key) and marker.is_file()
    if files > MAX_STATE_FILES or size > MAX_STATE_BYTES or not restored:
        for child in state.iterdir():
            remove(child)
        return False
    for child in state.iterdir():
        if child.name != STATE_MARKER and child.name not in keys:
            remove(child)
        elif child.is_dir():
            for part in child.iterdir():
                if part.name not in {"corpus", "failures", PENDING, EVIDENCE}:
                    remove(part)
            failures = child / "failures"
            settle(child / PENDING, failures, published=published)
            if failures.is_dir():
                _ = cap_failures(failures)
    return True


def settle(pending: Path, failures: Path, *, published: bool) -> None:
    """Drop the passing inputs a publication closed, or replay them again."""
    if not pending.is_dir():
        return
    if not published:
        failures.mkdir(exist_ok=True)
        for path in pending.iterdir():
            if path.is_file() and not (failures / path.name).exists():
                _ = path.replace(failures / path.name)
    shutil.rmtree(pending)


def saved_inputs(directory: Path) -> int:
    """Return how many saved inputs a harness holds, passing ones included."""
    return sum(
        1
        for name in ("failures", PENDING)
        if (directory / name).is_dir()
        for _ in (directory / name).iterdir()
    )


def cap_failures(failures: Path) -> int:
    """Keep at most MAX_FAILURES saved inputs of at most MAX_INPUT_BYTES.

    Return how many inputs were removed.
    """
    kept: list[Path] = []
    removed = 0
    for path in sorted(failures.iterdir()):
        if (
            not path.is_file()
            or path.is_symlink()
            or path.stat().st_size > MAX_INPUT_BYTES
        ):
            remove(path)
            removed += 1
        else:
            kept.append(path)
    for path in kept[MAX_FAILURES:]:
        path.unlink()
        removed += 1
    return removed


def load_evidence(directory: Path) -> dict[str, list[list[str]]]:
    """Return each way each saved input of a harness has failed.

    An entry maps an input's file name to its identities, oldest first:
    the rule, exception type, file, function and line of a failure it
    was published under. Anything malformed reads as no evidence, which
    only keeps an alert open.
    """
    try:
        raw = read_regular(directory / EVIDENCE, MAX_EVIDENCE_BYTES)
        value = cast("object", json.loads(raw))
    except (OSError, ValueError, RecursionError):
        return {}
    if not isinstance(value, dict):
        return {}
    evidence: dict[str, list[list[str]]] = {}
    for name, item in cast("dict[str, object]", value).items():
        identities = parse_identities(item)
        if identities is not None:
            evidence[name] = identities
    return evidence


def save_evidence(directory: Path, evidence: dict[str, list[list[str]]]) -> None:
    """Write the evidence of the saved inputs a harness still holds."""
    kept = {
        name: evidence[name]
        for name in sorted(evidence)
        if any((directory / part / name).is_file() for part in ("failures", PENDING))
    }
    _ = (directory / EVIDENCE).write_text(json.dumps(kept), encoding="utf-8")


def truncate_log(path: Path) -> None:
    """Keep only the last LOG_LIMIT bytes of a log."""
    if path.stat().st_size > LOG_LIMIT:
        data = read_regular(path, LOG_LIMIT, tail=True)
        _ = path.write_bytes(data)


def executed_units(text: str) -> int:
    """Return the input count libFuzzer's final stats report, or 0."""
    found = EXECUTED.findall(text)
    return int(cast("str", found[-1])) if found else 0
