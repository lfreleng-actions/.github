# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Constants, types and log parsing shared by both sides of fuzz_publish.py."""

from __future__ import annotations

import json
import os
import posixpath
import re
import stat
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


EXIT_REFUSED = 2


SCHEMA = 1


TOOL_NAME = "fuzz"


UNCAUGHT = "fuzz/uncaught-exception"


TIMEOUT = "fuzz/timeout"


OUT_OF_MEMORY = "fuzz/out-of-memory"


HARNESS_ERROR = "fuzz/harness-error"


RULES: dict[str, tuple[str, str]] = {
    UNCAUGHT: (
        "Uncaught exception",
        "An input made the fuzzed function raise an exception.",
    ),
    TIMEOUT: (
        "Input over the time limit",
        "An input ran for longer than the 10 second limit.",
    ),
    OUT_OF_MEMORY: (
        "Input over the memory limit",
        "An input used more than the 2 GiB memory limit.",
    ),
    HARNESS_ERROR: (
        "Harness did not run",
        "The fuzz harness could not start, or overran its wall-clock limit.",
    ),
}


PLACEHOLDER = "<unknown>"


BRACKETED = frozenset(
    {"<module>", "<lambda>", "<listcomp>", "<dictcomp>", "<setcomp>", "<genexpr>"}
)


MAX_NAME = 200


PHASES = frozenset({"replay", "fuzz", "merge"})


# The harness contract's limits, and the bounds on what one run keeps.
INPUT_TIMEOUT = 10


RSS_LIMIT_MB = 2048


DEFAULT_SECONDS = 300


TOTAL_SECONDS = 45 * 60


MAX_FAILURES = 20


MAX_INPUT_BYTES = 1 << 20


LOG_LIMIT = 1 << 20


MAX_CORPUS_FILES = 4000


MAX_CORPUS_BYTES = 32 << 20


MAX_STATE_FILES = 100_000


MAX_STATE_BYTES = 1 << 30


MAX_RECORD_BYTES = 4 << 20


MAX_EVIDENCE_BYTES = 256 << 10


MAX_SOURCE_BYTES = 8 << 20


REPLAY_WALL = 60


FUZZ_SLACK = 120


MERGE_WALL = 600


PROBE_WALL = 60


FAILURE_PREFIXES = ("crash-", "timeout-", "oom-")


STATE_MARKER = "state.json"


# Per harness, each way a saved input has failed since it was saved, so
# a replay that fails another way keeps those alerts open and a replay
# that passes can say which alerts it closes.
EVIDENCE = "evidence.json"


# Per harness, the saved inputs whose replay passed, kept with their
# evidence until a run restores the state from a run whose upload code
# scanning processed, so a failed or withheld upload cannot lose the
# evidence that lets their alerts close.
PENDING = "fixed"


# An identity: the rule, exception type, file, function and line.
EVIDENCE_FIELDS = 5


# The most identities one saved input keeps; a run that would need
# more refuses, as when a new failure cannot be saved.
MAX_IDENTITIES = 4


# The key sarif_fingerprint.py writes and the upload guard requires.
# The builder fills it itself from the identity the publish job's
# evidence check compares, so an edit to the failing line keeps the
# alert rather than closing it and opening another.
FINGERPRINT_KEY = "lfrelengContentHash/v1"


# The rules whose results a saved failing input reproduces.
REPRODUCIBLE = frozenset({UNCAUGHT, TIMEOUT, OUT_OF_MEMORY})


UNCAUGHT_BANNER = "=== Uncaught Python exception: ==="


TIMEOUT_BANNER = "=== Timeout:"


OOM_MARKER = "ERROR: libFuzzer: out-of-memory"


LIBFUZZER_ERROR = "ERROR: libFuzzer:"


TRACEBACK_START = "Traceback (most recent call last):"


TRACEBACK_FRAME = re.compile(r'\s*File "([^"\x00]+)", line ([0-9]{1,9}), in (.+)')


TIMEOUT_FRAME = re.compile(r'\s*File "([^"\x00]+)", line ([0-9]{1,9}) in (.+)')


EXECUTED = re.compile(r"stat::number_of_executed_units:\s*([0-9]{1,18})")


SEGMENT = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9_.-]*")


COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


LINE_NUMBER = re.compile(r"[1-9][0-9]{0,8}")


LINE_BREAK = re.compile(r"\r\n|\r|\n")


class RefusalError(Exception):
    """The handover is missing, incomplete or fails validation."""


@dataclass(frozen=True)
class Frame:
    """One stack frame as a log reports it; every field is unvalidated."""

    path: str
    line: int
    function: str


@dataclass(frozen=True)
class Failure:
    """What a failing process's log shows, innermost frame first."""

    rule: str
    exception: str = ""
    frames: tuple[Frame, ...] = ()


def plain_name(text: str) -> str:
    """Return text if it is a plain dotted identifier, else a placeholder."""
    name = text.strip()
    if name in BRACKETED:
        return name
    short = 0 < len(name) <= MAX_NAME and name.isascii()
    if short and all(part.isidentifier() for part in name.split(".")):
        return name
    return PLACEHOLDER


def harness_path(text: str) -> str | None:
    """Return text if it names a harness the way discovery accepts one."""
    if len(text) > MAX_NAME * 4 or not text.endswith(".py"):
        return None
    parts = text.split("/")
    if any(part in {".", ".."} or not SEGMENT.fullmatch(part) for part in parts):
        return None
    return text


def clean_relative(text: str) -> str | None:
    """Return text if it is a plain relative path with no '..' segment."""
    if not text or "\x00" in text or "\\" in text or text.startswith("/"):
        return None
    if any(part in {"", ".", ".."} for part in text.split("/")):
        return None
    return text


def inside(base: Path, relative: str) -> Path | None:
    """Return the regular file relative names under base, or None.

    No component may be a symlink, so the file cannot lie outside base.
    """
    clean = clean_relative(relative)
    if clean is None:
        return None
    path = base
    parts = clean.split("/")
    for index, part in enumerate(parts):
        path /= part
        try:
            mode = path.lstat().st_mode
        except OSError:
            return None
        last = index == len(parts) - 1
        if stat.S_ISLNK(mode) or not (
            stat.S_ISREG(mode) if last else stat.S_ISDIR(mode)
        ):
            return None
    return path


def read_regular(path: Path, limit: int, *, tail: bool = False) -> bytes:
    """Read a regular file without following a final symlink.

    A file over limit bytes raises OSError, unless tail is set, which
    returns its last limit bytes instead.
    """
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            msg = f"{path} is not a regular file"
            raise OSError(msg)
        if info.st_size > limit:
            if not tail:
                msg = f"{path} is over {limit} bytes"
                raise OSError(msg)
            _ = handle.seek(info.st_size - limit)
        return handle.read(limit)


def frames_after(lines: list[str], start: int, pattern: re.Pattern[str]) -> list[Frame]:
    """Return the frames of the last stack block after lines[start]."""
    frames: list[Frame] = []
    block_open = False
    for line in lines[start + 1 :]:
        if LIBFUZZER_ERROR in line:
            break
        if TRACEBACK_START in line or "most recent call first" in line:
            if pattern is TIMEOUT_FRAME and block_open:
                break
            frames = []
            block_open = True
            continue
        match = pattern.fullmatch(line)
        if match:
            frames.append(Frame(match[1], int(match[2]), match[3].strip()))
    return frames


def classify(text: str, exit_code: int | None, *, timed_out: bool) -> Failure | None:
    """Return the failure a process's log shows, or None when it passed."""
    if timed_out or exit_code is None:
        return Failure(HARNESS_ERROR)
    if exit_code == 0:
        return None
    lines = LINE_BREAK.split(text)
    for index in range(len(lines) - 1, -1, -1):
        line = lines[index]
        if UNCAUGHT_BANNER in line:
            following = [item for item in lines[index + 1 :] if item.strip()]
            first = following[0] if following else ""
            exception = plain_name(first.split(":", 1)[0])
            frames = frames_after(lines, index, TRACEBACK_FRAME)
            return Failure(UNCAUGHT, exception, tuple(reversed(frames)))
        if TIMEOUT_BANNER in line:
            frames = frames_after(lines, index, TIMEOUT_FRAME)
            return Failure(TIMEOUT, "", tuple(frames))
        if OOM_MARKER in line:
            return Failure(OUT_OF_MEMORY)
    return Failure(HARNESS_ERROR)


def locate(
    failure: Failure,
    root: str,
    harness: str,
    accepts: Callable[[str, int], bool],
) -> tuple[str, int, str]:
    """Return the file, line and function a failure's result points at.

    The innermost accepted frame in the repository that is not the
    harness wins; failing that, the innermost accepted harness frame;
    failing that, the harness file itself.
    """
    prefix = root.rstrip("/") + "/"
    fallback: tuple[str, int, str] | None = None
    if failure.rule in {UNCAUGHT, TIMEOUT}:
        for frame in failure.frames:
            raw = frame.path
            if raw.startswith("/"):
                if not raw.startswith(prefix):
                    continue
                raw = raw[len(prefix) :]
            relative = clean_relative(posixpath.normpath(raw))
            if relative is None or not accepts(relative, frame.line):
                continue
            if relative == harness:
                if fallback is None:
                    fallback = (relative, frame.line, plain_name(frame.function))
                continue
            return relative, frame.line, plain_name(frame.function)
    return fallback or (harness, 1, PLACEHOLDER)


def read_log(path: Path) -> str:
    """Return the last LOG_LIMIT bytes of a log as text."""
    return read_regular(path, LOG_LIMIT, tail=True).decode("utf-8", errors="replace")


def parse_identities(value: object) -> list[list[str]] | None:
    """Return value as a list of failure identities, or None if malformed.

    An identity is EVIDENCE_FIELDS strings, its last a line number; a
    list holds one to MAX_IDENTITIES of them.
    """
    if not isinstance(value, list):
        return None
    items = cast("list[object]", value)
    if not 1 <= len(items) <= MAX_IDENTITIES:
        return None
    identities: list[list[str]] = []
    for item in items:
        parts = cast("list[object]", item) if isinstance(item, list) else []
        if len(parts) != EVIDENCE_FIELDS or not all(
            isinstance(part, str) for part in parts
        ):
            return None
        identity = cast("list[str]", parts)
        if not LINE_NUMBER.fullmatch(identity[-1]):
            return None
        identities.append(identity)
    return identities


def parse_harnesses(text: str) -> list[str]:
    """Return the JSON array of harness paths, sorted, or raise ValueError."""
    value = cast("object", json.loads(text))
    if not isinstance(value, list) or not value:
        msg = "harnesses must be a non-empty JSON array"
        raise ValueError(msg)  # argparse reports ValueError
    paths: list[str] = []
    for item in cast("list[object]", value):
        if not isinstance(item, str) or harness_path(item) is None:
            msg = f"not a harness path: {item!r}"
            raise ValueError(msg)
        paths.append(item)
    if len(set(paths)) != len(paths):
        msg = "harnesses repeat a path"
        raise ValueError(msg)
    return sorted(paths)
