# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Report organisation repositories that share an OpenSSF Scorecard slot.

Each repository runs Scorecard weekly on Sunday at its own minute. The
slots sit on a grid, minute-of-day 4 + 9k UTC for k from 0 to 159, so
none falls on :00 or :30. A repository created from a template inherits
the template's cron line and shares its slot until someone moves it;
this script finds those.

The scorecard-slots.yaml workflow fetches the data and passes it in a
directory laid out as:

- repos.json: a JSON array of the repositories to audit, each an object
  with 'name', 'is_template' and 'created_at' as the REST API lists
  them;
- <name>/<file>: the default-branch text of each Scorecard workflow
  the repository carries, for <file> in WORKFLOW_FILES;
- <name>/<file>.blame.json: the GraphQL blame ranges of that file, an
  array of {startingLine, endingLine, commit: {committedDate}}.

A repository may schedule Scorecard from either file:
security-workflows keeps its schedule in openssf-scorecard-self.yaml,
because its openssf-scorecard.yaml is the reusable lane.

Findings:

- a cron value two or more repositories share. The repository that has
  held it longest keeps it: a template first, so the repository created
  from one moves, then the oldest commit date of the cron line, then
  the oldest repository. Every other one gets a free slot;
- a Scorecard schedule that is not weekly on Sunday, which also gets a
  free slot.

A free slot is the first unused grid slot, or once the grid is full the
first unused minute of Sunday that is not :00 or :30.

Usage: scorecard_slots.py --data=DIR [--summary=FILE] [--output=FILE]

The summary (Markdown) and output (GitHub step outputs 'findings' and
'slack_list') files are appended to, as GitHub Actions expects.

Exit codes: 0 audited, with or without findings; 2 bad arguments or
unreadable input.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

# The workflow runs this file under python -I, which leaves the script's
# directory off sys.path; the schedule reader beside it lives there.
_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from scorecard_schedule import schedule_crons  # noqa: E402

WORKFLOW_FILES = ("openssf-scorecard.yaml", "openssf-scorecard-self.yaml")
GRID_START = 4
GRID_STEP = 9
GRID_SIZE = 160
MINUTES_PER_DAY = 24 * 60
EXIT_USAGE = 2
SLACK_MAX_ENTRIES = 50
SLACK_MAX_CHARS = 2500
MONTHS = (
    "jan",
    "feb",
    "mar",
    "apr",
    "may",
    "jun",
    "jul",
    "aug",
    "sep",
    "oct",
    "nov",
    "dec",
)
WEEKDAYS = ("sun", "mon", "tue", "wed", "thu", "fri", "sat")
SUNDAYS = ({0}, {7}, {0, 7})
UNSAFE = re.compile(r"[^0-9A-Za-z._*/,\- ]")


class InputError(Exception):
    """The data directory does not hold what the workflow writes."""


@dataclass
class Entry:
    """One Scorecard cron line in one repository."""

    repo: str
    file: str
    line: int
    cron: str
    is_template: bool
    created_at: str
    held_since: str
    sunday_minute: int | None = None
    findings: list[str] = field(default_factory=list[str])
    slot: str | None = None
    moves: bool = False

    @property
    def key(self) -> str:
        """Return the value that identifies this entry's slot."""
        if self.sunday_minute is not None:
            return cron_for(self.sunday_minute)
        return " ".join(self.cron.split())

    def rank(self) -> tuple[int, str, str, str]:
        """Order entries so the one that has held a slot longest sorts first."""
        return (
            0 if self.is_template else 1,
            instant(self.held_since),
            instant(self.created_at),
            self.repo,
        )


def instant(stamp: str) -> str:
    """Return an ISO 8601 timestamp as UTC text that sorts by time.

    GraphQL's GitTimestamp keeps the committer's offset, so the text of
    two stamps does not order them. An unknown or unparsable stamp sorts
    last.
    """
    try:
        moment = datetime.fromisoformat(stamp)
    except ValueError:
        return "~"
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).isoformat()


def cron_for(minute_of_day: int) -> str:
    """Return the weekly Sunday cron value for a minute of the day."""
    return f"{minute_of_day % 60} {minute_of_day // 60} * * 0"


def field_values(
    text: str, low: int, high: int, names: tuple[str, ...] = (), base: int = 0
) -> set[int] | None:
    """Return the values a cron field matches, or None when it does not parse.

    names spells the values from base upward, as month and weekday names
    do. A field is a comma list of '*', 'n' or 'n-m', each with an
    optional '/step'; 'n/step' runs from n to high.
    """

    def number(word: str) -> int | None:
        if word.isdigit():
            return int(word)
        return names.index(word) + base if word in names else None

    values: set[int] = set()
    for item in text.lower().split(","):
        span, slash, step_text = item.partition("/")
        step = int(step_text) if step_text.isdigit() else 0
        if slash and step < 1:
            return None
        first, dash, last = span.partition("-")
        start = low if span == "*" else number(first)
        end = high if span == "*" or (slash and not dash) else start
        if dash:
            end = number(last)
        if start is None or end is None or not low <= start <= end <= high:
            return None
        values.update(range(start, end + 1, step or 1))
    return values


def sunday_minute(cron: str) -> int | None:
    """Return the minute of day for a weekly Sunday cron, else None.

    The cron's meaning decides, not its spelling: a month of '1-12' or
    '*/1' runs every month as '*' does. A day of month must start with
    '*', since cron runs a job when either a restricted day of month or
    the weekday matches, so '1-31' runs it every day.
    """
    fields = cron.split()
    if len(fields) != 5:  # noqa: PLR2004
        return None
    minute, hour, day, month, weekday = fields
    if not day.startswith("*") or field_values(day, 1, 31) != set(range(1, 32)):
        return None
    if field_values(month, 1, 12, MONTHS, 1) != set(range(1, 13)):
        return None
    if field_values(weekday, 0, 7, WEEKDAYS) not in SUNDAYS:
        return None
    minutes, hours = field_values(minute, 0, 59), field_values(hour, 0, 23)
    if not (minutes and hours and len(minutes) == 1 and len(hours) == 1):
        return None
    return hours.pop() * 60 + minutes.pop()


def line_date(blame: object, line: int) -> str:
    """Return the commit date of the blame range covering line, or ''."""
    if not isinstance(blame, list):
        return ""
    for item in cast("list[object]", blame):
        if not isinstance(item, dict):
            continue
        span = cast("dict[str, object]", item)
        start, end = span.get("startingLine"), span.get("endingLine")
        commit = span.get("commit")
        if not (
            isinstance(start, int) and isinstance(end, int) and isinstance(commit, dict)
        ):
            continue
        if start <= line <= end:
            date = cast("dict[str, object]", commit).get("committedDate")
            return date if isinstance(date, str) else ""
    return ""


def load_repos(data: Path) -> list[dict[str, object]]:
    """Read repos.json from the data directory."""
    try:
        raw = cast(
            "object", json.loads((data / "repos.json").read_text(encoding="utf-8"))
        )
    except (OSError, ValueError) as exc:
        msg = f"cannot read {data / 'repos.json'}: {exc}"
        raise InputError(msg) from exc
    if not isinstance(raw, list):
        msg = "repos.json is not a JSON array"
        raise InputError(msg)
    repos: list[dict[str, object]] = []
    for item in cast("list[object]", raw):
        if not isinstance(item, dict) or not isinstance(
            cast("dict[str, object]", item).get("name"), str
        ):
            msg = "repos.json holds an entry without a 'name'"
            raise InputError(msg)
        repos.append(cast("dict[str, object]", item))
    return repos


def load_entries(data: Path, repo: dict[str, object]) -> list[Entry]:
    """Return every Scorecard cron entry one repository carries."""
    name = cast("str", repo["name"])
    created = repo.get("created_at")
    entries: list[Entry] = []
    for file in WORKFLOW_FILES:
        path = data / name / file
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
            blame_path = path.with_name(f"{file}.blame.json")
            blame = (
                cast("object", json.loads(blame_path.read_text(encoding="utf-8")))
                if blame_path.is_file()
                else None
            )
        except (OSError, ValueError) as exc:
            msg = f"cannot read {path}: {exc}"
            raise InputError(msg) from exc
        for line, cron in schedule_crons(text):
            entry = Entry(
                repo=name,
                file=file,
                line=line,
                cron=cron,
                is_template=repo.get("is_template") is True,
                created_at=created if isinstance(created, str) else "",
                held_since=line_date(blame, line),
                sunday_minute=sunday_minute(cron),
            )
            entries.append(entry)
    return entries


def free_slots(used: set[int]) -> list[int]:
    """Return unused minutes of the day, grid slots first."""
    grid = [GRID_START + GRID_STEP * k for k in range(GRID_SIZE)]
    on_grid = set(grid)
    rest = [m for m in range(MINUTES_PER_DAY) if m % 30 != 0 and m not in on_grid]
    return [m for m in grid + rest if m not in used]


def audit(entries: list[Entry]) -> list[Entry]:
    """Mark findings and suggested slots on entries; return those with findings."""
    groups: dict[str, list[Entry]] = {}
    for entry in entries:
        groups.setdefault(entry.key, []).append(entry)
    for key, members in groups.items():
        if len({m.repo for m in members}) < 2:  # noqa: PLR2004
            continue
        members.sort(key=Entry.rank)
        holder = members[0]
        others = ", ".join(sorted({m.repo for m in members} - {holder.repo}))
        why = "template" if holder.is_template else "held longest"
        holder.findings.append(f"Shares `{key}` with {others}; keeps it ({why})")
        for member in members[1:]:
            if member.repo == holder.repo:
                continue
            member.findings.append(f"Shares `{key}` with {holder.repo}, which keeps it")
            member.moves = True
    for entry in entries:
        if entry.sunday_minute is None:
            entry.findings.append(f"`{entry.key}` is not weekly on Sunday")
            entry.moves = True
    flagged = sorted(
        (e for e in entries if e.findings), key=lambda e: (e.key, e.rank())
    )
    used = {e.sunday_minute for e in entries if e.sunday_minute is not None}
    slots = iter(free_slots(used))
    for entry in flagged:
        if entry.moves:
            slot = next(slots, None)
            entry.slot = cron_for(slot) if slot is not None else None
    return flagged


def cell(text: str) -> str:
    """Escape text for a Markdown table cell."""
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def summary(flagged: list[Entry], scanned: int, unscheduled: list[str]) -> str:
    """Render the job summary in Markdown."""
    out = ["## OpenSSF Scorecard Slot Audit", ""]
    scheduled = scanned - len(unscheduled)
    out.extend([f"Audited {scanned} repositories; {scheduled} schedule Scorecard.", ""])
    if flagged:
        out.extend(
            [
                f"### ⚠️ {len(flagged)} Scorecard schedules need attention",
                "",
                "| Repository | File | Schedule | Finding | Held since | Suggested slot |",
                "| ---------- | ---- | -------- | ------- | ---------- | -------------- |",
            ]
        )
        for e in flagged:
            if e.moves:
                slot = f"`{e.slot}`" if e.slot else "none free"
            else:
                slot = "keeps slot"
            row = [
                e.repo,
                f"{e.file}:{e.line}",
                f"`{e.cron}`",
                "; ".join(e.findings),
                e.held_since or "unknown",
                slot,
            ]
            out.append("| " + " | ".join(cell(c) for c in row) + " |")
        out.extend(["", "Move each flagged repository to its suggested slot."])
    else:
        out.extend(["### ✅ Every Scorecard schedule has its own Sunday slot", ""])
    if unscheduled:
        head = f"{len(unscheduled)} repositories without a Scorecard schedule"
        out.extend(["", f"<details><summary>{head}</summary>", ""])
        out.extend(f"- `{name}`" for name in unscheduled)
        out.extend(["", "</details>"])
    return "\n".join(out) + "\n"


def slack_list(flagged: list[Entry]) -> str:
    """Return the moves as one line, joined by literal backslash-n, for Slack.

    The workflow interpolates this into a double-quoted YAML scalar, so
    each entry keeps only characters a repository name or cron value
    needs, and the list stays within Slack's 3000-character section
    limit.
    """
    lines: list[str] = []
    chars = 0
    movers = [e for e in flagged if e.moves]
    for e in movers:
        target = e.slot or "no free slot"
        repo, key, slot = (UNSAFE.sub("", part) for part in (e.repo, e.key, target))
        text = f"{repo}: {key} -> {slot}"
        cost = len(text) + (1 if lines else 0)
        if len(lines) >= SLACK_MAX_ENTRIES or chars + cost > SLACK_MAX_CHARS:
            break
        lines.append(text)
        chars += cost
    if len(movers) > len(lines):
        lines.append(f"... and {len(movers) - len(lines)} more")
    return "\\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Audit the data directory and write the summary and step outputs."""
    parser = argparse.ArgumentParser(description="Report shared Scorecard slots.")
    _ = parser.add_argument("--data", required=True, help="directory to audit")
    _ = parser.add_argument("--summary", help="Markdown file to append the report to")
    _ = parser.add_argument("--output", help="GitHub output file to append to")
    args = parser.parse_args(argv)
    data = Path(cast("str", args.data))
    try:
        repos = load_repos(data)
        entries = [e for repo in repos for e in load_entries(data, repo)]
    except InputError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return EXIT_USAGE
    scheduled = {e.repo for e in entries}
    unscheduled = sorted(
        cast("str", r["name"]) for r in repos if r["name"] not in scheduled
    )
    flagged = audit(entries)
    report = summary(flagged, len(repos), unscheduled)
    print(report)
    for e in flagged:
        print(f"::warning::{e.repo} ({e.file}:{e.line}): {'; '.join(e.findings)}")
    summary_path = cast("str | None", args.summary)
    output_path = cast("str | None", args.output)
    if summary_path:
        with Path(summary_path).open("a", encoding="utf-8") as handle:
            _ = handle.write(report)
    if output_path:
        with Path(output_path).open("a", encoding="utf-8") as handle:
            _ = handle.write(
                f"findings={len(flagged)}\nslack_list={slack_list(flagged)}\n"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
