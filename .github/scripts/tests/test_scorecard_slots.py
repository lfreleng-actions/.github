# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Contract tests for .github/scripts/scorecard_slots.py.

Each test lays out a data directory the way scorecard-slots.yaml does,
runs the script over it as a subprocess and reads back the step outputs
and job summary it appends. The suite imports nothing from pytest, so
the pre-commit type checkers resolve it without a test environment.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import cast

SCRIPT = Path(__file__).resolve().parent.parent / "scorecard_slots.py"
EXIT_USAGE = 2
OLD = "2025-01-01T00:00:00Z"
NEW = "2026-06-01T00:00:00Z"


@dataclass
class Repo:
    """One repository to write into the data directory."""

    name: str
    cron: str | None = None
    file: str = "openssf-scorecard.yaml"
    since: str = OLD
    is_template: bool = False
    created_at: str = OLD
    text: str | None = None


@dataclass
class Run:
    """What one run of the script left behind."""

    code: int
    outputs: dict[str, str]
    summary: str
    stderr: str


def workflow(cron: str) -> str:
    """Return a Scorecard caller scheduled at cron, as the template has it."""
    return (
        "---\n"
        'name: "OpenSSF Scorecard"\n'
        "# yamllint disable-line rule:truthy\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "  schedule:\n"
        f'    - cron: "{cron}"\n'
        "  push:\n"
        '    branches: ["main"]\n'
    )


def write(data: Path, repos: list[Repo]) -> None:
    """Lay out repos.json and each repository's files under data."""
    data.mkdir()
    listing = [
        {"name": r.name, "is_template": r.is_template, "created_at": r.created_at}
        for r in repos
    ]
    _ = (data / "repos.json").write_text(json.dumps(listing), encoding="utf-8")
    for r in repos:
        if r.text is None and r.cron is None:
            continue
        folder = data / r.name
        folder.mkdir(exist_ok=True)
        text = r.text if r.text is not None else workflow(cast("str", r.cron))
        _ = (folder / r.file).write_text(text, encoding="utf-8")
        blame = [
            {"startingLine": 1, "endingLine": 6, "commit": {"committedDate": OLD}},
            {"startingLine": 7, "endingLine": 7, "commit": {"committedDate": r.since}},
            {"startingLine": 8, "endingLine": 9, "commit": {"committedDate": OLD}},
        ]
        _ = (folder / f"{r.file}.blame.json").write_text(
            json.dumps(blame), encoding="utf-8"
        )


def run(tmp: Path, repos: list[Repo] | None = None) -> Run:
    """Run the script over repos, or over tmp/data as it stands."""
    data = tmp / "data"
    if repos is not None:
        write(data, repos)
    output, summary = tmp / "output", tmp / "summary.md"
    proc = subprocess.run(
        [
            sys.executable,
            "-I",
            str(SCRIPT),
            f"--data={data}",
            f"--summary={summary}",
            f"--output={output}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    outputs: dict[str, str] = {}
    if output.exists():
        for line in output.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            outputs[key] = value
    text = summary.read_text(encoding="utf-8") if summary.exists() else ""
    return Run(proc.returncode, outputs, text, proc.stderr)


def row(result: Run, repo: str) -> str:
    """Return the summary table row for repo, or ''."""
    prefix = f"| {repo} |"
    return next((x for x in result.summary.splitlines() if x.startswith(prefix)), "")


def test_distinct_grid_slots_report_nothing(tmp_path: Path) -> None:
    """An organisation on its own slots, as after #277, has no findings."""
    result = run(
        tmp_path,
        [Repo("a", "4 0 * * 0"), Repo("b", "13 0 * * 0"), Repo("c", "55 23 * * 0")],
    )
    assert result.code == 0, result.stderr
    assert result.outputs == {"findings": "0", "slack_list": ""}
    assert "✅" in result.summary


def test_shared_slot_moves_the_newer_holder(tmp_path: Path) -> None:
    """The repository whose cron line is newer moves to the first free slot."""
    result = run(
        tmp_path,
        [
            Repo("newer", "4 0 * * 0", since=NEW),
            Repo("older", "4 0 * * 0", since=OLD, created_at=NEW),
            Repo("next", "13 0 * * 0"),
        ],
    )
    assert result.code == 0, result.stderr
    assert result.outputs["findings"] == "2"
    assert "keeps slot" in row(result, "older")
    assert "`22 0 * * 0`" in row(result, "newer")
    assert result.outputs["slack_list"] == "newer: 4 0 * * 0 -> 22 0 * * 0"


def test_sunday_spelt_seven_shares_the_slot(tmp_path: Path) -> None:
    """Weekday 7 is Sunday, so it shares the slot that weekday 0 holds."""
    result = run(tmp_path, [Repo("a", "4 0 * * 0"), Repo("b", "4 0 * * 7", since=NEW)])
    assert result.outputs["findings"] == "2"
    assert "`13 0 * * 0`" in row(result, "b")


def test_template_keeps_its_slot(tmp_path: Path) -> None:
    """A template keeps its slot even when its cron line changed last."""
    result = run(
        tmp_path,
        [
            Repo("actions-template", "4 0 * * 0", since=NEW, is_template=True),
            Repo("from-template", "4 0 * * 0", since=OLD),
        ],
    )
    assert "keeps slot" in row(result, "actions-template")
    assert "`13 0 * * 0`" in row(result, "from-template")


def test_schedule_off_sunday_is_reported(tmp_path: Path) -> None:
    """A schedule that is not weekly on Sunday gets a finding and a slot."""
    result = run(tmp_path, [Repo("a", "4 0 * * 0"), Repo("monday", "4 0 * * 1")])
    assert result.outputs["findings"] == "1"
    line = row(result, "monday")
    assert "not weekly on Sunday" in line
    assert "`13 0 * * 0`" in line


def test_equivalent_spellings_share_the_slot(tmp_path: Path) -> None:
    """A month of 1-12, */1 or jan-dec runs every Sunday, as * does."""
    result = run(
        tmp_path,
        [
            Repo("a", "4 0 * * 0"),
            Repo("range", "4 0 * 1-12 0", since=NEW),
            Repo("step", "04 0 */1 */1 SUN", since=NEW),
            Repo("names", "4 0 * jan-dec 0,7", since=NEW),
            Repo("own", "13 0 * 1-6,7-12 sun"),
        ],
    )
    assert result.outputs["findings"] == "4", result.summary
    assert "not weekly on Sunday" not in result.summary
    assert "keeps slot" in row(result, "a")
    assert "`22 0 * * 0`" in row(result, "names")
    assert row(result, "own") == ""


def test_restricted_day_of_month_is_not_weekly(tmp_path: Path) -> None:
    """Cron ORs a restricted day of month with the weekday, so 1-31 is daily."""
    result = run(
        tmp_path,
        [
            Repo("a", "4 0 * * 0"),
            Repo("daily", "4 0 1-31 * 0"),
            Repo("odd", "4 0 * 2-12 0"),
        ],
    )
    assert "not weekly on Sunday" in row(result, "daily")
    assert "not weekly on Sunday" in row(result, "odd")
    assert "Shares" not in result.summary


def test_repository_without_scorecard_has_no_finding(tmp_path: Path) -> None:
    """A repository with no Scorecard workflow is listed, not flagged."""
    result = run(tmp_path, [Repo("a", "4 0 * * 0"), Repo("bare")])
    assert result.code == 0, result.stderr
    assert result.outputs["findings"] == "0"
    assert "- `bare`" in result.summary


def test_full_grid_falls_back_to_any_free_minute(tmp_path: Path) -> None:
    """With every grid slot taken, the mover gets a minute off :00 and :30."""
    repos = [
        Repo(f"r{k:03}", f"{(4 + 9 * k) % 60} {(4 + 9 * k) // 60} * * 0")
        for k in range(160)
    ]
    repos.append(Repo("late", "4 0 * * 0", since=NEW))
    result = run(tmp_path, repos)
    assert result.outputs["findings"] == "2"
    assert "`1 0 * * 0`" in row(result, "late")


def test_security_workflows_self_file_is_read(tmp_path: Path) -> None:
    """The schedule in openssf-scorecard-self.yaml claims a slot."""
    data = tmp_path / "data"
    write(
        data,
        [
            Repo(
                "security-workflows",
                "4 0 * * 0",
                file="openssf-scorecard-self.yaml",
            ),
            Repo("copy", "4 0 * * 0", since=NEW),
        ],
    )
    lane = "---\non:\n  workflow_call:\n    inputs: {}\n"
    _ = (data / "security-workflows" / "openssf-scorecard.yaml").write_text(
        lane, encoding="utf-8"
    )
    result = run(tmp_path)
    assert "openssf-scorecard-self.yaml:7" in row(result, "security-workflows")
    assert "keeps slot" in row(result, "security-workflows")
    assert "`13 0 * * 0`" in row(result, "copy")


def test_inline_comments_are_not_read(tmp_path: Path) -> None:
    """A cron value inside a trailing comment claims no slot."""
    block = (
        "on:\n"
        "  schedule:\n"
        '    - cron: "13 0 * * 0"  # was cron: "4 0 * * 1"\n'
        "    # - cron: '4 0 * * 0'\n"
    )
    flow = 'on:\n  schedule: [{cron: "22 0 * * 0"}]  # cron: "4 0 * * 0"\n'
    result = run(
        tmp_path,
        [Repo("a", "4 0 * * 0"), Repo("b", text=block), Repo("c", text=flow)],
    )
    assert result.code == 0, result.stderr
    assert result.outputs["findings"] == "0"
    assert "3 schedule Scorecard" in result.summary


def test_multiline_flow_schedule_is_read(tmp_path: Path) -> None:
    """A flow sequence spread over several lines still claims its slot."""
    text = 'on:\n  schedule: [\n    {cron: "4 0 * * 0"},\n  ]\n'
    result = run(tmp_path, [Repo("a", "4 0 * * 0"), Repo("b", text=text)])
    assert result.outputs["findings"] == "2"
    line = row(result, "b")
    assert "openssf-scorecard.yaml:3" in line
    assert "`13 0 * * 0`" in line


def test_sequence_at_schedule_indent_is_read(tmp_path: Path) -> None:
    """A '- cron:' item level with 'schedule:' belongs to it."""
    text = 'on:\n  schedule:\n  - cron: "4 0 * * 0"\n  push:\n    cron: "4 0 * * 1"\n'
    result = run(tmp_path, [Repo("a", "4 0 * * 0"), Repo("b", text=text)])
    assert result.outputs["findings"] == "2"
    line = row(result, "b")
    assert "openssf-scorecard.yaml:3" in line
    assert "not weekly on Sunday" not in result.summary


def test_inline_flow_mapping_trigger_is_read(tmp_path: Path) -> None:
    """'on: {schedule: [...]}' on one line still claims its slot."""
    text = 'on: {workflow_dispatch: {}, schedule: [{cron: "4 0 * * 0"}]}\n'
    result = run(tmp_path, [Repo("a", "4 0 * * 0"), Repo("b", text=text)])
    assert result.outputs["findings"] == "2"
    line = row(result, "b")
    assert "openssf-scorecard.yaml:1" in line
    assert "`13 0 * * 0`" in line


def test_unquoted_weekday_list_is_read_whole(tmp_path: Path) -> None:
    """A block plain scalar keeps its commas, so '0,1' is not Sunday only."""
    text = "on:\n  schedule:\n    - cron: 4 0 * * 0,1\n"
    result = run(tmp_path, [Repo("b", text=text)])
    assert result.outputs["findings"] == "1"
    line = row(result, "b")
    assert "`4 0 * * 0,1`" in line
    assert "not weekly on Sunday" in line


def test_quoted_keys_are_read(tmp_path: Path) -> None:
    """Quoted 'schedule' and 'cron' keys still claim their slots."""
    double = 'on:\n  "schedule":\n    - "cron": "4 0 * * 0"\n'
    single = "on: {'schedule': [{'cron': '4 0 * * 0'}]}\n"
    result = run(
        tmp_path,
        [Repo("a", "4 0 * * 0"), Repo("b", text=double), Repo("c", text=single)],
    )
    assert result.outputs["findings"] == "3"
    assert "openssf-scorecard.yaml:3" in row(result, "b")
    assert "`13 0 * * 0`" in row(result, "b")
    assert "`22 0 * * 0`" in row(result, "c")


def test_block_scalar_cron_is_decoded(tmp_path: Path) -> None:
    """A folded or literal cron value is read from the lines below its key."""
    folded = "on:\n  schedule:\n    - cron: >-\n        4 0 * * 0\n  push:\n"
    literal = "on:\n  schedule:\n    - cron: |\n        13 0 * * 0\n"
    result = run(
        tmp_path,
        [Repo("a", "4 0 * * 0"), Repo("b", text=folded), Repo("c", text=literal)],
    )
    assert result.outputs["findings"] == "2"
    assert "not weekly on Sunday" not in result.summary
    line = row(result, "b")
    assert "openssf-scorecard.yaml:3" in line
    assert "`22 0 * * 0`" in line


def test_hash_in_block_scalar_cron_is_text(tmp_path: Path) -> None:
    """A '#' in a block scalar's text is data, not a comment."""
    literal = "on:\n  schedule:\n    - cron: |-\n        4 0 * * 0 # text\n"
    folded = "on:\n  schedule:\n    - cron: >-  # comment\n        4 0 * * 0 # text\n"
    result = run(
        tmp_path,
        [Repo("a", "4 0 * * 0"), Repo("b", text=literal), Repo("c", text=folded)],
    )
    assert result.outputs["findings"] == "2"
    assert "4 0 * * 0 # text" in row(result, "b")
    assert "not weekly on Sunday" in row(result, "c")


def test_multiline_quoted_cron_is_folded(tmp_path: Path) -> None:
    """A quoted cron value spread over lines is read whole, at its key's line."""
    double = 'on:\n  schedule:\n    - cron: "4 0\n        * * 0"\n  push:\n'
    single = "on:\n  schedule: [{cron: '13 0\n    * * 0'}]\n"
    result = run(
        tmp_path,
        [Repo("a", "4 0 * * 0"), Repo("b", text=double), Repo("c", text=single)],
    )
    assert result.outputs["findings"] == "2"
    assert "not weekly on Sunday" not in result.summary
    assert "3 schedule Scorecard" in result.summary
    line = row(result, "b")
    assert "openssf-scorecard.yaml:3" in line
    assert "`22 0 * * 0`" in line


def test_double_quoted_escapes_are_decoded(tmp_path: Path) -> None:
    """A double-quoted cron value is read with its escapes decoded."""
    escaped = 'on:\n  schedule:\n    - cron: "4 0\\u0020*\\x20* 0"\n  push:\n'
    joined = 'on:\n  schedule:\n    - cron: "13 0 \\\n        * * 0"\n'
    result = run(
        tmp_path,
        [Repo("a", "4 0 * * 0"), Repo("b", text=escaped), Repo("c", text=joined)],
    )
    assert result.outputs["findings"] == "2"
    assert "not weekly on Sunday" not in result.summary
    assert "3 schedule Scorecard" in result.summary
    line = row(result, "b")
    assert "openssf-scorecard.yaml:3" in line
    assert "`22 0 * * 0`" in line


def test_multiline_plain_cron_is_folded(tmp_path: Path) -> None:
    """A plain cron value spread over lines is read whole, at its key's line."""
    block = "on:\n  schedule:\n    - cron: 4 0\n        * * 0\n  push:\n"
    flow = "on:\n  schedule: [{cron: 13 0\n    * * 0}]\n"
    item = "on:\n  schedule:\n    - {cron: 22 0\n       * * 0}\n"
    result = run(
        tmp_path,
        [
            Repo("a", "4 0 * * 0"),
            Repo("b", text=block),
            Repo("c", text=flow),
            Repo("d", text=item),
        ],
    )
    assert result.outputs["findings"] == "2"
    assert "not weekly on Sunday" not in result.summary
    assert "4 schedule Scorecard" in result.summary
    line = row(result, "b")
    assert "openssf-scorecard.yaml:3" in line
    assert "`31 0 * * 0`" in line


def test_anchored_schedule_is_read(tmp_path: Path) -> None:
    """An anchor or tag on 'on', 'schedule' or 'cron' hides no schedule."""
    block = 'on: &trigger\n  schedule: &weekly\n    - cron: "4 0 * * 0"\n'
    flow = 'on: &t {schedule: &s [{cron: &c "13 0 * * 0"}]}\n'
    tagged = "on:\n  schedule: !!seq\n    - cron: !!str 22 0 * * 0\n"
    result = run(
        tmp_path,
        [
            Repo("a", "4 0 * * 0"),
            Repo("b", text=block),
            Repo("c", text=flow),
            Repo("d", text=tagged),
        ],
    )
    assert result.outputs["findings"] == "2"
    assert "not weekly on Sunday" not in result.summary
    assert "4 schedule Scorecard" in result.summary
    line = row(result, "b")
    assert "openssf-scorecard.yaml:3" in line
    assert "`31 0 * * 0`" in line


def test_aliased_cron_is_resolved(tmp_path: Path) -> None:
    """An alias reads its anchor's value; the cron keeps its key's line."""
    flow = "env: {CRON: &weekly '4 0 * * 0'}\non: {schedule: [{cron: *weekly}]}\n"
    block = "env:\n  CRON: &c >-\n    13 0 * * 0\non:\n  schedule:\n    - cron: *c\n"
    whole = "x: &s [{cron: '22 0 * * 0'}]\non:\n  schedule: *s\n"
    result = run(
        tmp_path,
        [
            Repo("a", "4 0 * * 0"),
            Repo("b", text=flow),
            Repo("c", text=block),
            Repo("d", text=whole),
        ],
    )
    assert result.outputs["findings"] == "2"
    assert "not weekly on Sunday" not in result.summary
    assert "4 schedule Scorecard" in result.summary
    line = row(result, "b")
    assert "openssf-scorecard.yaml:2" in line
    assert "`31 0 * * 0`" in line


def test_quoted_alias_is_literal(tmp_path: Path) -> None:
    """A quoted '*name' is a string, not an alias; a block scalar is text."""
    flow = "env: {CRON: &weekly '4 0 * * 0'}\non: {schedule: [{cron: \"*weekly\"}]}\n"
    block = "x: &w 13 0 * * 0\non:\n  schedule:\n    - cron: |\n        *w\n"
    result = run(
        tmp_path,
        [Repo("a", "4 0 * * 0"), Repo("b", text=flow), Repo("c", text=block)],
    )
    assert "not weekly on Sunday" in row(result, "b")
    assert "`*weekly`" in row(result, "b")
    assert "not weekly on Sunday" in row(result, "c")
    assert "`*w`" in row(result, "c")


def test_anchor_in_block_scalar_is_text(tmp_path: Path) -> None:
    """An '&name' in a block scalar's text does not shadow a real anchor."""
    text = (
        "env:\n"
        "  CRON: &weekly '4 0 * * 0'\n"
        "  DOCUMENTATION: |\n"
        "    Example: &weekly 13 0 * * 0\n"
        "  STEPS:\n"
        "    - |\n"
        "      x: &weekly 22 0 * * 0\n"
        "on:\n"
        "  schedule:\n"
        "    - cron: *weekly\n"
    )
    result = run(tmp_path, [Repo("a", "4 0 * * 0"), Repo("b", text=text)])
    assert result.outputs["findings"] == "2"
    assert "not weekly on Sunday" not in result.summary
    assert "openssf-scorecard.yaml:10" in row(result, "b")


def test_multiline_anchor_is_read_whole(tmp_path: Path) -> None:
    """An anchored scalar over several lines reads whole, quoted or plain."""
    quoted = 'env:\n  CRON: &w "4 0\n    * * 0"\non:\n  schedule:\n    - cron: *w\n'
    flow = "env: {CRON: &w 4 0\n    * * 0}\non: {schedule: [{cron: *w}]}\n"
    result = run(
        tmp_path,
        [Repo("a", "4 0 * * 0"), Repo("b", text=quoted), Repo("c", text=flow)],
    )
    assert result.outputs["findings"] == "3"
    assert "not weekly on Sunday" not in result.summary
    assert "openssf-scorecard.yaml:6" in row(result, "b")
    assert "openssf-scorecard.yaml:3" in row(result, "c")


def test_cron_outside_schedule_value_is_ignored(tmp_path: Path) -> None:
    """A sibling dispatch input named 'cron' is not part of the schedule."""
    text = (
        'on: {schedule: [{cron: "13 0 * * 0"}],'
        " workflow_dispatch: {inputs: {cron: {type: string}}}}\n"
    )
    spread = (
        'on: {schedule: [{cron: "22 0 * * 0"}\n'
        "  ], workflow_dispatch: {inputs: {cron: {type: string}}}}\n"
    )
    result = run(
        tmp_path,
        [Repo("a", "4 0 * * 0"), Repo("b", text=text), Repo("c", text=spread)],
    )
    assert result.code == 0, result.stderr
    assert result.outputs["findings"] == "0"
    assert "3 schedule Scorecard" in result.summary


def test_schedule_key_outside_trigger_is_ignored(tmp_path: Path) -> None:
    """Only 'on.schedule' counts: not a dispatch input nor a run script."""
    block = (
        "on:\n"
        "  schedule:\n"
        '    - cron: "13 0 * * 0"\n'
        "  workflow_dispatch:\n"
        "    inputs:\n"
        "      schedule:\n"
        "        description: |\n"
        '          - cron: "4 0 * * 0"\n'
        "jobs:\n"
        "  example:\n"
        "    steps:\n"
        "      - run: |\n"
        "          schedule:\n"
        '            - cron: "4 0 * * 0"\n'
    )
    flow = (
        'on: {schedule: [{cron: "22 0 * * 0"}],'
        " workflow_dispatch: {inputs: {schedule: {type: string}}}}\n"
    )
    below = 'on:\n  {push: {}, schedule: [{cron: "31 0 * * 0"}]}\n'
    result = run(
        tmp_path,
        [
            Repo("a", "4 0 * * 0"),
            Repo("b", text=block),
            Repo("c", text=flow),
            Repo("d", text=below),
        ],
    )
    assert result.code == 0, result.stderr
    assert result.outputs["findings"] == "0"
    assert "4 schedule Scorecard" in result.summary


def test_held_since_compares_offsets(tmp_path: Path) -> None:
    """Commit dates with different offsets are ordered by time, not text."""
    result = run(
        tmp_path,
        [
            Repo("utc", "4 0 * * 0", since="2026-01-01T09:00:00Z"),
            Repo("east", "4 0 * * 0", since="2026-01-01T10:00:00+02:00"),
        ],
    )
    assert result.outputs["findings"] == "2"
    assert "keeps slot" in row(result, "east")
    assert "`13 0 * * 0`" in row(result, "utc")


def test_unreadable_listing_fails(tmp_path: Path) -> None:
    """A data directory without repos.json is a usage error, not a pass."""
    (tmp_path / "data").mkdir()
    result = run(tmp_path)
    assert result.code == EXIT_USAGE
    assert "repos.json" in result.stderr
    assert result.outputs == {}
