# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Render an organisation-wide zizmor posture summary.

Reads the repository matrix produced by the discover job (MATRIX
environment variable: a JSON array of {repo, default_branch}), queries
each repository's open zizmor code-scanning alerts on its default
branch, and appends one untruncated, worst-first table covering the
whole organisation to GITHUB_STEP_SUMMARY (and stdout).

Severity decoding matches the ruleset-enforced PR gate and the
github-security-report tool: prefer rule.security_severity_level
(critical/high/medium/low), fall back to the SARIF level in
rule.severity (error -> high, warning -> medium, note -> low,
none -> informational). The audit's --min-severity low floor keeps
informational findings out of the uploaded SARIF, so a note alert is
a genuine Low finding.

Requires: GH_TOKEN with cross-repo security_events read access, ORG,
MATRIX. Exits non-zero if any repository's alerts cannot be read
(other than the no-code-scanning 404), so an incomplete posture never
masquerades as a complete one.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import cast

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "informational")

# SARIF level -> security scale, the only axis zizmor populates.
_SARIF_LEVELS: dict[str, str] = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "informational",
}

_TITLES: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Info",
}


class GhNotFoundError(RuntimeError):
    """Raised when the gh CLI cannot be found on PATH."""

    def __init__(self) -> None:
        """Build the error with its fixed message."""
        super().__init__("gh CLI not found on PATH")


def _gh_executable() -> str:
    """Resolve the absolute path of the gh CLI."""
    gh = shutil.which("gh")
    if gh is None:
        raise GhNotFoundError
    return gh


def _parse_alert_pages(payload: str) -> tuple[list[dict[str, object]] | None, str]:
    """Flatten a ``gh api --paginate --slurp`` payload into alert objects.

    The payload is one outer JSON array wrapping the per-page arrays.
    Returns (alerts, "") on success and (None, error) when the payload
    does not have that shape: a malformed response must surface as an
    error rather than an apparently clean repository.
    """
    try:
        pages = cast("object", json.loads(payload))
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON from gh api: {exc}"
    if not isinstance(pages, list):
        return None, "malformed gh api response: outer payload is not a list"
    alerts: list[dict[str, object]] = []
    for page in cast("list[object]", pages):
        if not isinstance(page, list):
            return None, "malformed gh api response: page is not a list"
        for alert in cast("list[object]", page):
            if not isinstance(alert, dict):
                return None, "malformed gh api response: alert is not an object"
            alerts.append(cast("dict[str, object]", alert))
    return alerts, ""


def _gh_api_objects(path: str) -> tuple[list[dict[str, object]] | None, str | None]:
    """Fetch a paginated array endpoint as a list of objects.

    Uses ``gh api --paginate --slurp``, which wraps the per-page arrays
    in one outer JSON array -- a single unambiguous document to parse
    (line-oriented parsing of jq output would depend on its formatting).

    Returns (objects, None) on success, (None, "no-data") when code
    scanning has no analyses (a 404 with the repository itself still
    readable), and (None, error) otherwise after three attempts. A 404
    can also mean the repository is unreadable (GitHub hides private
    repos behind 404), so it only counts as no-data when a probe of the
    base repository endpoint succeeds; anything else is an error, which
    fails the job rather than under-reporting posture.
    """
    error = "unknown error"
    for _ in range(3):
        proc = subprocess.run(  # noqa: S603
            [_gh_executable(), "api", "--paginate", "--slurp", path],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            alerts, parse_err = _parse_alert_pages(proc.stdout)
            if alerts is None:
                return None, parse_err
            return alerts, None
        error = proc.stderr.strip() or "unknown error"
        if "HTTP 404" in error:
            if _repo_readable(path):
                return None, "no-data"
            return None, error
        time.sleep(5)
    return None, error


def _repo_readable(alerts_path: str) -> bool:
    """Probe the base repository endpoint behind an alerts path."""
    repo_path = alerts_path.split("/code-scanning/", 1)[0]
    proc = subprocess.run(  # noqa: S603
        [_gh_executable(), "api", repo_path, "--jq", ".name"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0


def _bucket(alert: dict[str, object]) -> str:
    """Resolve one alert onto the security severity scale."""
    rule_obj = alert.get("rule")
    rule = cast("dict[str, object]", rule_obj) if isinstance(rule_obj, dict) else {}
    sec_obj = rule.get("security_severity_level")
    sec = sec_obj.strip().lower() if isinstance(sec_obj, str) else ""
    if sec in SEVERITIES:
        return sec
    level_obj = rule.get("severity")
    level = level_obj.strip().lower() if isinstance(level_obj, str) else ""
    return _SARIF_LEVELS.get(level, "informational")


def _count_repo(
    org: str, repo: str, branch: str
) -> tuple[dict[str, int] | None, str | None]:
    """Count one repository's open zizmor alerts per severity."""
    path = (
        f"/repos/{org}/{repo}/code-scanning/alerts"
        f"?state=open&tool_name=zizmor&per_page=100"
        f"&ref=refs/heads/{branch}"
    )
    alerts, err = _gh_api_objects(path)
    if alerts is None:
        return None, err
    counts = dict.fromkeys(SEVERITIES, 0)
    for alert in alerts:
        counts[_bucket(alert)] += 1
    return counts, None


def _collect(
    org: str, matrix: list[object]
) -> tuple[
    list[tuple[str, dict[str, int]]],
    list[str],
    list[str],
    list[tuple[str, str]],
]:
    """Count alerts per repository and sort offenders worst-first.

    Malformed matrix entries land in the errors list so the summary
    reports them (and the job fails) instead of dropping them.
    """
    offenders: list[tuple[str, dict[str, int]]] = []
    clean: list[str] = []
    no_data: list[str] = []
    errors: list[tuple[str, str]] = []

    for entry in matrix:
        if not isinstance(entry, dict):
            errors.append((repr(entry), "malformed matrix entry: not an object"))
            continue
        entry_map = cast("dict[str, object]", entry)
        repo = entry_map.get("repo")
        branch = entry_map.get("default_branch")
        if not isinstance(repo, str) or not isinstance(branch, str):
            errors.append((str(repo), "malformed matrix entry: repo/default_branch"))
            continue
        counts, err = _count_repo(org, repo, branch)
        if counts is None:
            if err == "no-data":
                no_data.append(repo)
            else:
                errors.append((repo, err or "unknown error"))
        elif sum(counts.values()) == 0:
            clean.append(repo)
        else:
            offenders.append((repo, counts))

    # Worst-first: severity tuple descending, then name for stability.
    offenders.sort(
        key=lambda item: (
            tuple(-item[1][sev] for sev in SEVERITIES),
            item[0],
        )
    )
    return offenders, clean, no_data, errors


def _offender_table(
    offenders: list[tuple[str, dict[str, int]]], *, complete: bool
) -> list[str]:
    """Render the worst-first findings table (or the all-clear line).

    The celebratory all-clear only appears when every repository was
    read successfully; an incomplete run must not claim a clean estate.
    """
    if not offenders:
        if complete:
            return ["No open zizmor findings anywhere. :rainbow:"]
        return ["No open zizmor findings in the readable repositories."]

    totals = dict.fromkeys(SEVERITIES, 0)
    for _, counts in offenders:
        for sev in SEVERITIES:
            totals[sev] += counts[sev]

    # The Info column appears only when informational findings exist
    # (the low severity floor normally keeps them out entirely).
    show_info = totals["informational"] > 0
    columns = SEVERITIES if show_info else SEVERITIES[:-1]

    title_cells = " | ".join(_TITLES[sev] for sev in columns)
    lines = [
        f"| Repository | {title_cells} | Total |",
        "| :--- |" + " ---: |" * (len(columns) + 1),
    ]
    for repo, counts in offenders:
        cells = " | ".join(str(counts[sev]) for sev in columns)
        lines.append(f"| {repo} | {cells} | {sum(counts.values())} |")
    total_cells = " | ".join(str(totals[sev]) for sev in columns)
    lines.append(f"| **Total** | {total_cells} | **{sum(totals.values())}** |")
    return lines


def _repo_list_details(summary: str, names: list[str]) -> list[str]:
    """Render a collapsed details block listing repositories."""
    return [
        "<details>",
        f"<summary>{summary} ({len(names)})</summary>",
        "",
        ", ".join(f"`{name}`" for name in sorted(names)),
        "",
        "</details>",
    ]


def _load_matrix(raw: str) -> list[object] | None:
    """Parse the MATRIX environment variable into its raw entries.

    Returns None when the payload is not a JSON array at all; entry
    validation happens in _collect so malformed entries are reported
    rather than silently dropped.
    """
    parsed = cast("object", json.loads(raw))
    if not isinstance(parsed, list):
        return None
    return cast("list[object]", parsed)


def main() -> int:
    """Render the posture summary; non-zero when any repo is unreadable."""
    org = os.environ["ORG"]
    matrix = _load_matrix(os.environ["MATRIX"])
    if matrix is None:
        print("Error: MATRIX is not a JSON array", file=sys.stderr)
        return 1

    offenders, clean, no_data, errors = _collect(org, matrix)

    unreadable = f", {len(errors)} unreadable" if errors else ""
    scanned = (
        f"{len(matrix)} repositories scanned: {len(offenders)} with findings,"
        f" {len(clean)} clean, {len(no_data)} without code-scanning data{unreadable}."
    )

    lines: list[str] = [f"## Zizmor organisation posture: {org}", "", scanned, ""]
    lines.extend(_offender_table(offenders, complete=not errors))
    lines.append("")
    if clean:
        lines.extend(_repo_list_details("Clean repositories", clean))
    if no_data:
        lines.extend(_repo_list_details("No code-scanning data", no_data))
    if errors:
        lines.append("")
        lines.append(f"### Unreadable repositories ({len(errors)})")
        lines.append("")
        for repo, err in errors:
            first_line = err.splitlines()[0] if err else "unknown error"
            lines.append(f"- `{repo}`: {first_line}")

    output = "\n".join(lines) + "\n"
    print(output)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with Path(summary_path).open("a", encoding="utf-8") as handle:
            _ = handle.write(output)

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
