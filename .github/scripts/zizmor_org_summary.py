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
import subprocess
import sys
import time

SEVERITIES = ("critical", "high", "medium", "low", "informational")

# SARIF level -> security scale, the only axis zizmor populates.
_SARIF_LEVELS = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "informational",
}


def _gh_api_objects(path: str) -> tuple[list[dict] | None, str | None]:
    """Fetch a paginated array endpoint as a list of objects.

    Returns (objects, None) on success, (None, "no-data") when code
    scanning has no analyses (404), and (None, error) otherwise after
    three attempts.
    """
    error = "unknown error"
    for _ in range(3):
        proc = subprocess.run(  # noqa: S603,S607
            ["gh", "api", "--paginate", path, "--jq", ".[]"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            objects = [
                json.loads(line)
                for line in proc.stdout.splitlines()
                if line.strip()
            ]
            return objects, None
        error = proc.stderr.strip() or "unknown error"
        if "HTTP 404" in error:
            return None, "no-data"
        time.sleep(5)
    return None, error


def _bucket(alert: dict) -> str:
    """Resolve one alert onto the security severity scale."""
    rule = alert.get("rule") or {}
    sec = (rule.get("security_severity_level") or "").strip().lower()
    if sec in SEVERITIES:
        return sec
    level = (rule.get("severity") or "").strip().lower()
    return _SARIF_LEVELS.get(level, "informational")


def _count_repo(org: str, repo: str, branch: str) -> tuple[dict | None, str | None]:
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


def main() -> int:
    org = os.environ["ORG"]
    matrix = json.loads(os.environ["MATRIX"])

    offenders: list[tuple[str, dict]] = []
    clean: list[str] = []
    no_data: list[str] = []
    errors: list[tuple[str, str]] = []

    for entry in matrix:
        repo = entry["repo"]
        counts, err = _count_repo(org, repo, entry["default_branch"])
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

    totals = dict.fromkeys(SEVERITIES, 0)
    for _, counts in offenders:
        for sev in SEVERITIES:
            totals[sev] += counts[sev]

    # The Info column appears only when informational findings exist
    # (the low severity floor normally keeps them out entirely).
    show_info = totals["informational"] > 0
    columns = SEVERITIES if show_info else SEVERITIES[:-1]
    titles = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "informational": "Info",
    }

    lines: list[str] = []
    lines.append(f"## Zizmor organisation posture: {org}")
    lines.append("")
    lines.append(
        f"{len(matrix)} repositories scanned: "
        f"{len(offenders)} with findings, {len(clean)} clean, "
        f"{len(no_data)} without code-scanning data"
        + (f", {len(errors)} unreadable" if errors else "")
        + "."
    )
    lines.append("")
    if offenders:
        header = (
            "| Repository | "
            + " | ".join(titles[sev] for sev in columns)
            + " | Total |"
        )
        rule = "| :--- |" + " ---: |" * (len(columns) + 1)
        lines.append(header)
        lines.append(rule)
        for repo, counts in offenders:
            cells = " | ".join(str(counts[sev]) for sev in columns)
            lines.append(
                f"| {repo} | {cells} | {sum(counts.values())} |"
            )
        total_cells = " | ".join(str(totals[sev]) for sev in columns)
        lines.append(
            f"| **Total** | {total_cells} | "
            f"**{sum(totals.values())}** |"
        )
    else:
        lines.append("No open zizmor findings anywhere. :rainbow:")
    lines.append("")
    if clean:
        lines.append("<details>")
        lines.append(f"<summary>Clean repositories ({len(clean)})</summary>")
        lines.append("")
        lines.append(", ".join(f"`{name}`" for name in sorted(clean)))
        lines.append("")
        lines.append("</details>")
    if no_data:
        lines.append("<details>")
        lines.append(
            f"<summary>No code-scanning data ({len(no_data)})</summary>"
        )
        lines.append("")
        lines.append(", ".join(f"`{name}`" for name in sorted(no_data)))
        lines.append("")
        lines.append("</details>")
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
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(output)

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
