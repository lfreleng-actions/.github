# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Read and validate the SARIF logs findings_ratchet.py compares.

The ratchet accepts the subset of SARIF that aislop and zizmor emit and
refuses the rest, rather than resolve constructs no caller produces. A
log it cannot count without guessing raises SarifError, so the caller
can fail closed: README.md lists the accepted subset.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

LEVELS = ("error", "warning", "note", "none")
UNSUPPORTED = "unsupported SARIF construct"


class SarifError(Exception):
    """A SARIF file is missing, unreadable or not a SARIF log."""


def as_dict(value: object) -> dict[str, object]:
    """Return value as a JSON object, or an empty one."""
    return cast("dict[str, object]", value) if isinstance(value, dict) else {}


def as_list(value: object) -> list[object]:
    """Return value as a JSON array, or an empty one."""
    return cast("list[object]", value) if isinstance(value, list) else []


def as_str(value: object) -> str:
    """Return value as a string, or an empty one."""
    return value if isinstance(value, str) else ""


def objects_problem(value: object, name: str, *, required: bool) -> str:
    """Return why value is not an array of objects, or ''."""
    if value is None and not required:
        return ""
    if not isinstance(value, list):
        return f"'{name}' is not an array"
    if not all(isinstance(item, dict) for item in cast("list[object]", value)):
        return f"an entry of '{name}' is not an object"
    return ""


def level_problem(value: object, where: str) -> str:
    """Return why an optional SARIF level is unsupported, or ''."""
    if value is None or value in LEVELS:
        return ""
    return f"{where} level {json.dumps(value)} is not one of {', '.join(LEVELS)}"


def location_problem(location: object) -> str:
    """Return why one result location is outside the subset, or ''."""
    physical = as_dict(location).get("physicalLocation")
    if physical is None:
        return ""
    if not isinstance(physical, dict):
        return "a 'physicalLocation' is not an object"
    artifact = cast("dict[str, object]", physical).get("artifactLocation")
    if artifact is None:
        return ""
    artifact = as_dict(artifact)
    for name in ("uriBaseId", "index"):
        if name in artifact:
            return f"{UNSUPPORTED}: 'artifactLocation.{name}'"
    if not as_str(artifact.get("uri")):
        return "an artifactLocation has no 'uri'"
    return ""


def rule_problem(result: dict[str, object], rules: list[object]) -> str:
    """Return why a result's rule ID cannot be read without guessing, or ''."""
    if "rule" in result and not isinstance(result["rule"], dict):
        return "a result's 'rule' is not an object"
    for name, value in (
        ("ruleId", result.get("ruleId")),
        ("rule.id", as_dict(result.get("rule")).get("id")),
    ):
        if value is not None and not as_str(value):
            return f"a result's '{name}' is not a non-empty string"
    if not result_rule(result, rules):
        return "a result's rule ID cannot be resolved"
    return ""


def result_problem(result: dict[str, object], rules: list[object]) -> str:
    """Return why one result is not usable, or ''."""
    problem = level_problem(result.get("level"), "a result")
    if problem:
        return problem
    reference = as_dict(result.get("rule"))
    if "toolComponent" in reference:
        return f"{UNSUPPORTED}: 'rule.toolComponent'"
    for name, index in (
        ("ruleIndex", result.get("ruleIndex")),
        ("rule.index", reference.get("index")),
    ):
        if index is not None and (
            type(index) is not int or not 0 <= index < len(rules)
        ):
            return f"{UNSUPPORTED}: '{name}' {json.dumps(index)} is not a driver rule"
    problem = rule_problem(result, rules) or objects_problem(
        result.get("locations"), "locations", required=False
    )
    if problem:
        return problem
    for location in as_list(result.get("locations")):
        problem = location_problem(location)
        if problem:
            return problem
    return ""


def run_problem(run: dict[str, object]) -> str:
    """Return why one SARIF run is not usable, or ''."""
    tool = as_dict(run.get("tool"))
    driver = tool.get("driver")
    if not isinstance(driver, dict):
        return "a run has no 'tool.driver' object"
    for name, present in (
        ("tool.extensions", "extensions" in tool),
        ("originalUriBaseIds", "originalUriBaseIds" in run),
    ):
        if present:
            return f"{UNSUPPORTED}: '{name}'"
    rules = cast("dict[str, object]", driver).get("rules")
    for name, value, required in (
        ("tool.driver.rules", rules, False),
        ("results", run.get("results"), True),
    ):
        problem = objects_problem(value, name, required=required)
        if problem:
            return problem
    for rule in as_list(rules):
        config = as_dict(as_dict(rule).get("defaultConfiguration"))
        problem = level_problem(config.get("level"), "a rule default")
        if problem:
            return problem
    for result in as_list(run.get("results")):
        problem = result_problem(as_dict(result), as_list(rules))
        if problem:
            return problem
    return ""


def sarif_problem(data: object) -> str:
    """Return why parsed JSON is not a usable SARIF log, or ''."""
    if not isinstance(data, dict):
        return "not a JSON object"
    runs = cast("dict[str, object]", data).get("runs")
    problem = objects_problem(runs, "runs", required=True)
    if problem:
        return problem
    for run in as_list(runs):
        problem = run_problem(as_dict(run))
        if problem:
            return problem
    return ""


def load_sarif(path_text: str) -> dict[str, object]:
    """Read a SARIF log, raising SarifError when it cannot be used."""
    if not path_text:
        msg = "no file given"
        raise SarifError(msg)
    try:
        data = cast("object", json.loads(Path(path_text).read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        msg = f"cannot read {path_text} as JSON: {exc}"
        raise SarifError(msg) from exc
    problem = sarif_problem(data)
    if problem:
        msg = f"{path_text} is not a usable SARIF log: {problem}"
        raise SarifError(msg)
    return as_dict(data)


def result_rule(result: dict[str, object], rules: list[object]) -> str:
    """Return a result's rule ID from ruleId, rule.id or a driver rule index."""
    rule_id = as_str(result.get("ruleId"))
    if rule_id:
        return rule_id
    reference = as_dict(result.get("rule"))
    rule_id = as_str(reference.get("id"))
    if rule_id:
        return rule_id
    index = result.get("ruleIndex", reference.get("index"))
    if type(index) is not int or not 0 <= index < len(rules):
        return ""
    return as_str(as_dict(rules[index]).get("id"))


def result_location(result: dict[str, object]) -> tuple[str, int | None]:
    """Return the first location's artifact URI and start line."""
    locations = as_list(result.get("locations"))
    if not locations:
        return ("", None)
    physical = as_dict(as_dict(locations[0]).get("physicalLocation"))
    uri = as_str(as_dict(physical.get("artifactLocation")).get("uri"))
    line = as_dict(physical.get("region")).get("startLine")
    if isinstance(line, bool) or not isinstance(line, int):
        return (uri, None)
    return (uri, line)
