# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Contract tests for actions/findings-ratchet/findings_ratchet.py.

Each test runs the script as a subprocess, as the composite action
does, against small hand-written SARIF fixtures, and reads back its
exit code, its GITHUB_OUTPUT and GITHUB_STEP_SUMMARY files and the
workflow commands it prints.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

SCRIPT = Path(__file__).resolve().parent.parent / "findings_ratchet.py"

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_USAGE = 2

DEP_RULE = "security/vulnerable-dependency"


@dataclass(frozen=True)
class Outcome:
    """What one run of the script produced."""

    code: int
    stdout: str
    stderr: str
    outputs: dict[str, str]
    summary: str

    def commands(self, name: str) -> list[str]:
        """Return the printed workflow commands of one kind."""
        return [
            line for line in self.stdout.splitlines() if line.startswith(f"::{name} ")
        ]


def result(
    rule: str,
    uri: str,
    *,
    line: int = 1,
    message: str = "finding",
    level: str | None = "warning",
) -> dict[str, object]:
    """Build one SARIF result."""
    body: dict[str, object] = {
        "ruleId": rule,
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
    }
    if level is not None:
        body["level"] = level
    return body


def sarif(
    results: Sequence[dict[str, object]],
    rules: Sequence[Mapping[str, object]] = (),
    run_extra: Mapping[str, object] | None = None,
) -> str:
    """Build a SARIF 2.1.0 log with one run, plus any extra run members."""
    run: dict[str, object] = {
        "tool": {"driver": {"name": "test", "rules": list(rules)}},
        "results": list(results),
    }
    run |= dict(run_extra or {})
    return json.dumps({"version": "2.1.0", "runs": [run]})


def with_artifact(**fields: object) -> dict[str, object]:
    """Build a result whose first artifactLocation holds exactly fields."""
    body = result("rule-a", "a.py")
    body["locations"] = [
        {
            "physicalLocation": {
                "artifactLocation": dict(fields),
                "region": {"startLine": 1},
            }
        }
    ]
    return body


def with_rule(reference: Mapping[str, object]) -> dict[str, object]:
    """Build a result naming its rule only through a rule reference."""
    body = result("rule-a", "a.py")
    del body["ruleId"]
    body["rule"] = dict(reference)
    return body


def unsupported_logs() -> list[object]:
    """Return logs using one SARIF construct outside the subset each."""
    rules = [{"id": "rule-a"}]
    extension = {"name": "ext", "rules": [{"id": "rule-a"}]}
    bad_index = result("rule-a", "a.py")
    del bad_index["ruleId"]
    bad_index["ruleIndex"] = 1
    cases = [
        ("uriBaseId", sarif([with_artifact(uri="a.py", uriBaseId="SRC")])),
        ("index", sarif([with_artifact(index=0)])),
        (
            "originalUriBaseIds",
            sarif(
                [result("rule-a", "a.py")],
                run_extra={"originalUriBaseIds": {"SRC": {"uri": "file:///c/"}}},
            ),
        ),
        (
            "extensions",
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {
                                "driver": {"name": "t"},
                                "extensions": [extension],
                            },
                            "results": [result("rule-a", "a.py")],
                        }
                    ],
                }
            ),
        ),
        (
            "toolComponent",
            sarif([with_rule({"index": 0, "toolComponent": {"index": 0}})], rules),
        ),
        ("rule.index", sarif([with_rule({"index": 1})], rules)),
        ("ruleIndex", sarif([bad_index], rules)),
    ]
    return [pytest.param(log, id=name) for name, log in cases]


def malformed_logs() -> list[object]:
    """Return logs with locations or a rule ID that cannot be read as given."""

    def changed(**fields: object) -> dict[str, object]:
        body = result("rule-a", "a.py")
        body |= fields
        return body

    def unnamed(**fields: object) -> dict[str, object]:
        body = changed(**fields)
        del body["ruleId"]
        return body

    cases = [
        ("locations-string", sarif([changed(locations="a.py")])),
        ("locations-object", sarif([changed(locations={"physicalLocation": {}})])),
        ("location-not-object", sarif([changed(locations=[1])])),
        (
            "physicalLocation-string",
            sarif([changed(locations=[{"physicalLocation": "a.py"}])]),
        ),
        ("no-rule", sarif([unnamed()])),
        ("rule-without-id", sarif([unnamed(ruleIndex=0)], [{}, {}])),
        ("ruleId-number", sarif([changed(ruleId=5)])),
        ("ruleId-empty", sarif([changed(ruleId="")])),
        ("rule-string", sarif([unnamed(rule="rule-a")])),
        ("rule-id-number", sarif([with_rule({"id": 5})])),
    ]
    return [pytest.param(log, id=name) for name, log in cases]


@pytest.fixture
def run(tmp_path: Path) -> Callable[..., Outcome]:
    """Return a runner that writes fixtures and invokes the script."""

    def _run(
        head: str | None,
        base: str | None = None,
        *,
        tool: str = "generic",
        extra: Sequence[str] = (),
    ) -> Outcome:
        args = [sys.executable, str(SCRIPT), f"--tool={tool}"]
        head_path = tmp_path / "head.sarif"
        base_path = tmp_path / "base.sarif"
        if head is not None:
            _ = head_path.write_text(head, encoding="utf-8")
        args.append(f"--head-sarif={head_path}")
        if base is not None:
            _ = base_path.write_text(base, encoding="utf-8")
            args.append(f"--base-sarif={base_path}")
        args += list(extra)
        output_file = tmp_path / "output"
        summary_file = tmp_path / "summary"
        _ = output_file.write_text("", encoding="utf-8")
        _ = summary_file.write_text("", encoding="utf-8")
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            env={
                "GITHUB_OUTPUT": str(output_file),
                "GITHUB_STEP_SUMMARY": str(summary_file),
                "PATH": "/usr/bin:/bin",
            },
        )
        outputs: dict[str, str] = {}
        for line in output_file.read_text(encoding="utf-8").splitlines():
            name, _sep, value = line.partition("=")
            outputs[name] = value
        return Outcome(
            code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            outputs=outputs,
            summary=summary_file.read_text(encoding="utf-8"),
        )

    return _run


def test_hw_bom_408_shape_passes_with_one_fixed(run: Callable[..., Outcome]) -> None:
    """Base has minimatch and glob, head only minimatch with new advice."""
    base = sarif(
        [
            result(
                DEP_RULE,
                "package.json",
                level="note",
                message="minimatch (moderate, dev-only) — upgrade to 9.0.5",
            ),
            result(
                DEP_RULE,
                "package.json",
                level="note",
                message="glob (moderate, dev-only) — upgrade to 10.4.5",
            ),
        ]
    )
    head = sarif(
        [
            result(
                DEP_RULE,
                "package.json",
                level="note",
                message="minimatch (moderate, dev-only) — upgrade to 10.0.1",
            )
        ]
    )
    out = run(head, base, tool="aislop")
    assert out.code == EXIT_PASS, out.stdout + out.stderr
    assert out.outputs == {
        "verdict": "pass",
        "effective-mode": "ratchet",
        "base-count": "2",
        "head-count": "1",
        "new-count": "0",
        "fixed-count": "1",
    }
    assert out.commands("error") == []
    assert "glob" in out.summary


def test_aislop_subject_separates_packages(run: Callable[..., Outcome]) -> None:
    """Swapping one vulnerable package for another is a new finding."""
    base = sarif(
        [result(DEP_RULE, "package.json", message="glob (moderate) — upgrade to 2")]
    )
    head = sarif(
        [result(DEP_RULE, "package.json", message="minimatch (high) — upgrade to 3")]
    )
    out = run(head, base, tool="aislop")
    assert out.code == EXIT_FAIL
    assert out.outputs["new-count"] == "1"
    assert out.outputs["fixed-count"] == "1"


def dependency_without_text(message: Mapping[str, object]) -> str:
    """Build an aislop log whose dependency result has the given message."""
    body = result(DEP_RULE, "package.json")
    body["message"] = dict(message)
    return sarif([body])


UNNAMED_PACKAGE_MESSAGES = [
    pytest.param({"id": "dependency", "arguments": ["glob"]}, id="message-id"),
    pytest.param({"text": ""}, id="empty-text"),
    pytest.param({"text": "   "}, id="blank-text"),
]


@pytest.mark.parametrize("message", UNNAMED_PACKAGE_MESSAGES)
def test_aislop_dependency_without_text_head_fails(
    run: Callable[..., Outcome], message: Mapping[str, object]
) -> None:
    """A head dependency result naming no package fails, never matches."""
    base = dependency_without_text({"id": "dependency", "arguments": ["minimatch"]})
    out = run(dependency_without_text(message), base, tool="aislop")
    assert out.code == EXIT_FAIL
    assert out.outputs["verdict"] == "fail"
    assert out.outputs["head-count"] == ""
    assert len(out.commands("error")) == 1


@pytest.mark.parametrize("message", UNNAMED_PACKAGE_MESSAGES)
def test_aislop_dependency_without_text_base_falls_back(
    run: Callable[..., Outcome], message: Mapping[str, object]
) -> None:
    """A base dependency result naming no package selects absolute mode."""
    head = sarif([result(DEP_RULE, "package.json", message="glob (moderate)")])
    out = run(head, dependency_without_text(message), tool="aislop")
    assert out.code == EXIT_FAIL
    assert out.outputs["effective-mode"] == "absolute"
    assert out.outputs["head-count"] == "1"
    assert out.outputs["new-count"] == ""
    assert len(out.commands("warning")) == 1


def test_dependency_without_text_ignored_when_not_counted(
    run: Callable[..., Outcome],
) -> None:
    """Only a counted aislop dependency result needs a package name."""
    log = dependency_without_text({"id": "dependency"})
    excluded = run(log, log, tool="aislop", extra=[f"--exclude-rules={DEP_RULE}"])
    assert excluded.code == EXIT_PASS
    assert excluded.outputs["head-count"] == "0"
    generic = run(log, log, tool="generic")
    assert generic.code == EXIT_PASS
    assert generic.outputs["effective-mode"] == "ratchet"
    assert generic.outputs["head-count"] == "1"


def test_new_rule_finding_fails_and_is_annotated(run: Callable[..., Outcome]) -> None:
    """A finding from a rule the base lacks fails and is annotated."""
    base = sarif([result("rule-a", "src/a.py", line=3)])
    head = sarif(
        [
            result("rule-a", "src/a.py", line=3),
            result("rule-b", "src/b.py", line=7, message="bad thing"),
        ]
    )
    out = run(head, base)
    assert out.code == EXIT_FAIL
    assert out.outputs["verdict"] == "fail"
    assert out.outputs["new-count"] == "1"
    errors = out.commands("error")
    assert len(errors) == 1
    assert errors[0].startswith("::error file=src/b.py,line=7,")
    assert errors[0].endswith("::New finding rule-b: bad thing")
    new_row = out.summary.index("rule-b")
    old_row = out.summary.index("| rule-a")
    assert new_row < old_row


def test_annotate_false_suppresses_annotations(run: Callable[..., Outcome]) -> None:
    """annotate=false still fails but prints no ::error per finding."""
    head = sarif([result("rule-b", "b.py")])
    out = run(head, sarif([]), extra=["--annotate=false"])
    assert out.code == EXIT_FAIL
    assert out.commands("error") == []


def test_moved_lines_unchanged_set_passes(run: Callable[..., Outcome]) -> None:
    """Identical findings on moved lines are neither new nor fixed."""
    base = sarif(
        [
            result("rule-a", "a.py", line=10, message="x on line 10"),
            result("rule-b", "b.py", line=4),
        ]
    )
    head = sarif(
        [
            result("rule-b", "b.py", line=40),
            result("rule-a", "a.py", line=12, message="x on line 12"),
        ]
    )
    out = run(head, base)
    assert out.code == EXIT_PASS
    assert out.outputs["new-count"] == "0"
    assert out.outputs["fixed-count"] == "0"


@pytest.mark.parametrize(
    ("counts", "expected"),
    [((2, 3), (EXIT_FAIL, "1", "0")), ((3, 2), (EXIT_PASS, "0", "1"))],
)
def test_count_per_rule_and_file(
    run: Callable[..., Outcome],
    counts: tuple[int, int],
    expected: tuple[int, str, str],
) -> None:
    """Counts for one rule and file are compared, not instances."""
    base_count, head_count = counts
    code, new, fixed = expected
    base = sarif([result("rule-a", "a.py", line=n) for n in range(base_count)])
    head = sarif([result("rule-a", "a.py", line=n + 5) for n in range(head_count)])
    out = run(head, base)
    assert out.code == code
    assert out.outputs["new-count"] == new
    assert out.outputs["fixed-count"] == fixed


def test_annotation_prefers_findings_absent_from_base(
    run: Callable[..., Outcome],
) -> None:
    """With 1 -> 2, the annotated finding is the one the base lacks."""
    base = sarif([result("rule-a", "a.py", line=1, message="old")])
    head = sarif(
        [
            result("rule-a", "a.py", line=1, message="old"),
            result("rule-a", "a.py", line=9, message="fresh"),
        ]
    )
    out = run(head, base)
    errors = out.commands("error")
    assert len(errors) == 1
    assert "line=9" in errors[0]


def test_zizmor_rule_default_level_note_counts(run: Callable[..., Outcome]) -> None:
    """A result without level takes its rule's default level."""
    rules = [{"id": "zizmor/artipacked", "defaultConfiguration": {"level": "note"}}]
    head = sarif(
        [result("zizmor/artipacked", ".github/workflows/x.yaml", level=None)], rules
    )
    out = run(head, sarif([], rules), tool="zizmor")
    assert out.code == EXIT_FAIL
    assert out.outputs["head-count"] == "1"
    filtered = run(
        head, sarif([], rules), tool="zizmor", extra=["--levels=error,warning"]
    )
    assert filtered.code == EXIT_PASS
    assert filtered.outputs["head-count"] == "0"


def test_missing_level_without_rule_default_is_warning(
    run: Callable[..., Outcome],
) -> None:
    """A result with no level and no rule default counts as a warning."""
    head = sarif([result("rule-a", "a.py", level=None)])
    out = run(head, None, extra=["--mode=absolute", "--levels=warning"])
    assert out.outputs["head-count"] == "1"


def test_zizmor_counts_per_rule_and_file(run: Callable[..., Outcome]) -> None:
    """Zizmor findings in one file and rule match despite new text."""
    base = sarif(
        [result("zizmor/template-injection", "w.yaml", message="jobs.a.steps[0]")]
    )
    head = sarif(
        [result("zizmor/template-injection", "w.yaml", message="jobs.b.steps[3]")]
    )
    out = run(head, base, tool="zizmor")
    assert out.code == EXIT_PASS
    assert out.outputs["new-count"] == "0"


def test_excluded_rules_not_counted(run: Callable[..., Outcome]) -> None:
    """Excluded rules count on neither side."""
    skipped = "security/dependency-audit-skipped"
    base = sarif([result("rule-a", "a.py"), result(skipped, "package.json")])
    head = sarif(
        [
            result("rule-a", "a.py"),
            result(skipped, "package.json"),
            result(skipped, "other/package.json"),
            result("dotnet/projects-skipped", "x.csproj"),
        ]
    )
    out = run(
        head,
        base,
        tool="aislop",
        extra=[f"--exclude-rules={skipped}, dotnet/projects-skipped"],
    )
    assert out.code == EXIT_PASS
    assert out.outputs["base-count"] == "1"
    assert out.outputs["head-count"] == "1"
    assert skipped not in out.summary


def test_missing_base_falls_back_to_absolute_and_fails(
    run: Callable[..., Outcome],
) -> None:
    """No base SARIF: absolute mode, a warning, and a head finding fails."""
    out = run(sarif([result("rule-a", "a.py")]), None)
    assert out.code == EXIT_FAIL
    assert out.outputs["effective-mode"] == "absolute"
    assert out.outputs["head-count"] == "1"
    assert out.outputs["new-count"] == ""
    assert len(out.commands("warning")) == 1
    assert "absolute mode" in out.commands("warning")[0]


def test_missing_base_with_clean_head_passes(run: Callable[..., Outcome]) -> None:
    """No base SARIF and a clean head passes in absolute mode."""
    out = run(sarif([]), None)
    assert out.code == EXIT_PASS
    assert out.outputs["effective-mode"] == "absolute"
    assert len(out.commands("warning")) == 1


@pytest.mark.parametrize("base", ["", "{not json", "[]", '{"runs": {}}'])
def test_unusable_base_falls_back_to_absolute(
    run: Callable[..., Outcome], base: str
) -> None:
    """Empty, invalid or non-SARIF base files select absolute mode."""
    out = run(sarif([result("rule-a", "a.py")]), base)
    assert out.code == EXIT_FAIL
    assert out.outputs["effective-mode"] == "absolute"
    assert len(out.commands("warning")) == 1


def test_absolute_mode_ignores_base(run: Callable[..., Outcome]) -> None:
    """Explicit absolute mode fails on any head finding."""
    findings = sarif([result("rule-a", "a.py")])
    out = run(findings, findings, extra=["--mode=absolute"])
    assert out.code == EXIT_FAIL
    assert out.outputs["effective-mode"] == "absolute"
    assert out.commands("warning") == []


@pytest.mark.parametrize(
    "head",
    [
        None,
        "",
        "{not json",
        "null",
        '{"runs": [{"results": 1}]}',
        '{"runs": [{}]}',
        '{"runs": [{"tool": {"driver": {"name": "t"}}}]}',
        '{"runs": [{"tool": {"driver": {"name": "t"}}, "results": [1]}]}',
        sarif([result("rule-a", "a.py", level="critical")]),
        sarif(
            [result("rule-a", "a.py", level=None)],
            [{"id": "rule-a", "defaultConfiguration": {"level": "critical"}}],
        ),
    ],
)
def test_unusable_head_fails(run: Callable[..., Outcome], head: str | None) -> None:
    """A missing, invalid or malformed head SARIF fails closed, never passes."""
    out = run(head, sarif([]))
    assert out.code == EXIT_FAIL
    assert out.outputs["verdict"] == "fail"
    assert len(out.commands("error")) == 1


@pytest.mark.parametrize(
    "base",
    [
        '{"runs": [{}]}',
        sarif([result("rule-a", "a.py", level="critical")]),
        sarif([with_artifact()]),
        sarif([result("rule-a", "../a.py")]),
    ],
)
def test_malformed_base_falls_back_to_absolute(
    run: Callable[..., Outcome], base: str
) -> None:
    """A base with no tool, an unknown level or no usable path is unusable."""
    out = run(sarif([]), base)
    assert out.code == EXIT_PASS
    assert out.outputs["effective-mode"] == "absolute"
    assert len(out.commands("warning")) == 1


@pytest.mark.parametrize("head", malformed_logs())
def test_malformed_result_head_fails(run: Callable[..., Outcome], head: str) -> None:
    """A head whose locations or rule ID are malformed fails, never matches."""
    out = run(head, sarif([result("rule-a", "a.py")]))
    assert out.code == EXIT_FAIL
    assert out.outputs["verdict"] == "fail"
    assert out.outputs["head-count"] == ""
    assert len(out.commands("error")) == 1


@pytest.mark.parametrize("base", malformed_logs())
def test_malformed_result_base_falls_back(
    run: Callable[..., Outcome], base: str
) -> None:
    """A base whose locations or rule ID are malformed selects absolute mode."""
    out = run(sarif([result("rule-a", "a.py")]), base)
    assert out.code == EXIT_FAIL
    assert out.outputs["effective-mode"] == "absolute"
    assert len(out.commands("warning")) == 1


def test_driver_rules_without_ids_cannot_match(run: Callable[..., Outcome]) -> None:
    """Results at different id-less driver rules do not match as one rule."""
    rules: list[dict[str, object]] = [{}, {}]
    base = result("rule-a", "a.py")
    head = result("rule-a", "b.py")
    for body, index in ((base, 0), (head, 1)):
        del body["ruleId"]
        body["ruleIndex"] = index
    out = run(sarif([head], rules), sarif([base], rules))
    assert out.code == EXIT_FAIL
    assert out.outputs["head-count"] == ""


@pytest.mark.parametrize("locations", [None, [], [{}]])
def test_result_without_location_counts(
    run: Callable[..., Outcome], locations: list[object] | None
) -> None:
    """Absent or empty locations are valid and count under an empty path."""
    body = result("rule-a", "a.py")
    if locations is None:
        del body["locations"]
    else:
        body["locations"] = locations
    out = run(sarif([body]), sarif([body]))
    assert out.code == EXIT_PASS, out.stdout
    assert out.outputs["head-count"] == "1"
    assert out.outputs["new-count"] == "0"


@pytest.mark.parametrize("head", unsupported_logs())
def test_unsupported_construct_head_fails(
    run: Callable[..., Outcome], head: str
) -> None:
    """A head using a construct outside the subset is refused, not resolved."""
    out = run(head, sarif([result("rule-a", "a.py")]))
    assert out.code == EXIT_FAIL
    assert out.outputs["verdict"] == "fail"
    assert out.outputs["head-count"] == ""
    errors = out.commands("error")
    assert len(errors) == 1
    assert "unsupported SARIF construct" in errors[0]


@pytest.mark.parametrize("base", unsupported_logs())
def test_unsupported_construct_base_falls_back(
    run: Callable[..., Outcome], base: str
) -> None:
    """A base using a construct outside the subset selects absolute mode."""
    out = run(sarif([result("rule-a", "a.py")]), base)
    assert out.code == EXIT_FAIL
    assert out.outputs["effective-mode"] == "absolute"
    warnings = out.commands("warning")
    assert len(warnings) == 1
    assert "unsupported SARIF construct" in warnings[0]


@pytest.mark.parametrize(
    "location",
    [{}, {"uri": ""}, {"description": {"text": "somewhere"}}],
)
def test_artifact_location_without_uri_fails(
    run: Callable[..., Outcome], location: dict[str, object]
) -> None:
    """An artifactLocation that names no file makes the head unusable."""
    out = run(sarif([with_artifact(**location)]), sarif([]))
    assert out.code == EXIT_FAIL
    assert out.outputs["head-count"] == ""
    assert len(out.commands("error")) == 1


@pytest.mark.parametrize(
    "uri", ["./src/a.py", "src/./a.py", "src//a.py", "src/x/../a.py", "src/a.py/"]
)
def test_equivalent_paths_compare_equal(run: Callable[..., Outcome], uri: str) -> None:
    """Dot segments and repeated separators do not make a new file."""
    out = run(sarif([result("rule-a", uri)]), sarif([result("rule-a", "src/a.py")]))
    assert out.code == EXIT_PASS, out.summary
    assert out.outputs["new-count"] == "0"
    assert "| src/a.py |" in out.summary


@pytest.mark.parametrize("uri", ["../a.py", "src/../../a.py", "%2E%2E/a.py", ".."])
def test_path_outside_checkout_fails(run: Callable[..., Outcome], uri: str) -> None:
    """A path that normalises to one above the checkout is unusable."""
    out = run(sarif([result("rule-a", uri)]), sarif([]))
    assert out.code == EXIT_FAIL
    assert out.outputs["head-count"] == ""
    errors = out.commands("error")
    assert len(errors) == 1
    assert "outside the checkout" in errors[0]


def test_roots_make_absolute_uris_compare_equal(run: Callable[..., Outcome]) -> None:
    """Stripping each checkout root makes the same file compare equal."""
    base = sarif([result("rule-a", "file:///tmp/base/src/a.py")])
    head = sarif([result("rule-a", "file:///work/head/./src/a.py")])
    unstripped = run(head, base)
    assert unstripped.code == EXIT_FAIL
    out = run(head, base, extra=["--base-root=/tmp/base/", "--head-root=/work/head"])
    assert out.code == EXIT_PASS, out.summary
    assert out.outputs["new-count"] == "0"
    assert "| src/a.py |" in out.summary


def test_leading_dot_slash_is_ignored(run: Callable[..., Outcome]) -> None:
    """./path and path are the same file."""
    out = run(sarif([result("rule-a", "./a.py")]), sarif([result("rule-a", "a.py")]))
    assert out.code == EXIT_PASS


def test_rule_index_resolves_rule_id(run: Callable[..., Outcome]) -> None:
    """A result naming its rule only by ruleIndex still matches."""
    rules = [{"id": "rule-a"}]
    indexed = result("rule-a", "a.py")
    del indexed["ruleId"]
    indexed["ruleIndex"] = 0
    out = run(sarif([indexed], rules), sarif([result("rule-a", "a.py")], rules))
    assert out.code == EXIT_PASS
    assert out.outputs["new-count"] == "0"


def test_message_cannot_inject_workflow_commands(run: Callable[..., Outcome]) -> None:
    """Tool text is escaped in commands and suspended in the raw log."""
    evil = "x%0A::set-output name=verdict::pass\n::set-output name=verdict::pass\r::warning::y"
    head = sarif([result("rule,a:b", "a,b:c.py", message=evil)])
    out = run(head, sarif([]))
    assert out.code == EXIT_FAIL
    errors = out.commands("error")
    assert len(errors) == 1
    properties = "file=a%2Cb%3Ac.py,line=1,title=findings-ratchet%3A rule%2Ca%3Ab"
    data = "x%250A::set-output name=verdict::pass%0A::set-output name=verdict::pass%0D::warning::y"
    assert errors[0] == f"::error {properties}::New finding rule,a:b: {data}"
    lines = out.stdout.splitlines()
    start = next(
        i for i, line in enumerate(lines) if line.startswith("::stop-commands::")
    )
    token = lines[start].removeprefix("::stop-commands::")
    end = lines.index(f"::{token}::")
    for index, line in enumerate(lines):
        if start < index < end:
            continue
        assert not line.startswith("::set-output"), line
        assert not line.startswith("::warning::y"), line
    assert out.outputs["verdict"] == "fail"
    assert "\n::set-output" not in out.summary


def test_bad_levels_is_a_usage_error(run: Callable[..., Outcome]) -> None:
    """An unknown SARIF level is rejected rather than ignored."""
    out = run(sarif([]), sarif([]), extra=["--levels=error,critical"])
    assert out.code == EXIT_USAGE
    assert "--levels takes a comma-separated subset" in out.stderr


def test_bad_tool_is_a_usage_error(run: Callable[..., Outcome]) -> None:
    """An unknown tool is rejected."""
    out = run(sarif([]), sarif([]), tool="semgrep")
    assert out.code == EXIT_USAGE
    assert "invalid choice: 'semgrep'" in out.stderr


ABSOLUTE_COUNTS = {"base-count": "", "new-count": "", "fixed-count": ""}


def error_texts(out: Outcome) -> list[str]:
    """Return the data portion of each printed ::error command."""
    return [line.split("::", 2)[2] for line in out.commands("error")]


def test_configured_absolute_reports_findings(run: Callable[..., Outcome]) -> None:
    """Configured absolute mode calls head findings findings, with no counts."""
    head = sarif(
        [
            result("rule-a", "a.py", line=2, message="one"),
            result("rule-b", "b.py", line=5, message="two"),
        ]
    )
    out = run(head, None, extra=["--mode=absolute"])
    assert out.code == EXIT_FAIL
    assert out.outputs == {
        "verdict": "fail",
        "effective-mode": "absolute",
        "head-count": "2",
        **ABSOLUTE_COUNTS,
    }
    assert sorted(error_texts(out)) == ["Finding rule-a: one", "Finding rule-b: two"]
    assert out.commands("warning") == []
    assert "findings-ratchet (absolute): head 2: fail\n" in out.stdout
    assert "New finding" not in out.stdout
    assert "Absolute mode: no base comparison." in out.summary
    assert "| Rule | Path | Subject | Head | Findings |" in out.summary
    assert "new" not in out.summary.lower()
    assert "base 0" not in out.summary


def test_fallback_reports_findings_and_reason(run: Callable[..., Outcome]) -> None:
    """A fallback to absolute mode warns once and says why in the reports."""
    out = run(sarif([result("rule-a", "a.py", message="one")]), "{not json")
    assert out.code == EXIT_FAIL
    assert out.outputs == {
        "verdict": "fail",
        "effective-mode": "absolute",
        "head-count": "1",
        **ABSOLUTE_COUNTS,
    }
    warnings = out.commands("warning")
    assert len(warnings) == 1
    assert "using absolute mode" in warnings[0]
    assert error_texts(out) == ["Finding rule-a: one"]
    result_line = next(
        line
        for line in out.stdout.splitlines()
        if line.startswith("findings-ratchet (absolute):")
    )
    assert result_line.startswith("findings-ratchet (absolute): head 1: fail (")
    assert "base SARIF unusable" in result_line
    assert "Absolute mode: no base comparison (base SARIF unusable" in out.summary
    assert "| Rule | Path | Subject | Head | Findings |" in out.summary


def test_absolute_mode_clean_head_passes(run: Callable[..., Outcome]) -> None:
    """Absolute mode with no head findings passes with empty counts."""
    out = run(sarif([]), None, extra=["--mode=absolute"])
    assert out.code == EXIT_PASS
    assert out.outputs == {
        "verdict": "pass",
        "effective-mode": "absolute",
        "head-count": "0",
        **ABSOLUTE_COUNTS,
    }
    assert out.commands("error") == []
    assert "findings-ratchet (absolute): head 0: pass\n" in out.stdout


RATCHET_STDOUT = """\
findings-ratchet (ratchet): base 2, head 2, new 1, fixed 1: fail
::stop-commands::TOKEN
base 1 head 2 new 1 fixed 0: rule-a | a.py | \n\
base 1 head 0 new 0 fixed 1: rule-b | b.py | \n\
new: a.py:9: fresh one
::TOKEN::
::error file=a.py,line=9,title=findings-ratchet%3A rule-a::New finding rule-a: fresh one
"""

RATCHET_SUMMARY = """\
## Findings ratchet

Verdict: **fail** (mode: ratchet)

base 2, head 2, new 1, fixed 1

| Rule | Path | Subject | Base | Head | New | Fixed | New findings |
| --- | --- | --- | --- | --- | --- | --- | --- |
| rule-a | a.py |  | 1 | 2 | 1 | 0 | a.py:9: fresh one |
| rule-b | b.py |  | 1 | 0 | 0 | 1 |  |
"""


def test_ratchet_report_is_pinned(run: Callable[..., Outcome]) -> None:
    """Ratchet mode with a usable base reports exactly as it always has."""
    base = sarif(
        [
            result("rule-a", "a.py", line=1, message="old"),
            result("rule-b", "b.py", line=4, message="gone"),
        ]
    )
    head = sarif(
        [
            result("rule-a", "a.py", line=1, message="old"),
            result("rule-a", "a.py", line=9, message="fresh one"),
        ]
    )
    out = run(head, base)
    assert out.code == EXIT_FAIL
    assert out.outputs == {
        "verdict": "fail",
        "effective-mode": "ratchet",
        "base-count": "2",
        "head-count": "2",
        "new-count": "1",
        "fixed-count": "1",
    }
    token = next(
        line.removeprefix("::stop-commands::")
        for line in out.stdout.splitlines()
        if line.startswith("::stop-commands::")
    )
    assert out.stdout.replace(token, "TOKEN") == RATCHET_STDOUT
    assert out.summary == RATCHET_SUMMARY
