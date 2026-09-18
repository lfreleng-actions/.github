# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Contract tests for scripts/agents/aislop-gate.sh.

The gate passes only on an empty ``diagnostics`` array. Every case below
that ends nonzero is one that aislop's own exit code would have passed.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from .conftest import write

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from .conftest import GitRepo, Outcome, Stub

SCRIPT = "aislop-gate.sh"

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_NO_REPORT = 2
EXIT_ENGINE_MISSING = 3
EXIT_USAGE = 64


def report(
    findings: Sequence[dict[str, object]] = (),
    *,
    lint_skipped: bool = False,
) -> str:
    """Build a minimal aislop JSON report."""
    body: dict[str, object] = {
        "score": 100,
        "diagnostics": list(findings),
        "engines": {"lint": {"issues": 0, "skipped": lint_skipped}},
        "summary": {"errors": 0, "warnings": 0},
    }
    return json.dumps(body)


def finding(severity: str) -> dict[str, object]:
    """Build one diagnostic of the given severity."""
    return {
        "filePath": "a.py",
        "line": 1,
        "column": 1,
        "rule": "ai-slop/narrative-comment",
        "severity": severity,
        "message": "narrative comment",
    }


def report_with_engines(engines: object) -> str:
    """Build a clean report whose ``engines`` member is *engines*."""
    return json.dumps(
        {
            "score": 100,
            "diagnostics": [],
            "engines": engines,
            "summary": {"errors": 0, "warnings": 0},
        }
    )


def report_missing_engines() -> str:
    """Build a clean report that omits ``engines`` altogether."""
    return json.dumps(
        {
            "score": 100,
            "diagnostics": [],
            "summary": {"errors": 0, "warnings": 0},
        }
    )


@pytest.fixture
def staged_markdown(git_repo: GitRepo) -> GitRepo:
    """Stage a Markdown-only change, which no engine binary scores."""
    _ = write(git_repo.path / "NOTES.md", "# Notes\n")
    git_repo.run("add", "NOTES.md")
    return git_repo


@pytest.fixture
def staged_python(git_repo: GitRepo) -> GitRepo:
    """Stage a Python change, which needs ruff behind aislop."""
    _ = write(git_repo.path / "mod.py", "X = 1\n")
    git_repo.run("add", "mod.py")
    return git_repo


@pytest.fixture
def staged_pyi(git_repo: GitRepo) -> GitRepo:
    """Stage a stub-only change; aislop classifies .pyi as Python."""
    _ = write(git_repo.path / "mod.pyi", "X: int\n")
    git_repo.run("add", "mod.pyi")
    return git_repo


@pytest.fixture
def untracked_python(git_repo: GitRepo) -> GitRepo:
    """Leave a Python file untracked: aislop scans it, `git diff` omits it."""
    _ = write(git_repo.path / "new_mod.py", "X = 1\n")
    return git_repo


def test_usage_without_arguments(run_script: Callable[..., Outcome]) -> None:
    """No mode is a usage error, not a vacuous pass."""
    outcome = run_script(SCRIPT)
    assert outcome.returncode == EXIT_USAGE


def test_usage_rejects_unknown_flag(
    run_script: Callable[..., Outcome], git_repo: GitRepo
) -> None:
    """An unknown flag is a usage error rather than a base ref."""
    outcome = run_script(SCRIPT, "--all", cwd=git_repo.path)
    assert outcome.returncode == EXIT_USAGE


def test_unresolvable_base_is_usage_error(
    run_script: Callable[..., Outcome],
    git_repo: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
) -> None:
    """A base ref with no merge base must not fall through to a scan."""
    stub = make_stub("aislop", report(), 0)
    outcome = run_script(SCRIPT, "no-such-branch", cwd=git_repo.path)
    assert outcome.returncode == EXIT_USAGE
    assert not stub.argv_file.exists()


def test_clean_report_passes(
    run_script: Callable[..., Outcome],
    staged_markdown: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
) -> None:
    """An empty diagnostics array is the one passing shape."""
    stub = make_stub("aislop", report(lint_skipped=True), 0)
    outcome = run_script(SCRIPT, "--staged", cwd=staged_markdown.path)
    assert outcome.returncode == EXIT_CLEAN, outcome.stderr
    assert stub.argv()[1:] == ["ci", "--staged"]


def test_warning_only_report_fails(
    run_script: Callable[..., Outcome],
    staged_markdown: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
) -> None:
    """Aislop exits 0 on warnings; the gate must not."""
    _ = make_stub("aislop", report([finding("warning")]), 0)
    outcome = run_script(SCRIPT, "--staged", cwd=staged_markdown.path)
    assert outcome.returncode == EXIT_FINDINGS
    assert "narrative comment" in outcome.stderr


def test_info_only_report_fails(
    run_script: Callable[..., Outcome],
    staged_markdown: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
) -> None:
    """Any severity counts, including info."""
    _ = make_stub("aislop", report([finding("info")]), 0)
    outcome = run_script(SCRIPT, "--staged", cwd=staged_markdown.path)
    assert outcome.returncode == EXIT_FINDINGS


def test_error_report_fails(
    run_script: Callable[..., Outcome],
    staged_markdown: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
) -> None:
    """Errors fail even when aislop itself already exited nonzero."""
    _ = make_stub("aislop", report([finding("error")]), 1)
    outcome = run_script(SCRIPT, "--staged", cwd=staged_markdown.path)
    assert outcome.returncode == EXIT_FINDINGS


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(
            json.dumps({"score": 100, "diagnostics": None}), id="null-diagnostics"
        ),
        pytest.param(json.dumps({"score": 100}), id="missing-diagnostics"),
        pytest.param(json.dumps({"error": "engine crashed"}), id="error-object"),
        pytest.param(json.dumps({"diagnostics": {}}), id="object-not-array"),
        pytest.param("[]", id="array-not-object"),
        pytest.param("", id="empty-output"),
        pytest.param("Update available: 0.14.1 -> 0.16.0\n", id="not-json"),
    ],
)
def test_report_without_diagnostics_array_fails(
    run_script: Callable[..., Outcome],
    staged_markdown: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
    body: str,
) -> None:
    """A scan that did not run is not a clean scan."""
    _ = make_stub("aislop", body, 0)
    outcome = run_script(SCRIPT, "--staged", cwd=staged_markdown.path)
    assert outcome.returncode == EXIT_NO_REPORT, outcome.stderr


def test_error_object_is_reported(
    run_script: Callable[..., Outcome],
    staged_markdown: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
) -> None:
    """The aislop error message reaches the caller."""
    _ = make_stub("aislop", json.dumps({"error": "engine crashed"}), 0)
    outcome = run_script(SCRIPT, "--staged", cwd=staged_markdown.path)
    assert "engine crashed" in outcome.stderr


def test_missing_engine_fails_for_python(
    run_script: Callable[..., Outcome],
    staged_python: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
) -> None:
    """A skipped lint engine with Python in scope is an under-report."""
    _ = make_stub("aislop", report(lint_skipped=True), 0)
    outcome = run_script(SCRIPT, "--staged", cwd=staged_python.path)
    assert outcome.returncode == EXIT_ENGINE_MISSING
    assert "doctor" in outcome.stderr


def test_missing_engine_fails_for_go(
    run_script: Callable[..., Outcome],
    git_repo: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
) -> None:
    """The same holds for Go, which needs golangci-lint."""
    _ = write(git_repo.path / "main.go", "package main\n")
    git_repo.run("add", "main.go")
    _ = make_stub("aislop", report(lint_skipped=True), 0)
    outcome = run_script(SCRIPT, "--staged", cwd=git_repo.path)
    assert outcome.returncode == EXIT_ENGINE_MISSING


def test_missing_engine_fails_for_python_stub(
    run_script: Callable[..., Outcome],
    staged_pyi: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
) -> None:
    """A .pyi-only change is Python to ruff, so a skipped engine fails."""
    _ = make_stub("aislop", report(lint_skipped=True), 0)
    outcome = run_script(SCRIPT, "--staged", cwd=staged_pyi.path)
    assert outcome.returncode == EXIT_ENGINE_MISSING


def test_missing_engine_fails_for_untracked_python(
    run_script: Callable[..., Outcome],
    untracked_python: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
) -> None:
    """Untracked Python is in aislop's scope, so it must count here too."""
    _ = make_stub("aislop", report(lint_skipped=True), 0)
    outcome = run_script(SCRIPT, "--changes", cwd=untracked_python.path)
    assert outcome.returncode == EXIT_ENGINE_MISSING


def test_missing_engine_fails_for_non_ascii_python_path(
    run_script: Callable[..., Outcome],
    git_repo: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
) -> None:
    """Git C-quotes non-ASCII paths, which would hide the .py suffix."""
    _ = write(git_repo.path / "résumé.py", "X = 1\n")
    git_repo.run("add", "résumé.py")
    _ = make_stub("aislop", report(lint_skipped=True), 0)
    outcome = run_script(SCRIPT, "--staged", cwd=git_repo.path)
    assert outcome.returncode == EXIT_ENGINE_MISSING


def test_clean_report_from_failed_scan_fails(
    run_script: Callable[..., Outcome],
    staged_python: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
) -> None:
    """A clean report from a nonzero aislop is a scan that stopped early."""
    _ = make_stub("aislop", report(), 1)
    outcome = run_script(SCRIPT, "--staged", cwd=staged_python.path)
    assert outcome.returncode == EXIT_NO_REPORT


def test_absent_engine_status_fails_closed(
    run_script: Callable[..., Outcome],
    staged_python: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
) -> None:
    """Absent engine status proves nothing about whether lint ran."""
    _ = make_stub("aislop", report_missing_engines(), 0)
    outcome = run_script(SCRIPT, "--staged", cwd=staged_python.path)
    assert outcome.returncode == EXIT_NO_REPORT


def test_null_engine_status_fails_closed(
    run_script: Callable[..., Outcome],
    staged_python: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
) -> None:
    """A null engines member fails the gate rather than raising."""
    _ = make_stub("aislop", report_with_engines(None), 0)
    outcome = run_script(SCRIPT, "--staged", cwd=staged_python.path)
    assert outcome.returncode == EXIT_NO_REPORT
    assert "Traceback" not in outcome.stderr


def test_engine_status_without_skipped_fails_closed(
    run_script: Callable[..., Outcome],
    staged_python: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
) -> None:
    """A lint object with no `skipped` key does not establish lint ran."""
    _ = make_stub("aislop", report_with_engines({"lint": {"issues": 0}}), 0)
    outcome = run_script(SCRIPT, "--staged", cwd=staged_python.path)
    assert outcome.returncode == EXIT_NO_REPORT


def test_absent_engine_status_passes_without_scored_languages(
    run_script: Callable[..., Outcome],
    staged_markdown: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
) -> None:
    """Markdown needs no lint engine, so absent status is not a failure."""
    _ = make_stub("aislop", report_missing_engines(), 0)
    outcome = run_script(SCRIPT, "--staged", cwd=staged_markdown.path)
    assert outcome.returncode == EXIT_CLEAN


def test_skipped_engine_is_fine_without_scored_languages(
    run_script: Callable[..., Outcome],
    staged_markdown: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
) -> None:
    """Markdown-only scopes legitimately skip the lint engine."""
    _ = make_stub("aislop", report(lint_skipped=True), 0)
    outcome = run_script(SCRIPT, "--staged", cwd=staged_markdown.path)
    assert outcome.returncode == EXIT_CLEAN


def test_present_engine_passes_for_python(
    run_script: Callable[..., Outcome],
    staged_python: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
) -> None:
    """With the engine running and no findings, Python passes."""
    _ = make_stub("aislop", report(lint_skipped=False), 0)
    outcome = run_script(SCRIPT, "--staged", cwd=staged_python.path)
    assert outcome.returncode == EXIT_CLEAN, outcome.stderr


def test_changes_mode_passes_through(
    run_script: Callable[..., Outcome],
    git_repo: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
) -> None:
    """--changes gates the working tree against HEAD."""
    stub = make_stub("aislop", report(), 0)
    outcome = run_script(SCRIPT, "--changes", cwd=git_repo.path)
    assert outcome.returncode == EXIT_CLEAN, outcome.stderr
    assert stub.argv()[1:] == ["ci", "--changes"]


def test_base_ref_resolves_to_merge_base(
    run_script: Callable[..., Outcome],
    git_repo: GitRepo,
    make_stub: Callable[[str, str, int], Stub],
) -> None:
    """The branch ref must never reach aislop; the merge base must."""
    fork_point = git_repo.head()
    git_repo.run("checkout", "-q", "-b", "feature")
    git_repo.commit("Feat: branch work")
    git_repo.run("checkout", "-q", "main")
    git_repo.commit("Chore: main moved on")
    advanced = git_repo.head()
    git_repo.run("checkout", "-q", "feature")

    stub = make_stub("aislop", report(), 0)
    outcome = run_script(SCRIPT, "main", cwd=git_repo.path)

    assert outcome.returncode == EXIT_CLEAN, outcome.stderr
    argv = stub.argv()[1:]
    assert argv == ["ci", "--changes", "--base", fork_point]
    assert "main" not in argv
    assert advanced not in argv
