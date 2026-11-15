# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Interpreter selection tests for actions/findings-ratchet/action.yaml.

The script tests launch findings_ratchet.py with sys.executable, so
they cannot show which Python the action itself selects. These tests
read the setup-python version spec from action.yaml and run the
comparison step's own shell, with a real interpreter and with one that
reports an older version.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ACTION_DIR = Path(__file__).resolve().parent.parent
ACTION = ACTION_DIR / "action.yaml"
MINIMUM_MINOR = 11
BASH = shutil.which("bash") or "/bin/bash"


def action_text() -> str:
    """Return action.yaml as text."""
    return ACTION.read_text(encoding="utf-8")


def python_version_spec() -> str:
    """Return the python-version the setup-python step requests."""
    pattern = r"^\s+python-version:\s*'([^']*)'\s*$"
    found: list[str] = re.findall(pattern, action_text(), re.MULTILINE)
    assert len(found) == 1, found
    return found[0]


def ratchet_script() -> str:
    """Return the run block of the step with id 'ratchet', dedented."""
    lines = action_text().splitlines()
    start = lines.index("      id: 'ratchet'")
    run_at = next(i for i in range(start, len(lines)) if lines[i] == "      run: |")
    body: list[str] = []
    for line in lines[run_at + 1 :]:
        if line.strip() and not line.startswith("        "):
            break
        body.append(line)
    return textwrap.dedent("\n".join(body)) + "\n"


def run_step(tmp_path: Path, python: str) -> subprocess.CompletedProcess[str]:
    """Run the comparison step's shell with PYTHON set to python."""
    head = tmp_path / "head.sarif"
    _ = head.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [{"tool": {"driver": {"name": "t"}}, "results": []}],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "output"
    summary = tmp_path / "summary"
    _ = output.write_text("", encoding="utf-8")
    _ = summary.write_text("", encoding="utf-8")
    return subprocess.run(
        [BASH, "-c", ratchet_script()],
        capture_output=True,
        text=True,
        check=False,
        env={
            "PATH": "/usr/bin:/bin",
            "PYTHON": python,
            "GITHUB_ACTION_PATH": str(ACTION_DIR),
            "GITHUB_OUTPUT": str(output),
            "GITHUB_STEP_SUMMARY": str(summary),
            "INPUT_HEAD_SARIF": str(head),
            "INPUT_BASE_SARIF": "",
            "INPUT_HEAD_ROOT": "",
            "INPUT_BASE_ROOT": "",
            "INPUT_TOOL": "generic",
            "INPUT_MODE": "absolute",
            "INPUT_LEVELS": "error,warning,note,none",
            "INPUT_EXCLUDE_RULES": "",
            "INPUT_ANNOTATE": "true",
        },
    )


def old_python(tmp_path: Path) -> tuple[Path, Path]:
    """Write an interpreter that reports Python 3.9 and marks any script run."""
    marker = tmp_path / "script-ran"
    stub = tmp_path / "python3.9"
    code = 'import sys; sys.version_info = (3, 9, 18, "final", 0); exec(sys.argv[1])'
    _ = stub.write_text(
        textwrap.dedent(
            f"""\
            #!/bin/sh
            if [ "$1" = "-I" ]; then shift; fi
            if [ "$1" = "-c" ]; then
              exec '{sys.executable}' -I -c '{code}' "$2"
            fi
            : > '{marker}'
            """
        ),
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub, marker


@pytest.mark.xfail(strict=True, reason="issue #363")
def test_version_spec_excludes_python_below_3_11() -> None:
    """The setup-python spec cannot resolve to a Python below 3.11."""
    spec = python_version_spec()
    assert spec != "3.x"
    match = re.fullmatch(r">=3\.(\d+)", spec)
    assert match is not None, spec
    assert int(match.group(1)) >= MINIMUM_MINOR


def test_setup_python_keeps_environment_and_pin() -> None:
    """The step stays pinned, leaves PATH alone and binds python-path."""
    text = action_text()
    assert re.search(r"uses: actions/setup-python@[0-9a-f]{40}\s", text)
    assert "update-environment: 'false'" in text
    assert "PYTHON: ${{ steps.setup-python.outputs.python-path }}" in text


def test_step_runs_comparison_on_supported_python(tmp_path: Path) -> None:
    """A supported interpreter runs the comparison and writes outputs."""
    proc = run_step(tmp_path, sys.executable)
    assert proc.returncode == 0, proc.stderr
    assert "verdict=pass" in (tmp_path / "output").read_text(encoding="utf-8")


@pytest.mark.xfail(strict=True, reason="issue #363")
def test_step_refuses_python_below_3_11(tmp_path: Path) -> None:
    """An interpreter reporting 3.9 stops the step before the script."""
    stub, marker = old_python(tmp_path)
    proc = run_step(tmp_path, str(stub))
    assert proc.returncode == 2
    assert "::error title=findings-ratchet::Python 3.11 or later" in proc.stdout
    assert not marker.exists()
    assert (tmp_path / "output").read_text(encoding="utf-8") == ""


@pytest.mark.xfail(strict=True, reason="issue #363")
def test_step_refuses_missing_python(tmp_path: Path) -> None:
    """An interpreter that cannot start stops the step with an error."""
    proc = run_step(tmp_path, str(tmp_path / "absent"))
    assert proc.returncode == 2
    assert "::error title=findings-ratchet::" in proc.stdout
