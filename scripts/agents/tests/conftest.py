# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Fixtures for the scripts/agents reference-script tests.

Every test runs a script as a subprocess against a throwaway git
repository and stubbed `aislop` or `gh` executables, so the suite needs
only git, ssh-keygen and python3 on the machine running it.
"""

from __future__ import annotations

import os
import stat
import subprocess
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

SCRIPTS_DIR = Path(__file__).resolve().parent.parent


def write(path: Path, text: str, *, executable: bool = False) -> Path:
    """Write text to a file, optionally marking it executable."""
    _ = path.write_text(text, encoding="utf-8")
    if executable:
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


STUB_SOURCE = textwrap.dedent(
    """\
    #!/bin/sh
    # Record the invocation, replay the canned response, exit as told.
    printf '%s\\n' "$0" "$@" > "$STUB_ARGV"
    if [ -n "${STUB_STDOUT:-}" ]; then cat "$STUB_STDOUT"; fi
    exit "${STUB_EXIT:-0}"
    """
)


@dataclass(frozen=True)
class Outcome:
    """Result of running a reference script."""

    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class Stub:
    """A stubbed executable on PATH plus the files it reads and writes."""

    argv_file: Path
    stdout_file: Path

    def argv(self) -> list[str]:
        """Return the recorded invocation, one element per line."""
        return self.argv_file.read_text(encoding="utf-8").splitlines()


@dataclass(frozen=True)
class GitRepo:
    """A throwaway repository configured for SSH commit signing."""

    path: Path
    env: dict[str, str]

    def run(self, *args: str) -> None:
        """Run git in the repository, failing the test on a nonzero exit."""
        _ = self.output(*args)

    def output(self, *args: str, check: bool = True) -> str:
        """Run git in the repository and return its stdout."""
        proc = subprocess.run(
            ["git", *args],
            cwd=self.path,
            env=self.env,
            capture_output=True,
            text=True,
            check=check,
        )
        return proc.stdout

    def head(self) -> str:
        """Return the SHA of HEAD."""
        return self.output("rev-parse", "HEAD").strip()

    def message(self) -> str:
        """Return the full commit message of HEAD."""
        return self.output("--no-pager", "log", "-1", "--format=%B")

    def commit(self, subject: str, *, trailers: str = "") -> None:
        """Add a signed commit touching a fresh file."""
        marker = (
            self.path
            / f"{subject.split(':', maxsplit=1)[0].lower()}-{self.head_count()}"
        )
        _ = write(marker, f"{subject}\n")
        self.run("add", str(marker))
        body = subject if not trailers else f"{subject}\n\n{trailers}"
        self.run("commit", "-q", "-S", "-s", "-m", body)

    def head_count(self) -> int:
        """Return the number of commits reachable from HEAD."""
        count = self.output("rev-list", "--count", "HEAD", check=False).strip()
        return int(count or 0)

    def break_signing(self) -> None:
        """Point signing at a key that does not exist so -S fails."""
        self.run("config", "user.signingkey", str(self.path / "missing.pub"))

    def install_commit_msg_hook(self, script: str) -> None:
        """Install a commit-msg hook with the given shell body."""
        hooks = self.path / ".git" / "hooks"
        hooks.mkdir(exist_ok=True)
        _ = write(hooks / "commit-msg", f"#!/bin/sh\n{script}\n", executable=True)


@pytest.fixture
def clean_env(tmp_path: Path) -> dict[str, str]:
    """Return an environment isolated from the developer's git setup.

    The developer may sign with GPG, set core.hooksPath globally, or
    carry a commit template; none of that may leak into the tests.
    """
    home = tmp_path / "home"
    home.mkdir()
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(home),
        "GIT_CONFIG_GLOBAL": str(home / ".gitconfig"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Test Author",
        "GIT_AUTHOR_EMAIL": "author@example.com",
        "GIT_COMMITTER_NAME": "Test Author",
        "GIT_COMMITTER_EMAIL": "author@example.com",
        "GIT_EDITOR": "true",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    _ = write(
        home / ".gitconfig",
        "[user]\n\tname = Test Author\n\temail = author@example.com\n",
    )
    return env


@pytest.fixture
def stub_path(tmp_path: Path, clean_env: dict[str, str]) -> Path:
    """Create a directory that shadows real tools and prepend it to PATH."""
    bin_dir = tmp_path / "stub-bin"
    bin_dir.mkdir()
    clean_env["PATH"] = f"{bin_dir}{os.pathsep}{clean_env['PATH']}"
    return bin_dir


@pytest.fixture
def make_stub(
    tmp_path: Path, stub_path: Path, clean_env: dict[str, str]
) -> Callable[[str, str, int], Stub]:
    """Return a factory that installs a stub executable on PATH."""

    def factory(name: str, stdout: str, exit_code: int = 0) -> Stub:
        stdout_file = write(tmp_path / f"{name}.stdout", stdout)
        argv_file = tmp_path / f"{name}.argv"
        _ = write(stub_path / name, STUB_SOURCE, executable=True)
        clean_env["STUB_ARGV"] = str(argv_file)
        clean_env["STUB_STDOUT"] = str(stdout_file)
        clean_env["STUB_EXIT"] = str(exit_code)
        return Stub(argv_file=argv_file, stdout_file=stdout_file)

    return factory


@pytest.fixture
def git_repo(tmp_path: Path, clean_env: dict[str, str]) -> GitRepo:
    """Create a repository with one signed commit and SSH signing set up."""
    key = tmp_path / "signing-key"
    keygen = subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        capture_output=True,
        text=True,
        check=False,
    )
    if keygen.returncode != 0:
        pytest.skip(f"ssh-keygen unavailable: {keygen.stderr.strip()}")

    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    repo = GitRepo(path=repo_path, env=clean_env)
    repo.run("init", "-q", "-b", "main")
    repo.run("config", "gpg.format", "ssh")
    repo.run("config", "user.signingkey", str(key.with_suffix(".pub")))
    repo.run("config", "commit.gpgsign", "false")
    repo.commit("Feat: initial commit")
    return repo


@pytest.fixture
def run_script(clean_env: dict[str, str]) -> Callable[..., Outcome]:
    """Return a runner that executes a reference script by name."""

    def runner(
        name: str,
        *args: str,
        cwd: Path | None = None,
        extra_env: Mapping[str, str] | None = None,
    ) -> Outcome:
        env = dict(clean_env)
        if extra_env:
            env.update(extra_env)
        proc = subprocess.run(
            [str(SCRIPTS_DIR / name), *args],
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        return Outcome(proc.returncode, proc.stdout, proc.stderr)

    return runner
