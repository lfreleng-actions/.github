# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Contract tests for scripts/agents/gerrit-amend.sh.

Each failure case below is a way an amend can drop or replace the
Change-Id while reporting success; the script must refuse or detect
every one of them, leave HEAD alone where it can, and keep the message
file on every path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .conftest import write

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from .conftest import GitRepo, Outcome

SCRIPT = "gerrit-amend.sh"

EXIT_OK = 0
EXIT_NO_CHANGE_ID = 2
EXIT_FILE_LACKS_ID = 3
EXIT_AMEND_FAILED = 4
EXIT_ID_CHANGED = 5
EXIT_USAGE = 64

CHANGE_ID = "Change-Id: I0123456789abcdef0123456789abcdef01234567"
OTHER_ID = "Change-Id: Ifedcba9876543210fedcba9876543210fedcba98"

# A hook that behaves like Gerrit's: mints a Change-Id when none is
# present, and leaves an existing one alone.
GERRIT_LIKE_HOOK = f"""
if ! grep -q '^Change-Id:' "$1"; then
  printf '\\n%s\\n' '{OTHER_ID}' >> "$1"
fi
"""

# A hook that rewrites the trailer, standing in for whatever might
# replace the Change-Id behind the script's back.
REWRITING_HOOK = f"""
sed -i.bak 's/^Change-Id: .*/{OTHER_ID}/' "$1" && rm -f "$1.bak"
"""


@pytest.fixture
def gerrit_repo(git_repo: GitRepo) -> GitRepo:
    """Return a repository whose HEAD carries a Change-Id."""
    git_repo.commit("Fix: gerrit change", trailers=CHANGE_ID)
    return git_repo


def write_message(path: Path, *lines: str) -> Path:
    """Write a commit message file and return its path."""
    _ = write(path, "\n".join(lines) + "\n")
    return path


def test_usage_rejects_extra_arguments(
    run_script: Callable[..., Outcome], gerrit_repo: GitRepo
) -> None:
    """More than one argument is a usage error."""
    outcome = run_script(SCRIPT, "a", "b", cwd=gerrit_repo.path)
    assert outcome.returncode == EXIT_USAGE


def test_usage_rejects_unreadable_file(
    run_script: Callable[..., Outcome], gerrit_repo: GitRepo
) -> None:
    """A missing message file is a usage error, not an amend."""
    head = gerrit_repo.head()
    outcome = run_script(SCRIPT, "no-such-file", cwd=gerrit_repo.path)
    assert outcome.returncode == EXIT_USAGE
    assert gerrit_repo.head() == head


def test_refuses_when_head_has_no_change_id(
    run_script: Callable[..., Outcome], git_repo: GitRepo
) -> None:
    """No original ID means nothing to preserve: refuse before amending.

    Amending anyway would let the hook mint a fresh ID and destroy the
    commit worth inspecting to find out why it carried none.
    """
    git_repo.install_commit_msg_hook(GERRIT_LIKE_HOOK)
    head = git_repo.head()
    outcome = run_script(SCRIPT, cwd=git_repo.path)
    assert outcome.returncode == EXIT_NO_CHANGE_ID
    assert git_repo.head() == head
    assert "Change-Id" not in git_repo.message()


def test_refuses_when_head_has_two_change_ids(
    run_script: Callable[..., Outcome], git_repo: GitRepo
) -> None:
    """Two IDs is ambiguous; refuse rather than pick one."""
    git_repo.commit("Fix: doubled", trailers=f"{CHANGE_ID}\n{OTHER_ID}")
    head = git_repo.head()
    outcome = run_script(SCRIPT, cwd=git_repo.path)
    assert outcome.returncode == EXIT_NO_CHANGE_ID
    assert git_repo.head() == head


def test_refuses_message_file_without_change_id(
    run_script: Callable[..., Outcome], gerrit_repo: GitRepo, tmp_path: Path
) -> None:
    """A file lacking the ID would orphan the change; refuse up front."""
    msg = write_message(tmp_path / "msg", "Fix: reworded", "", "Body.")
    head = gerrit_repo.head()
    outcome = run_script(SCRIPT, str(msg), cwd=gerrit_repo.path)
    assert outcome.returncode == EXIT_FILE_LACKS_ID
    assert gerrit_repo.head() == head
    assert msg.exists()
    assert CHANGE_ID in outcome.stderr


def test_refuses_message_file_with_different_change_id(
    run_script: Callable[..., Outcome], gerrit_repo: GitRepo, tmp_path: Path
) -> None:
    """Merely having *a* Change-Id line is not enough; it must be HEAD's."""
    msg = write_message(tmp_path / "msg", "Fix: reworded", "", OTHER_ID)
    head = gerrit_repo.head()
    outcome = run_script(SCRIPT, str(msg), cwd=gerrit_repo.path)
    assert outcome.returncode == EXIT_FILE_LACKS_ID
    assert gerrit_repo.head() == head
    assert msg.exists()


def test_failed_amend_keeps_head_and_file(
    run_script: Callable[..., Outcome], gerrit_repo: GitRepo, tmp_path: Path
) -> None:
    """When git refuses (here: signing fails), report it; do not pass.

    An unconditional verify-after-amend would compare HEAD against
    itself and report success for a commit that was never rewritten.
    """
    gerrit_repo.break_signing()
    msg = write_message(tmp_path / "msg", "Fix: reworded", "", CHANGE_ID)
    head = gerrit_repo.head()
    outcome = run_script(SCRIPT, str(msg), cwd=gerrit_repo.path)
    assert outcome.returncode == EXIT_AMEND_FAILED
    assert gerrit_repo.head() == head
    assert msg.exists()
    assert str(msg) in outcome.stderr


def test_detects_change_id_rewritten_during_amend(
    run_script: Callable[..., Outcome], gerrit_repo: GitRepo, tmp_path: Path
) -> None:
    """A hook that swaps the ID after the pre-check must still be caught.

    Checking that *a* ``Change-Id:`` line exists would pass here; only
    comparing the exact value catches it.
    """
    gerrit_repo.install_commit_msg_hook(REWRITING_HOOK)
    msg = write_message(tmp_path / "msg", "Fix: reworded", "", CHANGE_ID)
    outcome = run_script(SCRIPT, str(msg), cwd=gerrit_repo.path)
    assert outcome.returncode == EXIT_ID_CHANGED
    assert "do not push" in outcome.stderr
    assert CHANGE_ID in outcome.stderr
    assert OTHER_ID in outcome.stderr
    assert msg.exists()


def test_amend_without_file_preserves_message_and_id(
    run_script: Callable[..., Outcome], gerrit_repo: GitRepo
) -> None:
    """The no-edit form rewrites the commit and keeps the message."""
    before = gerrit_repo.message()
    head = gerrit_repo.head()
    _ = write(gerrit_repo.path / "extra", "more\n")
    gerrit_repo.run("add", "extra")
    outcome = run_script(SCRIPT, cwd=gerrit_repo.path)
    assert outcome.returncode == EXIT_OK, outcome.stderr
    assert gerrit_repo.head() != head
    assert gerrit_repo.message() == before
    assert CHANGE_ID in outcome.stdout


def test_amend_with_file_applies_message_and_preserves_id(
    run_script: Callable[..., Outcome], gerrit_repo: GitRepo, tmp_path: Path
) -> None:
    """The file form applies the new message with the ID intact."""
    msg = write_message(
        tmp_path / "msg", "Fix: reworded subject", "", "New body.", "", CHANGE_ID
    )
    outcome = run_script(SCRIPT, str(msg), cwd=gerrit_repo.path)
    assert outcome.returncode == EXIT_OK, outcome.stderr
    message = gerrit_repo.message()
    assert message.startswith("Fix: reworded subject\n")
    assert "New body." in message
    assert message.count("Change-Id:") == 1
    assert CHANGE_ID in message
    assert msg.exists()


def test_amend_is_signed_and_signed_off(
    run_script: Callable[..., Outcome], gerrit_repo: GitRepo
) -> None:
    """The amended commit carries a good signature and a DCO trailer."""
    outcome = run_script(SCRIPT, cwd=gerrit_repo.path)
    assert outcome.returncode == EXIT_OK, outcome.stderr
    raw = gerrit_repo.output("cat-file", "commit", "HEAD")
    assert "\ngpgsig " in raw
    assert "Signed-off-by: Test Author <author@example.com>" in gerrit_repo.message()
