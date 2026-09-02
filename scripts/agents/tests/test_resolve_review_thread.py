# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Contract tests for scripts/agents/resolve-review-thread.sh.

GitHub answers a rejected GraphQL mutation with HTTP 200 and an
``errors`` array, so ``gh api`` exits 0. The script has to read the
payload; these tests hold it to that.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable

    from .conftest import Outcome, Stub

pytestmark = pytest.mark.xfail(
    strict=True, reason="scripts/agents reference scripts not yet implemented"
)

SCRIPT = "resolve-review-thread.sh"

EXIT_OK = 0
EXIT_NO_RESPONSE = 2
EXIT_GRAPHQL_ERRORS = 3
EXIT_STILL_OPEN = 4
EXIT_USAGE = 64

THREAD_ID = "PRRT_kwDOPjTE6851erd-"


def response(*, resolved: bool) -> str:
    """Build a successful mutation payload."""
    return json.dumps(
        {"data": {"resolveReviewThread": {"thread": {"isResolved": resolved}}}}
    )


ERROR_RESPONSE = json.dumps(
    {
        "data": {"resolveReviewThread": None},
        "errors": [
            {
                "type": "FORBIDDEN",
                "path": ["resolveReviewThread"],
                "message": "Resource not accessible by personal access token",
            }
        ],
    }
)


def test_usage_without_argument(run_script: Callable[..., Outcome]) -> None:
    """No thread ID is a usage error."""
    outcome = run_script(SCRIPT)
    assert outcome.returncode == EXIT_USAGE


@pytest.mark.parametrize(
    "bad_id",
    [
        pytest.param("3852741024", id="discussion-comment-id"),
        pytest.param("PRRC_kwDOPjTE6851erd-", id="comment-node-id"),
        pytest.param("PRRT_abc; rm -rf /", id="shell-metacharacters"),
        pytest.param("", id="empty"),
    ],
)
def test_usage_rejects_non_thread_ids(
    run_script: Callable[..., Outcome],
    make_stub: Callable[[str, str, int], Stub],
    bad_id: str,
) -> None:
    """Only a PRRT_ node ID is accepted, and gh is never called otherwise."""
    stub = make_stub("gh", response(resolved=True), 0)
    outcome = run_script(SCRIPT, bad_id)
    assert outcome.returncode == EXIT_USAGE
    assert not stub.argv_file.exists()


def test_resolved_thread_passes(
    run_script: Callable[..., Outcome], make_stub: Callable[[str, str, int], Stub]
) -> None:
    """A clean payload with isResolved true is the one passing shape."""
    stub = make_stub("gh", response(resolved=True), 0)
    outcome = run_script(SCRIPT, THREAD_ID)
    assert outcome.returncode == EXIT_OK, outcome.stderr
    assert "resolved" in outcome.stdout
    argv = stub.argv()[1:]
    assert argv[:2] == ["api", "graphql"]
    assert f"id={THREAD_ID}" in argv


def test_thread_id_travels_as_variable_not_in_query(
    run_script: Callable[..., Outcome], make_stub: Callable[[str, str, int], Stub]
) -> None:
    """The ID is a GraphQL variable; it must not be spliced into the query."""
    stub = make_stub("gh", response(resolved=True), 0)
    _ = run_script(SCRIPT, THREAD_ID)
    query_lines = [line for line in stub.argv() if line.startswith("query=")]
    assert len(query_lines) == 1
    assert THREAD_ID not in query_lines[0]
    assert "$id" in query_lines[0]


def test_graphql_errors_with_http_200_fail(
    run_script: Callable[..., Outcome], make_stub: Callable[[str, str, int], Stub]
) -> None:
    """Gh exits 0 on a rejected mutation; the script must not."""
    _ = make_stub("gh", ERROR_RESPONSE, 0)
    outcome = run_script(SCRIPT, THREAD_ID)
    assert outcome.returncode == EXIT_GRAPHQL_ERRORS
    assert "FORBIDDEN" in outcome.stderr


def test_unresolved_thread_fails(
    run_script: Callable[..., Outcome], make_stub: Callable[[str, str, int], Stub]
) -> None:
    """A well-formed payload that says isResolved false is a failure."""
    _ = make_stub("gh", response(resolved=False), 0)
    outcome = run_script(SCRIPT, THREAD_ID)
    assert outcome.returncode == EXIT_STILL_OPEN
    assert "still open" in outcome.stderr


def test_gh_failure_without_json_fails(
    run_script: Callable[..., Outcome], make_stub: Callable[[str, str, int], Stub]
) -> None:
    """A transport failure with no payload is reported as such."""
    _ = make_stub("gh", "", 1)
    outcome = run_script(SCRIPT, THREAD_ID)
    assert outcome.returncode == EXIT_NO_RESPONSE
    assert "gh exited 1" in outcome.stderr


def test_gh_failure_with_json_errors_reports_errors(
    run_script: Callable[..., Outcome], make_stub: Callable[[str, str, int], Stub]
) -> None:
    """When gh exits nonzero and carries errors, the errors are what matter."""
    _ = make_stub("gh", ERROR_RESPONSE, 1)
    outcome = run_script(SCRIPT, THREAD_ID)
    assert outcome.returncode == EXIT_GRAPHQL_ERRORS


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(json.dumps({"data": None}), id="null-data"),
        pytest.param(json.dumps({"data": {}}), id="missing-mutation"),
        pytest.param(
            json.dumps({"data": {"resolveReviewThread": None}}), id="null-mutation"
        ),
        pytest.param("[]", id="array"),
        pytest.param("not json", id="not-json"),
    ],
)
def test_malformed_success_payload_fails(
    run_script: Callable[..., Outcome],
    make_stub: Callable[[str, str, int], Stub],
    body: str,
) -> None:
    """Anything short of an explicit isResolved true is not a pass."""
    _ = make_stub("gh", body, 0)
    outcome = run_script(SCRIPT, THREAD_ID)
    assert outcome.returncode == EXIT_NO_RESPONSE, outcome.stderr
