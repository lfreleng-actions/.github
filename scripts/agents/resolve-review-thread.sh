#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Reference implementation of the AGENTS.md review-thread resolution
# step: resolve one pull request review thread and prove it resolved.
#
# GitHub's GraphQL API answers a rejected mutation with HTTP 200 and an
# `errors` array, so `gh api` exits 0 and a caller reading the exit
# status reports success while the thread stays open. This script
# judges the payload, not the transport.
#
# Contract
#   resolve-review-thread.sh <thread-node-id>
#
#   <thread-node-id> is the review thread's GraphQL node ID (PRRT_...),
#   not a #discussion_r comment ID. Runs under the credentials `gh`
#   already holds (GH_TOKEN, or `gh auth login`); the token never
#   appears on a command line. Passes (exit 0) only when the response
#   carries no `errors` and reports `isResolved: true`.
#
# Exit status
#   0   thread resolved
#   2   gh failed or returned no usable JSON
#   3   GraphQL response carries errors
#   4   response reports the thread still unresolved
#   64  usage error
#
# The tests under scripts/agents/tests define the contract precisely.

set -euo pipefail

thread_id="${1:-}"
if [ "$#" -ne 1 ] || ! [[ "$thread_id" =~ ^PRRT_[A-Za-z0-9_-]+$ ]]; then
  echo 'usage: resolve-review-thread.sh <PRRT_... thread node id>' >&2
  exit 64
fi

# $id is a GraphQL variable, not a shell expansion: single quotes are
# deliberate.
# shellcheck disable=SC2016
query='mutation($id: ID!) {
  resolveReviewThread(input: {threadId: $id}) { thread { isResolved } }
}'

response="$(mktemp)"
trap 'rm -f "$response"' EXIT

# The ID travels as a GraphQL variable, never spliced into the query.
rc=0
gh api graphql -f query="$query" -f id="$thread_id" > "$response" || rc=$?

python3 - "$response" "$rc" <<'PY'
import json
import sys

path, rc = sys.argv[1], int(sys.argv[2])

try:
    with open(path, encoding="utf-8") as fh:
        body = json.load(fh)
except (OSError, ValueError):
    body = None

def fail(code, message):
    sys.stderr.write(f"resolve-review-thread: {message}\n")
    sys.exit(code)


if not isinstance(body, dict):
    fail(2, f"gh exited {rc} without a usable JSON response")

errors = body.get("errors")
if errors:
    fail(3, f"GraphQL errors: {json.dumps(errors)}")

if rc:
    fail(2, f"gh exited {rc}")

try:
    resolved = body["data"]["resolveReviewThread"]["thread"]["isResolved"]
except (KeyError, TypeError):
    fail(2, "response carries no thread.isResolved field")

if resolved is not True:
    fail(4, "thread still open")

print("resolve-review-thread: resolved")
PY
