#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Reference implementation of the AGENTS.md Gerrit amend rule: amend
# HEAD without losing its Change-Id.
#
# Gerrit identifies a change by the Change-Id trailer, not the commit
# SHA. `git commit --amend -m` and `--amend -F` replace the whole
# message; the commit-msg hook then finds no Change-Id and mints a new
# one, and the push opens a duplicate change instead of a new patchset.
#
# Contract
#   gerrit-amend.sh                 amend with the message unchanged
#   gerrit-amend.sh <message-file>  amend with the message in the file
#
#   Refuses to amend when HEAD's trailer block carries no Change-Id,
#   or when the message file's trailer block does not carry exactly
#   that Change-Id. Signs the amend
#   (-S) and adds the DCO trailer (-s). Passes (exit 0) only when the
#   Change-Id on the new HEAD is identical to the one captured before
#   the amend. Never deletes the message file: on every failure path it
#   holds the only copy of the edited message.
#
# Exit status
#   0   amended; Change-Id preserved
#   2   HEAD carries no single Change-Id; nothing amended
#   3   message file lacks HEAD's Change-Id; nothing amended
#   4   git commit --amend failed; HEAD untouched
#   5   Change-Id changed by the amend; do not push
#   64  usage error
#
# The tests under scripts/agents/tests define the contract precisely.

set -euo pipefail

[ "$#" -le 1 ] || {
  echo 'usage: gerrit-amend.sh [<message-file>]' >&2
  exit 64
}

# Distinguish "no argument" from "one unreadable argument" by count,
# not by emptiness: an empty path is a caller's unset variable, and
# treating it as the no-file form would silently amend with the old
# message instead of the one the caller meant to apply.
msg_file="${1:-}"
if [ "$#" -eq 1 ] && [ ! -r "$msg_file" ]; then
  echo "gerrit-amend: cannot read message file '$msg_file'" >&2
  exit 64
fi

# Read the trailer block, not the whole message. Gerrit honours
# Change-Id only as a trailer, so a line sitting in the body is not one
# and must not satisfy this check: "preserving" it would still open a
# new change. Within the block, every Change-Id is collected, well
# formed or not, so a second malformed one cannot hide behind a good
# one; counting and validation happen below.
change_id_of() {
  git --no-pager log -1 --format='%(trailers:key=Change-Id)' "$1"
}

orig_id="$(change_id_of HEAD)"
if [ -z "$orig_id" ]; then
  echo 'gerrit-amend: HEAD carries no Change-Id; investigate before amending' >&2
  exit 2
fi
if [ "$(printf '%s\n' "$orig_id" | wc -l)" -ne 1 ]; then
  echo 'gerrit-amend: HEAD carries more than one Change-Id; refusing' >&2
  exit 2
fi
if ! printf '%s\n' "$orig_id" | grep -qE '^Change-Id: I[0-9a-f]{40}$'; then
  echo "gerrit-amend: HEAD's Change-Id is malformed: $orig_id" >&2
  echo 'gerrit-amend: a bare or truncated value preserves nothing' >&2
  exit 2
fi

if [ -n "$msg_file" ]; then
  # Require exactly HEAD's Change-Id and nothing else. Comparing against
  # the single-line orig_id rejects a missing ID, a different one, and a
  # second one alongside it. The last case would otherwise amend first
  # and only fail afterwards, on the post-amend comparison.
  file_ids="$(git interpret-trailers --parse <"$msg_file" |
    grep '^Change-Id:' || true)"
  if [ "$file_ids" != "$orig_id" ]; then
    echo "gerrit-amend: '$msg_file' must carry exactly HEAD's $orig_id" >&2
    echo 'gerrit-amend: make that the only Change-Id in the message' >&2
    exit 3
  fi
fi

if [ -n "$msg_file" ]; then
  set -- git commit -S -s --amend -F "$msg_file"
else
  set -- git commit -S -s --amend --no-edit
fi

if ! "$@"; then
  echo 'gerrit-amend: amend failed; HEAD untouched' >&2
  [ -n "$msg_file" ] && echo "gerrit-amend: message kept at $msg_file" >&2
  exit 4
fi

new_id="$(change_id_of HEAD)"
if [ "$new_id" != "$orig_id" ]; then
  echo 'gerrit-amend: Change-Id CHANGED by the amend; do not push' >&2
  echo "gerrit-amend:   before: $orig_id" >&2
  echo "gerrit-amend:   after:  ${new_id:-<none>}" >&2
  [ -n "$msg_file" ] && echo "gerrit-amend: message kept at $msg_file" >&2
  exit 5
fi

echo "gerrit-amend: amended; $orig_id preserved"
