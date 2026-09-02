#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Reference implementation of the AGENTS.md AI-slop gate.
#
# Contract
#   aislop-gate.sh <base-ref>   gate committed work against the merge
#                               base of HEAD and <base-ref>
#   aislop-gate.sh --staged     gate exactly what is staged
#   aislop-gate.sh --changes    gate the uncommitted working tree
#
#   Passes (exit 0) only when the aislop report carries a `diagnostics`
#   array and that array is empty. Any finding at any severity fails,
#   which is stricter than aislop's own exit code (thresholded on error
#   severity and score). A report without a diagnostics array is a scan
#   that did not run, and fails rather than passing vacuously. When the
#   gated files include Python or Go and the report shows the lint
#   engine skipped, the engine binary aislop delegates to is absent and
#   the scan under-reports; that fails too.
#
# Exit status
#   0   clean: diagnostics array present and empty
#   1   findings on the gated files
#   2   scan did not produce a usable report
#   3   lint engine missing for a language in scope
#   64  usage error
#
# The tests under scripts/agents/tests define the contract precisely.

set -euo pipefail

usage() {
  echo 'usage: aislop-gate.sh <base-ref> | --staged | --changes' >&2
  exit 64
}

[ "$#" -eq 1 ] || usage

scope_files() {
  case "$1" in
    --staged) git diff --cached --name-only --diff-filter=ACMR ;;
    --changes) git diff --name-only --diff-filter=ACMR HEAD ;;
    *) git diff --name-only --diff-filter=ACMR "$1" ;;
  esac
}

case "$1" in
  --staged | --changes)
    mode="$1"
    set -- aislop ci "$1"
    ;;
  -*)
    usage
    ;;
  *)
    # aislop hands --base straight to a two-dot `git diff <base>`, so a
    # branch ref that has advanced past the fork point drags in files
    # changed only on the target. Resolve the merge base instead.
    if ! base_sha="$(git merge-base HEAD "$1" 2>/dev/null)"; then
      echo "aislop-gate: cannot resolve merge base of HEAD and '$1'" >&2
      exit 64
    fi
    mode="$base_sha"
    set -- aislop ci --changes --base "$base_sha"
    ;;
esac

report="$(mktemp)"
files="$(mktemp)"
trap 'rm -f "$report" "$files"' EXIT

scope_files "$mode" > "$files"

# aislop's exit code is not the gate: it exits 0 on warning-only
# reports. Capture the report and judge it on its content.
"$@" > "$report" || true

python3 - "$report" "$files" <<'PY'
import json
import sys

report_path, files_path = sys.argv[1], sys.argv[2]


def fail(code, message):
    sys.stderr.write(f"aislop-gate: {message}\n")
    sys.exit(code)


try:
    with open(report_path, encoding="utf-8") as fh:
        report = json.load(fh)
except (OSError, ValueError) as exc:
    fail(2, f"report is not JSON ({exc}); scan did not run")

if not isinstance(report, dict):
    fail(2, "report is not a JSON object; scan did not run")

diagnostics = report.get("diagnostics")
if not isinstance(diagnostics, list):
    error = report.get("error")
    if error:
        sys.stderr.write(f"aislop-gate: aislop reported: {error}\n")
    fail(2, "report carries no diagnostics array; treating this as a failed scan")

with open(files_path, encoding="utf-8") as fh:
    scoped = [line.strip() for line in fh if line.strip()]

needs_engine = [f for f in scoped if f.endswith((".py", ".go"))]
lint = report.get("engines", {}).get("lint", {})
if needs_engine and lint.get("skipped") is True:
    fail(
        3,
        "lint engine skipped while Python or Go files are in scope;"
        " ruff or golangci-lint is not available to aislop, so the scan"
        " under-reports. Install the engine (see `aislop doctor`) and re-run.",
    )

if diagnostics:
    for d in diagnostics:
        sys.stderr.write(
            "{}:{}:{}: [{}] {} {}\n".format(
                d.get("filePath", "?"),
                d.get("line", "?"),
                d.get("column", "?"),
                d.get("severity", "?"),
                d.get("rule", "?"),
                d.get("message", ""),
            )
        )
    fail(1, f"{len(diagnostics)} finding(s) on gated files")

print(f"aislop-gate: clean ({len(scoped)} file(s) gated)")
PY
