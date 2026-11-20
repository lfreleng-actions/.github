# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Fuzz a repository's Python harnesses and turn what fails into SARIF.

fuzz-sarif-repository.yaml runs this script on both sides of a trust
boundary:

- ``fuzz`` runs in the job that executes the repository's code and
  holds no secret. Per harness, in path order, it replays the failing
  inputs earlier runs saved, setting aside each one that now passes
  until a publication acknowledges it, then fuzzes for the harness's
  share of the budget and saves each new failing input unless a saved
  one already fails the same way. It
  bounds the saved state and writes a handover directory: a run record,
  one log per process and the failing inputs.
- ``sarif`` runs in the job that holds the upload token. It treats the
  handover as hostile data: it executes nothing from it, refuses a
  handover that is missing, incomplete or malformed, and validates each
  field a result carries against the checkout, falling back to the
  harness file or a fixed placeholder. Messages hold fixed wording and
  those validated fields alone, never text quoted from a log.
- ``evidence`` and ``bind`` run in the job that holds the upload token
  and FUZZ_EVIDENCE_KEY. ``evidence`` counts the open alerts an upload
  would close without evidence; ``bind`` signs, once code scanning
  processes an upload, which input reproduced each reported result, so
  a later passing replay of that input alone can close its alert. A
  failure only the restored state records is signed only when the
  handed-over binding, for the previous analysis, already holds it.

Usage:
  fuzz_publish.py fuzz --root=DIR --source-root=DIR --python=PATH
      --harnesses=JSON --state=DIR --output=DIR --commit=SHA
      [--fuzz-seconds=N] [--restored-key=KEY] [--published=true|false]
      [--binding=FILE]
  fuzz_publish.py sarif --handover=DIR --source-root=DIR --commit=SHA
      --harnesses=JSON --output=FILE [--summary=FILE]
  fuzz_publish.py evidence --summary=FILE --alerts=FILE --handover=DIR
      --repository=OWNER/NAME [--sarif-id=ID]
  fuzz_publish.py bind --summary=FILE --handover=DIR
      --repository=OWNER/NAME --sarif-id=ID [--previous-sarif-id=ID]
      --output=FILE

The code lives in sibling modules: fuzz_common.py (constants, types,
log parsing), fuzz_state.py (budget and saved state), fuzz_runner.py
(the fuzz side), fuzz_record.py (the run record), fuzz_sarif.py
(the sarif side) and fuzz_evidence.py (the evidence check and binding).

Exit codes: 0 done, whatever the harnesses found; 2 bad arguments, a
fuzz run that could not do its work, a handover the sarif step
refuses (nothing is written), or an evidence check or binding that
cannot run.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import cast

# The workflow runs this file under python -I, which leaves the script's
# directory off sys.path; the sibling modules live there, in the tools
# checkout, not in the repository under test.
_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from fuzz_common import DEFAULT_SECONDS  # noqa: E402
from fuzz_evidence import bind_main, evidence_main  # noqa: E402
from fuzz_runner import fuzz_main  # noqa: E402
from fuzz_sarif import sarif_main  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    """Dispatch to the fuzz, sarif, evidence or bind side."""
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n", 1)[0] if __doc__ else None
    )
    sides = parser.add_subparsers(dest="side", required=True)
    fuzz = sides.add_parser("fuzz", help="run harnesses and write a handover")
    _ = fuzz.add_argument("--root", required=True, help="checkout to fuzz")
    _ = fuzz.add_argument(
        "--source-root", required=True, help="pristine checkout of the commit"
    )
    _ = fuzz.add_argument("--python", required=True, help="interpreter with Atheris")
    _ = fuzz.add_argument("--harnesses", required=True, help="JSON array of paths")
    _ = fuzz.add_argument("--state", required=True, help="saved state directory")
    _ = fuzz.add_argument("--output", required=True, help="handover directory")
    _ = fuzz.add_argument("--commit", required=True, help="commit under test")
    _ = fuzz.add_argument("--fuzz-seconds", type=int, default=DEFAULT_SECONDS)
    _ = fuzz.add_argument("--restored-key", default="", help="cache key restored")
    _ = fuzz.add_argument(
        "--published",
        choices=("true", "false"),
        default="false",
        help="whether the run that saved the restored state published it",
    )
    _ = fuzz.add_argument("--binding", default="", help="restored evidence binding")
    sarif = sides.add_parser("sarif", help="build SARIF from a handover")
    _ = sarif.add_argument("--handover", required=True, help="handover directory")
    _ = sarif.add_argument("--source-root", required=True, help="checkout fuzzed")
    _ = sarif.add_argument("--commit", required=True, help="commit discovered")
    _ = sarif.add_argument("--harnesses", required=True, help="JSON array of paths")
    _ = sarif.add_argument("--output", required=True, help="SARIF to write")
    _ = sarif.add_argument("--summary", default="", help="summary JSON to write")
    evidence = sides.add_parser("evidence", help="count unproven open alerts")
    _ = evidence.add_argument("--summary", required=True, help="summary JSON")
    _ = evidence.add_argument("--alerts", required=True, help="open alerts, JSONL")
    _ = evidence.add_argument("--handover", required=True, help="handover directory")
    _ = evidence.add_argument("--repository", required=True, help="OWNER/NAME")
    _ = evidence.add_argument("--sarif-id", default="", help="latest analysis")
    bind = sides.add_parser("bind", help="sign a processed upload's inputs")
    _ = bind.add_argument("--summary", required=True, help="summary JSON")
    _ = bind.add_argument("--handover", required=True, help="handover directory")
    _ = bind.add_argument("--repository", required=True, help="OWNER/NAME")
    _ = bind.add_argument("--sarif-id", required=True, help="upload's SARIF ID")
    _ = bind.add_argument(
        "--previous-sarif-id", default="", help="analysis the evidence check read"
    )
    _ = bind.add_argument("--output", required=True, help="binding to write")
    args = parser.parse_args(argv)
    sides_main = {
        "fuzz": fuzz_main,
        "sarif": sarif_main,
        "evidence": evidence_main,
        "bind": bind_main,
    }
    return sides_main[cast("str", args.side)](args)


if __name__ == "__main__":
    sys.exit(main())
