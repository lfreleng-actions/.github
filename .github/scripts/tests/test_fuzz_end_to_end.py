# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""End-to-end test of the fuzz publisher's script under real Atheris.

A fixture repository holds a harness written to the harness contract
and a planted defect. The test fuzzes it, builds SARIF, replays the
saved input on a second run, fixes the defect and checks the third run
drops the input and reports clean. It runs only when FUZZ_E2E_PYTHON
names an interpreter with Atheris installed, and skips otherwise.
"""

from __future__ import annotations

import json
import os
import textwrap
import unittest
from pathlib import Path
from typing import cast

import fuzz_common as fc
import fuzz_publish as fp
import fuzz_state as fs

HARNESS = "fuzz/fuzz_parse.py"
COMMIT = "e" * 40
DEFECT = textwrap.dedent(
    """\
    def parse(data: bytes) -> int:
        if len(data) >= 4 and data[0] == 0x21:
            return data[len(data)]
        return len(data)
    """
)
FIXED = DEFECT.replace("data[len(data)]", "data[-1]")
# Harness discovery selects any tracked .py file holding the marker line,
# this one included, so the marker exists only in the generated harness.
HARNESS_SOURCE = textwrap.dedent(
    """\
    import sys
    from pathlib import Path

    HERE = Path(__file__).resolve().parent
    sys.path.insert(0, str(HERE.parent))

    from pkg.parse import parse


    def TestOneInput(data: bytes) -> None:
        parse(data)


    def main() -> None:
        import @ENGINE@

        args = list(sys.argv)
        if not any(Path(arg).is_file() for arg in args[1:]):
            args.append(str(HERE / "seeds"))
        atheris.Setup(args, TestOneInput)
        atheris.Fuzz()


    if __name__ == "__main__":
        main()
    """
).replace("@ENGINE@", "atheris")


def interpreter() -> Path:
    """Return the Atheris interpreter, or skip."""
    value = os.environ.get("FUZZ_E2E_PYTHON", "")
    if not value or not Path(value).is_file():
        reason = "FUZZ_E2E_PYTHON names no interpreter with Atheris"
        raise unittest.SkipTest(reason)
    return Path(value)


def fuzz(root: Path, state: Path, output: Path, python: Path, key: str) -> int:
    """Run the fuzz side once, as the fuzz job does."""
    return fp.main(
        [
            "fuzz",
            f"--root={root}",
            f"--source-root={root}",
            f"--python={python}",
            f"--harnesses={json.dumps([HARNESS])}",
            f"--state={state}",
            f"--output={output}",
            f"--commit={COMMIT}",
            "--fuzz-seconds=5",
            f"--restored-key={key}",
        ]
    )


def sarif(root: Path, handover: Path, output: Path) -> list[dict[str, object]]:
    """Run the SARIF side once, as the publish job does."""
    code = fp.main(
        [
            "sarif",
            f"--handover={handover}",
            f"--source-root={root}",
            f"--commit={COMMIT}",
            f"--harnesses={json.dumps([HARNESS])}",
            f"--output={output}",
        ]
    )
    assert code == 0
    log = cast("dict[str, list[dict[str, object]]]", json.loads(output.read_text()))
    return cast("list[dict[str, object]]", log["runs"][0]["results"])


def record(handover: Path) -> dict[str, object]:
    """Return a handover's run record."""
    return cast("dict[str, object]", json.loads((handover / "record.json").read_text()))


def harness_entry(handover: Path) -> dict[str, object]:
    """Return the record's one harness entry."""
    return cast("list[dict[str, object]]", record(handover)["harnesses"])[0]


def test_fuzz_replay_and_fix(tmp_path: Path) -> None:
    """A planted defect is found, replayed, then dropped once fixed."""
    python = interpreter()
    root = tmp_path / "repo"
    (root / "fuzz" / "seeds").mkdir(parents=True)
    (root / "pkg").mkdir()
    _ = (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    _ = (root / "pkg" / "parse.py").write_text(DEFECT, encoding="utf-8")
    _ = (root / HARNESS).write_text(HARNESS_SOURCE, encoding="utf-8")
    _ = (root / "fuzz" / "seeds" / "one").write_bytes(b"!ab")
    state = tmp_path / "state"
    key = "fuzz-state/org/repo/1-1"

    first = tmp_path / "first"
    assert fuzz(root, state, first, python, "") == 0
    assert record(first)["restored"] is False
    results = sarif(root, first, tmp_path / "first.sarif")
    print(json.dumps(results, indent=2))
    [result] = results
    assert result["ruleId"] == fc.UNCAUGHT
    assert cast("dict[str, str]", result["message"])["text"] == (
        f"Uncaught IndexError in parse, reached from fuzz harness {HARNESS}"
    )
    saved = list((state / fs.harness_key(HARNESS) / "failures").iterdir())
    assert len(saved) == 1

    second = tmp_path / "second"
    assert fuzz(root, state, second, python, key) == 0
    entry = harness_entry(second)
    print(json.dumps(entry, indent=2))
    assert record(second)["restored"] is True
    processes = cast("list[dict[str, object]]", entry["processes"])
    assert processes[0]["phase"] == "replay"
    assert processes[0]["exit_code"] != 0
    [again] = sarif(root, second, tmp_path / "second.sarif")
    assert again["message"] == result["message"]
    assert len(list((state / fs.harness_key(HARNESS) / "failures").iterdir())) == 1

    _ = (root / "pkg" / "parse.py").write_text(FIXED, encoding="utf-8")
    third = tmp_path / "third"
    assert fuzz(root, state, third, python, key) == 0
    entry = harness_entry(third)
    print(json.dumps(entry, indent=2))
    assert entry["fixed"] == 1
    processes = cast("list[dict[str, object]]", entry["processes"])
    assert processes[0]["fixed"] == [
        [fc.UNCAUGHT, "IndexError", "pkg/parse.py", "parse", "3"]
    ]
    assert list((state / fs.harness_key(HARNESS) / "failures").iterdir()) == []
    assert sarif(root, third, tmp_path / "third.sarif") == []
