# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Pin the trust boundary of the fuzz publisher's workflows.

The fuzz job executes the repository it fuzzes, so it must hold
nothing; the jobs that hold the upload token must execute nothing from
the target checkout or the handover; and publish must take its results
by the artifact ID its own fuzz job reported. A small reader for the
YAML subset these workflows use keeps the suite free of third-party
imports, so the pre-commit type checkers resolve it without a test
environment.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import cast

WORKFLOWS = Path(__file__).resolve().parents[2] / "workflows"
CALLER = WORKFLOWS / "fuzz-sarif-publish.yaml"
REPOSITORY = WORKFLOWS / "fuzz-sarif-repository.yaml"
PINNED = re.compile(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}")
TOOLS = ".fuzz-tools/.github/scripts/"
Node = dict[str, object]


def parse(text: str) -> Node:
    """Return the mapping a workflow file holds.

    Handles block mappings and sequences, block scalars and quoted or
    plain scalars, which is all these workflows use.
    """
    lines = [line for line in text.splitlines() if line.strip() != "---"]
    value, _ = block(lines, 0, 0)
    return cast("Node", value)


def indent_of(line: str) -> int:
    """Return a line's indentation."""
    return len(line) - len(line.lstrip(" "))


def skip(lines: list[str], index: int) -> int:
    """Return the next line that is neither blank nor a comment."""
    while index < len(lines) and (
        not lines[index].strip() or lines[index].lstrip().startswith("#")
    ):
        index += 1
    return index


def scalar(text: str) -> object:
    """Return a plain or quoted scalar without a trailing comment."""
    text = text.strip()
    if text[:1] in {"'", '"'}:
        return text[1 : text.rindex(text[0])]
    text = re.sub(r"\s+#.*$", "", text)
    return {} if text == "{}" else text


def block(lines: list[str], index: int, indent: int) -> tuple[object, int]:
    """Parse the mapping or sequence starting at lines[index]."""
    index = skip(lines, index)
    if index < len(lines) and lines[index].lstrip().startswith("- "):
        items: list[object] = []
        while index < len(lines) and indent_of(lines[index]) == indent:
            line = lines[index]
            if not line.lstrip().startswith("- "):
                break
            lines[index] = " " * (indent + 2) + line.lstrip()[2:]
            if ":" in lines[index] and lines[index].lstrip()[:1] not in {"'", '"'}:
                item, index = block(lines, index, indent + 2)
            else:
                item, index = scalar(lines[index]), index + 1
            items.append(item)
            index = skip(lines, index)
        return items, index
    mapping: Node = {}
    while index < len(lines) and indent_of(lines[index]) == indent:
        key, _, rest = lines[index].strip().partition(":")
        rest = rest.strip()
        index += 1
        if rest[:1] in {"|", ">"}:
            body: list[str] = []
            while index < len(lines) and (
                not lines[index].strip() or indent_of(lines[index]) > indent
            ):
                body.append(lines[index].strip())
                index += 1
            mapping[key.strip("'\"")] = "\n".join(body).strip()
        elif rest and not rest.startswith("#"):
            mapping[key.strip("'\"")] = scalar(rest)
        else:
            following = skip(lines, index)
            if following < len(lines) and indent_of(lines[following]) > indent:
                child = indent_of(lines[following])
                mapping[key.strip("'\"")], index = block(lines, following, child)
            else:
                mapping[key.strip("'\"")] = None
        index = skip(lines, index)
    return mapping, index


def jobs(path: Path) -> dict[str, Node]:
    """Return a workflow's jobs."""
    workflow = parse(path.read_text(encoding="utf-8"))
    return cast("dict[str, Node]", workflow["jobs"])


def steps(job: Node) -> list[Node]:
    """Return a job's steps."""
    return cast("list[Node]", job.get("steps") or [])


def text(value: object) -> str:
    """Return every string a parsed node holds, joined."""
    if isinstance(value, dict):
        return "\n".join(
            f"{key}\n{text(item)}" for key, item in cast("Node", value).items()
        )
    if isinstance(value, list):
        return "\n".join(text(item) for item in cast("list[object]", value))
    return str(value)


def holds_secret(job: Node) -> bool:
    """Return whether a job references a secret or passes one on."""
    return "secrets." in text(job) or "secrets" in job


def test_reader_sees_every_job() -> None:
    """The reader finds the jobs and steps each workflow declares."""
    assert set(jobs(CALLER)) == {
        "discover",
        "select",
        "repository",
        "summarise",
        "notify-failure",
    }
    repository = jobs(REPOSITORY)
    assert set(repository) == {"restore", "fuzz", "publish"}
    assert len(steps(repository["fuzz"])) > 5


def test_fuzz_job_holds_nothing() -> None:
    """The job that runs harnesses has no secret, environment or write."""
    fuzz = jobs(REPOSITORY)["fuzz"]
    assert "secrets" not in text(fuzz)
    assert "environment" not in fuzz
    assert fuzz["permissions"] == {"contents": "read"}
    checkouts = [
        cast("Node", step["with"])
        for step in steps(fuzz)
        if str(step.get("uses", "")).startswith("actions/checkout@")
    ]
    assert checkouts
    assert all(item["persist-credentials"] == "false" for item in checkouts)
    for path in ("target", "source"):
        found = [item for item in checkouts if item.get("path") == path]
        assert [item["ref"] for item in found] == ["${{ inputs.commit }}"], path
    assert "--source-root=${GITHUB_WORKSPACE}/source" in text(fuzz)
    assert all("token" not in item for item in checkouts)


def test_only_the_fuzz_job_runs_harnesses() -> None:
    """Only the fuzz job installs the repository or invokes the fuzz side."""
    for path in (CALLER, REPOSITORY):
        for name, job in jobs(path).items():
            body = text(job)
            runs_code = "uv sync" in body or re.search(r"\bfuzz \\", body)
            assert bool(runs_code) == (path == REPOSITORY and name == "fuzz"), name


def test_jobs_holding_a_secret_execute_nothing_from_the_target() -> None:
    """Steps in a job with a secret run only pinned actions and tool scripts."""
    checked = 0
    for path in (CALLER, REPOSITORY):
        for name, job in jobs(path).items():
            if not holds_secret(job):
                continue
            if "uses" in job:
                # A reusable call: its own jobs are checked where defined.
                assert str(job["uses"]).startswith("$/.github/workflows/"), name
                continue
            checked += 1
            for step in steps(job):
                uses = str(step.get("uses", ""))
                assert not uses or PINNED.fullmatch(uses), (name, uses)
                assert "working-directory" not in step, name
                script = str(step.get("run", ""))
                env = cast("dict[str, str]", step.get("env") or {})
                for line in script.splitlines():
                    assert not re.match(r"(source|\.|bash|sh|eval)\s", line), line
                    assert not re.search(r"(^|\s)\./|target/|fuzz-handover/", line), (
                        line
                    )
                    if "${PYTHON}" in line:
                        assert line.startswith('"${PYTHON}" -I "${SCRIPT}"'), line
                        assert env["SCRIPT"].startswith(TOOLS), env
                for value in env.values():
                    assert "target" not in value, (name, value)
                for value in cast("dict[str, str]", step.get("with") or {}).values():
                    assert "python-version-file" not in str(value)
    assert checked >= 3


def test_target_and_handover_are_only_ever_arguments() -> None:
    """The publish job names the checkout and handover only as data paths."""
    publish = jobs(REPOSITORY)["publish"]
    for step in steps(publish):
        for line in str(step.get("run", "")).splitlines():
            for place in ("/target", "/fuzz-handover"):
                if place in line:
                    assert re.fullmatch(
                        r'\s*"--[\w-]+=\$\{\w+\}/[\w-]+"( \\)?', line
                    ), line


def test_publish_takes_results_by_its_own_fuzz_jobs_artifact_id() -> None:
    """Rule 3: publish downloads by the ID in its own fuzz job's outputs."""
    repository = jobs(REPOSITORY)
    fuzz = repository["fuzz"]
    publish = repository["publish"]
    outputs = cast("dict[str, str]", fuzz["outputs"])
    assert outputs["artifact-id"] == "${{ steps.upload.outputs.artifact-id }}"
    [upload] = [step for step in steps(fuzz) if step.get("id") == "upload"]
    assert str(upload["uses"]).startswith("actions/upload-artifact@")
    assert publish["needs"] == "fuzz"
    downloads = [
        step
        for step in steps(publish)
        if str(step.get("uses", "")).startswith("actions/download-artifact@")
    ]
    assert len(downloads) == 1
    options = cast("dict[str, str]", downloads[0]["with"])
    assert options["artifact-ids"] == "${{ needs.fuzz.outputs.artifact-id }}"
    assert "name" not in options
    assert "pattern" not in options
    check = [step for step in steps(publish) if "ARTIFACT_ID" in text(step)]
    assert check
    assert steps(publish).index(check[0]) < steps(publish).index(downloads[0])
    caller = jobs(CALLER)["repository"]
    assert caller["uses"] == "$/.github/workflows/fuzz-sarif-repository.yaml"
    assert "matrix" in cast("Node", caller["strategy"])


def test_schedule_inputs_secret_and_variables() -> None:
    """The caller has the schedule, inputs, secret and variables the issue sets."""
    workflow = parse(CALLER.read_text(encoding="utf-8"))
    on = cast("Node", workflow["on"])
    assert cast("list[Node]", on["schedule"]) == [{"cron": "0 8 * * *"}]
    inputs = cast("Node", cast("Node", on["workflow_dispatch"])["inputs"])
    assert set(inputs) == {"org", "repo", "fuzz_seconds", "dry_run"}
    body = CALLER.read_text(encoding="utf-8")
    assert "inputs.token" not in body
    for name in ("FUZZ_SARIF_PAT", "FUZZ_SCAN_INCLUDE", "FUZZ_SCAN_EXCLUDE"):
        assert name in body
    concurrency = cast("Node", workflow["concurrency"])
    assert concurrency == {
        "group": "fuzz-sarif-publish",
        "cancel-in-progress": "false",
    }


def test_fuzz_job_fails_unless_the_cache_holds_its_state() -> None:
    """The save is looked up by its exact key, which must hit, before publish."""
    fuzz = steps(jobs(REPOSITORY)["fuzz"])
    [save] = [
        s for s in fuzz if str(s.get("uses", "")).startswith("actions/cache/save@")
    ]
    after = fuzz[fuzz.index(save) + 1 :]
    [verify] = [
        s for s in after if str(s.get("uses", "")).startswith("actions/cache/restore@")
    ]
    options = cast("Node", verify["with"])
    assert options["key"] == cast("Node", save["with"])["key"]
    assert options["lookup-only"] == "true"
    assert options["fail-on-cache-miss"] == "true"
    assert "restore-keys" not in options
    assert verify.get("if") == save.get("if")


def test_publication_is_recorded_after_the_upload_for_the_next_run() -> None:
    """The record saved after a processed upload is the one the fuzz job finds."""
    repository = jobs(REPOSITORY)
    fuzz = repository["fuzz"]
    publish = steps(repository["publish"])
    outputs = cast("dict[str, str]", fuzz["outputs"])
    assert outputs["state-key"] == "${{ steps.restore.outputs.state-key }}"
    [upload] = [s for s in publish if s.get("name") == "Publish SARIF to code scanning"]
    [record] = [
        s
        for s in publish
        if str(s.get("uses", "")).startswith("actions/cache/save@")
        and "fuzz-published/" in text(s)
    ]
    assert publish.index(upload) < publish.index(record)
    assert record.get("if") == upload.get("if")
    saved_with = cast("Node", record["with"])
    [lookup] = [s for s in steps(fuzz) if s.get("id") == "published"]
    found_with = cast("Node", lookup["with"])
    assert lookup.get("if") == "steps.restore.outputs.matched-key != ''"
    assert found_with["path"] == saved_with["path"]
    assert found_with["lookup-only"] == "true"
    assert "restore-keys" not in found_with
    prefix = "${{ format('fuzz-published/{0}', "
    assert found_with["key"] == prefix + "steps.restore.outputs.matched-key) }}"
    assert saved_with["key"] == prefix + "needs.fuzz.outputs.state-key) }}"
    assert "--published=${PUBLISHED}" in text(fuzz)


def test_withheld_upload_fails_the_publish_job_after_its_summary() -> None:
    """An upload the evidence check withholds fails the job, so Slack hears of it."""
    publish = steps(jobs(REPOSITORY)["publish"])
    [upload] = [s for s in publish if s.get("id") == "publish"]
    [summary] = [s for s in publish if s.get("name") == "Summarise this repository"]
    [fail] = [s for s in publish if s.get("name") == "Fail a withheld upload"]
    assert upload.get("if") == (
        "${{ !inputs.dry_run && steps.evidence.outputs.skip != 'true' }}"
    )
    assert fail.get("if") == (
        "${{ !inputs.dry_run && steps.evidence.outputs.skip == 'true' }}"
    )
    assert "exit 1" in str(fail["run"])
    assert publish.index(summary) < publish.index(fail)


def test_evidence_binding_is_signed_after_the_upload_and_handed_over() -> None:
    """The publish job signs and saves the binding; only the restore job restores it."""
    repository = jobs(REPOSITORY)
    fuzz = steps(repository["fuzz"])
    restored = steps(repository["restore"])
    publish = steps(repository["publish"])
    [upload] = [s for s in publish if s.get("id") == "publish"]
    [evidence] = [s for s in publish if s.get("id") == "evidence"]
    key = "${{ secrets.evidence_key }}"
    assert cast("Node", evidence["env"])["FUZZ_EVIDENCE_KEY"] == key
    assert "evidence \\" in str(evidence["run"])
    [bind] = [s for s in publish if "bind \\" in str(s.get("run", ""))]
    assert cast("Node", bind["env"])["FUZZ_EVIDENCE_KEY"] == key
    [save] = [
        s
        for s in publish
        if str(s.get("uses", "")).startswith("actions/cache/save@")
        and "fuzz-evidence/" in text(s)
    ]
    order = [publish.index(step) for step in (evidence, upload, bind, save)]
    assert order == sorted(order)
    assert bind.get("if") == save.get("if") == upload.get("if")
    assert "steps.publish.outputs.sarif-id" in text(save)
    [restore] = [s for s in restored if s.get("name") == "Restore the evidence binding"]
    options = cast("Node", restore["with"])
    assert options["path"] == cast("Node", save["with"])["path"]
    prefix = "fuzz-evidence/${{ inputs.org }}/${{ inputs.repo }}/"
    assert options["restore-keys"] == prefix
    binding = "--binding=${RUNNER_TEMP}/fuzz-restored/fuzz-evidence/binding.json"
    assert binding in text(fuzz)
    caller = cast("Node", jobs(CALLER)["repository"]["secrets"])
    assert caller["evidence_key"] == "${{ secrets.FUZZ_EVIDENCE_KEY }}"


def test_cache_archives_are_extracted_only_in_the_restore_job() -> None:
    """A forged archive lands in a job that holds and runs nothing after it.

    The cache action extracts an archive wherever its members point, so
    every other job only looks keys up, and the fuzz job takes what was
    restored as an artifact, by the ID the restore job reported.
    """
    repository = jobs(REPOSITORY)
    restore = repository["restore"]
    for name, job in repository.items():
        if name == "restore":
            continue
        for step in steps(job):
            if str(step.get("uses", "")).startswith("actions/cache/restore@"):
                assert cast("Node", step["with"])["lookup-only"] == "true", name
    assert not holds_secret(restore)
    assert "environment" not in restore
    assert restore["permissions"] == {"contents": "read"}
    assert all("run" not in step for step in steps(restore))
    uses = [str(step.get("uses", "")) for step in steps(restore)]
    assert not [item for item in uses if item.startswith("actions/checkout@")]
    assert uses[-1].startswith("actions/upload-artifact@")
    restored = [
        step
        for step in steps(restore)
        if str(step.get("uses", "")).startswith("actions/cache/restore@")
    ]
    extracted = [cast("Node", step["with"])["path"] for step in restored]
    assert extracted == [
        "${{ runner.temp }}/fuzz-state",
        "${{ runner.temp }}/fuzz-evidence",
    ]
    fuzz = repository["fuzz"]
    assert fuzz["needs"] == "restore"
    [save] = [
        step
        for step in steps(fuzz)
        if str(step.get("uses", "")).startswith("actions/cache/save@")
    ]
    saved = cast("Node", save["with"])
    assert saved["path"] == extracted[0]
    assert saved["key"] == "${{ steps.restore.outputs.state-key }}"
    [check] = [step for step in steps(fuzz) if step.get("id") == "restore"]
    env = cast("dict[str, str]", check["env"])
    assert env["ARTIFACT_ID"] == "${{ needs.restore.outputs.artifact-id }}"
    assert env["PREFIX"] + env["RUN"] == cast("Node", restored[0]["with"])["key"]
    [download] = [
        step
        for step in steps(fuzz)
        if str(step.get("uses", "")).startswith("actions/download-artifact@")
    ]
    options = cast("dict[str, str]", download["with"])
    assert options["artifact-ids"] == "${{ steps.restore.outputs.artifact-id }}"
    assert "name" not in options
    assert "pattern" not in options
    assert steps(fuzz).index(check) < steps(fuzz).index(download)


def test_restored_artifact_extracts_where_the_fuzz_job_reads_it() -> None:
    """The restored state and binding land at the paths the fuzz job reads.

    Two upload paths make their common parent the artifact's root, so
    it holds fuzz-state/ and fuzz-evidence/; merge-multiple extracts
    that root into the download path with no artifact-name directory.
    """
    repository = jobs(REPOSITORY)
    [upload] = [s for s in steps(repository["restore"]) if s.get("id") == "upload"]
    uploaded = str(cast("Node", upload["with"])["path"]).splitlines()
    assert uploaded == [
        "${{ runner.temp }}/fuzz-state/",
        "${{ runner.temp }}/fuzz-evidence/",
    ]
    fuzz = steps(repository["fuzz"])
    [download] = [
        s
        for s in fuzz
        if str(s.get("uses", "")).startswith("actions/download-artifact@")
    ]
    options = cast("Node", download["with"])
    assert options["path"] == "${{ runner.temp }}/fuzz-restored"
    assert options["merge-multiple"] == "true"
    body = text(fuzz)
    assert 'restored="${RUNNER_TEMP}/fuzz-restored/fuzz-state"' in body
    assert "--binding=${RUNNER_TEMP}/fuzz-restored/fuzz-evidence/binding.json" in body
