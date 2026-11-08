<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# Findings ratchet

A composite action that compares the SARIF report of a pull request
head against the SARIF report of its merge base, and fails when the
head **adds** findings. A pull request that removes some findings,
or changes nothing, passes even when findings remain.

The organisation pull-request gates in this repository
(`.github/workflows/aislop.yaml` and `.github/workflows/zizmor.yaml`)
are its intended callers. They run in the target repository's checkout,
so they reach this action through a pinned reference:

```yaml
- name: 'Ratchet findings'
  # yamllint disable-line rule:line-length
  uses: lfreleng-actions/.github/actions/findings-ratchet@<commit-sha>
  with:
    head-sarif: ${{ steps.head.outputs['sarif-file'] }}
    base-sarif: ${{ steps.base.outputs['sarif-file'] }}
    head-root: ${{ github.workspace }}/head
    base-root: ${{ github.workspace }}/base
    tool: 'zizmor'
```

The action needs `python3` (3.11 or later) on `PATH`, as GitHub-hosted
Ubuntu runners provide. Its script, `findings_ratchet.py`, and the
`sarif_log.py` module beside it that reads and validates the reports,
need nothing beyond the standard library.

## Inputs

<!-- markdownlint-disable MD013 -->

| Input           | Required | Default                   | Description                                                                                                                   |
| --------------- | -------- | ------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `head-sarif`    | Yes      |                           | SARIF from the pull request head                                                                                              |
| `base-sarif`    | No       | `''`                      | SARIF from the merge base, scanned with identical settings and scope. Empty, missing or invalid selects absolute mode (below) |
| `head-root`     | No       | `''`                      | Absolute directory to strip from head artifact URIs                                                                           |
| `base-root`     | No       | `''`                      | Absolute directory to strip from base artifact URIs                                                                           |
| `tool`          | Yes      |                           | `aislop`, `zizmor` or `generic`: selects the subject normaliser                                                               |
| `mode`          | No       | `ratchet`                 | `ratchet` or `absolute`                                                                                                       |
| `levels`        | No       | `error,warning,note,none` | SARIF levels that count                                                                                                       |
| `exclude-rules` | No       | `''`                      | Comma-separated rule IDs never counted, on either side                                                                        |
| `annotate`      | No       | `true`                    | Emit one `::error file=…,line=…` annotation per new finding, or per head finding in absolute mode                             |

<!-- markdownlint-enable MD013 -->

A result with no `level` takes its rule's
`defaultConfiguration.level`, else `warning`, which is how
`zizmor.yaml` counts today.

Keep the `exclude-rules` list in the caller. For aislop, the coverage
notices `security/dependency-audit-skipped`, `dotnet/projects-skipped`
and `cppcheck/chunks-skipped` are the expected entries.

## Outputs

<!-- markdownlint-disable MD013 -->

| Output           | Description                                                 |
| ---------------- | ----------------------------------------------------------- |
| `verdict`        | `pass` or `fail`                                            |
| `effective-mode` | The mode applied: `ratchet`, or `absolute` after a fallback |
| `base-count`     | Counted findings in the base SARIF (empty in absolute mode) |
| `head-count`     | Counted findings in the head SARIF                          |
| `new-count`      | Findings the head adds (empty in absolute mode)             |
| `fixed-count`    | Findings the head removes (empty in absolute mode)          |

<!-- markdownlint-enable MD013 -->

Absolute mode has no base to compare with, so `base-count`,
`new-count` and `fixed-count` are empty there, whether the caller set
the mode or the action fell back to it; `head-count` holds the
findings it judges. When the head SARIF is missing or invalid,
`verdict` is `fail` and the four counts are empty.

## Matching

Neither aislop nor zizmor sets `fingerprints` or
`partialFingerprints`, and line numbers and message texts move between
the base and head scans. The action so **counts** findings per
key rather than matching them one to one. The key is
`(ruleId, path, subject)`:

- `ruleId` comes from the result's `ruleId`, else `rule.id`, else the
  driver rule at `ruleIndex` or `rule.index`.
- `path` is the first location's `artifactLocation.uri`, with
  `file://` removed, percent-escapes decoded and `/` separators,
  normalised with `posixpath.normpath` so `./a.py`, `src/./a.py` and
  `src//a.py` name the same files as `a.py` and `src/a.py`, then with
  the given root removed.
- `subject` depends on `tool`:
  - `aislop`, rule `security/vulnerable-dependency`: the package name,
    the message text up to the first space. `minimatch (moderate) —
    upgrade to …` gives `minimatch`, so a change in the suggested
    upgrade is not a different finding. A counted result of this rule
    must carry a literal `message.text` naming the package; the action
    refuses one that has a `message.id` and no text, or an empty text
    (below).
  - `zizmor`: empty. zizmor's symbolic route and fragment change with
    unrelated edits, so findings count per rule and file.
  - `generic`, and every other aislop rule: empty.

For each key, `new = max(0, head - base)` and
`fixed = max(0, base - head)`.

Counting decides the verdict. Annotations then need concrete head
findings: for a key with `new` above zero, the action reports first
the head findings whose line and message match no base finding.

## Verdict

- **ratchet** fails when the total `new` is above zero. A pull request
  with fewer findings passes, as does one with an unchanged set, such
  as a documentation edit in a file that already carries a finding.
- **absolute** fails when the head holds any counted finding. The base
  SARIF is not read.

### Fail closed

- In `ratchet` mode, an empty, missing or invalid `base-sarif`
  switches to absolute mode and says so in a `::warning::`.
- A missing or invalid `head-sarif` always fails, never passes.

A file is invalid when its content is not JSON, or not a SARIF log the
action can count without guessing:

- the top level is not an object holding a `runs` array of objects;
- a run has no `tool.driver` object, or no `results` array of objects;
- a run's `tool.driver.rules`, where present, is not an array of
  objects;
- a result's `level`, or a rule's `defaultConfiguration.level`, is
  present and not one of `error`, `warning`, `note` or `none`;
- a result's `locations` is present and not an array of objects, or a
  location's `physicalLocation` is present and not an object;
- an `artifactLocation` in a result's `locations` has no `uri`;
- the action cannot resolve a result's rule ID: `ruleId` or `rule.id`
  is present and not a non-empty string, `rule` is not an object, or
  none of them names a rule, as with an index to a driver rule with no
  `id`;
- a path normalises to one above the checkout, such as `../a.py`;
- with `tool: aislop`, a counted `security/vulnerable-dependency`
  result has no literal `message.text` naming a package, as with a
  `message.id` reference, so the action cannot tell packages apart;
- it uses a construct outside the supported subset (below).

A result whose `locations` is absent or empty, or whose location has
no `physicalLocation`, is valid and counts with an empty path.

### Supported SARIF subset

The action serves the SARIF that aislop and zizmor (auditor persona)
emit, and reads the subset they use and nothing more: a file named by
`physicalLocation.artifactLocation.uri`, and a rule named by `ruleId`,
`rule.id` or an index into `tool.driver.rules`. It refuses the
constructs below **on purpose**, with an `unsupported SARIF construct`
error, rather than resolve them: neither producer emits them, and each
resolver would be more code that can be wrong in a gate that must fail
closed.

- `artifactLocation.uriBaseId`, and a run's `originalUriBaseIds`;
- `artifactLocation.index`, which names an entry of the run's
  `artifacts` table;
- `run.tool.extensions`, and `rule.toolComponent`;
- a `ruleIndex` or `rule.index` that is not an index into
  `tool.driver.rules`.

A refused head fails; a refused base switches to absolute mode with a
warning, as any other invalid file does. Supporting another producer
means emitting this subset, not adding resolvers here.

## Reporting

In ratchet mode, the step summary holds one table of keys with base,
head, new and fixed counts, new findings first, each new finding with
its head location and message. Annotations cover new findings alone,
as `New finding <rule>: <message>`.

Absolute mode compares nothing, so it reports no finding as new. The
step summary says `Absolute mode: no base comparison`, with the reason
after a fallback, and its table has the columns `Rule`, `Path`,
`Subject`, `Head` and `Findings`, listing every head finding. The log's
result line gives the head count alone, plus any fallback reason, and
annotations read `Finding <rule>: <message>`. A fallback states its
reason once, in its `::warning::`, not on each annotation.

The job log prints the same table as the step summary between
`::stop-commands::` markers, so tool text there cannot run a workflow
command. Annotations escape `%`, `\r` and `\n` in their data as
`aislop.yaml`'s `wf_escape` does, plus `:` and `,` in their
properties.

Exit codes: `0` pass, `1` fail, `2` usage error (an unknown `tool`,
`mode`, `annotate` value or level).

## Tests

`tests/test_findings_ratchet.py` runs the script against small
hand-written SARIF fixtures. From the repository root:

```bash
uv sync
uv run pytest -q actions/findings-ratchet/tests
```

`.github/workflows/findings-ratchet.yaml` runs the suite, and
`basedpyright` over this directory, on every change to it.
