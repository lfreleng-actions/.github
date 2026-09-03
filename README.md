<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# .github — Organisation-Wide Configuration

This repository contains shared configuration and community health files
for the [lfreleng-actions](https://github.com/lfreleng-actions) GitHub
organisation (Linux Foundation Release Engineering).

Files placed here are automatically inherited by all repositories in the
organisation unless overridden at the repository level.

## Contents

### Contributor Guidance

- **[`AGENTS.md`](AGENTS.md)** — The default guidance document for AI
  coding agents working on any repository in the organisation. Covers
  commit format, signing and DCO, pre-commit hooks, testing gates, and
  pull request review cycles. It binds every contribution, including
  those from third parties and the agents acting on their behalf.
  Individual repositories are to carry a thin `AGENTS.md` stub that links
  back here and may impose further requirements; no local file can relax
  the rules here. Unlike the community health files below, GitHub does
  not inject `AGENTS.md` into other repositories' checkouts, so the
  organisation distributes it through that stub, whose shape §12
  defines. Rolling the stub out across the organisation is follow-up
  work; until it lands, the rules bind regardless of whether a given
  agent loaded the file.
- **[`scripts/agents/`](scripts/agents/)** — Reference implementations
  of the three `AGENTS.md` rules that are contracts with exit
  semantics: the AI-slop gate (`aislop-gate.sh`), the Change-Id
  preserving Gerrit amend (`gerrit-amend.sh`), and review-thread
  resolution (`resolve-review-thread.sh`). Each has a pytest suite
  under `scripts/agents/tests/` covering the false-pass cases review
  has found; the tests define what "correct" means, and agents in
  other repositories may run, vendor or reimplement the scripts against
  them. `agent-scripts.yaml` runs the suite on every change.

### Organisation Profile

- **[`profile/README.md`](profile/README.md)** — The public-facing
  organisation profile displayed at
  [github.com/lfreleng-actions](https://github.com/lfreleng-actions).
  Contains a categorised directory of all actions, tools, and test
  fixtures in the organisation.

### Shared Configuration

- **[`release-drafter.yml`](release-drafter.yml)** — Organisation-wide
  [release-drafter](https://github.com/release-drafter/release-drafter)
  configuration. Provides default categories, autolabeler rules (mapping
  Conventional Commits prefixes to labels), and version-resolver settings.
  Any repository without its own `.github/release-drafter.yml` inherits
  this configuration automatically.
- **[`.github/harden-runner/`](.github/harden-runner/)** — Shared
  [harden-runner](https://github.com/step-security/harden-runner) egress
  allow-lists. Organisation workflows run harden-runner in `block` mode
  and load
  [`allow_list.txt`](.github/harden-runner/lfreleng-actions/allow_list.txt)
  at runtime, so harden-runner denies any host the list omits. See
  [Harden-runner egress allow-list](#harden-runner-egress-allow-list)
  below for the wildcard matching rules, which are easy to get wrong.

### Workflows

- **[`allow-list-bump.yaml`](.github/workflows/allow-list-bump.yaml)** —
  A scheduled (Monday 05:00 UTC) sweep that bumps stale
  `step-security/harden-runner` egress allow-list pins across the
  `*-workflows` family and opens a pull request per repository, authored
  by the organisation's bot. These pins are values of `config:` and
  `default:` keys rather than `uses:` references, so Dependabot cannot
  see them and they drift. See
  [Allow-list bump sweep](#allow-list-bump-sweep) below for setup.
- **[`repo-audit.yaml`](.github/workflows/repo-audit.yaml)** — Runs on
  a weekly schedule (Monday 10:00 UTC). Compares the current list of
  repositories in the organisation against the profile README and sends a
  Slack notification to `#releng-scm` when it finds new repositories
  that lack documentation or an explicit exclusion entry.
- **[`zizmor.yaml`](.github/workflows/zizmor.yaml)** — Organisation-wide
  static security audit of GitHub Actions workflows and composite actions
  using [zizmor](https://docs.zizmor.sh/). Runs on every pull request
  and push, uploads results to GitHub code scanning as SARIF on pushes
  to the default branch after merge, and runs in **advisory mode**
  (does not block merges), and the workflow runs across the
  organisation as a *required workflow* via an organisation ruleset;
  see [Organisation-wide zizmor audit](#organisation-wide-zizmor-audit)
  below for the one-time org-admin configuration.
- **[`zizmor-sarif-publish.yaml`](.github/workflows/zizmor-sarif-publish.yaml)**
  — A scheduled (weekday) workflow that publishes zizmor findings to each
  in-scope repository's **default-branch** code scanning. The ruleset-driven
  `zizmor.yaml` runs on pull requests, so it never populates the
  default-branch alert list; this workflow closes that gap so downstream
  reporting reflects reality. See
  [Organisation-wide zizmor SARIF publisher](#organisation-wide-zizmor-sarif-publisher)
  below for setup.
- **[`aislop.yaml`](.github/workflows/aislop.yaml)** — Organisation-wide
  AI-slop / code-quality scan of pull request changes using
  [aislop](https://github.com/scanaislop/aislop). Runs on every pull
  request across the organisation as a *required workflow* via an
  organisation ruleset, scans **the files the PR changes** (not the
  whole repository), and **blocks** a pull request whose changed files
  carry any finding, at any severity. The `AISLOP_GATE_LEVEL`
  organisation or repository variable relaxes or tightens that; see
  [Organisation-wide aislop scan](#organisation-wide-aislop-scan) below
  for the one-time org-admin configuration.
- **[`aislop-sarif-publish.yaml`](.github/workflows/aislop-sarif-publish.yaml)**
  — A scheduled (daily) workflow that runs a **full-repository** aislop
  scan against each in-scope repository, publishes the findings to its
  **default-branch** code scanning as SARIF, and renders a ranked
  organisation-wide score table so the repositories needing the most
  attention are easy to spot. See
  [Organisation-wide aislop SARIF publisher](#organisation-wide-aislop-sarif-publisher)
  below for setup.
- **[`agent-scripts.yaml`](.github/workflows/agent-scripts.yaml)** —
  Runs the contract tests for the `AGENTS.md` reference scripts under
  `scripts/agents/` on every pull request that touches them.

### Repository Exclusions

- **`excluded-repos.json`** — A JSON file listing repository names to
  exclude from the weekly audit. This covers forks of upstream
  actions, placeholder/template repositories not yet developed, and backup
  directories that are not real repositories.

## How It Works

### Release Drafter Inheritance

When a repository in the `lfreleng-actions` organisation runs the
`release-drafter/release-drafter` action and does **not** have its own
`.github/release-drafter.yml`, GitHub automatically falls back to the
configuration in this repository. The shared configuration uses the
`$OWNER/$REPOSITORY` template variables so that release notes, download
badges, and issue links resolve to the correct URLs for any inheriting
repository.

Repositories that need custom categories or version-resolver rules can
override the defaults by adding their own `.github/release-drafter.yml`.

### Harden-runner egress allow-list

Organisation workflows run
[harden-runner](https://github.com/step-security/harden-runner) under
`egress-policy: block`, which denies every outbound connection the
policy does not name. The permitted endpoints live in
[`.github/harden-runner/lfreleng-actions/allow_list.txt`](.github/harden-runner/lfreleng-actions/allow_list.txt),
loaded at runtime by
[harden-runner-block-action](https://github.com/lfreleng-actions/harden-runner-block-action).
The [directory README](.github/harden-runner/README.md) covers the file
format and layout.

#### Wildcard matching covers one label

A `*.host` entry matches a single label. It does not match a nested
subdomain, and it does not match the bare apex. harden-runner documents
neither case, so a controlled probe under `egress-policy: block`
established the behaviour. A policy carrying `*.ubuntu.com` and no
other `ubuntu.com` entry gave:

| Target | Labels below apex | Result |
| --- | --- | --- |
| `archive.ubuntu.com` | 1 | allowed |
| `azure.archive.ubuntu.com` | 2 | **blocked** |
| `ubuntu.com` | 0 (apex) | **blocked** |

A second run adding `azure.archive.ubuntu.com` explicitly admitted that
host moments later, so a mirror outage does not account for the
difference. Note that `egress-policy: audit` cannot answer this
question, because audit mode never enforces `allowed-endpoints`.

Two consequences when editing the allow-list:

- A host two or more labels below its apex needs its own entry
  **alongside** the wildcard. Deleting such an entry as "redundant"
  breaks the workflows that reach it.
- An apex host needs its own entry as well, which is why
  `sonarcloud.io:443` sits beside `*.sonarcloud.io:443`.

#### Distribution package mirrors

One gap no allow-list can close: Fedora, EPEL, CentOS Stream, Rocky,
AlmaLinux, openSUSE and Arch ship repository configuration that resolves
a metalink or mirrorlist, then downloads from whichever third-party
mirror it returns. Those mirrors share no parent domain and change by
source IP and by the hour, so a vendor wildcard admits the mirror list
and then the next connection fails.

Pin the repository `baseurl` to the vendor-owned HTTPS host and clear
`metalink`/`mirrorlist` in the job instead. The allow-list header names
the host to use for each distribution.

### Organisation-wide zizmor audit

The `zizmor.yaml` workflow performs static security analysis of GitHub
Actions workflows and composite actions across every repository in the
organisation. It uses [zizmor](https://docs.zizmor.sh/), which detects
common security defects including template-injection vulnerabilities,
credential persistence (`artipacked`), excessive permission scopes,
dangerous triggers (`pull_request_target`), unpinned `uses:` references,
and more.

#### Mode of operation

- **Output**: SARIF, uploaded to GitHub code scanning on pushes to
  the default branch (i.e. after merge). PR runs skip
  the SARIF upload: fork PRs cannot perform the upload because
  `GITHUB_TOKEN` lacks `security-events: write` there, and uploading
  on PRs would publish unreviewed findings before reviewers approve
  the change. Findings appear in each repository's **Security → Code
  scanning** tab once the change lands on the default branch.
- **Severity floor**: `low` (the workflow reports findings down to the
  low tier; the informational and unknown tiers stay out to limit
  noise).
- **Persona**: `auditor` (the broadest persona; it runs the extra audit
  types on top of the default high-signal set).
- **Advisory**: zizmor exits `0` when emitting SARIF, so the workflow
  always reports success in the PR checks UI. Merge-blocking remains
  **disabled** at the workflow level on purpose. After the team
  triages the pre-existing finding backlog across the organisation, an
  org-level **code-scanning ruleset** can switch selected findings to
  merge-blocking (see *Promoting findings to merge-blocking* below).

#### One-time org-admin setup

Unlike `release-drafter.yml` (which GitHub auto-inherits from the
`.github` repository), workflow files in `.github/workflows/` are
**not** automatically run for other repositories. To execute
`zizmor.yaml` against every repository in the organisation without
copying it into each repo, configure it as a *required workflow* via
an organisation ruleset:

1. Go to **Organisation settings** → [**Repository →
   Rulesets**][org-rulesets] (you must be an organisation owner).
2. Click **New ruleset** → **New branch ruleset**.
3. Set:
   - **Ruleset name**: `zizmor security audit`
   - **Enforcement status**: `Active`
   - **Bypass list**: leave empty
   - **Target repositories**: `All repositories` (or use *Dynamic list
     of repositories* with property filters to limit scope; the
     initial rollout should target *All repositories*).
   - **Target branches**: `Default branch` (and `master` if you have
     repositories still using that name; or use `Include by pattern`
     with `main` and `master`).
4. Under **Rules**, enable **Require workflows to pass before merging**
   and click **Add workflow**:
   - **Repository**: `lfreleng-actions/.github`
   - **Workflow file path**: `.github/workflows/zizmor.yaml`
   - **Ref**: `main`
5. For the initial advisory rollout, leave **Do not require
   workflows to pass before merging** *checked* so the workflow runs
   without blocking merges (advisory mode is also reinforced by the
   SARIF output, which causes zizmor to exit 0). Later, after the
   team clears the backlog, uncheck this option to make the workflow
   required before merging.
6. Click **Create**.

[org-rulesets]: https://github.com/organizations/lfreleng-actions/settings/rules

After saving, every pull request opened in the organisation will
trigger a `zizmor` run sourced from `lfreleng-actions/.github`. The
checks appear in PRs as
`🌈 Zizmor Scan / Audit workflows`,
and findings populate the target repository's **Security → Code
scanning** tab once the change lands on the default branch.

#### Updating zizmor

The audit logic and the pinned zizmor version both live in the
[`zizmor-scan-action`](https://github.com/lfreleng-actions/zizmor-scan-action)
composite action. `zizmor.yaml` pins that action by commit SHA, and the
action reads its `zizmor==<version>` pin from its own bundled
`pyproject.toml` at run time, so this workflow embeds no version string.

The action's own repository owns the zizmor version. Dependabot's `uv`
ecosystem opens a weekly PR there; merging it cuts a new action
release. [Dependabot](.github/dependabot.yml) in this repository then
bumps the pinned action ref under its `github-actions` ecosystem
(`CI(actions): Bump lfreleng-actions/zizmor-scan-action ...`). After
that PR merges, every audited repository picks up the new version on
its next run. A 7-day cooldown blocks churn on releases that upstream
retracts or supersedes within days.

To upgrade manually, bump the pinned action ref in
[`.github/workflows/zizmor.yaml`](.github/workflows/zizmor.yaml) and
merge a PR through the normal review process.

#### Promoting findings to merge-blocking

After the team triages the existing backlog of findings across the
organisation (auto-fixed via `zizmor --fix`, suppressed via inline
`# zizmor: ignore[rule]` comments, or addressed in a per-repo
`zizmor.yml` configuration), a **code-scanning ruleset** can promote
individual rules — or all rules at a chosen severity — to
merge-blocking:

1. Organisation settings → Repository → Rulesets → New ruleset →
   *New code scanning ruleset*.
2. Add `zizmor` (the SARIF *category*) as a tool, set the alert
   threshold to `error` (or the desired severity), and target the
   default branch.

Until an org admin completes that step, `zizmor` operates purely as a
reporting tool.

### Organisation-wide zizmor SARIF publisher

The `zizmor.yaml` audit runs on `pull_request` events (delivered by an
organisation ruleset) and never uploads SARIF to a repository's
**default-branch** code scanning — organisation rulesets do not deliver a
post-merge `push` event to the target repositories. As a result, each
repository's default-branch **Security → Code scanning** alert list stays
empty even when its workflows contain zizmor findings, and anything built
on that data (e.g. `github-security-report-action`) under-reports zizmor
accordingly.

The `zizmor-sarif-publish.yaml` workflow closes that gap. On a weekday
schedule (`0 6 * * 1-5`, 06:00 UTC) it:

1. Enumerates the in-scope repositories for the target organisation
   (via the shared
   [`repo-discovery.yaml`](.github/workflows/repo-discovery.yaml)
   reusable workflow).
2. Applies the [repository scope policy](#repository-scope-policy) from
   [`.github/scan-scope.json`](.github/scan-scope.json) — the
   per-organisation scan toggles and `include`/`exclude` globs, plus any
   patterns from the `ZIZMOR_SCAN_INCLUDE` / `ZIZMOR_SCAN_EXCLUDE`
   variables.
3. Checks out each repository at its default branch, runs
   [`zizmor-scan-action`](https://github.com/lfreleng-actions/zizmor-scan-action),
   and uploads the SARIF to that repository's code scanning via
   `POST /code-scanning/sarifs` against the **default-branch HEAD** (so
   results land in the default-branch alert list, not a PR-scoped
   analysis).

A final job renders the organisation posture summary to the run's step
summary. When a **scheduled** run fails or a maintainer cancels it, the
workflow posts a Slack alert to `#releng-scm` (reusing the
`SLACK_BOT_TOKEN` secret and `SLACK_CHANNEL_ID` variable documented
under [Slack Setup](#slack-setup)), so a silent daily breakage never
slips past the team. Manual `workflow_dispatch` runs stay quiet, since
a maintainer already watches those.

#### Required secret

Writing code-scanning results to *other* repositories is beyond what the
default `GITHUB_TOKEN` can do, so the workflow needs a dedicated PAT in
the **`ZIZMOR_SARIF_PAT`** repository secret. A **classic PAT** needs the
scopes:

| Scope             | For                                       |
| ----------------- | ----------------------------------------- |
| `repo`            | check out repositories (incl. private)    |
| `read:org`        | list organisation repositories            |
| `security_events` | upload SARIF / write code-scanning alerts |

A fine-grained PAT scoped to the organisation works too: Contents read,
Metadata read, and Code scanning alerts **write**.

#### Manual dispatch inputs

**Run workflow** also triggers the workflow on demand, with three
optional inputs (all blank by default):

- **`org`** — scan a different organisation. When blank, the workflow
  targets the organisation it runs in (`github.repository_owner`), which
  matches the scheduled run. The workflow reads that organisation's scope
  policy from `.github/scan-scope.json`; an organisation with no
  entry falls back to the default toggles and the scan variables alone.
- **`repo`** — scan a single named repository (for smoke-testing). The
  scope policy still applies, so the workflow produces an empty matrix —
  publishing nothing — for any repository that the toggles or scope policy
  remove (a skipped category such as archived, fork, template, private or
  disabled, an `exclude` match, or a repository outside a configured
  `include` allow-list).
- **`token`** — override the `ZIZMOR_SARIF_PAT` secret for an ad-hoc run.
  When blank, the workflow uses the secret. **Caution:** GitHub stores and
  shows `workflow_dispatch` inputs in the run parameters without masking
  them, so prefer the secret for routine use and reserve this input for
  testing.

### Organisation-wide aislop scan

The `aislop.yaml` workflow scans pull request changes across every
repository in the organisation using
[aislop](https://github.com/scanaislop/aislop), which detects the
hallmarks of low-quality or AI-generated "slop" code: swallowed
exceptions, narrative/meta comments, formatting drift, lint errors,
excessive complexity, and basic security issues. It scores the scanned
files 0–100 and reports each finding with severity and location.

#### Scan behaviour

- **Scope**: the files **changed on the pull request**, and nothing
  else (via
  `aislop ci --changes --base <PR base branch>`), so the check reports
  on what the PR introduces rather than pre-existing repository state.
  Whole-repository scanning belongs to the scheduled
  `aislop-sarif-publish.yaml` workflow.
- **Implementation**: the scan itself runs through
  [`aislop-scan-action`](https://github.com/lfreleng-actions/aislop-scan-action)
  (pinned by commit SHA), which installs the aislop CLI from its
  bundled, integrity-checked lock file, renders the step summary, and
  exposes the gate result as an output.
- **Output**: a step summary with the score, per-engine issue counts,
  severity/rule breakdowns and the top findings, plus inline PR
  annotations for the top findings. No SARIF upload happens on pull
  requests.
- **Gating**: the scan step always succeeds; a separate gate step
  decides enforcement based on the organisation variable
  **`AISLOP_GATE_LEVEL`**:
  - **`any`** (the default when the variable is unset) — the run
    **fails** when the changed files carry **any finding, at any
    severity**: high, medium and low all block. Because the scan
    scope is the pull request's changed files, passing this gate
    means the pull request adds no findings.
  - **`high`** — the run fails on **high-severity** findings alone (an
    aislop error-severity diagnostic). Medium and low stay advisory.
    This was the previous default; use it as a per-repository escape
    hatch while clearing an existing backlog.
  - **`all`** — the run fails on the full aislop quality gate (score
    below the configured threshold **or** any high-severity finding).
  - **`off`** — advisory: the workflow reports without blocking.

  A **repository** variable of the same name overrides the
  organisation value, so a repository carrying a backlog can sit at
  `high` without weakening the estate-wide default.

  For backward compatibility, when `AISLOP_GATE_LEVEL` is unset the
  legacy **`AISLOP_ENFORCE`** `= true` variable still selects the
  `all` tier. Changing the level requires no workflow change.
- **Version pin**: the aislop CLI version pin lives in
  `aislop-scan-action` (its bundled `package.json` / `package-lock.json`);
  bump it there via a PR and release, then update the action pin here.

#### Enabling the check org-wide

Configure `aislop.yaml` as a *required workflow* via an organisation
ruleset, mirroring the zizmor audit:

1. Go to **Organisation settings** → [**Repository →
   Rulesets**][org-rulesets] (you must be an organisation owner).
2. Click **New ruleset** → **New branch ruleset**.
3. Set:
   - **Ruleset name**: `aislop code quality scan`
   - **Enforcement status**: `Active`
   - **Bypass list**: leave empty
   - **Target repositories**: `All repositories`
   - **Target branches**: `Default branch` (and `master` if you have
     repositories still using that name).
4. Under **Rules**, enable **Require workflows to pass before merging**
   and click **Add workflow**:
   - **Repository**: `lfreleng-actions/.github`
   - **Workflow file path**: `.github/workflows/aislop.yaml`
   - **Ref**: `main`
5. The `any` gate level is the default, so the check blocks a merge
   whenever a pull request's changed files carry a finding of any
   severity once you enable **Require workflows to pass before
   merging**. To report without blocking first, either leave **Do not
   require workflows to pass before merging** *checked* or set the
   `AISLOP_GATE_LEVEL` organisation variable to `off`; `high`
   restores the earlier behaviour, which blocked on high severity
   alone, and `all` enforces the score threshold as well.
6. Click **Create**.

After saving, every pull request opened in the organisation will
trigger an aislop run sourced from `lfreleng-actions/.github`. The
checks appear in PRs as `AI Slop Scan 🧹 / Audit changes`.

### Organisation-wide aislop SARIF publisher

The `aislop.yaml` check runs on `pull_request` events and scans
changed files alone, so it never populates a repository's
**default-branch**
code scanning. The `aislop-sarif-publish.yaml` workflow closes that
gap. On a daily schedule (`0 7 * * *`, 07:00 UTC — offset from the
zizmor publisher at 06:00) it:

1. Enumerates the in-scope repositories for the target organisation
   (via the shared
   [`repo-discovery.yaml`](.github/workflows/repo-discovery.yaml)
   reusable workflow — **the same discovery the zizmor publisher
   uses**, so the two scanners always cover the same repository
   selection).
2. Applies the [repository scope policy](#repository-scope-policy) from
   [`.github/scan-scope.json`](.github/scan-scope.json), plus any
   patterns from the `AISLOP_SCAN_INCLUDE` / `AISLOP_SCAN_EXCLUDE`
   variables.
3. Checks out each repository at its default branch, runs a
   **full-repository** scan with
   [`aislop-scan-action`](https://github.com/lfreleng-actions/aislop-scan-action),
   and uploads the SARIF to that
   repository's code scanning via `POST /code-scanning/sarifs` against
   the **default-branch HEAD**. Findings appear in each repository's
   **Security → Code scanning** tab under the `aislop` tool.
4. Aggregates per-repository score metrics into a ranked, worst-first
   table in the run's step summary, answering "which repositories have
   the biggest problems?" at a glance.

When a **scheduled** run fails or a maintainer cancels it, the workflow
posts a Slack alert to `#releng-scm` (reusing the `SLACK_BOT_TOKEN`
secret and `SLACK_CHANNEL_ID` variable documented under
[Slack Setup](#slack-setup)), so a silent daily breakage never slips
past the team. Manual `workflow_dispatch` runs stay quiet, since a
maintainer already watches those.

#### Publisher token

Writing code-scanning results to *other* repositories is beyond what
the default `GITHUB_TOKEN` can do, so the workflow needs a dedicated
PAT in the **`AISLOP_SARIF_PAT`** repository secret. The aislop and
zizmor publishers use separately scoped credentials by design — they
do not share secrets. A
**classic PAT** needs the scopes `repo`, `read:org` and
`security_events`; a fine-grained PAT scoped to the organisation needs
Contents read, Metadata read, and Code scanning alerts **write**.

#### Manual dispatch

**Run workflow** also triggers the workflow on demand, with the same
three optional inputs as the zizmor publisher (`org`, `repo`, and
`token`); see
[Manual dispatch inputs](#manual-dispatch-inputs) above for their
semantics. The `token` input falls back to the `AISLOP_SARIF_PAT`
secret when blank.

### Repository scope policy

The `zizmor-sarif-publish.yaml` and `aislop-sarif-publish.yaml`
workflows read their scope (through the shared
[`repo-discovery.yaml`](.github/workflows/repo-discovery.yaml)
reusable workflow) from
[`.github/scan-scope.json`](.github/scan-scope.json), keyed
by organisation. Each organisation provides four boolean scan toggles and
two **glob** pattern lists:

```json
{
  "organisations": {
    "example-org": {
      "scan_archived": false,
      "scan_forks": false,
      "scan_templates": true,
      "scan_private": false,
      "include": [],
      "exclude": ["*-sandbox"]
    }
  }
}
```

#### Scan toggles

The toggles opt extra repository categories into the scan. Each defaults to
`false`, so a bare configuration scans normal, active, public, first-party
repositories.

| Toggle           | When `true`                     |
| ---------------- | ------------------------------- |
| `scan_archived`  | also scan archived repositories |
| `scan_forks`     | also scan forks                 |
| `scan_templates` | also scan template repositories |
| `scan_private`   | also scan private repositories  |

The workflow skips a repository when one of its categories has the matching
toggle off. It also skips disabled repositories, because GitHub blocks
their checkout.

#### Name patterns

After the toggles, `include`/`exclude` globs filter by repository name:

- **Case-insensitive globs** — patterns support `*` (any run), `?` (one
  character), and `[..]` character classes; a pattern with no wildcards is
  an exact name. Separator-aware patterns such as `*[-_./]test[-_./]*`
  match a `test` path *segment* without catching names like `latest` or
  `attestation`.
- **`exclude`** — drops a repository whose name matches any exclude
  pattern.
- **`include`** — acts as an allow-list: a non-empty list keeps the
  repositories matching at least one include pattern (`exclude` still
  removes matches afterwards). An empty `include` list keeps every
  repository.

#### Run-time pattern variables

Two optional repository variables extend the policy without editing the
JSON, using the same glob syntax (values separated by commas, spaces, or
newlines):

- **`ZIZMOR_SCAN_INCLUDE`** — extra `include` (allow-list) patterns.
- **`ZIZMOR_SCAN_EXCLUDE`** — extra `exclude` patterns.

The `aislop-sarif-publish.yaml` workflow honours the analogous
**`AISLOP_SCAN_INCLUDE`** / **`AISLOP_SCAN_EXCLUDE`** variables, so the
two scanners can diverge at run time without editing the shared JSON.

The workflow merges the variable patterns with the organisation's JSON
lists before matching.

### Allow-list bump sweep

The workflow-repo family pins the `step-security/harden-runner` egress
allow-list with a custom `uses:`-style coordinate consumed by
[`harden-runner-block-action`][hrba]:

[hrba]: https://github.com/lfreleng-actions/harden-runner-block-action

<!-- markdownlint-disable MD013 -->

```yaml
config: '@18d9c4446bea555d0783e850f6d295f844fe8f67'  # v0.1.1
```

<!-- markdownlint-enable MD013 -->

Because these are values of `config:` and `default:` keys rather than
`uses:` references, Dependabot cannot see them and they drift. A stale
pin gives no warning: it omits newly allow-listed endpoints, so
block-mode jobs fail later with confusing `ECONNREFUSED` errors against hosts added
to the allow-list weeks earlier.

Every Monday, `allow-list-bump.yaml` enumerates the in-scope
repositories, clones them side by side, runs [`gha-workflow-linter`][linter]
once across the whole set with `--multi-repo --update-allow-list`, and
opens a pull request wherever a pin moved. A Slack digest links every
pull request.

One sweep rather than a job per repository: a single hardened runner,
one toolchain install and one linter process cover the whole family,
and the job that produces the digest also sends it, rather than
passing it between jobs as artefacts. A multi-repository run does
share one resolution cache, but that is not what earns the
arrangement here: every repository in scope sets a Dependabot
cooldown, and the linter bypasses that cache whenever a cooldown
applies, so each repository still resolves the allow-list host for
itself.

[linter]: https://github.com/lfreleng-actions/gha-workflow-linter

#### Scope

The sweep covers the **`*-workflows` family**, and nothing else. Those
repositories host the reusable build workflows consumers run, where a
missing endpoint breaks real builds in downstream projects. Standard
GitHub plumbing elsewhere in the organisation touches a small, stable
endpoint set, so a pin some versions behind has little practical effect,
and weekly pull requests against it would create review noise.

To sweep something else, run the workflow manually and supply an
`extra-include` glob. The `ALLOW_LIST_BUMP_EXCLUDE` variable removes
repositories from every run.

#### Behaviour

- Runs with `--no-auto-fix`, so each pull request carries a diff
  confined to allow-list pins. Action version bumps belong to Dependabot, and
  mixing them makes the change harder to review and harder to revert.
- The pinned reference and its version comment change, and nothing
  else: quoting style, spacing and comment position all survive. The
  release the sweep moves to is the newest one eligible under the
  repository's own Dependabot cooldown, which is not always the newest
  released, and the pull request says so rather than calling it
  current.
- The sweep leaves alone any pin carrying an `allow-list-pin-ok`
  directive.
- Each repository carries at most one sweep pull request, on a fixed
  `chore/allow-list-bump` branch. A newer release supersedes the open
  proposal in place rather than opening a second one beside it. A
  re-run leaves the branch untouched when the open pull request already
  carries the identical change, so an unreviewed pull request does not
  reset its own review state every week; it rewrites the branch when
  the target version moves or a pin appears that the proposal does not
  yet cover. The comparison spans the files the pull request already
  changes and the files this run rewrites, matching the two sets and
  then their contents, so a commit merged into the default branch for
  unrelated reasons does not force a rewrite. It looks at file contents
  alone, so a hand-edited title or a description that has fallen out of
  step gets put right without a commit. Comparing the description folds
  out the link to the sweep run that last touched it, which would
  otherwise differ every week.
- Each rewrite builds its commit on a staging ref at the default branch
  and then moves the proposal branch onto it. The proposal branch must
  never point at the default branch, even for an instant, because
  GitHub closes a pull request the moment head and base coincide,
  taking its number, review threads and approvals with it. Building on
  the default branch also keeps a workflow added there since the
  proposal opened from landing as an add/add conflict, and keeps an
  unrelated edit to a proposed file out of the diff under review.
- The default branch can move while the sweep runs, between taking the
  checkouts and writing. Each proposal builds on where that branch now
  stands, not where the checkout found it. Where it moved under a file
  the sweep rewrites, the checkout no longer describes that file and
  any proposal from it would revert whatever landed, so the sweep
  leaves that repository for the next run — whose checkout includes the
  change — and names it in the run and the digest. Retiring a proposal
  waits on any movement at all, since it rests entirely on the checkout
  showing nothing to do and no later run can reopen what it closes.
- A proposal that no longer changes anything gets retired. When the
  default branch reaches the selected release by some other route, or
  its pins already sit ahead of it, the sweep closes the open pull
  request, deletes the branch and says so in the digest, rather than
  leaving a no-op sitting in the review queue. A repository that has
  removed its last workflow counts here too: the linter then reports a
  clean result with no findings, and its proposal has nothing left to
  propose. A repository whose allow-list host would not resolve gets
  nothing done to it: with the host unknown, "nothing to fix" and
  "could not look" are indistinguishable, and the run fails rather than
  acting on the difference.
- A stale pin the linter can see but cannot rewrite — one inside a
  multi-line scalar, for instance — leaves the repository neither
  current nor fixable. The sweep names it in the run and in the digest
  and leaves every proposal alone, rather than retiring a pull request
  in a repository that is still stale. Where such a repository already
  carries an open proposal, the digest links and counts it as open, and
  notes what still needs doing by hand.
- Nearly every repository pins one allow-list host, and the pull
  request title names the release it moves to. A repository pinning
  more than one resolves more than one release, so naming a single
  version would describe part of the change as though it were the
  whole. Those pull requests carry a title without a version, list
  every host and its release in the body and the commit message, and
  the run warns that it found more than one.
- Pull requests come from the organisation's `lf-releng-bot` GitHub
  App, not from a maintainer. Code review is mandatory across the
  organisation and nobody may approve their own work, so a sweep
  raising pull requests as a person would produce changes that person
  could not merge.
- Commits reach the branch through the GitHub API rather than a push, so
  GitHub signs them. The default branch of every repository in scope
  carries a `required_signatures` rule, which an unverified commit
  would fail.
- A `dry-run` dispatch input reports what would change without opening
  anything.
- The workflow pins the linter version in `LINTER_VERSION`, matching the
  commit-pinned actions around it. An unpinned install would let one bad
  release reach every repository in the sweep at once. Bump it when the
  linter ships something the sweep needs.

#### Required configuration

<!-- markdownlint-disable MD013 -->

| Name                        | Kind     | Purpose                                                                                                                  |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------ |
| `LF_RELENG_BOT_CLIENT_ID`   | Variable | Client ID of the `lf-releng-bot` GitHub App, shared with the other bot-authored workflows                                |
| `LF_RELENG_BOT_PRIVATE_KEY` | Secret   | Private key (PEM) for that App. The sweep mints a short-lived installation token scoped to the repositories in the sweep |
| `ALLOW_LIST_BUMP_EXCLUDE`   | Variable | Optional extra exclude globs                                                                                             |
| `SLACK_BOT_TOKEN`           | Secret   | Shared with the other scheduled workflows                                                                                |
| `SLACK_CHANNEL_ID`          | Variable | Shared with the other scheduled workflows                                                                                |

<!-- markdownlint-enable MD013 -->

The bot App must have write access to `contents`, `pull requests` and
`workflows` on every repository the sweep covers. `workflows` matters in
its own right: every file the sweep rewrites lives under
`.github/workflows`. Minting the token fails outright when a repository
in scope is missing from the installation.

The bot's token writes and does nothing else. Repository discovery and
the linter's own lookups use the ephemeral `GITHUB_TOKEN`: listing an
organisation's public repositories needs no more, and
`.github/scan-scope.json` sets `scan_private` to false. The lookups read
public release data right across GitHub — the allow-list host, and every
organisation whose actions these workflows call — almost none of which
lies inside the App's repository selection. A cold-cache sweep of the
whole family measured 2 REST calls and 174 GraphQL points, against a
limit of 1000 per hour for each.

All jobs run in the `production` environment, so environment protection
rules can guard the App key and the Slack token.

### Repository Audit Workflow

The `repo-audit.yaml` workflow:

1. Lists all repositories in the organisation via the GitHub API
2. Filters out repositories named in `excluded-repos.json`
3. Parses the profile README for documented repository links
4. Compares the two sets and identifies any undocumented repositories
5. Posts a summary to the GitHub Actions job output
6. Sends a Slack notification to `#releng-scm` if any updates need attention

The workflow requires:

- **`SLACK_BOT_TOKEN`** — A repository secret containing a Slack bot
  token with `chat:write` permission for the
  `linuxfoundation.slack.com` workspace
- **`SLACK_CHANNEL_ID`** — A repository variable containing the channel
  ID for the `#releng-scm` channel

See the [Slack setup instructions](#slack-setup) below.

### Excluded Repositories

The `excluded-repos.json` file contains a JSON object with an
`excluded` array of repository names (not full paths) to skip
during the audit. Typical exclusions include:

- Forks of upstream actions (e.g. `gh-action-pypi-publish`)
- Repositories still at the template/placeholder stage
- Backup or archive directories

To add a new exclusion, edit `excluded-repos.json` and add the
repository name to the `excluded` array.

## Slack Setup

The repository audit workflow and the scheduled zizmor / AI slop SARIF
publishers send notifications using the official
[Slack GitHub Action](https://github.com/slackapi/slack-github-action).
The publishers reuse the same `SLACK_BOT_TOKEN` secret and
`SLACK_CHANNEL_ID` variable, and post to `#releng-scm` when a
scheduled run fails. Complete the following one-time setup steps:

### 1. Create a Slack App

1. Go to [api.slack.com/apps](https://api.slack.com/apps) and sign in
   to the `linuxfoundation.slack.com` workspace
2. Click **Create New App** → **From scratch**
3. Name it `LF RelEng GitHub Notifications` (or similar)
4. Select the `linuxfoundation` workspace

### 2. Configure Bot Permissions

1. Navigate to **OAuth & Permissions** in the app settings
2. Under **Bot Token Scopes**, add:
   - `chat:write` — to post messages
   - `chat:write.customize` — to customise the bot name/icon per message
3. Click **Install to Workspace** and authorise the app
4. Copy the **Bot User OAuth Token** (starts with `xoxb-`)

### 3. Invite the Bot to the Channel

In Slack, open the `#releng-scm` channel and run:

```text
/invite @LF RelEng GitHub Notifications
```

### 4. Get the Channel ID

1. In Slack, right-click the `#releng-scm` channel name
2. Select **View channel details**
3. The Channel ID is at the bottom of the details panel (e.g.
   `C0123456789`)

### 5. Configure GitHub Secrets and Variables

In the [`.github` repository settings](https://github.com/lfreleng-actions/.github/settings):

1. Go to **Secrets and variables** → **Actions**
2. Add a **Repository secret**:
   - Name: `SLACK_BOT_TOKEN`
   - Value: the `xoxb-` token from step 2
3. Add a **Repository variable**:
   - Name: `SLACK_CHANNEL_ID`
   - Value: the channel ID from step 4

## Tagging and Releasing Actions

For instructions on tagging and releasing actions in this organisation,
see the
[organisation profile README](profile/README.md#tagging-and-releasing-actions).

## Contributing

Changes to this repository affect all repositories in the organisation.
Please open a pull request and ensure all pre-commit hooks pass before
merging. The repository uses the standard `lfreleng-actions` pre-commit
configuration including yamllint, actionlint, markdownlint, REUSE/SPDX
verification, and GitHub workflow schema validation.
