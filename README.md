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

### Workflows

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
- **Severity floor**: `medium` (the workflow filters out informational
  and low findings to reduce noise).
- **Persona**: `regular` (zizmor's default; high-signal, low-noise).
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

The repository audit workflow sends notifications using the official
[Slack GitHub Action](https://github.com/slackapi/slack-github-action).
Complete the following one-time setup steps:

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
