<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# Linux Foundation Release Engineering

[Documentation](https://docs.releng.linuxfoundation.org/)

## GitHub Actions

The [Linux Foundation](https://www.linuxfoundation.org/) Release Engineering
team maintains this organisation. It provides a comprehensive collection of
GitHub Actions and CI/CD tooling used across Linux
Foundation hosted projects.

All actions follow Conventional Commits, use pinned dependencies, and ship
with signed tags and provenance attestations.

## 🔧 Build & Test Actions

<!-- markdownlint-disable MD013 -->

| Action                        | Description                                                  |
| ----------------------------- | ------------------------------------------------------------ |
| [python-build-action]         | Build a Python project                                       |
| [python-test-action]          | Test a Python project and generate coverage reports          |
| [python-audit-action]         | Audit Python dependencies for known security vulnerabilities |
| [python-twine-check-action]   | Verify Python build artefacts with Twine before publishing   |
| [python-notebook-test-action] | Check Jupyter Notebooks with pytest and nbmake               |
| [python-sbom-action]          | Generate CycloneDX SBOM reports for Python projects          |
| [tox-run-action]              | Run tox with specified Python version and environments       |
| [gradle-build-action]         | Set up a specific JDK version and run a Gradle build         |
| [maven-build-action]          | Set up Maven and build a Java project                        |
| [maven-make-build-action]     | Set up Maven and run make                                    |
| [node-build-action]           | Set up Node.js and build a project with npm or yarn          |
| [make-action]                 | Execute the steps described in a Makefile                    |

<!-- markdownlint-enable MD013 -->

## 📦 Publishing & Release Actions

<!-- markdownlint-disable MD013 -->

| Action                         | Description                                               |
| ------------------------------ | --------------------------------------------------------- |
| [pypi-publish-action]          | Publish a Python project to PyPI                          |
| [pypi-version-check-action]    | Check PyPI for a given package and optional build/release |
| [draft-release-promote-action] | Promote a draft GitHub release to a full release          |
| [release-assets-action]        | Upload build artefacts and assets to a GitHub release     |
| [nexus-publish-action]         | Publish content to Sonatype Nexus Repository servers      |
| [nexus-docker-login-action]    | Docker login for all registries in Nexus3 and DockerHub   |
| [helm-chart-publish-action]    | Publish Helm Charts to an OCI container repository        |
| [chartmuseum-action]           | Start and run a ChartMuseum Helm Chart repository         |

<!-- markdownlint-enable MD013 -->

## 🐍 Python Project Metadata Actions

<!-- markdownlint-disable MD013 -->

| Action                                | Description                                               |
| ------------------------------------- | --------------------------------------------------------- |
| [python-project-metadata-action]      | Extract Python project metadata from a repository         |
| [python-project-name-action]          | Extract a Python project name and derive the package name |
| [python-project-version-action]       | Return the version of a Python project                    |
| [python-project-version-patch-action] | Replace/update the Python project version string          |
| [python-dynamic-version-action]       | Check dynamic versioning setup in pyproject.toml          |
| [python-supported-versions-action]    | Extract supported Python versions for build/matrix jobs   |
| [python-dependencies-update-action]   | Update the dependencies of a Python project               |

<!-- markdownlint-enable MD013 -->

## 🏷️ Tag & Version Validation Actions

<!-- markdownlint-disable MD013 -->

| Action                                  | Description                                                           |
| --------------------------------------- | --------------------------------------------------------------------- |
| [tag-validate-action]                   | Unified tag validation for SemVer/CalVer and cryptographic signatures |
| [tag-validate-semantic-action]          | Check a string/tag for Semantic Versioning conformity                 |
| [tag-validate-calver-action]            | Check a string/tag for Calendar Versioning conformity                 |
| [tag-push-verify-action]                | Verify a workflow trigger was a tag push of a given type              |
| [python-project-tag-push-verify-action] | Check a pushed tag matches the declared Python project version        |
| [version-extract-action]                | Extract version strings from supported software project types         |

<!-- markdownlint-enable MD013 -->

## 🔄 Gerrit Integration Actions

<!-- markdownlint-disable MD013 -->

| Action                          | Description                                                              |
| ------------------------------- | ------------------------------------------------------------------------ |
| [github2gerrit-action]          | Create Gerrit changes from GitHub pull requests                          |
| [gerrit-clone-action]           | Bulk clone repositories from Gerrit with multi-threading and retry logic |
| [checkout-gerrit-change-action] | Checkout a mirrored Gerrit change                                        |
| [gerrit-review-action]          | Set review votes on a Gerrit system                                      |
| [gerrit-change-info]            | Retrieve Gerrit change request information                               |
| [gerrit-action]                 | Start Gerrit server containers with pull-replication for CI testing      |

<!-- markdownlint-enable MD013 -->

## 🔐 Security & Credentials Actions

<!-- markdownlint-disable MD013 -->

| Action                           | Description                                                             |
| -------------------------------- | ----------------------------------------------------------------------- |
| [1password-secrets-action]       | Securely retrieve secrets from 1Password vaults                         |
| [credential-load-action]         | Retrieve project/repository specific credentials from a 1Password vault |
| [sigul-docker]                   | Sign build packages, artefacts, and git tags using Sigul                |
| [spdx-verify-action]             | Verify files contain the required SPDX license headers                  |
| [sonarqube-cloud-scan-action]    | Perform a SonarQube Cloud scan and upload the results                   |
| [sonatype-lifecycle-scan-action] | Run a Sonatype Lifecycle (Nexus IQ) scan                                |

<!-- markdownlint-enable MD013 -->

## 🔍 Repository & Code Quality Actions

<!-- markdownlint-disable MD013 -->

| Action                             | Description                                                         |
| ---------------------------------- | ------------------------------------------------------------------- |
| [repository-metadata-action]       | Gather repository metadata                                          |
| [repository-content-action]        | Scan a repository for different content types                       |
| [repository-tags]                  | Fetch tags, count them, identify the latest tag, and determine type |
| [build-metadata-action]            | Capture and verify comprehensive build metadata across languages    |
| [project-name-action]              | Compare project name to GitHub repository name                      |
| [openssf-scorecard-summary-action] | Generate OpenSSF Scorecard summary output with report URL           |
| [pinned-versions-action]           | Verify action/workflow calls use pinned SHA commit values           |
| [standalone-linting-action]        | Run linting tools that do not run under pre-commit.ci               |
| [gha-workflow-linter]              | Lint and verify GitHub workflow/action calls                        |
| [action-semantic-pull-request]     | Ensure PR titles match the Conventional Commits specification       |

<!-- markdownlint-enable MD013 -->

## 🛠️ Utility Actions

<!-- markdownlint-disable MD013 -->

| Action                         | Description                                                        |
| ------------------------------ | ------------------------------------------------------------------ |
| [git-configure-action]         | Configure Git settings from inside a GitHub Action                 |
| [git-commit-message-action]    | Retrieve a Git commit message and check for Change-Id and DCO      |
| [inject-issue-id-action]       | Add issue tracker reference to a commit message body               |
| [path-check-action]            | Check if a given path exists in the repository and report its type |
| [file-grep-regex-action]       | Extract a string from a file using grep and a regular expression   |
| [file-sed-regex-action]        | Perform string substitutions in a file using sed                   |
| [json-key-value-lookup-action] | Look up a value in a JSON key/value table                          |
| [url-download-action]          | Download content from a URL using wget                             |
| [url-validity-action]          | Check a URL for a valid server response                            |
| [verify-release-schema-action] | Verify release file contents against an approved schema            |
| [github-list-releases-action]  | Return a list of releases for a GitHub repository                  |
| [http-api-tool-docker]         | Test HTTP/HTTPS API endpoints for service availability             |
| [go-httpbin-action]            | Create a local go-httpbin service with HTTPS support               |
| [hw-bom-javascript]            | Generate a hardware bill of materials                              |

<!-- markdownlint-enable MD013 -->

## 📊 Reporting Tools

<!-- markdownlint-disable MD013 -->

| Tool                          | Description                                                                |
| ----------------------------- | -------------------------------------------------------------------------- |
| [project-reporting-tool]      | Comprehensive multi-repository analysis tool for Linux Foundation projects |
| [project-reporting-artifacts] | Generated reports and data artefacts from the Project Reporting Tool       |
| [github-report]               | GitHub organisation posture reporting                                      |
| [github-network-audit]        | Build harden-runner egress allowlists from StepSecurity endpoint data      |

<!-- markdownlint-enable MD013 -->

## 🧪 Test Fixtures & Sample Projects

These repositories provide test fixtures and sample projects that
verify the actions and workflows in this organisation:

<!-- markdownlint-disable MD013 -->

| Repository                          | Purpose                                                 |
| ----------------------------------- | ------------------------------------------------------- |
| [test-python-project]               | Sample Python project (Typer CLI)                       |
| [test-go-project]                   | Sample Go project (calculator CLI)                      |
| [test-node-project]                 | Sample Node.js project (Express HTTP server)            |
| [test-docker-project]               | Sample project that builds a Docker image               |
| [test-makefile-helm-chart]          | Template Makefile for building a sample Helm Chart      |
| [test-deploy-gerrit]                | Gerrit server connectivity and pull-replication testing |
| [test-http-api-tool]                | Workflow tests for the HTTP API testing tool            |
| [test-pypi-publish-action]          | PyPI publishing workflow tests                          |
| [test-python-audit-action]          | Python dependency audit workflow tests                  |
| [test-draft-release-promote-action] | Draft release promotion workflow tests                  |
| [test-release-process]              | End-to-end release workflow testing                     |
| [test-tags-semantic]                | SemVer tag signature test fixtures                      |
| [test-tags-calver]                  | CalVer tag signature test fixtures                      |

<!-- markdownlint-enable MD013 -->

## 📋 Organisation Resources

<!-- markdownlint-disable MD013 -->

| Repository                  | Purpose                                                                                                |
| --------------------------- | ------------------------------------------------------------------------------------------------------ |
| [actions-template]          | Template repository for creating new GitHub Actions                                                    |
| [.github]                   | Organisation-wide configuration (default community health files, shared release-drafter configuration) |
| [releng-reusable-workflows] | Shared/common workflows leveraging these actions (hosted in the [lfit](https://github.com/lfit) org)   |

<!-- markdownlint-enable MD013 -->

## 🔨 Tools

<!-- markdownlint-disable MD013 -->

| Tool                   | Description                                                      |
| ---------------------- | ---------------------------------------------------------------- |
| [dependamerge]         | Bulk merge/close pull requests and Gerrit changes across an org  |
| [docs-conf]            | Sphinx build configuration for Release Engineering documentation |
| [gerrit-to-platform]   | Gerrit hooks to allow using GitHub and GitLab as CI platforms    |
| [markdown-table-fixer] | Fix markdown table formatting as a CLI tool or pre-commit hook   |
| [pull-request-fixer]   | Fix pull request titles, bodies, and files across a GitHub org   |

<!-- markdownlint-enable MD013 -->

## Building GitHub Workflows

The actions published here are designed for projects using both
GitHub and Gerrit as the source of code/truth. They all work in
native GitHub environments, and can also be used in Gerrit
environments with some adaptation to the workflows.

Workflow adaptation for Gerrit is documented in the
[gerrit-to-platform documentation][gerrit-to-platform-docs].
Some [example workflows][gerrit-to-platform-examples] are also
available.

### Example Workflows

<!-- markdownlint-disable MD013 -->

| Workflow                                                 | Description                                                           |
| -------------------------------------------------------- | --------------------------------------------------------------------- |
| [`github-vanilla-verify.yaml`][wf-github-vanilla]        | A simple workflow that verifies PRs with no Gerrit integration        |
| [`gerrit-verify.yaml`][wf-gerrit-verify]                 | A workflow with Gerrit integration that verifies pull requests        |
| [`gerrit-verify-manual-dispatch.yaml`][wf-gerrit-manual] | A Gerrit integrated verify workflow that can also be manually invoked |
| [`gerrit-merge.yaml`][wf-gerrit-merge]                   | A GitHub workflow that handles merged changes in Gerrit               |

<!-- markdownlint-enable MD013 -->

## Tagging and Releasing Actions

### Prerequisites

1. Merge all open/pending pull requests
2. Sync your fork with upstream:

<!-- markdownlint-disable MD013 -->

``` shell
git fetch upstream
git checkout main
git merge --ff-only upstream/main
git push origin main
```

<!-- markdownlint-enable MD013 -->

### Creating a release

Create and push a signed, annotated tag:

``` shell
git tag -s -a v1.2.3 -m "v1.2.3"
git push upstream v1.2.3
```

The tag push triggers one of two release workflows:

<!-- markdownlint-disable MD013 -->

| Workflow                  | Use case                                |
| ------------------------- | --------------------------------------- |
| `tag-push.yaml`           | Generic (non-language-specific) actions |
| `build-test-release.yaml` | Python actions that publish to PyPI     |

<!-- markdownlint-enable MD013 -->

> **Note:** These workflows live in each action repository,
> not in this `.github` repo.

#### Generic action/repository (`tag-push.yaml`)

Verifies the tag is valid semver then promotes the
corresponding draft GitHub release.

#### Python action/repository (`build-test-release.yaml`)

Runs the full Python release pipeline:

1. Tag format and signature validation
2. Python build with Sigstore signing and attestations
3. Pytest test suite
4. SBOM generation and Grype vulnerability scan
5. pip-audit for known security issues
6. Publish to test.pypi.org then pypi.org
7. Attach build artefacts to the GitHub release
8. Promote the draft release

> **Note:** Release workflows for other language types
> (Go, Maven, etc.) still need authoring.

## Contributing

Contributions are welcome. Please open an issue or pull request against
the relevant repository. All repositories follow the
[Conventional Commits](https://www.conventionalcommits.org/) specification
for commit messages and PR titles. The
[Apache-2.0](https://spdx.org/licenses/Apache-2.0.html) license applies
to all repositories unless otherwise stated.

<!-- Build & Test Actions -->
[python-build-action]: https://github.com/lfreleng-actions/python-build-action
[python-test-action]: https://github.com/lfreleng-actions/python-test-action
[python-audit-action]: https://github.com/lfreleng-actions/python-audit-action
[python-twine-check-action]: https://github.com/lfreleng-actions/python-twine-check-action
[python-notebook-test-action]: https://github.com/lfreleng-actions/python-notebook-test-action
[python-sbom-action]: https://github.com/lfreleng-actions/python-sbom-action
[tox-run-action]: https://github.com/lfreleng-actions/tox-run-action
[gradle-build-action]: https://github.com/lfreleng-actions/gradle-build-action
[maven-build-action]: https://github.com/lfreleng-actions/maven-build-action
[maven-make-build-action]: https://github.com/lfreleng-actions/maven-make-build-action
[node-build-action]: https://github.com/lfreleng-actions/node-build-action
[make-action]: https://github.com/lfreleng-actions/make-action

<!-- Publishing & Release Actions -->
[pypi-publish-action]: https://github.com/lfreleng-actions/pypi-publish-action
[pypi-version-check-action]: https://github.com/lfreleng-actions/pypi-version-check-action
[draft-release-promote-action]: https://github.com/lfreleng-actions/draft-release-promote-action
[release-assets-action]: https://github.com/lfreleng-actions/release-assets-action
[nexus-publish-action]: https://github.com/lfreleng-actions/nexus-publish-action
[nexus-docker-login-action]: https://github.com/lfreleng-actions/nexus-docker-login-action
[helm-chart-publish-action]: https://github.com/lfreleng-actions/helm-chart-publish-action
[chartmuseum-action]: https://github.com/lfreleng-actions/chartmuseum-action

<!-- Python Project Metadata Actions -->
[python-project-metadata-action]: https://github.com/lfreleng-actions/python-project-metadata-action
[python-project-name-action]: https://github.com/lfreleng-actions/python-project-name-action
[python-project-version-action]: https://github.com/lfreleng-actions/python-project-version-action
[python-project-version-patch-action]: https://github.com/lfreleng-actions/python-project-version-patch-action
[python-dynamic-version-action]: https://github.com/lfreleng-actions/python-dynamic-version-action
[python-supported-versions-action]: https://github.com/lfreleng-actions/python-supported-versions-action
[python-dependencies-update-action]: https://github.com/lfreleng-actions/python-dependencies-update-action

<!-- Tag & Version Validation Actions -->
[tag-validate-action]: https://github.com/lfreleng-actions/tag-validate-action
[tag-validate-semantic-action]: https://github.com/lfreleng-actions/tag-validate-semantic-action
[tag-validate-calver-action]: https://github.com/lfreleng-actions/tag-validate-calver-action
[tag-push-verify-action]: https://github.com/lfreleng-actions/tag-push-verify-action
[python-project-tag-push-verify-action]: https://github.com/lfreleng-actions/python-project-tag-push-verify-action
[version-extract-action]: https://github.com/lfreleng-actions/version-extract-action

<!-- Gerrit Integration Actions -->
[github2gerrit-action]: https://github.com/lfreleng-actions/github2gerrit-action
[gerrit-clone-action]: https://github.com/lfreleng-actions/gerrit-clone-action
[checkout-gerrit-change-action]: https://github.com/lfreleng-actions/checkout-gerrit-change-action
[gerrit-review-action]: https://github.com/lfreleng-actions/gerrit-review-action
[gerrit-change-info]: https://github.com/lfreleng-actions/gerrit-change-info
[gerrit-action]: https://github.com/lfreleng-actions/gerrit-action

<!-- Security & Credentials Actions -->
[1password-secrets-action]: https://github.com/lfreleng-actions/1password-secrets-action
[credential-load-action]: https://github.com/lfreleng-actions/credential-load-action
[sigul-docker]: https://github.com/lfreleng-actions/sigul-docker
[spdx-verify-action]: https://github.com/lfreleng-actions/spdx-verify-action
[sonarqube-cloud-scan-action]: https://github.com/lfreleng-actions/sonarqube-cloud-scan-action
[sonatype-lifecycle-scan-action]: https://github.com/lfreleng-actions/sonatype-lifecycle-scan-action

<!-- Repository & Code Quality Actions -->
[repository-metadata-action]: https://github.com/lfreleng-actions/repository-metadata-action
[repository-content-action]: https://github.com/lfreleng-actions/repository-content-action
[repository-tags]: https://github.com/lfreleng-actions/repository-tags
[build-metadata-action]: https://github.com/lfreleng-actions/build-metadata-action
[project-name-action]: https://github.com/lfreleng-actions/project-name-action
[openssf-scorecard-summary-action]: https://github.com/lfreleng-actions/openssf-scorecard-summary-action
[pinned-versions-action]: https://github.com/lfreleng-actions/pinned-versions-action
[standalone-linting-action]: https://github.com/lfreleng-actions/standalone-linting-action
[gha-workflow-linter]: https://github.com/lfreleng-actions/gha-workflow-linter
[action-semantic-pull-request]: https://github.com/lfreleng-actions/action-semantic-pull-request

<!-- Utility Actions -->
[git-configure-action]: https://github.com/lfreleng-actions/git-configure-action
[git-commit-message-action]: https://github.com/lfreleng-actions/git-commit-message-action
[inject-issue-id-action]: https://github.com/lfreleng-actions/inject-issue-id-action
[path-check-action]: https://github.com/lfreleng-actions/path-check-action
[file-grep-regex-action]: https://github.com/lfreleng-actions/file-grep-regex-action
[file-sed-regex-action]: https://github.com/lfreleng-actions/file-sed-regex-action
[json-key-value-lookup-action]: https://github.com/lfreleng-actions/json-key-value-lookup-action
[url-download-action]: https://github.com/lfreleng-actions/url-download-action
[url-validity-action]: https://github.com/lfreleng-actions/url-validity-action
[verify-release-schema-action]: https://github.com/lfreleng-actions/verify-release-schema-action
[github-list-releases-action]: https://github.com/lfreleng-actions/github-list-releases-action
[http-api-tool-docker]: https://github.com/lfreleng-actions/http-api-tool-docker
[go-httpbin-action]: https://github.com/lfreleng-actions/go-httpbin-action
[hw-bom-javascript]: https://github.com/lfreleng-actions/hw-bom-javascript

<!-- Reporting Tools -->
[project-reporting-tool]: https://github.com/lfreleng-actions/project-reporting-tool
[project-reporting-artifacts]: https://github.com/lfreleng-actions/project-reporting-artifacts
[github-report]: https://github.com/lfreleng-actions/github-report
[github-network-audit]: https://github.com/lfreleng-actions/github-network-audit

<!-- Test Fixtures & Sample Projects -->
[test-python-project]: https://github.com/lfreleng-actions/test-python-project
[test-go-project]: https://github.com/lfreleng-actions/test-go-project
[test-node-project]: https://github.com/lfreleng-actions/test-node-project
[test-docker-project]: https://github.com/lfreleng-actions/test-docker-project
[test-makefile-helm-chart]: https://github.com/lfreleng-actions/test-makefile-helm-chart
[test-deploy-gerrit]: https://github.com/lfreleng-actions/test-deploy-gerrit
[test-http-api-tool]: https://github.com/lfreleng-actions/test-http-api-tool
[test-pypi-publish-action]: https://github.com/lfreleng-actions/test-pypi-publish-action
[test-python-audit-action]: https://github.com/lfreleng-actions/test-python-audit-action
[test-draft-release-promote-action]: https://github.com/lfreleng-actions/test-draft-release-promote-action
[test-release-process]: https://github.com/lfreleng-actions/test-release-process
[test-tags-semantic]: https://github.com/lfreleng-actions/test-tags-semantic
[test-tags-calver]: https://github.com/lfreleng-actions/test-tags-calver

<!-- Organisation Resources -->
[actions-template]: https://github.com/lfreleng-actions/actions-template
[.github]: https://github.com/lfreleng-actions/.github
[releng-reusable-workflows]: https://github.com/lfit/releng-reusable-workflows

<!-- Tools -->
[dependamerge]: https://github.com/lfit/dependamerge
[docs-conf]: https://gerrit.linuxfoundation.org/infra/admin/repos/releng/docs-conf
[gerrit-to-platform]: https://gerrit.linuxfoundation.org/infra/admin/repos/releng/gerrit_to_platform
[markdown-table-fixer]: https://github.com/lfreleng-actions/markdown-table-fixer
[pull-request-fixer]: https://github.com/lfreleng-actions/pull-request-fixer

<!-- Building GitHub Workflows -->
[gerrit-to-platform-docs]: https://github.com/lfit/releng-gerrit_to_platform
[gerrit-to-platform-examples]: https://github.com/lfit/releng-gerrit_to_platform/tree/main/examples/workflows
[wf-github-vanilla]: https://github.com/lfit/releng-gerrit_to_platform/blob/main/examples/workflows/github-vanilla-verify.yaml
[wf-gerrit-verify]: https://github.com/lfit/releng-gerrit_to_platform/blob/main/examples/workflows/gerrit-verify.yaml
[wf-gerrit-manual]: https://github.com/lfit/releng-gerrit_to_platform/blob/main/examples/workflows/gerrit-verify-manual-dispatch.yaml
[wf-gerrit-merge]: https://github.com/lfit/releng-gerrit_to_platform/blob/main/examples/workflows/gerrit-merge.yaml
