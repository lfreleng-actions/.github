<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# lfreleng-actions egress allow-list

`allow_list.txt` is the shared [harden-runner][hr] egress allow-list for
the `lfreleng-actions` organisation. Workflows load it with
[harden-runner-block-action][block] and run harden-runner in `block`
mode, so harden-runner denies any host this file omits.

Each entry is a `host[:port]` token, and a `*.host` wildcard matches
subdomains. We keep the file sorted alphabetically (`LC_ALL=C`).

## Documented entries

This table records why specific endpoints appear, and does not yet
cover every entry: tooling generated the initial list in bulk, and we
will backfill the rest over time, potentially from the tooling that
produced them.

<!-- markdownlint-disable MD013 -->

| Endpoint                                  | Source / reason                                                                                                                               |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `tuf-repo.github.com:443`                 | GitHub TUF trust root, fetched by `gh attestation verify` when checking the Sigstore provenance of the zizmor binary (zizmor security audit). |
| `tmaproduction.blob.core.windows.net:443` | Azure blob storage that serves GitHub's artifact attestation bundles, fetched by `gh attestation verify` during the same provenance check.    |

<!-- markdownlint-enable MD013 -->

[hr]: https://github.com/step-security/harden-runner
[block]: https://github.com/lfreleng-actions/harden-runner-block-action
