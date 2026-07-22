<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# lfreleng-actions egress allow-list

`allow_list.txt` is the shared [harden-runner][hr] egress allow-list for
the `lfreleng-actions` organisation. Workflows load it with
[harden-runner-block-action][block] and run harden-runner in `block`
mode, so harden-runner denies any host this file omits.

Each entry is a `host[:port]` token, one per line, and a `*.host`
wildcard matches subdomains. We keep the file sorted alphabetically
(`LC_ALL=C`). [`harden-runner-block-action`][block] strips `#`
comments and collapses all whitespace (including newlines) into the
single space-separated string harden-runner's `allowed-endpoints`
input expects, so the multi-line, commented form in `allow_list.txt`
is purely for human readability — it has no effect on what
harden-runner sees.

## Documented entries

Every entry carries a `# comment` directly above it in `allow_list.txt`
recording its provenance: the service, and the tool, action or task
that reaches it. The [github-network-audit][audit] tool reconstructed
most notes from StepSecurity run data. Hand-written notes cover the
endpoints the audit data cannot observe, such as harden-runner's own
control-plane API.

When you add an entry, record its reason as a comment on the line(s)
above it rather than here — the file is the single source of truth for
this now. Correct or extend a comment whenever you touch an entry.

[hr]: https://github.com/step-security/harden-runner
[block]: https://github.com/lfreleng-actions/harden-runner-block-action
[audit]: https://github.com/lfreleng-actions/github-network-audit
