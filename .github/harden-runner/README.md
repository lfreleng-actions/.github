<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# harden-runner egress allow-lists

This directory holds the shared [harden-runner][hr] egress allow-lists
for the organisation. Each `allow_list.txt` enumerates the
`host[:port]` endpoints that CI workflows may reach; harden-runner runs
in `block` mode and denies any host a list omits, so the list acts as
the single source of truth for permitted egress.

This is the network-egress sibling of the vulnerability-suppression
lists under [`../python-audit/`](../python-audit). The two serve
different tools and hold different data — endpoints here, vulnerability
IDs there — but follow the same layout because both actions share one
config resolver.

## How the lists work

[harden-runner-block-action][block] loads a list out-of-band, ahead of
harden-runner itself:

1. It fetches the `allow_list.txt` for the workflow's organisation,
   strips `#` comments and collapses all whitespace (including
   newlines) into the single space-separated string harden-runner's
   `allowed-endpoints` input expects.
2. It publishes that string as an environment variable
   (`CONNECTION_ALLOW_LIST` by default).
3. A following [step-security/harden-runner][hr] step consumes the
   variable as `allowed-endpoints` under `egress-policy: block`.

Loading the list this way means a workflow needs no org- or repo-level
GitHub variable to hold the allow-list, and it keeps working for pull
requests raised from forks.

## Layout

Files live one directory per organisation, keyed on the GitHub owner
of the repository running the workflow (`github.repository_owner`):

```text
.github/harden-runner/<org>/allow_list.txt
```

[harden-runner-block-action][block] resolves the list in this order and
uses the first file that exists:

1. `.github/harden-runner/<org>/allow_list.txt` — org-specific list
2. `.github/harden-runner/allow_list.txt` — family-wide default

## File format

One `host[:port]` entry per line, sorted alphabetically (`LC_ALL=C`). A
`*.host` entry matches subdomains. A `#` introduces a comment, either
as a full-line comment or trailing on an entry; the parser skips blank
lines.

Record why each entry is present in a `# comment` directly above it:
the service, and the tool, action or task that reaches it. The
[github-network-audit][audit] tool reconstructs most notes from
StepSecurity run data; hand-written notes cover endpoints that data
cannot observe, such as harden-runner's own control-plane API. Correct
or extend a comment whenever you touch an entry.

[hr]: https://github.com/step-security/harden-runner
[block]: https://github.com/lfreleng-actions/harden-runner-block-action
[audit]: https://github.com/lfreleng-actions/github-network-audit
