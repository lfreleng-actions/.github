<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# harden-runner egress allow-lists

This directory holds the shared [harden-runner][hr] egress allow-lists
for the organisation. Each list enumerates the
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
of the repository running the workflow (`github.repository_owner`),
alongside the purpose-specific lists described below:

```text
.github/harden-runner/<org>/allow_list.txt
```

[harden-runner-block-action][block] resolves the list in this order and
uses the first file that exists:

1. `.github/harden-runner/<org>/allow_list.txt` — org-specific list
2. `.github/harden-runner/allow_list.txt` — family-wide default

When both miss, as they do in a fork, the action falls back to the
one directory under `.github/harden-runner/` that holds a file with
the requested name. That fallback works while a single
`allow_list.txt` exists here, and fails once there are two.

The organisation list stays the baseline for general workflows.

### Purpose-specific lists

[`lf-gerrit-servers/`](lf-gerrit-servers/) is the first directory
here that is not an organisation. Its
[`gerrit_servers.txt`](lf-gerrit-servers/gerrit_servers.txt) holds
the Linux Foundation project Gerrit servers and nothing else, on both
the SSH (`29418`) and HTTPS (`443`) ports. A job that talks to
nothing beyond GitHub and a project Gerrit, such as a Gerrit vote, can
load it by itself in `block` mode; a job that needs both lists loads the
organisation list as `config` and this one as `supplemental_config`.
Its entries also appear in the organisation list on purpose, so a
workflow can move between the two without both changing in lockstep.

Never name a list in such a directory `allow_list.txt`: a
second file of that name makes the fork fallback above ambiguous, and
it then fails for every fork. Give the file a descriptive name and
have consumers load it by explicit path, which never falls back:

```yaml
- uses: lfreleng-actions/harden-runner-block-action@<sha>  # <version>
  with:
    config: 'lfreleng-actions//.github/harden-runner/lf-gerrit-servers/gerrit_servers.txt@<sha>'
```

## File format

One `host[:port]` entry per line, sorted alphabetically (`LC_ALL=C`). A
`#` introduces a comment, either as a full-line comment or trailing on
an entry; the parser skips blank lines.

A `*.host` wildcard matches every name below `host`, at any depth, but
not the bare apex, and it opens the first port listed for it and no
other. An explicit entry overrides any wildcard for its host and opens
its own ports alone. So a host reached on a second port, such as an apt
mirror over plain HTTP, needs explicit entries for every port it uses. The
[repository README](../../README.md#how-entries-match) gives the
evidence; the [probe workflow](../workflows/allow-list-probe.yaml)
checks these rules on amd64 and arm64.

Record why each entry is present in a `# comment` directly above it:
the service, and the tool, action or task that reaches it. The
[github-network-audit][audit] tool reconstructs most notes from
StepSecurity run data; hand-written notes cover endpoints that data
cannot observe, such as harden-runner's own control-plane API. Correct
or extend a comment whenever you touch an entry.

## Every hostname must resolve

Before enabling block mode, harden-runner resolves every non-wildcard
entry. If any one fails to resolve to an A record, it reverts and the
job runs with no egress filtering at all, while still reporting
success. So remove or correct an entry once its host goes away, rather
than leaving it in place as harmless.

Two safeguards back this up:

- [harden-runner-block-action][block] checks each hostname first and,
  by default, drops any that no longer resolve before harden-runner
  sees them (`invalid_records: filter`).
- The daily [`allow-list-dns-check.yaml`][dns-check] workflow checks
  the organisation list and the Gerrit servers list on the default
  branch and at the latest release, and posts any hostname that no
  longer resolves to `#releng-scm`.

[hr]: https://github.com/step-security/harden-runner
[block]: https://github.com/lfreleng-actions/harden-runner-block-action
[audit]: https://github.com/lfreleng-actions/github-network-audit
[dns-check]: ../workflows/allow-list-dns-check.yaml
