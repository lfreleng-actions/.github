<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# python-audit vulnerability allow-lists

This directory holds the shared vulnerability allow-lists consumed by
[python-audit-action][audit]. Each `allow_list.txt` lists the
vulnerability IDs that [pip-audit][pip-audit] should ignore across an
organisation's Python CI, so the organisation suppresses a disputed,
unfixable or runner-image-bound advisory once, here, instead of in
every calling workflow.

This is the vulnerability-suppression sibling of the network egress
allow-lists under [`../harden-runner/`](../harden-runner). The two
serve different tools and hold different data — vulnerability IDs here,
`host:port` endpoints there — but follow the same layout because both
actions share one config resolver.

## Layout

Files live one directory per organisation, keyed on the GitHub owner
of the repository running the workflow (`github.repository_owner`):

```text
.github/python-audit/<org>/allow_list.txt
```

[python-audit-action][audit] resolves the list in this order and uses
the first file that exists:

1. `.github/python-audit/<org>/allow_list.txt` — org-specific list
2. `.github/python-audit/allow_list.txt` — family-wide default

When neither file exists the action proceeds with the caller's
`ignore_vulns` input alone (a missing central list is not an error).

## File format

Whitespace-separated vulnerability IDs, one per line by convention. A
`#` introduces a comment, either as a full-line comment or trailing on
an entry; the parser skips blank lines. IDs from this file merge with
the caller's `ignore_vulns` input, dropping duplicates.

The action validates every token against the shapes it recognises
(`CVE-`, `GHSA-`, `PYSEC-`, `OSV-`, `PVE-`) and drops anything else
before passing the merged list to pip-audit, so a malformed or injected
token never reaches the CLI.

Record why each ID is present in a `# comment` directly above it: the
package, the advisory, and whether the entry is temporary (pending an
upstream fix or a runner-image bump) or permanent (a disputed or
won't-fix advisory). Link the upstream issue or advisory where one
exists, and remove entries once they no longer apply.

[audit]: https://github.com/lfreleng-actions/python-audit-action
[pip-audit]: https://github.com/pypa/pip-audit
