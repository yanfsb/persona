# Historical note: implementation backlog

> Archived and curated. This execution journal is not a current backlog, acceptance report, or release-status source. Use the [release notes](../releases/), [implementation matrix](../implementation-matrix.md), and [release procedure](../releasing.md) for current evidence.

The original backlog tracked work from a read-only Git identity auditor toward a bounded directory-scoped Git/GitHub guardrail. Its durable decisions are recorded in [ADR-0001](../adr/0001-directory-scoped-guardrails.md): no global persona switch; keep per-property evidence separate from authorization; fail closed for unsupported managed operations; keep tokens/private keys in native facilities; treat Zsh as optional UX; and state direct-binary/same-user bypasses plainly.

Historical checklists and local validation snapshots were deliberately omitted from this curated archive because they can be superseded by newer CI results. They must not be used as evidence that the current source passes hosted CI. Project-specific local paths, test identities and environment workarounds were omitted as well.
