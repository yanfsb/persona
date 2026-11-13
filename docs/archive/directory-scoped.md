# Historical note: initial directory-scoped plan

> Archived and curated. This is not a current specification or user guide. Superseded by [ADR-0001](../adr/0001-directory-scoped-guardrails.md) and the [current implementation matrix](../implementation-matrix.md).

The initial proposal explored selecting distinct Git identity, signing, SSH and GitHub account context by directory while keeping one operating-system account. Its core goals were predictable nested-directory/worktree selection, no global account switching, local diagnostics, and explicit limits on claims of anonymity or isolation.

The draft began as research for a read-only auditor. That stage and its proposed implementation constraints are obsolete: the current project is the Rust `persona` CLI with bounded managed adapters. Original local development paths, environment inventory, handles and personal workflow constraints were intentionally omitted from this public-facing archive summary.
