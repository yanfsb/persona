# Historical note: CLI architecture sketch

> Archived and curated. This proposal is not the implementation contract. See [ADR-0001](../adr/0001-directory-scoped-guardrails.md), [CLI reference](../cli.md), and [managed commands](../managed-commands.md).

The sketch proposed a directory-aware identity tool with offline diagnostics, policy files, explicit integration installation, and a fail-closed approach for operations whose context could not be established. It considered optional shell UX and reproducible Nix/Cargo distribution.

The proposed command name `idctx`, interaction examples and feature list were provisional and are not promises of current behavior. The current binary is named `persona`; exact supported operations are documented in the current CLI and managed-command references. Personal paths and environment-specific examples from the draft were intentionally omitted from this archive summary.
