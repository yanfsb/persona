# Implementation and evidence matrix

This matrix distinguishes source implementation, local tests, and hosted CI. A test in the tree is not evidence that it passed in the current release candidate. A documented target is not a stable-support promise.

## Current release gate

| Item | Current evidence | Status |
|---|---|---|
| Version | `0.1.1-rc.1`; historical predecessor at [`releases/v0.1.0-rc.1.md`](releases/v0.1.0-rc.1.md); candidate note at [`releases/v0.1.1-rc.1.md`](releases/v0.1.1-rc.1.md) | Patch release candidate; do not treat as a stable or production-security release |
| Declared targets | Apple Silicon macOS, Linux arm64, Linux x86_64 (`Cargo.toml`, CI matrix) | Target declaration only |
| CI-fix branch | Run [43128664622](https://github.com/yanfsb/persona/actions/runs/43128664622), commit `e61a72d` on `fix/ci-fixtures` | Passed on Linux x86_64, Linux arm64, and macOS arm64; this run predates and does not cover the open-source-preparation candidate. |
| Merged open-source-preparation baseline | Run [43489260619](https://github.com/yanfsb/persona/actions/runs/43489260619), merge commit `d43baba` on `main` | Passed on Linux x86_64, Linux arm64, and macOS arm64, including the workflow Nix checks. This is not evidence for the new patch candidate. |
| Earlier failed run | Run `42851871730`: Linux stale-ref race assertion and macOS key-staging fixture failed | Historical failures resolved by the CI-fix branch; preserve the RC1 release-time record below. |
| Real-provider pilot | Account binding, repository metadata read, and SSH fetch were checked in a limited local pilot | Managed publication and production use were **not** exercised; no release-readiness claim. |
| Private vulnerability reporting | GitHub API readback reports the channel enabled; repository owner `yanfsb` has admin access | Channel enabled. Notification delivery and monitoring are not independently observable from this workflow; confirm maintainer coverage before making support commitments. |
| License/public visibility | GitHub reports public visibility and Apache-2.0 metadata; Cargo declares MIT OR Apache-2.0. The GitHub contributors endpoint lists only `yanfsb` | Public visibility and metadata are observed; sole-account contribution history does not itself establish separate legal rights-holder authority. |

The CI-fix and merged open-source-preparation commits have green hosted runs on all three platforms; the merged main run also passed workflow Nix checks. The patch candidate must have a green hosted run on its exact commit and installation-smoke evidence for the released source/Nix package. Local test success does not substitute for that evidence. Do not mark a failed test skipped or retry-only to obtain a green badge.

## Source surfaces and tests

| Area | Implementation | Relevant tests/evidence | User-facing documentation |
|---|---|---|---|
| CLI, diagnostics and output | `src/main.rs`, `src/audit.rs`, `src/authorization.rs`, `src/report.rs` | `tests/cli.rs`, unit tests in source | [CLI](cli.md), [security model](security-model.md) |
| Profiles, scopes and migration | `src/config.rs`, `src/storage.rs`, `src/context.rs` | `tests/config.rs`, `tests/config_file.rs`, `tests/context.rs`, `tests/scope.rs` | [Configuration](configuration.md), [Getting started](getting-started.md) |
| Managed Git and bounded publication | `src/git_command.rs`, `src/git.rs`, `src/push.rs`, `src/git_https.rs`, `src/ssh_transport.rs` | `tests/git.rs`, `tests/git_adapter.rs`, `tests/git_https.rs`, `tests/ssh_transport.rs`, `tests/push.rs` | [Managed commands](managed-commands.md) |
| GitHub CLI and credential binding | `src/gh_adapter.rs`, `src/credential.rs` | `tests/gh_adapter.rs`, `tests/cli.rs`; provider calls use synthetic/local fixtures | [Managed commands](managed-commands.md), [Security](security-model.md) |
| Signing and tag verification | `src/gpg.rs`, `src/ssh_signature.rs` | `tests/signing.rs`, `tests/identity.rs` | [Configuration](configuration.md), [Security](security-model.md) |
| Installation, hooks, shell | `src/installer.rs`, `src/hooks.rs`, `shell/persona.zsh` | `tests/installer.rs`, `tests/hooks.rs`, `tests/shell_zsh.rs`; Nix `installed-smoke` | [Installation](installation.md), [Managed commands](managed-commands.md) |
| Documentation links/navigation | `tests/documentation.rs`, `just docs-check` | Local links and required public guide inventory | [Documentation index](README.md) |

## Intentional boundaries

- The command surface is bounded; unsupported or ambiguous managed invocations are refused.
- The adapters do not mediate direct native executables, all network clients, or hostile same-user processes. This is not a sandbox or anonymity system.
- Offline status/diagnostic paths do not contact providers or retrieve private credentials. Explicit enrollment and transport operations are online.
- Routine tests use synthetic identity/account fixtures and local services; no real provider is required. The separately performed local pilot covered only binding, repository metadata read, and SSH fetch; it did not exercise managed publication.
- A GitHub release operation cannot atomically bind a tag name to an object ID. A concurrent tag change can only be detected by a subsequent check.

## Evidence maintenance

Update this matrix when a test, platform claim, command boundary, or release gate changes. Cite exact tests and distinguish current local results from the latest hosted workflow. Historical acceptance notes are in the curated [`docs/archive`](archive/README.md); they do not override the current CI result or release note.
