# Consolidated TODO

This checklist brings together the open-source preparation work and the local Persona pilot. It is a working plan, not evidence that a release gate has passed.

## Completed

- [x] **CI fixes:** signed commit [`e61a72d`](https://github.com/yanfsb/persona/commit/e61a72dca799f0a1c8cab3c28fcd007940c906ad) on `fix/ci-fixtures`; hosted CI passed on Linux x86_64, Linux arm64, and macOS arm64 ([run 43128664622](https://github.com/yanfsb/persona/actions/runs/43128664622)).
- [x] **Open-source preparation drafted:** focused guides, dual-license files, contribution/security policies, documentation tests, and source-packaging tooling. These changes have not yet passed CI as a combined candidate.
- [x] **Local pilot configured:** scoped identity, GitHub account binding, SSH fetch, signing checks, and a pre-push hook limited to the Persona repository. Global shims were not installed. A managed provider push was not tested.

## P0 — Reconcile both workstreams

- [x] **T01 — Preserve and review the combined diff.** The documentation work is isolated on `docs/open-source-prep`, based on the green CI-fix commit; the `fix/ci-fixtures` remote branch was not rewritten. Preserve all uncommitted changes. Use separate worktrees before concurrent sessions.
- [x] **T02 — Correct current validation claims.** Updated the README, evidence matrix, security model, and release docs: the CI-fix branch passed; a limited real-account read/fetch pilot succeeded; managed publication remains untested. Kept RC1 release-time evidence separate from later results.
- [x] **T03 — Consolidate pilot recovery instructions privately.** Private recovery notes now record hook removal, rollback backups, and pinned-baseline maintenance outside the repository. No tokens or private-key material were copied into them.

## P1 — Validate the combined candidate

- [x] **T04 — Review documentation against actual CLI behavior.** Compared documented command families and examples with source-built Clap help; clarified that `--online-verified` is the explicit online check. The managed-operation grammar remains deliberately bounded and points readers to the implementation matrix/tests.
- [x] **T05 — Run combined local validation.** `just check` passed formatting, all targets/tests, Clippy, MSRV 1.85, and documentation tests; `just build` passed; `actionlint` from the flake-locked Nixpkgs revision passed on `.github/workflows/ci.yml`; `nix flake check` passed all five checks on local `aarch64-darwin`. Nix skipped Linux systems locally, and the existing hosted CI run still does **not** cover this candidate. The full suite exposed a concurrent one-time push-handoff race; exclusive nonblocking file locking is now held through authorization/consumption, and the integration test holds the handoff lock in a helper process while a real competing hook runs; both that test and lock-exclusion tests pass.
- [x] **T06 — Serialize concurrent configuration updates.** Added a private-state advisory lock held from config load through atomic write for profile, scope, GitHub enroll/unbind, migration, and rollback mutations. Enrollment reloads current config after its online step before applying the binding. Storage tests verify lock exclusion and latest-content reads; a multi-process CLI test gates Git after one scope mutation has loaded config, while a test-support-only signal confirms the second process received kernel lock contention before release. Both updates survive. Test support is enabled only in test/CI checks, not release builds. `just check`, the release build, and all five local aarch64-darwin Nix checks pass.
- [x] **T07 — Validate release packaging.** In disposable snapshot `/tmp/persona-source-package-final.ndFP2q`, created a temporary test commit/tag (`v0.1.0-test.2`, not in this repository), packaged the final candidate, verified `SHA256SUMS`, extracted it, and passed `cargo build --locked --release`. `nix flake check` passed all five aarch64-darwin checks from the extracted archive, including installed-smoke install, refresh, remove, and rollback. Linux systems were skipped locally.

## P2 — Public-release gates

- [x] **T08 — Confirm licensing attribution and ownership.** Owner confirmed Persona is currently a solo project and intends a later open-source release. Dual licensing remains `MIT OR Apache-2.0`; the generic `Persona contributors` notice is retained for now. Reconfirm the desired public-facing holder name before publication.
- [x] **T09 — Review publication exposure.** Read-only review of the current candidate, all 12 local commits, the sole tag/release (`v0.1.0-rc.1`), and its downloaded assets. Gitleaks 8.28.0 scanned the working tree and Git history; its only matches were the documented synthetic HTTPS fixture private keys. The RC1 archive checksum verified and it contains the same fixtures. The repository remains private; no publication or visibility changes were made.
- [ ] **T10 — Resolve private vulnerability reporting.** The repository remains private. GitHub returned 404 for the private-vulnerability-reporting endpoint and `security_and_analysis` was null; this does not establish whether reporting is disabled or unavailable. Confirm the setting, activation order, and monitored notifications.
- [ ] **T11 — Select the next RC and validate its exact commit.** Coordinate versions and release notes; require a fresh hosted CI pass on all three platforms.
- [ ] **T12 — Publish only with separate authorization.** Merge/push beyond the CI-fix branch, change repository visibility, create tags/releases, or update the dotfiles pin only with explicit authorization. The pilot policy currently denies tag publication.

## Later — Expand the personal rollout

- [ ] **T13 — Identify repositories needing another persona** before adding any further scopes.
- [ ] **T14 — Consider a controlled managed provider-push test** with explicit authorization. Do not rewrite history to address the three historical commits reported by GitHub as `bad_email`.
- [ ] **T15 — Reassess global shims/hooks** only after the pilot and repository exceptions are understood.

## Recommended order

`T01 → T02 → T04 → T05`, then resolve any findings before proceeding through `T06–T12`. Keep `T13–T15` separate from public-release readiness.
