# Persona Agent Guide

Guidance for coding agents working in the `persona` repository.

## Project overview

Persona is a Rust (edition 2024, MSRV `1.85`) directory-scoped Git and GitHub CLI identity guardrail targeting `aarch64-apple-darwin`, `aarch64-unknown-linux-gnu`, and `x86_64-unknown-linux-gnu`.

A single binary (`persona`) serves both the CLI and argv0-dispatched managed shims (`git`, `gh`, `ssh`, `git-credential-persona`), plus refreshable repository-local `pre-push` hooks.

Read these canonical docs before changing behavior or security boundaries:

- [Security model](docs/security-model.md)
- [Managed command surface](docs/managed-commands.md)
- [Configuration](docs/configuration.md)
- [CLI reference](docs/cli.md)
- [Contributing](CONTRIBUTING.md)
- [Release procedure](docs/releasing.md)

## Security & design invariants

Never violate these invariants when implementing features or fixes:

1. **Fail closed on required evidence.** Missing, `UNKNOWN`, duplicate, or ambiguous required evidence must block authorization. Never fall back to native passthrough when a managed command or policy check fails.
2. **Command policies never weaken identity gates.** Per-profile `[profiles.git.commands]` / `[profiles.github.commands]` allowlists and denylists only govern workflow command eligibility; they must never disable author/committer isolation, cross-profile leak checks (`cross_profile_identity_check`), signing enforcement, destination allow/deny checks, SSH key isolation, or GitHub account/repository binding.
3. **Offline diagnostics stay offline.** `persona status` and `persona doctor` must not perform network I/O, DNS, SSH, `gh` calls, hook execution, credential helper invocations, or private-key/token reads (except explicitly requested online verification flows).
4. **No secret leakage.** Never pass tokens in argv, never store raw tokens (only account identifiers and keyed fingerprints), never leak `GH_TOKEN` into repo hooks or filters, and never emit secrets in errors or logs.
5. **Managed `HOME` isolation vs. credential lookup.** Managed network Git commands (`push`, `fetch`, `pull`, `clone`, `ls-remote`) isolate `HOME` to a temporary directory alongside `GIT_CONFIG_GLOBAL=/dev/null` while passing `PERSONA_REAL_HOME` so `git-credential-persona` (`src/credential.rs`) can still resolve OS keychains/credentials (e.g., `gh auth token` on macOS Keychain). Preserve this split.
6. **Bounded worktree asset uploads.** Release asset uploads (`src/asset_upload.rs`) must keep descriptor-relative no-follow reads confined to the physical worktree, disable curl config/proxies, reject redirects, and never auto-retry, overwrite, or delete assets.

## Repository map

- **Policy, config & context:** `src/lib.rs` (scope resolution), `src/config.rs`, `src/context.rs`, `src/paths.rs`, `src/storage.rs`, `src/command_policy.rs`, `src/destination.rs`, `src/authorization.rs`, `src/report.rs`
- **Auditing & signing:** `src/audit.rs`, `src/git.rs`, `src/gpg.rs`, `src/ssh_signature.rs`, `src/push.rs`
- **Managed adapters & transport:** `src/git_command.rs`, `src/git_adapter.rs`, `src/git_https.rs`, `src/ssh_adapter.rs`, `src/ssh_transport.rs`, `src/gh_adapter.rs`, `src/gh_runner.rs`, `src/asset_upload.rs`, `src/credential.rs`, `src/runner.rs`, `src/runtime.rs`
- **CLI, hooks & installation:** `src/main.rs`, `src/installer.rs`, `src/hooks.rs`, `src/pre_push.rs`, `src/push_handoff.rs`
- **Tests:** `tests/*.rs` integration suites (notably `tests/cli.rs`, `tests/git_adapter.rs`, `tests/gh_adapter.rs`, `tests/push.rs`, `tests/signing.rs`, `tests/installer.rs`, and [tests/documentation.rs](tests/documentation.rs))
- **Packaging & tooling:** [Justfile](Justfile), [flake.nix](flake.nix), [scripts/package-source.sh](scripts/package-source.sh), `shell/persona.zsh`

## Development & validation commands

Use [Justfile](Justfile) recipes so locked dependencies, `--features test-support`, MSRV, and native fixture tools match CI:

```sh
just fmt           # format Rust sources
just fmt-check     # verify formatting
just test          # full locked test suite (--features test-support, --test-threads=1)
just clippy        # clippy --all-targets --features test-support -- -D warnings
just msrv-check    # cargo +1.85 check --locked --all-targets --features test-support
just docs-check    # cargo test --locked --test documentation
just check         # fmt-check + test + clippy + msrv-check + docs-check
just build         # cargo build --locked --release
```

For Nix package and smoke validation (builds package + runs `test`, `clippy`, `fmt`, `installed-smoke`):

```sh
nix flake check --print-build-logs
```

### Important local gotchas

- **Installed shims on `PATH`:** If Persona shims (`git`, `gh`, `ssh`) are installed in a user bin directory (such as `~/.local/bin`), `command -v git` inside `just test` or native executable resolution during `persona install refresh` may pick up the shim instead of the real binary. Strip the shim directory from `PATH` when resolving native tools or running tests if shim shadowing occurs.
- **Single-threaded integration tests:** Always run the full suite with `--features test-support -- --test-threads=1` (as `just test` does) to avoid process-global/env races in integration tests.
- **No silent test skips:** Do not turn failures into skips or retries to make CI pass. Nix sandbox skips are explicitly justified via `PERSONA_TEST_SKIP_*` in [flake.nix](flake.nix).

## Privacy, fixtures & documentation rules

- **Synthetic data only:** Never include real identities, personal emails, local absolute paths, tokens, private keys, credential-store data, or live provider output in code, tests, fixtures, docs, or commits. Always use synthetic identities and `.invalid` domains (e.g., `author@example.invalid`).
- **No live provider tests:** Tests must use local fixtures and synthetic identities; never run automated tests against real GitHub accounts or remote repositories.
- **Keep docs & links synchronized:** When changing CLI commands, configuration fields, or managed command behavior, update the relevant guide(s) (`docs/cli.md`, `docs/configuration.md`, `docs/managed-commands.md`, `docs/security-model.md`, [implementation matrix](docs/implementation-matrix.md)) and CLI help. [tests/documentation.rs](tests/documentation.rs) validates all local Markdown links across the entire repository and parses the synthetic TOML example in [docs/configuration.md](docs/configuration.md), so always run `just docs-check` after editing any `.md` file.
- **Dual license:** Contributions are under `MIT OR Apache-2.0`.

## Release workflow essentials

Follow [docs/releasing.md](docs/releasing.md) strictly for releases:

1. Bump the version consistently across `Cargo.toml`, `Cargo.lock`, [flake.nix](flake.nix), `README.md`, `docs/releases/README.md`, and a new `docs/releases/vX.Y.Z-rc.N.md` note (never rewrite historical release records).
2. Run `just check`, `just build`, and `nix flake check` locally, then require green hosted CI on the **exact final candidate commit** across Linux x86_64, Linux aarch64, and macOS aarch64 before tagging.
3. Do not append commits after the CI gate without re-running CI, and never move an existing release tag.
4. Generate source archives and checksums with [scripts/package-source.sh](scripts/package-source.sh), verify `SHA256SUMS`, and publish tags/releases/assets strictly through managed `persona run -- git ...` and `persona run -- gh release ...` commands.
