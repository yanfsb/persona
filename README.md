# Persona

Persona is a directory-scoped Git/GitHub identity guardrail for developers who use more than one identity on the same macOS or Linux account. Its managed adapters enforce identity, signing, destination, SSH, and GitHub account separation while letting each profile configure allowed/denied commands for everyday workflows.

> **Release candidate:** `0.2.0-rc.1` shifts Persona to identity-separation guardrails with configurable allowlist/denylist command policies (`denylist` by default across `git`, `gh`, and `persona run`), wildcard owner/destination rules with explicit denies, `remote_tracking` upstream provenance, cross-profile commit identity checks, `persona baseline update`, and `persona hooks refresh`. The earlier limited real-account pilot covered binding, repository metadata reads, and SSH fetch, and `v0.1.1-rc.3` exercised managed tag push and GitHub release publication; release-specific publication evidence belongs in the published release record. Production use has not been evaluated. Do not rely on this release candidate as a production security boundary.

Persona is **not** a sandbox, firewall, anonymity system, or universal Git/GitHub replacement. Direct native binaries and hostile processes running as the same OS user can bypass its managed paths. See the [security model](docs/security-model.md) before use.

## What Persona does

- Associates local Git identities, signing policy, destinations (`OWNER/*` wildcards and `deny_destinations`), cross-profile leak checks, and optional GitHub account bindings (`repositories` and `deny_repositories`) with directory scopes.
- Evaluates configurable per-profile allowlists and denylists across managed `git`, `gh`, and `persona run` commands (`denylist` by default so day-to-day workflows keep moving while identity boundaries hold).
- Provides offline status/diagnostics and explicit policy checks (`status`, `doctor`, `check`, `baseline update`).
- Optionally installs managed `git`, `gh`, `ssh`, and credential-helper adapters, plus refreshable repository-local pre-push hooks.

Start with the [configuration](docs/configuration.md) and [managed command reference](docs/managed-commands.md); passing a local check is evidence only for the properties it examined.

## Quick start

Build from a checkout with Rust 1.85 or newer and the native tools listed in [Installation](docs/installation.md):

```sh
cargo build --locked --release
./target/release/persona --help
./target/release/persona status
```

Status and diagnostics are offline. For the safe setup flow and synthetic configuration examples, see [Getting started](docs/getting-started.md). Review a change with `--preview` before applying it; do not put credentials, private keys, or personal paths in a checked-in policy.

## Install

The project currently documents source builds and Nix packaging for Apple Silicon macOS and Linux arm64/x86_64. There are no prebuilt binary downloads or crates.io package. See [installation options and rollback](docs/installation.md).

## Documentation

- [Documentation index](docs/README.md)
- [Getting started](docs/getting-started.md)
- [Installation](docs/installation.md)
- [Configuration](docs/configuration.md)
- [CLI reference](docs/cli.md)
- [Managed Git and GitHub commands](docs/managed-commands.md)
- [Security model and limitations](docs/security-model.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Contributing](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)
- [Release procedure](docs/releasing.md)
- [Architecture decisions](docs/adr/0001-directory-scoped-guardrails.md)
- [Implementation and evidence matrix](docs/implementation-matrix.md)
- [Release notes](docs/releases/)

## Status and validation

The current source declares macOS arm64 and Linux arm64/x86_64 targets. A target is not a promise of stable support. Hosted CI passed on all three platforms for the CI-fix commit `e61a72d` and for the open-source-preparation candidate commit `a30dfa2` ([run 43361382293](https://github.com/yanfsb/persona/actions/runs/43361382293)), including the workflow Nix checks. This is not a release-readiness claim; a new public RC still requires CI on its exact candidate commit and installation smoke checks. The earlier limited pilot did not test managed publication; consult each release's publication record for its exact subsequent evidence. See the [evidence matrix](docs/implementation-matrix.md) and [release checklist](docs/releasing.md).

## License

Persona is offered under either the [MIT License](LICENSE-MIT) or [Apache License, Version 2.0](LICENSE-APACHE), at your option. See [CONTRIBUTING](CONTRIBUTING.md) for contribution terms.
