# Release procedure

This document describes the intended release process. A checklist is not evidence that its gates have passed. The next public release candidate must not be announced until each required check has current evidence.

## Before tagging

1. Confirm the intended version and update `Cargo.toml`, `Cargo.lock` and `flake.nix` together; update release notes without rewriting the historical `v0.1.0-rc.1` record.
2. Review changes, local docs checks, locked tests, formatting, Clippy, MSRV and Nix checks.
3. Push the candidate commit and require hosted CI to pass on macOS arm64, Linux arm64 and Linux x86_64, including installed smoke checks. A local run or workflow definition is not a substitute.
4. Confirm the private vulnerability-reporting channel is enabled and notifications reach a monitored maintainer. Confirm repository visibility and license metadata separately before public launch.
5. Review exactly what will be published: source files, Git history, tags, release assets and Nix references. Do not publish credentials, private paths, local state, or unintended internal notes.

## Source archive and checksums

Generate a versioned source archive from the exact tag and a `SHA256SUMS` file with:

```sh
scripts/package-source.sh vX.Y.Z-rc.N
```

The script reads the committed tag, writes under `target/release-artifacts/`, and refuses to overwrite prior outputs. `git archive` includes tracked source, `Cargo.lock`, Nix files and license texts while excluding `.git`, `target`, untracked build outputs and private state. Verify the checksum and extract/build the archive in a clean temporary directory before upload. A checksum detects accidental corruption; it does not authenticate the signer or establish provenance.

Do not claim prebuilt binaries, crates.io publication, signed attestations or binary-cache availability unless those distribution channels are separately implemented and verified.

## Distribution

The planned channels are tagged source archives and the Nix flake reference for the published tag, for the declared macOS arm64/Linux arm64/Linux x86_64 targets. Home Manager consumption installs the package only; it does not activate Persona policy, adapters, hooks, or account enrollment. Validate public anonymous source/Nix fetch after repository visibility changes.

## Publish and verify

After explicit maintainer authorization, create the tag/release from the reviewed candidate commit, upload source/checksum assets, then verify the release points to the expected tag/commit and that download checksums match. Run the published-source installation smoke check. Mark a release candidate as pre-release and state the exact validation performed: a limited real-account binding/read/fetch pilot was completed, but managed publication and production use were not exercised. Do not promise a release cadence or response SLA.

## Current baseline

`v0.1.0-rc.1` is a historical private release candidate; preserve its release-time evidence in [its notes](releases/v0.1.0-rc.1.md). The later failures in hosted run `42851871730` were corrected in CI-fix commit `e61a72d`; hosted run [43128664622](https://github.com/yanfsb/persona/actions/runs/43128664622) passed on all three matrix platforms. That run does not cover the candidate on `docs/open-source-prep` and is not evidence for a new release tag. Require CI on the exact reviewed candidate commit.

A limited real-account pilot verified account binding, repository metadata reads, and SSH fetch. Managed publication and production use remain untested. The repository is still private. Private vulnerability-reporting availability and monitored notifications are unconfirmed; an API 404 is inconclusive. Rights-holder attribution for the dual-license files also needs confirmation.
