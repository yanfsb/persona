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

After explicit maintainer authorization and the exact-commit hosted CI gate, use an explicit reviewed candidate Persona executable (rather than an older shadowing PATH installation). From its managed checkout, the bounded publication sequence is:

```sh
persona run -- git tag -s -m "Persona vX.Y.Z-rc.N" vX.Y.Z-rc.N
persona check --operation tag --tag vX.Y.Z-rc.N
persona run -- git push origin refs/tags/vX.Y.Z-rc.N:refs/tags/vX.Y.Z-rc.N
scripts/package-source.sh vX.Y.Z-rc.N
# Verify SHA256SUMS and extract/build the archive before creating the release.
persona run -- gh release create vX.Y.Z-rc.N --repo OWNER/REPO --prerelease --title "Persona vX.Y.Z-rc.N" --notes "Describe changes and include exact validation evidence."
persona run -- gh release upload vX.Y.Z-rc.N target/release-artifacts/persona-vX.Y.Z-rc.N.tar.gz target/release-artifacts/SHA256SUMS --repo OWNER/REPO
```

Replace placeholders and verify the selected profile, account, exact remote/destination, signer and release commit before publication. Archive/checksum generation is local build tooling, not a managed network operation. All publication must use the managed Git/gh commands; an unsupported command or policy failure is not permission to use a native publication fallback. Never move an existing release tag. Do not append fixes or validation-note commits after the CI gate; a changed candidate needs new CI. Put final commit/run/download evidence in the GitHub prerelease record.

Asset upload requires curl 8.3+ (included in the Nix package), an existing release, and the same matching signed-tag publication policy as release creation. Files must be inside the physical worktree and satisfy the [bounded asset contract](managed-commands.md#release-asset-upload). Uploads are sequential and non-overwriting; inspect confirmed/uncertain outcomes and GitHub state before retrying only missing assets. A server failure may leave an empty starter asset. No automatic retry, replacement or deletion is provided.

Verify the release points to the expected tag/commit and that downloaded checksums match. Run the published-source/Nix installation smoke check in a disposable environment, not against private host configuration. Mark a release candidate as pre-release and state the exact validation performed. Distinguish the earlier binding/read/fetch pilot, synthetic tests, actual release creation/upload and production use; do not copy an obsolete claim that publication is untested after exercising it. Do not promise a release cadence or response SLA.

## Current baseline

`v0.1.0-rc.1` is a historical release candidate; preserve its release-time evidence in [its notes](releases/v0.1.0-rc.1.md). Hosted run [43489260619](https://github.com/yanfsb/persona/actions/runs/43489260619) passed on all three matrix platforms for the merged open-source-preparation baseline. Run [43896139595](https://github.com/yanfsb/persona/actions/runs/43896139595) passed all three platforms for `beeadd1`, including the RC2 Git/signing changes and post-tag test fixes. Neither run is evidence for subsequent `v0.1.1-rc.3` changes; require CI on the exact reviewed candidate commit before tagging.

The earlier limited real-account pilot verified account binding, repository metadata reads, and SSH fetch, not managed publication or production use. Record subsequent candidate-specific publication evidence in that release's record. GitHub reports the repository public and Apache-2.0 metadata; the private vulnerability-reporting channel is enabled. The repository owner has admin access and is the sole account returned by GitHub's contributors endpoint. Notification monitoring and separate legal rights-holder authority are not independently verified.
