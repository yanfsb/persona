# Implementation backlog

## Completed

- [x] Add repository hygiene for Rust build artifacts.
- [x] Make Git integration tests discover the local Git executable through `Justfile` without a machine-specific path.
- [x] Establish format, test, and Clippy validation commands.

## Approved implementation steps

1. [DONE:1] Establish the repository validation baseline (`just check`).
2. [DONE:2] Implement the offline per-property status report, deterministic aggregation, versioned JSON/text output, and bounded subprocess runner, including process-group cleanup for descendant-held pipes.
3. [DONE:3] Integrate the physical Git checkout/worktree root before scope selection, observe effective Git author and committer identities through the controlled Git runner, and add the non-mutating `check` command with expected/observed/unknown findings. Signing, remotes, publication, SSH, and `gh` remain UNKNOWN for later steps.
4. [DONE:4] Add offline OpenPGP policy and verification. A scope may define `[scopes.git.signing]` with a full 40-hex primary `fingerprint` and an absolute `public_key` path to an exported public-key file. The checker observes effective Git signing configuration, signature presence, cryptographic validity, and the verified primary fingerprint separately. It imports only the configured public key into a temporary GnuPG home, never reads the user's GnuPG home/config/keyring, and performs no key retrieval or pinentry operation. Verification passes the selected absolute GPG executable through highest-precedence Git command-line configuration, so repository `gpg.program` helpers cannot replace it. Missing GPG or unavailable keys remain UNKNOWN; signing fixtures require GPG and fail with an actionable message when it is unavailable. Configured key files must be ASCII-armored public-only exports: private/secret armor is rejected before import, and a bounded GnuPG show-only packet parse rejects secret packet records.

Step 4 residual risks: verification covers the current `HEAD` commit only; it does not prove future commits, publication credentials, or network safety. Git signing configuration that uses an implicit/default or non-full key fails the signing-config property rather than being overclaimed as authorized; inability to observe effective Git configuration remains UNKNOWN.

Residual limitation: process-group cleanup cannot contain a descendant that escapes its process group; this implementation does not overclaim containment beyond that boundary.

5. [DONE:5] Add a non-network `check --operation push` audit. The hook-facing contract is `--remote <name> --destination <effective-url>` plus stdin lines in native pre-push shape (`local_ref local_oid remote_ref remote_oid`). A scope may define `[scopes.git.push]` with one exact `remote` and a non-empty exact `destinations` array. The audit reads only local Git configuration and objects; it never runs push, fetch, or ls-remote. It resolves pushurl/url values and local pushInsteadOf/insteadOf rewrites without printing destination values, then checks every locally bounded outgoing commit author and committer against the scope policy.

For a scope with a required OpenPGP signing policy, every outgoing commit in the supported update is checked independently for signature presence, cryptographic validity, and the allowed full primary fingerprint using the existing isolated temporary keyring and explicitly selected GPG executable. Known unsigned, invalid, or wrong-signer commits are FAIL; missing key/tool/object evidence is UNKNOWN. A scope without a signing policy reports outgoing signing as UNKNOWN rather than treating unsigned history as safe. Deletions, new branches, force updates, multiple updates, tag/non-branch updates, missing objects, shallow/partial repositories, and incomplete bounds remain UNKNOWN rather than PASS. Destination policy checks do not prove credentials or remote account ownership.

Step 5 limitations: annotated tag metadata/signatures are explicitly unsupported and reported UNKNOWN; exact destination matching does not establish authentication or current remote state; only caller-supplied tuples are audited, so this command is not a substitute for a hook receiving native Git input.

6. [DONE:6] Add cautious offline SSH/HTTPS/GitHub environment reporting. Inspect only parent-process variable presence for GH_TOKEN/GITHUB_TOKEN (with documented precedence), GH_HOST, GH_CONFIG_DIR, GIT_SSH, GIT_SSH_COMMAND, and SSH_AUTH_SOCK; never read values, auth files, Keychain, SSH configuration, or credential helpers. Observe only configured remote transport schemes through Git builtins, without exposing URL values. SSH and GitHub authenticated principals, account ownership, and HTTPS/SSH authentication remain UNKNOWN; no ssh, gh, helper, DNS, or network probe is performed.

Step 6 limitations: environment-variable presence and configured transport schemes are indicators only and do not prove selected principals, credentials, reachability, or account authentication. URI scheme parsing accepts only valid syntax and known transport schemes; malformed or unsupported values become `unknown` without serializing arbitrary URL text. Token and path values are deliberately not serialized.

7. [DONE:7] Add reproducible Nix packaging/checks for aarch64-darwin, make GPG available to checks, and document the CLI/configuration/offline contracts. The pinned flake evaluates and its package, format, test, and Clippy checks pass.
8. [DONE:8] Complete final validation and independent review. `just check`, `git diff --check`, `nix flake check`, and `nix build .#persona --no-link` passed. Nix validation was run from a temporary copy because this initial repository has no tracked files; no project files were staged or committed. Final read-only security review found no issues.

## Backlog

- [ ] Complete the Phase 0 research and architecture decision review in `directory-scoped.md`.
- [ ] Run the disposable Phase 1 proof-of-concept test matrix with explicit authorization.
- [ ] Decide whether native configuration is sufficient before expanding the Rust implementation.
