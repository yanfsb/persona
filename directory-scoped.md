# Directory-Scoped Identity — Initial Plan

**Status:** Draft / architecture discovery
**Date:** 2026-10-24
**Implementation language (tentative):** Rust
**Stage:** Research and proof of concept; **do not implement the full CLI yet**.

## 1. Problem

I want to operate a personal developer identity and a persistent pseudonymous identity on **the same macOS user account**, preserving my existing day-to-day workflow. Projects should use the intended Git author/committer, signing key, SSH credentials, and GitHub account without accidental cross-identity publication.

The objective is **reliable identity context and prevention of operational mistakes**, not a claim of strong anonymity or process isolation. The pseudonymous identity must not be publicly correlated with the personal identity through avoidable technical metadata.

### Existing environment and constraints

- macOS on Apple Silicon; `nix-darwin`, Home Manager and Nix tooling.
- Zsh, Neovim, tmux, Git, GitHub CLI (`gh`), SSH/GPG, and `direnv`.
- Projects are under `~/www`, organized by area, **not** by identity.
- Existing areas include `btc/`, `merge-ti/`, `personal-projects/`, `learning-repos/`, `other-repos/`, `sollus-repos/`, and `vinteum-repos/`.
- Some projects use **linked Git worktrees**; multiple tmux panes can operate concurrently.
- **Do not move or rename repositories, recreate the development environment, add a macOS user, or introduce a VM.**
- Avoid publishing persona-specific handles, paths, credentials or identifiers in public dotfiles.

## 2. Goals

1. Select an **expected identity from a directory scope**, without tying identity to repository organization.
2. Reuse native Git, SSH and `gh` features instead of reimplementing authentication or configuration parsing.
3. Validate the **effective** identity before sensitive operations, particularly publication.
4. Allow simultaneous personal and pseudonymous contexts in separate tmux panes, with no global account switch.
5. Preserve direct use of `git`, `gh`, Neovim and coding agents where possible.
6. Keep the implementation small, deterministic, testable and distributable via Nix.
7. Clearly distinguish verified properties, unverified assumptions and known OPSEC limitations.

## 3. Non-goals

- Anonymizing network traffic, enforcing Tor/VPN routing, leak-proofing DNS, or acting as a firewall.
- Isolating processes, Keychain access, files, clipboard, telemetry or other resources belonging to the same macOS user.
- Storing passwords, access tokens or private keys in the application's configuration.
- Replacing Git, SSH, GPG, `gh`, `direnv` or Nix.
- Building a daemon, universal plugin framework, custom shell or generic policy DSL.
- Automatically changing global Git/SSH/`gh` state when switching between projects.

## 4. Threat model and boundaries

**Prioritized:** accidental author/committer or email exposure; wrong signing key; wrong SSH/GitHub credential; pushing to an unintended remote; old commits with identifying metadata; environment variables overriding expected settings; errors when navigating worktrees and scopes.

**Out of scope for this tool:** a compromised macOS user session, malicious local programs, platform-side correlation, behavioral fingerprinting, payment correlation, endpoint compromise and global traffic analysis. Both identities share one OS user, so neither cryptographic nor process isolation should be asserted.

**Operating principle:** a positive local identity check does **not** mean an operation is network-anonymous. A Git `pre-push` hook may run after some contact with the remote has occurred. Network policy requires a separate design and verification process.

## 5. Proposed architecture — hypothesis, not final decision

Start with **native configuration plus a small Rust policy/audit CLI**, rather than a new directory activation runtime.

    Current directory / repository
            |
            v
    Scope resolver (expected identity)
            |
            v
    Rust identity inspector / policy checker
            |
            +--> Git effective author / committer / signing config
            +--> SSH authentication configuration / selected key
            +--> GitHub CLI configuration / effective authenticated account
            +--> Remote + outgoing commit metadata
            |
            v
    Findings: PASS / WARN / FAIL / UNKNOWN

### Native mechanisms to evaluate first

- **Git:** conditional include using `includeIf "worktree:..."` for scope-based configuration, especially linked worktrees; evaluate Git version compatibility. `user.useConfigOnly` may help avoid inferred identity. Check higher-priority local/worktree config, command-line options, and `GIT_AUTHOR_*` / `GIT_COMMITTER_*` overrides.
- **SSH:** distinct credentials and explicit host aliases / repository remotes. Assess key selection, agent behavior, and signing independently of author metadata.
- **GitHub CLI:** distinct `GH_CONFIG_DIR` contexts, but verify the **effective account**; `GH_TOKEN` and `GITHUB_TOKEN` override stored credentials. Investigate Keychain behavior and do not assume separated config directories guarantee separated secrets.
- **GPG / signing:** separate cryptographic identities and configured signing keys; potentially hardware-backed, but YubiKey integration is optional to the MVP.
- **direnv / shell:** use only if an actual gap requires environment activation. Do not duplicate its lifecycle management prematurely.

**Key distinction:** a Git commit's author, the SSH/HTTPS credential used to push, the GitHub account used by `gh`, and the outbound network path are independent facts. Validate each separately.

### Candidate CLI (only if justified by the POC)

    identity status                  # scope + expected identity + effective state
    identity check                   # local verification, no implicit network calls
    identity check --operation push  # publication-oriented metadata/policy check

Potential internal modules (adjust only when required): `config`, `scope`, `inspect`, `policy`, `cli`. Prefer Rust standard library and small, justified dependencies (`serde` + `toml` if TOML is chosen). Avoid a framework until needed.

### Example scope policy (illustrative, not production config)

    # ~/.config/identity/config.toml
    # Outside repos; never commit real pseudonym identifiers into public dotfiles.

    [[scopes]]
    path = "~/www/pseudonymous-repos"
    identity = "pseudonym"

    # Existing workspaces may continue to use the personal identity.
    [[scopes]]
    path = "~/www/btc"
    identity = "personal"

Resolution should use canonical paths, directory-component boundaries and the most specific matching ancestor. Define how to handle symlinks, worktrees, nested exceptions, missing directories and paths outside configured scopes. Prefer `unmanaged` to silently assuming an identity in unknown locations.

## 6. Research questions — must be answered before implementation

1. Can native Git `includeIf "worktree:..."` represent every relevant path in our `~/www` layout, including linked worktrees, nested repos and symlinked paths? Which Git version is required?
2. How do local/worktree config and Git environment variables override conditional includes? Can we reliably detect mismatches before commit or push?
3. Can two simultaneous panes use separate `gh` accounts without `gh auth switch`? What is the actual macOS Keychain behavior under different `GH_CONFIG_DIR` values?
4. What is the safest deterministic way to select SSH authentication and signing credentials? Can all checks be done offline, and which require explicit network access?
5. Do we need automatic shell activation at all? What is not solved by Git config + explicit `direnv` + verification?
6. What happens to long-lived editor/agent processes started before changing directories?
7. What can an ordinary `pre-commit` / `pre-push` hook enforce, what can bypass it, and what can already leak before it runs?
8. Which capabilities belong in a standalone identity auditor versus a separately designed network policy?

## 7. Proof of concept — disposable, no real pseudonymous account needed

Test using dummy identities, repositories and local remotes. Do not expose personal details in recorded results.

| Test                                         | Expected observation                                                         |
| -------------------------------------------- | ---------------------------------------------------------------------------- |
| Normal repository under each scope           | Correct effective author, committer, signing configuration                   |
| Linked worktree in a different scope         | Worktree's physical path controls the expected identity                      |
| Nested scope / symlink                       | Documented deterministic resolution                                          |
| Personal and pseudonymous panes in tmux      | No global mutable account state or cross-pane contamination                  |
| `GIT_AUTHOR_EMAIL` / local Git overrides     | Mismatch detected; no false PASS                                             |
| Inherited `GH_TOKEN` or `GITHUB_TOKEN`       | Precedence detected and status reported accurately                           |
| Incorrect SSH key or remote                  | Check fails or reports UNKNOWN; never silently passes                        |
| Outgoing history contains wrong author       | Publish check detects offending commits, not only `HEAD`                     |
| `direnv` / `nix develop` / persistent editor | No unexplained identity changes; limitations documented                      |
| Scope missing or profile invalid             | Explicit error/unknown; no silent fallback to personal for pseudonymous work |

Use local fixtures wherever possible. Do not perform live authentication or network probing without explicit approval. Record Git/`gh`/SSH versions and environment details.

## 8. Decision gate

After the POC, explicitly choose and justify **one** of:

- **A. Native-only:** no new CLI if Git/SSH/`gh`/`direnv` and simple checks sufficiently solve the problem.
- **B. Rust auditor (current favorite):** read-only context resolver, effective-state inspection and policy checks; native tools continue to apply configuration.
- **C. Rust runtime + Zsh adapter:** only if evidence shows automatic environment activation is needed and cannot be safely composed from existing tools.

Do **not** assume option C is better because it is more feature-rich. Estimate implementation and long-term maintenance costs, possible false confidence and failure modes for each choice.

## 9. Delivery phases

### Phase 0 — Research and architecture review

- Verify current primary documentation and compatibility with the installed tool versions.
- Audit the relevant current configuration **read-only**, if access is available; redact identifiers and secrets.
- Propose an ADR containing alternatives, risks, trade-offs and a decision gate.
- Identify invariants that can actually be enforced versus only observed.

### Phase 1 — POC

- Build disposable test repos/worktrees and identity configurations.
- Run the test matrix in Section 7; capture reproducible evidence.
- Prove that two tmux panes can operate concurrently without account switching.
- Identify gaps and decide whether custom Rust code is necessary.

### Phase 2 — Minimal implementation (conditional)

- Only if Phase 1 justifies it, implement the smallest Rust CLI with scope resolution, status and non-mutating policy checks.
- Return machine-readable findings and meaningful exit codes; distinguish PASS, WARN, FAIL and UNKNOWN.
- Add unit tests for path resolution and precedence; integration tests around Git/SSH/`gh` using isolated test state.
- Package reproducibly with Nix; avoid touching existing repos or global settings by default.

### Phase 3 — Optional integration

- Add Git hooks or thin shell/`direnv` integration only to close a measured gap.
- Provide rollback/uninstall instructions and a documented exception mechanism.
- Treat network enforcement as a separate future workstream.

## 10. Acceptance criteria

- No changes to the current `~/www` organization or personal workflow are required.
- The architecture works with linked worktrees and concurrent tmux panes.
- Every status report differentiates **expected identity**, **observed identity**, and **unverified conditions**.
- A mismatched author/committer, key, account, remote, or outgoing commit never produces a misleading PASS.
- The tool performs no implicit network calls during ordinary local checks.
- Configuration files do not contain tokens/private keys; no persona identifiers need to appear in public dotfiles.
- The implementation is small, tested and documented; Rust and an automatic runtime remain choices to justify, not predetermined outcomes.

## 11. Instructions for the next agent

**Start with research and a design review, not coding.** Challenge the proposed architecture. Verify Git conditional includes, credential precedence, worktree behavior and `gh` account isolation from primary sources and reproducible tests. Return:

1. A concise architecture decision record (ADR) comparing A/B/C.
2. A risk register, with severity and practical mitigations.
3. Reproducible POC/test plan and observed results (if experiments are authorized).
4. A minimal proposed CLI contract **only if the evidence justifies building it**.
5. A list of any assumptions that remain unverified.

Do not create accounts, publish commits, alter the existing dotfiles, change SSH/GPG credentials, move code or modify network routing without explicit authorization.

## References

- [Git config — conditional includes, `worktree`, and precedence](https://git-scm.com/docs/git-config)
- [Git worktree — per-worktree configuration](https://git-scm.com/docs/git-worktree)
- [GitHub CLI — environment variables and credential precedence](https://cli.github.com/manual/gh_help_environment)
- [GitHub CLI — authentication](https://cli.github.com/manual/gh_auth)
- [direnv — documentation](https://direnv.net/)
- [Git hooks](https://git-scm.com/docs/githooks)
