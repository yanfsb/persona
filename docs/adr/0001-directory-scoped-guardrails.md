# ADR-0001: Directory-scoped identity guardrails

- **Status:** Accepted; implementation in progress
- **Date:** 2026-10-29
- **Decision owners:** Persona maintainers
- **Platforms:** macOS and Linux, first-class targets

## Context

Persona began as a read-only auditor. The product requirement is broader: let a developer use distinct Git, signing, SSH and GitHub identities in different directory contexts on one OS account, preserve ordinary `git` and `gh` workflows, and block accidental use of a mismatched identity before presenting credentials to a remote in supported paths.

The existing auditor resolves physical checkout roots and observes Git/OpenPGP state, but it does not choose an identity, mediate normal Git/GitHub commands, or prevent an operation. Its current aggregate status also includes informational `UNKNOWN` findings, so it is not a suitable authorization decision. The old [`sketch.md`](../../sketch.md) and [`directory-scoped.md`](../../directory-scoped.md) are historical proposals, not the implementation contract.

The system operates within one macOS or Linux user account. Personas share that user's filesystem, processes, environment, credential stores and agents. This ADR addresses operational mistakes in integrated paths; it does not promise a security sandbox, immunity to a malicious same-user program, or anonymity.

### Confirmed constraints and evidence

- Directory/worktree selection must be deterministic and support nested scopes and concurrent terminal panes.
- Git author/committer metadata, signing identity, transport credential, GitHub principal and destination are distinct properties.
- GitHub CLI environment tokens override stored credentials. Its native CLI can select a named stored account without globally switching the active account; this was exercised with synthetic credentials only.
- `ssh -G` is not a safe generic inspection primitive: a synthetic OpenSSH config demonstrated that `Match exec` can run a command during configuration evaluation.
- On the installed Git 2.55, a synthetic linked-worktree test did not activate the tested `includeIf "worktree:"` rule. Native per-worktree Git configuration did select distinct identities in the same fixture. These results are compatibility evidence for that tested setup, not universal claims about every Git version/configuration.
- A synthetic native `pre-push` hook confirmed that the existing auditor's complete report returns `UNKNOWN` even when its push-destination and outgoing metadata findings pass. It also confirmed that explicit `GIT_DIR` inherited by the hook is rejected by the current inspector. A hook alone therefore cannot satisfy the pre-connection gate or be wired to the existing CLI unchanged.
- macOS/Linux parity must be demonstrated independently; the current package and the user's actual configuration are not evidence of Linux support.

## Decision

Persona will be a **directory-scoped context manager with operation-specific guardrails**. It will support ordinary Git and GitHub CLI operations through explicitly installed managed adapters, backed by a deterministic Rust core. It is neither just an auditor nor a general-purpose isolation runtime.

The complete initial product target is:

- macOS and Linux, including Linux without a graphical session;
- contributor and maintainer workflows: ordinary Git defaults, fork/upstream remotes, editing/reviewing history, PR lifecycle, publication, tags and releases; commands reached through Persona adapters outside configured scopes remain refused;
- completion of this target precedes onboarding on the owner's real repositories;
- GitHub server-side PR merges use a separate, explicit profile policy for the bound account, allowlisted repository, target branch and strategy. This never asserts that server-created merge commits were signed by the local Persona key. Auto-merge/queues, administrative bypass and branch deletion require separate explicit policy;
- commits ancestral to an explicitly user-approved, destination-bound pinned upstream OID may retain upstream authors, committers and signatures. New commits must satisfy the selected Persona policy; cherry-pick author preservation remains explicit;
- GitHub.com, native `git` over SSH and HTTPS, `gh`, and OpenPGP/SSH signing;
- directory scopes, linked worktrees, nested scopes, simultaneous panes, persistent tools, first publication and outgoing-history policy;
- an opt-in Zsh adapter for convenience, not a security authority;
- reproducible Nix distribution where available plus a native/Cargo installation path. Nix, Home Manager, Keychain, launchd and systemd are not core runtime requirements.

Unsupported network-capable invocations in a protected scope must be refused; they must not silently fall through to a native command and appear protected. `persona run` is a child-process launcher, not an escape hatch for refused Git/gh operations: managed descendants still pass through the same adapters, and arbitrary programs are not network-confined. The exact command/version matrix is an implementation gate, not a claim that every Git/GitHub feature is already supported.

## Decisions and rationale

### 1. Context is resolved for each operation; no active global persona

Resolve context from the operation's effective physical target, not from a mutable account switch or the shell prompt:

1. For an existing Git checkout, use its canonical physical worktree root. A linked worktree is resolved by its own checkout path, not the common repository directory.
2. For a non-Git working directory or a new clone, use the canonical current/explicit destination path.
3. Choose the most-specific configured ancestor scope. A nested scope replaces its parent policy; it does not inherit fields implicitly.
4. If `-C`, `--git-dir`, `--work-tree`, environment, symlink spelling, multiple destinations, or command semantics make the effective target ambiguous, refuse the protected operation instead of guessing.

Changing directory does not change global Git config, `gh auth switch`, SSH agents, other panes, or long-running process environments. Each managed operation resolves its own context. A shell `chpwd` hook may refresh a prompt/status cache, but cannot authorize I/O.

### 2. Profiles separate identity data from directory scopes

Use private configuration under `$XDG_CONFIG_HOME/persona` with `$HOME/.config/persona` as the documented fallback; mutable non-secret runtime/install metadata belongs under `$XDG_STATE_HOME/persona` (fallback `$HOME/.local/state/persona`). Create directories/files with restrictive owner-only permissions where supported. Paths are canonicalized consistently on both platforms; paths to future/missing scopes are not silently accepted as active scopes.

A reusable profile describes expected author/committer identity, signing requirement, host/account binding, allowed destination rules, and native credential selectors. A scope maps a directory to a profile and, only where justified, a stricter operation policy. Profiles contain references and identifiers, never token values, passwords, private keys or recovery codes. Unknown fields, duplicate identities, conflicting paths and incomplete required profile data are actionable configuration errors.

A repository-provided file cannot automatically weaken the user's protected policy. Trusting a policy from an untrusted repository requires an explicit user action and visible provenance. Add/update/remove commands require preview, validation, atomic write, backup and rollback.

### 3. Guard decisions are per operation and separate from evidence

The core returns evidence by property (`PASS`, `WARN`, `FAIL`, `UNKNOWN`). A separate authorization decision applies only the requirements for the requested operation:

- A required mismatch blocks.
- A required property that is `UNKNOWN` blocks; it never becomes `PASS` through aggregation.
- Informational/unrelated `UNKNOWN` remains visible but does not veto an operation that does not require that property.
- Optional diagnostics never silently weaken a required policy.

`status` is read-only, compact and non-authorizing. It shows the selected profile/scope and whether the needed integrations are installed, incomplete or absent. `check` evaluates a named operation and returns a decision. `run` resolves a context and launches a child only when the requested operation is authorized; it preserves argv, terminal, stdin/stdout/stderr, signals and child exit status without an implicit shell. Launcher/policy failures have distinct documented exit codes; `run` does not disguise a child failure. JSON output is versioned and contains no secrets.

A successful local decision means only that the stated local preconditions were met. It does not mean that a remote is reachable, that a token has not been revoked since enrollment, that a server accepted the credential, or that an account is anonymous.

### 4. Managed adapters are the synchronous enforcement point

A deterministic core resolves policy. Small executable adapters mediate supported normal `git` and `gh` invocations from the managed PATH. They must resolve the real native executable explicitly and avoid recursion. The adapter validates context, supported operation, effective destination and selected credential binding **before delegating to the native transport**. If operation arguments or context cannot be safely interpreted, it blocks and explains the unsupported case.

For Git, inspect local config and applicable local rewrites without running configured credential helpers, SSH, network commands, or arbitrary shell config. Reject or explicitly override conflicting `GIT_DIR`, `GIT_WORK_TREE`, `GIT_CONFIG_*`, askpass, helper, transport and URL overrides according to the operation contract. Network-capable Git subcommands are allowlisted per profile; clone uses its explicit destination directory, while fetch/pull/push use the physical worktree and exact configured remote. Unknown remote helpers/protocols block in protected scopes.

For GitHub CLI, select a named native `gh` account by explicit host and account selector and do not use global `gh auth switch`. Conflicting inherited token/host/config variables (including `GH_TOKEN`, `GITHUB_TOKEN`, `GH_ENTERPRISE_TOKEN`, `GITHUB_ENTERPRISE_TOKEN`, `GH_HOST`, and `GH_CONFIG_DIR`) block protected operations unless an explicitly reviewed profile policy defines their use. The adapter must not print or persist the returned token. GitHub.com is the initial provider target; other hosts require an explicit supported binding.

Adapters are best-effort controls on managed executable paths, not kernel enforcement. Running `/usr/bin/git`, another `gh`, `curl`, a custom SSH client, or a malicious same-user program can bypass them. The product must show its integration state and must never claim those paths are covered.

### 5. Credential bindings are explicit; no Persona credential vault

Profiles refer to native GitHub/SSH/GPG facilities. An explicit enrollment/verification action may contact a provider to associate a credential selector with a stable provider account identifier (not only a mutable username/handle). Day-to-day protected operation selects that locally enrolled credential and destination before invoking transport. Persona does not store a credential secret or switch a global account.

There is a hard boundary: the live server principal and token validity cannot be proven offline. Establishing or renewing an account binding requires an explicit authenticated network operation; that operation itself presents the selected credential and must be clearly described as enrollment/verification, not as a zero-network preflight. During a protected operation only, after validating syntax, scope and destination but before starting transport, the adapter may retrieve the profile-selected credential from its declared native selector and compare a private, non-reversible credential fingerprint with the enrolled binding. This detects replacement without transmitting the credential to the remote. Offline `status` and diagnostic `check` do not retrieve credentials. A selector whose value cannot be safely resolved/compared is unsupported for protected use. Subsequent revocation or account-side changes are only learned from server responses; local bindings do not guarantee current authorization.

For SSH, the selected host/key must be explicit and constrained to the enrolled profile. Do not run `ssh -G` or another parser that can execute `Match exec`, `ProxyCommand`, or configured helpers during ordinary offline status. In the initial protected transport, use a Persona-controlled OpenSSH invocation/configuration that selects the declared host and identity and refuses unsupported includes/commands; the exact mechanism must be validated on macOS and Linux. Agent-backed/hardware keys are permitted only where the selected public identity can be established locally; otherwise block rather than imply selection. Do not inspect or export private key material.

On Linux headless systems, rely only on native credential facilities actually available. If gh falls back to plaintext storage or no safe credential selector is available, diagnose and refuse the managed credential operation according to policy; Persona does not create a second store.

### 6. Git publication has two barriers and explicit history semantics

The primary adapter blocks before network transport if the destination, profile, host or locally selected credential is disallowed/unbound. This is necessary because `pre-push` may require remote negotiation/authentication before it can inspect the exact update and is not a pre-authentication boundary.

A managed, composable `pre-push` hook is a second barrier. It receives actual refs/OIDs from Git and checks the exact objects about to be published. The installer records ownership, preserves/chains existing hooks and refuses conflicts it cannot safely compose; it never overwrites arbitrary hook code. `--no-verify`, custom `core.hooksPath`, or direct executable invocation are documented bypasses, but the normal adapter path remains the primary guard even when hooks are absent.

Metadata policy must distinguish:

- committer identity for new commits;
- author identity, which may legitimately belong to an upstream author;
- preserved/cherry-picked commits and allowed provenance;
- signing mechanism, cryptographic validity, permitted signer and provider “Verified” display;
- outgoing refs, tags, deletions, force updates and first pushes.

Do not require every outgoing author to equal the local persona. Define allow/preserve rules and explicit behavior for each operation/ref kind. Any unimplemented or unbounded case blocks as unsupported; do not report a partial scan as authorization.

### 7. Zsh is optional UX; no daemon initially

The core and adapters work without a shell plugin. An optional Zsh adapter may provide a compact persona marker and launch helpers. It must be quiet, restore only its own variables, compose with `direnv`, and never claim to update already-running Neovim/agents. New managed commands from an editor/agent resolve their own target; `persona run` is the explicit launch path when a process context needs to be fixed.

No background daemon is included initially. A filesystem observer cannot substitute for a synchronous pre-transport gate and adds lifecycle/persistence/platform complexity. Reconsider a service only in a separate ADR if measurements show a concrete need that synchronous adapters cannot satisfy. No global “active persona” state or database is allowed.

### 8. Installation, distribution and platform policy

Installation is explicit, previewable, owner-aware and reversible. It records only which managed adapters/hooks/config entries it owns, backs up changed integration points, refuses to overwrite unknown user state, and can restore prior state. It does not edit real personal dotfiles or existing repositories silently. “Protection active” is shown only when the required adapters for that profile/operation are verifiably installed.

The Rust core must not shell out to package-manager-specific paths. Nix is one reproducible distribution path for macOS and Linux, not a runtime wrapper on every invocation. Cargo/native installation is documented with native Git/gh/OpenSSH/GPG requirements. Home Manager is an optional installer integration, not a core dependency. Platform-specific credential/agent adapters are isolated behind explicit capabilities; unsupported capability means blocked or visibly unprotected, not silent fallback.

### 9. Security boundary and non-goals

**The product reduces accidental identity/destination mistakes on its managed paths.** It is not process isolation, a firewall, VPN/Tor enforcement, an anonymous-account system, protection from compromised/malicious same-user programs, or a guarantee that every network call in the OS flows through Persona. It does not hide timing/behavioral metadata or isolate Keychain/agent/filesystem/clipboard/telemetry between personas.

A local `PASS` is limited to named evidence. Server acceptance and provider verification remain separate observations. No `UNKNOWN` property is described as passing. Offline status never runs ssh/gh/authentication helpers, reads private keys/tokens, or connects to a provider.

## Alternatives considered

| Alternative | Decision | Reason |
|---|---|---|
| Native conditional config only | Insufficient alone | Useful for effective Git defaults and worktrees, but does not mediate GitHub credentials/destinations or provide operation-level pre-transport authorization; Git 2.55 worktree include test also did not work in the tested case. Retain native config where reliable. |
| Read-only auditor | Insufficient as product | Valuable diagnostics and foundation, but cannot satisfy the confirmed guardrail requirement. |
| Shell-only activation | Rejected as authority | Long-lived processes and non-shell callers keep different environments; shell variables alone do not gate normal Git/gh calls. Retain as optional convenience. |
| Daemon | Deferred/rejected initially | Asynchronous observation does not close a synchronous authorization boundary and introduces persistence/service complexity. |
| New GitHub/SSH credential vault | Rejected | Duplicates native security storage, increases secret-handling risk and diverges across macOS/Linux/headless systems. |
| OS-level sandbox/firewall | Out of scope | Would require stronger system-specific privileges and still not solve account attribution; not the stated accidental-mistake product. |

## Consequences

### Positive

- Ordinary supported `git`/`gh` commands can be guarded without a per-command `persona` prefix.
- Concurrent panes and long-lived programs do not depend on one global account switch.
- Native signing and credential stores remain authoritative for secrets.
- Unsupported identity/destination cases fail visibly instead of falling back to another persona.
- macOS and Linux share one product contract, with explicit adapter capability reporting.

### Costs and trade-offs

- Executable shims/adapters, install state and hook composition are more complex than the existing auditor.
- Every external executable path, command grammar, credential helper and platform integration expands the supported matrix; unvalidated forms must be rejected.
- An account binding can become stale after server-side revocation/rotation. Only an explicit online enrollment or the eventual authenticated operation can reveal that.
- Same-user direct binary invocation remains a bypass; the product is an accidental-error guardrail, not a hostile-code sandbox.
- Requiring supported network-capable commands to pass through Persona may conflict with unrecognized tools; those tools remain visibly outside the guarantee until integrated.
- A platform is supported only after its integration, headless behavior, installation and rollback tests pass independently.

## Required implementation gates

These gates are acceptance criteria for the future implementation; this ADR does not claim they are already satisfied.

1. **Zero-contact denial tests:** instrument fake transports/credential helpers and prove rejected Git/gh operations start zero transports, request zero credentials and attempt zero network connections on both macOS and Linux.
2. **Credential binding tests:** synthetic gh account stores/tokens and SSH fixtures prove deterministic account/key selection, host/destination checks, token/environment override refusal, enrollment, stale binding and rotation behavior without real credentials.
3. **No helper side effects:** offline status/config checks cannot run SSH `Match exec`, ProxyCommand, credential helpers, shell snippets, network/DNS or Keychain/keyring lookup.
4. **Concurrency/process tests:** two panes/processes with different scopes remain independent; an already-open editor launching a new guarded Git/gh command resolves its target; environment changes do not leak or falsely update an existing process.
5. **Git metadata/ref tests:** first push, existing branch, multiple refs, upstream authors, cherry-picks, tags, deletion, force and missing-object cases produce the documented allow/deny outcome, with actual Git hook stdin and environment on macOS/Linux.
6. **Integration lifecycle:** installer preview/apply/remove preserves custom hooks and config, detects external modifications, and rollback restores only Persona-owned state in disposable HOME/repositories.
7. **Functional parity:** Nix/Cargo builds, CLI help/UX, JSON contracts, credential capability diagnostics, installation and all required tests pass independently on macOS and Linux (Linux headless included).
8. **Redaction/security review:** no token, passphrase, private key, secret URL userinfo or credential helper output appears in argv constructed by Persona, logs, JSON, diagnostics or persistent state. Secret material remains in native tools and only flows through the child process interface needed for the operation.
9. **Final adversarial review:** document and test supported/bypass paths; any uncovered normal GitHub/Git operation in a managed scope blocks the “protection active” claim.

## Open implementation questions (must be resolved by POC before claims)

- Which Git executable interception strategy works with system Git, Nix Git, Git subcommands, `gh`-spawned Git, `-C`, worktrees, shell command hashing and Home Manager on both OSes without recursion?
- How can the Persona-managed OpenSSH invocation honor required native agent/hardware-key workflows while excluding untrusted `Match exec`, ProxyCommand and implicit identities?
- Which gh storage formats/backends can be selected non-interactively and safely on macOS and Linux headless without parsing secret stores or requiring global account switching?
- How are credential-store account labels bound to stable provider identity, and what events invalidate enrollment?
- How are protected clone/first-push destinations resolved before contact, including local path, SSH alias, HTTPS, URL rewrites and implicit gh repository selection?
- How does hook composition preserve multiple existing hooks and account for Git's hook-time environment without allowing hooks to bypass the primary adapter?
- What exact author-preservation rules distinguish upstream/cherry-picked authors from prohibited identity leakage?
- Which `gh` operations and nested Git calls are supported at launch, and what is denied as unknown?

## Implementation sequence

The work will proceed in independently reviewed phases after this ADR: core authorization contract and port matrix; reusable profile/config UX; Git and gh adapters with fake transports; publication/hooks; optional shell UX; install/distribution/rollback. Each phase adds concrete fixtures and tests. “Product complete” remains false until all required implementation gates above pass on macOS and Linux. A separate implementation plan will identify each workstream, owner/boundary, test gate and residual risk before code is expanded.