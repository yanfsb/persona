# Directory-Scoped Identity CLI — Architecture & UX Design

**Status:** Proposed Post-POC Architecture
**Language:** Rust
**Platform:** macOS / Apple Silicon
**Shell:** Zsh (initial support)
**Distribution:** Nix / Cargo
**Design philosophy:** Native-first, directory-scoped, stateless, fail-closed for managed sensitive operations.

## 1. Product Vision

Build a lightweight, open-source CLI to manage multiple developer identity contexts within a single operating system user.

The application should allow developers to use separate Git, SSH, GPG and GitHub identities across different workspaces without manually switching accounts or changing global settings.

The product must integrate with existing tools rather than replace them.

### Primary user experience

```sh
cd ~/www/btc/bdk-repos/bdk
idctx status
# personal

cd ~/www/pseudonymous-repos/project
idctx status
# pseudonym
```

After the appropriate configuration is activated, normal commands should work:

```sh
git commit -m "fix: wallet synchronization"
git push
gh pr create
nvim .
```

The user should not need to prefix every ordinary command with `idctx`.

The CLI's purpose is to reduce identity confusion and accidental credential or metadata disclosure while preserving the existing development workflow.

**This is an identity context manager, not a security sandbox.**

## 2. Product Principles

### 2.1 Directory-scoped identity

Identity is associated with a directory or Git worktree, not with the current terminal session globally.

### 2.2 No global switching

Avoid modifying global Git settings, SSH agents or the active GitHub account when navigating between directories.

Multiple tmux panes must support different contexts simultaneously.

### 2.3 Native-first configuration

Delegate actual authentication and signing to Git, SSH, GPG and GitHub CLI.

The application coordinates, inspects and validates these tools.

### 2.4 Explicit security guarantees

Distinguish:

- Expected identity.
- Configured identity.
- Observed identity.
- Verified authentication.
- Unverified properties.

Do not claim that local configuration checks establish network anonymity.

### 2.5 Zero workflow disruption

Existing directories, repositories, dotfiles, Neovim configurations, Nix development shells and tmux workflows should remain usable without migration.

### 2.6 Predictable failure behavior

Inside a managed pseudonymous scope, missing or conflicting configuration must never silently select the personal identity.

### 2.7 Minimal implementation

No daemon, database, background service, custom credential store or generalized plugin framework.

## 3. Core Concepts

The product has four concepts.

### Identity

A named profile describing the expected configuration of development tools.

Examples:

- `personal`
- `pseudonym`

An identity profile should contain configuration references and expectations, not secrets.

### Scope

A directory associated with an identity.

Example:

```text
~/www/btc                  -> personal
~/www/merge-ti             -> personal
~/www/pseudonymous-repos   -> pseudonym
```

More specific scopes override their ancestors.

### Context

A resolved identity plus the effective tool configuration for a given working directory.

A context should be calculated from inputs, not stored as a global mutable "active identity."

### Policy

A set of requirements that operations must satisfy.

Examples:

- Expected Git email.
- Expected SSH host.
- Required signing key.
- Allowed remote destinations.
- Expected GitHub account.
- Outgoing commit metadata constraints.

## 4. Desired CLI UX

The proposed binary name is `idctx`, as a short form of _identity context_.

The name is provisional.

### 4.1 Daily usage

```sh
idctx status
```

Default output should be compact:

```text
pseudonym · ~/www/pseudonymous-repos/project
```

A more detailed view:

```sh
idctx status --verbose
```

```text
Identity   pseudonym
Scope      ~/www/pseudonymous-repos
Worktree   ~/www/pseudonymous-repos/project

Git
  Author      Pseudonym <...@users.noreply.github.com>
  Committer   Pseudonym <...@users.noreply.github.com>
  Signing     SSH · configured

Authentication
  SSH         github-pseudonym · configured
  GitHub      @pseudonym · not verified online

Policy
  Local       PASS
  Network     NOT EVALUATED
```

This command must remain read-only.

It must not require network access.

### 4.2 Identity validation

```sh
idctx check
```

Example:

```text
Checking identity: pseudonym

PASS  Git author
PASS  Git committer
PASS  Signing configuration
PASS  SSH configuration
PASS  Remote policy
WARN  GitHub authentication not verified

Local identity: VALID
```

The command checks configuration and identity invariants.

It does not automatically repair problems.

### 4.3 Publication preflight

```sh
idctx check --operation push
```

Example:

```text
Checking publication policy

PASS  Expected identity
PASS  Current Git configuration
PASS  Signing policy
PASS  Remote destination
FAIL  Outgoing commit metadata

Violation:
  Commit: a1b2c3d
  Field:  committer.email
  Reason: personal email detected

Publication preflight: FAILED
```

The command should support offline checks where possible.

Accurate outgoing-ref checks may require remote information. If the required remote state is unavailable, report `UNKNOWN`, not `PASS`.

An eventual Git `pre-push` integration can receive the specific refs involved in the push.

A standalone preflight and Git hook cannot guarantee network anonymity or prevent all connections to a remote.

### 4.4 Explicit execution

```sh
idctx run -- gh repo list
idctx run -- git status
idctx run -- codex
```

`run` executes a child process with the environment associated with the resolved identity.

This is useful for:

- Automation.
- Coding agents.
- Noninteractive shells.
- Applications not started through Zsh.
- Debugging.
- Environments where automatic activation is disabled.

The exit status of the child process must be propagated correctly.

The application must not execute commands through an implicit shell.

Use explicit executable paths and argument arrays.

### 4.5 Scope inspection

```sh
idctx scopes
```

Example:

```text
personal    ~/www/btc
personal    ~/www/merge-ti
pseudonym   ~/www/pseudonymous-repos
```

Optional future commands:

```sh
idctx scope add ~/www/new-project --profile pseudonym
idctx scope remove ~/www/new-project
```

Changes to central configuration must be explicit, previewable and reversible.

Scope editing is not essential to the first implementation.

### 4.6 Diagnostics

```sh
idctx doctor
```

Unlike `status`, `doctor` performs deeper checks.

Potential responsibilities:

- Git version compatibility.
- Missing profile references.
- Broken SSH paths.
- Conflicting environment variables.
- Unexpected configuration overrides.
- Unsupported worktree behavior.
- Stale shell context.
- Conflicting GitHub authentication configuration.
- Shell integration diagnostics.

Network-dependent diagnostics should require an explicit flag.

### 4.7 Machine-readable output

The CLI should eventually support:

```sh
idctx status --json
idctx check --json
```

Example:

```json
{
  "profile": "pseudonym",
  "scope": "/Users/example/www/pseudonymous-repos",
  "checks": [
    {
      "id": "git.author",
      "status": "pass"
    },
    {
      "id": "github.auth",
      "status": "unknown",
      "reason": "online verification not performed"
    }
  ]
}
```

This enables integration with shell prompts, scripts, CI and coding agents.

JSON output must have a documented schema and must not expose secrets.

## 5. Proposed Architecture

```text
                      User
                       |
              +--------+--------+
              |                 |
           CLI UX           Zsh Adapter
              |                 |
              +--------+--------+
                       |
                  Rust Core
                       |
          +------------+------------+
          |            |            |
     Scope Resolver  Profiles   Context Builder
          |            |            |
          +------------+------------+
                       |
               Context Inspection
                       |
          +------------+------------+
          |            |            |
         Git          SSH          gh/GPG
          |            |            |
          +------------+------------+
                       |
                 Policy Checks
                       |
                Result / Findings
```

### 5.1 CLI layer

Responsibilities:

- Parse commands.
- Resolve target working directory.
- Select output format.
- Present findings.
- Return documented exit codes.

Should not contain policy logic.

### 5.2 Scope resolver

Responsibilities:

- Normalize input paths.
- Match registered scopes.
- Apply longest-ancestor resolution.
- Handle unknown directories.
- Return expected identity.

Within a Git repository, use the canonical worktree root as the primary identity boundary.

For non-Git directories, use the current directory.

A nested directory policy must not silently change Git identity halfway through a single worktree.

### 5.3 Profile loader

Responsibilities:

- Read TOML.
- Validate profile fields.
- Resolve paths.
- Detect duplicate or invalid scopes.
- Reject unknown profile references.

No provider registry is required.

### 5.4 Context builder

Produces the expected environment and identity context.

Conceptual Rust types:

```rust
struct IdentityProfile {
    name: String,
    git: GitIdentity,
    ssh: SshIdentity,
    github: GithubIdentity,
}

struct Scope {
    path: PathBuf,
    profile: String,
}

struct IdentityContext {
    profile: IdentityProfile,
    scope: PathBuf,
    worktree: Option<PathBuf>,
}
```

This is an illustrative contract, not the final public API.

Use domain-specific validation and explicit error types.

Avoid introducing traits for a single implementation.

### 5.5 Tool inspectors

Tool-specific components inspect effective configurations.

**Git Inspector**

- Author and committer.
- Environment variable overrides.
- Configuration origin.
- Signing mode and key.
- Repository and worktree location.
- Remotes.
- Outgoing commit metadata.

Prefer invoking Git's native commands rather than implementing Git configuration parsing.

**SSH Inspector**

- Expected host alias.
- Effective client configuration.
- Selected identity files.
- Unexpected agent configuration or overrides.

Offline SSH configuration inspection does not prove which remote account successfully authenticates.

**GitHub Inspector**

- `GH_CONFIG_DIR`.
- Token environment overrides.
- Expected GitHub host/account.
- Auth configuration.

Do not equate a directory path with verified account identity.

**GPG / Signing Inspector**

- Expected signing mechanism.
- Configured key reference.
- Relevant environment.
- Availability where determinable without exposing secrets.

### 5.6 Policy checks

The policy layer compares expected and observed states.

Conceptual result:

```rust
enum CheckStatus {
    Pass,
    Warn,
    Fail,
    Unknown,
}

struct Finding {
    id: String,
    status: CheckStatus,
    message: String,
}
```

Core functions should be deterministic where practical.

Separate data collection from policy evaluation.

Avoid a generic rules engine or embedded expression language.

## 6. Shell Integration

The initial integration target is Zsh.

The shell adapter is optional and should remain small.

### Intended behavior

```text
User executes cd
       |
       v
Zsh detects directory change
       |
       v
idctx resolves context
       |
       v
Shell adapter applies environment changes
       |
       v
Commands inherit the selected context
```

### Lifecycle

Use:

- `chpwd` for directory changes.
- `precmd` for initial synchronization and reconciliation.
- `preexec` only if an identified requirement justifies it.

The adapter must avoid repeatedly loading complete configurations when nothing changed.

### Environment management

Potential managed variables:

```text
GH_CONFIG_DIR
GNUPGHOME
GIT_CONFIG_GLOBAL
GIT_SSH_COMMAND
```

Only manage variables required by the chosen integration.

Git-native conditional includes may remove the need to manage `GIT_CONFIG_GLOBAL`.

Do not modify `HOME`, `PATH` or the general XDG environment unnecessarily.

### Environment restoration

When transitioning:

```text
personal -> pseudonym -> unmanaged -> personal
```

The adapter must restore previously inherited values correctly, including variables that were originally unset.

A failed profile resolution must not retain stale pseudonymous or personal values in managed variables.

Only validated, allowlisted environment changes may be applied.

### Compatibility with direnv

The system must coexist with `direnv`.

Define a single owner for each managed variable.

Do not have `direnv` and `idctx` independently overwrite the same variable without explicit ordering and conflict handling.

Prefer using the existing environment mechanism where it demonstrably satisfies the requirement.

### Performance

The shell integration must remain unnoticeable during normal navigation.

Benchmark:

- Startup overhead.
- Directory transition latency.
- Profile resolution.
- Config reload latency.

No daemon or persistent cache is proposed initially.

## 7. Native Tool Integration

### Git

Preferred mechanisms:

- Conditional includes.
- `user.useConfigOnly`.
- Native Git signing.
- Native remote configuration.
- Git hooks where justified.

The current Git documentation includes the `worktree:` conditional include, but compatibility with the installed version must be verified.

Do not rely on Git config values alone when environment variables can override them.

### SSH

Use native host aliases and identity files.

The CLI must not implement SSH authentication or a custom key agent.

### GitHub CLI

Use context-specific configuration when supported.

Avoid `gh auth switch` as a global context-switching mechanism.

Inspect token precedence and macOS Keychain behavior.

### GPG and hardware keys

Treat signing as an adapter.

SSH signing and OpenPGP should be supported conceptually without requiring both.

YubiKey support should rely on standard SSH/GPG/FIDO2 tooling.

The CLI should not store private keys, PINs or recovery codes.

## 8. Configuration Model

Initial proposal:

```text
~/.config/idctx/
├── config.toml
└── profiles/
    ├── personal.toml
    └── pseudonym.toml
```

Example:

```toml
# config.toml

[[scopes]]
path = "~/www/btc"
profile = "personal"

[[scopes]]
path = "~/www/merge-ti"
profile = "personal"

[[scopes]]
path = "~/www/pseudonymous-repos"
profile = "pseudonym"
```

Example profile:

```toml
# profiles/pseudonym.toml

name = "pseudonym"

[git]
author = "Pseudonym"
email = "example@users.noreply.github.com"
signing_required = true

[ssh]
host = "github-pseudonym"

[github]
username = "pseudonym"
config_dir = "~/.config/gh-pseudonym"
```

These values are illustrative.

Do not store secret material in configuration files.

Avoid putting persona-specific information in public Nix/dotfiles repositories.

The first implementation may use a single TOML file if that is simpler.

## 9. UX Design Requirements

### Normal operation should be quiet

Directory changes should not print verbose banners or interfere with the shell.

Only show messages for actual errors or important context changes.

A shell prompt integration may optionally display:

```text
~/www/pseudonymous-repos/project  [pseudonym]
```

Prompt integration should be a separate optional feature.

### Commands should be predictable

- `status`: explain current context.
- `check`: evaluate policy.
- `doctor`: troubleshoot configuration.
- `run`: execute with scoped context.
- `scopes`: inspect configured directory associations.

Do not overload one command with unrelated responsibilities.

### Errors should be actionable

Bad:

```text
Identity mismatch
```

Good:

```text
FAIL git.committer.email

Expected:
  example@users.noreply.github.com

Observed:
  personal@example.com

Source:
  GIT_COMMITTER_EMAIL environment override

Action:
  remove or correct the override before committing
```

Do not expose unnecessary credential details or complete tokens.

### Failures must be explicit

Inside a managed pseudonymous context:

- Missing credentials: report failure or unknown as appropriate.
- Wrong Git email: fail.
- Wrong signing key: fail.
- Wrong remote under a restrictive policy: fail.
- Conflicting environment: fail.
- Unverified remote authentication: unknown.
- Unverified network anonymity: not evaluated.

Do not silently fall back to the personal profile.

### Preserve process semantics

`idctx run` must preserve:

- Standard input.
- Standard output.
- Standard error.
- Exit codes.
- Signal behavior where supported.
- Child process argument boundaries.

Do not concatenate commands into shell strings.

### No hidden network requests

Status and local checks should be offline by default.

Any check requiring remote authentication must be explicit.

## 10. Exit Codes

Proposed initial contract:

```text
0  Checks passed / successful operation
1  Policy violation
2  Configuration, usage or execution error
3  Required verification unavailable
```

The exact mapping should be reviewed against CLI conventions.

For `run`, preserve the child command's exit code, and document how launcher failures are distinguished.

Machine-readable results must carry the detailed statuses independently of exit codes.

## 11. Rust Implementation Structure

Suggested initial layout:

```text
idctx/
├── Cargo.toml
├── Cargo.lock
├── flake.nix
├── src/
│   ├── main.rs
│   ├── cli.rs
│   ├── config.rs
│   ├── scope.rs
│   ├── context.rs
│   ├── inspect/
│   │   ├── mod.rs
│   │   ├── git.rs
│   │   ├── ssh.rs
│   │   └── github.rs
│   └── policy.rs
├── shell/
│   └── idctx.zsh
├── tests/
└── README.md
```

This is a suggested organization, not an instruction to create every file immediately.

### Dependencies

Initial preference:

- `serde`
- `toml`
- `serde_json` if JSON output is implemented.
- `clap` if command parsing warrants it.
- `thiserror` if it materially simplifies error handling.
- `tempfile` for integration tests.

Avoid:

- Tokio.
- Database dependencies.
- Credential SDKs.
- Shell execution frameworks.
- Plugin registries.
- Background services.

### Internal boundaries

The architecture should separate:

1. Path/profile resolution.
2. Environment construction.
3. Tool inspection.
4. Policy evaluation.
5. CLI presentation.

Prefer small concrete types and functions over generic abstractions.

Subprocess inspection should use explicit arguments, bounded execution, controlled environment and safe output parsing.

## 12. Security Model

The CLI can prevent or detect many operational mistakes, but cannot guarantee identity unlinkability.

### Supported guarantees

Subject to implementation and testing:

- Deterministic expected-profile resolution.
- Detection of known Git metadata mismatches.
- Detection of known configuration overrides.
- Validation of configured authentication identity.
- Publication metadata checks.
- No global account switching.
- No implicit secret storage.

### Unsupported guarantees

- Operating-system process isolation.
- Resistance to a compromised user session.
- Network anonymity.
- VPN/Tor routing enforcement.
- Resistance to platform-side account correlation.
- Behavioral unlinkability.
- Complete prevention of bypassing hooks.
- Protection against arbitrary malicious tooling with access to the same user account.

A local `PASS` means only the documented checks passed.

## 13. Implementation Priority

### Milestone 1 — CLI core

Implement:

- Configuration parsing.
- Profile loading.
- Scope resolution.
- `status`.
- `check` with basic Git validation.

No shell integration yet.

### Milestone 2 — Tool inspection

Implement:

- Git configuration origin and overrides.
- SSH configuration inspection.
- GitHub CLI context inspection.
- Signing configuration validation.

Keep checks offline where possible.

### Milestone 3 — Execution context

Implement:

- `run`.
- Controlled environment construction.
- Environment override handling.
- Child process exit/signal propagation.

Validate independent operation across tmux panes.

### Milestone 4 — Publication policies

Implement:

- Remote validation.
- Commit metadata inspection.
- Outgoing ref handling.
- Git hook integration where beneficial.

Explicitly document limitations of offline checks and hooks.

### Milestone 5 — Optional Zsh integration

Only after the CLI core is stable.

Implement:

- Directory-change detection.
- Automatic context activation.
- Environment restoration.
- Conflict handling with `direnv`.
- Optional prompt indicator.

### Milestone 6 — Distribution and documentation

- Nix packaging.
- Cargo installation.
- Configuration examples.
- Threat model.
- Troubleshooting.
- Regression tests.
- Migration and uninstall instructions.

## 14. Required Test Coverage

At minimum:

- Scope resolution by canonical directory.
- Nested scopes.
- Symlink handling.
- Unknown/unmanaged paths.
- Linked Git worktrees.
- Monorepos.
- Git config override precedence.
- Author/committer environment overrides.
- SSH alias and identity selection.
- GitHub token precedence.
- Missing or corrupt configuration.
- Concurrent tmux contexts.
- `direnv` and Nix interaction.
- Long-lived process inheritance.
- Correct shell environment restoration.
- Child exit code propagation.
- Outgoing commit metadata.
- Multi-ref and new-branch pushes.
- Failures without unintended global mutations.

Use disposable repositories and temporary configuration directories for integration tests.

Do not require production GitHub credentials for the test suite.

## 15. Post-POC Architecture Decision

The proposed product architecture is:

**Rust CLI Core + Native Tool Configuration + Optional Thin Shell Adapter.**

The core is responsible for:

- Context resolution.
- Environment construction.
- Identity inspection.
- Policy validation.
- Explicit process execution.

Native tools remain responsible for:

- Git configuration and commits.
- SSH authentication.
- GPG/SSH signing.
- GitHub authentication.
- Development environments.

The shell adapter, if necessary, is responsible only for applying scoped environment changes to the current shell.

There should be no central daemon and no single globally active identity.

The product should remain useful even without shell integration through explicit commands.

## 16. Instructions for the Implementing Agent

Treat this document as a proposed product contract for the stage **after the POC has established the relevant native tool behaviors**.

Before implementation:

1. Review the POC findings and validate assumptions.
2. Confirm which responsibilities need custom Rust code.
3. Finalize the command interface and configuration schema.
4. Define error semantics and safety guarantees.
5. Produce a small implementation ADR.

During implementation:

- Prefer native tools.
- Keep scope resolution deterministic.
- Avoid mutable global state.
- Separate inspection from mutation.
- Make network operations explicit.
- Preserve the existing macOS workflow.
- Design tests before expanding functionality.
- Avoid unnecessary abstractions.
- Implement one milestone at a time.

Do not build a new version of `direnv`, Git, SSH or a password manager.

Do not introduce a daemon or general plugin architecture.

Do not implement VPN/Tor routing inside the initial identity CLI.

Do not assume that a configured GitHub account proves authenticated account identity.

Do not automatically modify personal dotfiles or existing repositories.

## 17. Definition of Success

The product is successful when a developer can:

1. Keep multiple identities on the same macOS user.
2. Associate identities with directory scopes.
3. Work on different identities in different tmux panes.
4. Continue using existing terminal and editor tooling.
5. Inspect the effective identity at any time.
6. Detect configuration and publication mistakes.
7. Run tools explicitly under a chosen context when necessary.
8. Optionally activate identity context automatically.
9. Understand exactly what the system verifies and what it cannot guarantee.
10. Maintain the entire setup without a daemon, duplicate developer environments or frequent manual account switching.

**Final architectural principle:**

> Identity should be a property of the working context, not a mutable global state. The CLI should make that context observable, executable and verifiable while leaving authentication and cryptographic operations to existing tools.
