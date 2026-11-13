# CLI reference

The CLI is implemented in Rust with Clap. `persona --help` and subcommand help are the executable syntax authority; this guide summarizes purpose and important side effects.

## Commands

| Command | Purpose and side effects |
|---|---|
| `persona`, `status`, `check`, `doctor` | Offline diagnostics by default; text or versioned JSON as supported. Push/tag checks consume explicit inputs and apply bounded policy. `check --online-verified` is an explicit GitHub query for outgoing commit verification. |
| `setup` | Create Persona's private configuration; does not activate a profile or install integrations. |
| `profile`, `scope` | Inspect/manage private policy. Mutations validate and support preview; see `persona profile --help` and `persona scope --help`. |
| `config migrate`, `config rollback` | Explicit policy migration and restoration from a Persona backup. |
| `run` | Start a program directly, without an implicit shell, with temporary managed PATH adapters. Not a sandbox or network restriction. |
| `install preview|apply|refresh|remove|rollback` | Preview and manage Persona-owned adapter symlinks in an existing user bin directory; explicit actions only. |
| `hooks install|remove` | Manage the Persona pre-push hook in one explicitly selected worktree. |
| `auth enroll|verify|unbind` | Explicit account-binding lifecycle. `enroll` contacts GitHub and requires user/online confirmation; `verify` compares local selection without an API call. |
| `credential-helper get|store|erase` | Bounded Git credential-helper protocol for managed calls. Do not configure globally. |
| `shell zsh init|marker` | Optional Zsh prompt convenience, not an authorization mechanism. |

## Examples

```sh
persona --help
persona doctor --format json
persona profile list
persona scope show example
persona install preview --bin-dir "$HOME/bin"
persona run -- git status
persona check --operation push --remote origin --destination https://example.invalid/org/repo.git < pre-push-tuples
```

The last command expects native Git pre-push tuples on standard input; without `--online-verified` it is an offline audit, not proof of remote reachability or credential validity. Adding `--online-verified` explicitly contacts GitHub to inspect outgoing commit verification; it still does not publish anything.

## Output and exit status

Human-readable text is not a stable machine schema. Diagnostic JSON is versioned and findings have property-specific status. Diagnostic status exit codes are 0 for PASS, 1 for FAIL, 2 for operational error, 3 for UNKNOWN, and 4 for WARN. Push authorization decisions use their own contract and allow only when every required property has exactly one PASS finding; consult current command help and the operation decision output before integrating scripts.

`--verbose` is text-only where available; `--format json` is the preferred diagnostic machine interface. Missing/malformed policy and invalid invocation are errors, not passing checks. See the [security model](security-model.md).
