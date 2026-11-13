# Troubleshooting

## `status` reports unmanaged or unknown

Status is local evidence, not an authorization request. Confirm that the current physical directory is within a configured scope and that its profile exists. Use `persona doctor` for full offline findings. `UNKNOWN` can mean required evidence is unavailable locally; it is not success.

## A managed command is refused

Persona deliberately refuses unsupported flags, ambiguous targets, unlisted destinations, missing account bindings and incomplete evidence. Read the refusal and consult [managed commands](managed-commands.md). Do not work around a refusal by assuming the native binary is protected; direct native invocations bypass adapters.

## Config is invalid or unsafe

The parser rejects unknown fields and unsupported versions. Validate syntax and names; scope paths must be absolute and profile references must exist. Use `persona config migrate --preview` before migration. Persona refuses unsafe default configuration paths rather than silently changing ownership or permissions.

## Installation or hook conflict

Use the relevant `--preview` command first. Persona refuses unowned files, externally changed symlinks, custom hook paths, or state it cannot safely compose. Review the private backup/manifest; remove or restore only Persona-owned unchanged paths. Do not manually delete paths that a manifest says are modified.

## Authentication or transport uncertainty

Offline diagnostics do not test credentials or connectivity. `check --online-verified` is an explicit GitHub query. Enrollment is explicitly online; `auth verify` is local selection/binding comparison. Never paste tokens or private key material into an issue. Report only redacted command, OS/architecture, Persona version, and safe diagnostic output.

For reproducible bugs, follow [Contributing](../CONTRIBUTING.md). For suspected security vulnerabilities, use [private reporting](../SECURITY.md), not a public issue.
