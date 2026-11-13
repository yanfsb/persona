# Security model and limitations

## Intended protection

Persona reduces accidental identity and destination mistakes in explicitly managed Git/GitHub CLI paths. It associates local identity policy with physical directory/worktree scopes, checks bounded command forms, and fails closed when required evidence is missing, ambiguous, unsupported, or unbounded. A PASS applies only to the named evidence checked for that operation.

## Boundaries

Persona is **not** a sandbox, process isolation system, firewall, network confinement layer, VPN/Tor enforcement, anonymity system, or universal Git/GitHub replacement. It does not defend against malicious code running as the same OS user. The user's processes, filesystem, credentials, agents and environment are shared.

Direct absolute native binaries (for example `/usr/bin/git`), other network tools, shell escapes, `--no-verify`, and unsupported adapters can bypass the managed PATH. A prompt marker or installed hook does not prove all processes are protected. Already-running processes are not changed.

## Offline versus online

Normal status and diagnostic checks are offline: they do not run network operations, DNS, SSH, GitHub CLI, hooks, or credential helpers and do not read private keys or tokens. Some explicitly requested actions are online: GitHub enrollment and optional online verification contact GitHub. Managed fetch/push and `gh` operations necessarily contact their configured remote after local policy gates.

Persona stores account identifiers and a keyed token fingerprint for enrollment; it does not store the token itself. Local binding does not prove that a remote server will accept a credential or that it has not been revoked. Never share token output, private keys, credential-store files, or real config in a report.

## Fail-closed evidence

A required mismatch blocks. Required `UNKNOWN`, missing, duplicate, or ambiguous evidence also blocks authorization. Unrelated unknown findings may remain visible without vetoing an operation that does not require them. Text diagnostic output is not a stable API; JSON output is versioned. Consult the CLI reference for exit statuses.

Local checks do not prove remote reachability, successful authentication, future commits, provider-side authorization, or that the caller used the observed destination. Release creation has an unavoidable concurrent retag/deletion race because the provider API cannot atomically bind tag name to tag-object OID; the race is detectable only after the call.

## Safe use

- Start with offline diagnostics and synthetic fixtures.
- Inspect every preview and use disposable repositories for installation/hook tests.
- Keep configuration, backups, tokens and private keys out of source control and public issue reports.
- Treat unsupported commands as unmanaged/blocked, not as implicitly protected.
- A limited real-account pilot verified binding, repository metadata reads, and SSH fetch only. Managed publication and production use have not been exercised. Do not use this release candidate as a security boundary for production publishing.
