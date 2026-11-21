# Security model and limitations

## Intended protection

Persona prevents cross-identity and wrong-destination mistakes across directory-scoped profiles by enforcing author/committer identity isolation, cross-profile commit leak checks (`cross_profile_identity_check`), cryptographic signing, destination allow/deny boundaries, SSH key isolation, and GitHub credential binding. Per-profile command policies (`denylist` by default, or `allowlist` for strict workflows) govern which `git`, `gh`, and `persona run` commands are permitted; command rules never weaken identity, signing, destination, or credential checks. Opt-in repository hardening flags (`strict_repo_hooks`, `strict_git_filters`, `strict_merge_drivers`) block local hooks, filters, and merge drivers on untrusted repositories when enabled. Non-GitHub HTTPS credential helpers are separately opt-in per host through `[profiles.<name>.https."<host>"]`; they are invoked only after exact fetch/push destination allow/deny checks, with a sanitized environment and only the real `HOME`/XDG config needed by the helper (`PERSONA_REAL_HOME` is used to recover that home from isolated Git processes). This option never handles GitHub hosts or weakens enrolled GitHub account bindings. A PASS applies only to the named evidence checked for that operation.

## Boundaries

Persona is **not** a sandbox, process isolation system, firewall, network confinement layer, VPN/Tor enforcement, anonymity system, or universal Git/GitHub replacement. It does not defend against malicious code running as the same OS user. The user's processes, filesystem, credentials, agents and environment are shared.

Direct absolute native binaries (for example `/usr/bin/git`), other network tools, shell escapes, `--no-verify`, and unsupported adapters can bypass the managed PATH. A prompt marker or installed hook does not prove all processes are protected. Already-running processes are not changed.

## Offline versus online

Normal status and diagnostic checks are offline: they do not run network operations, DNS, SSH, GitHub CLI, hooks, or credential helpers and do not read private keys or tokens. Some explicitly requested actions are online: GitHub enrollment and optional online verification contact GitHub. Managed fetch/push and `gh` operations necessarily contact their configured remote after local policy gates.

Persona stores account identifiers and a keyed token fingerprint for enrollment; it does not store the token itself. Local binding does not prove that a remote server will accept a credential or that it has not been revoked. Never share token output, private keys, credential-store files, or real config in a report.

## Fail-closed evidence

A required mismatch blocks. Required `UNKNOWN`, missing, duplicate, or ambiguous evidence also blocks authorization. Unrelated unknown findings may remain visible without vetoing an operation that does not require them. Text diagnostic output is not a stable API; JSON output is versioned. Consult the CLI reference for exit statuses.

Local checks do not prove remote reachability, successful authentication, future commits, provider-side authorization, or that the caller used the observed destination. Release creation and asset upload have an unavoidable concurrent retag/deletion race because the provider API cannot atomically bind tag name to tag-object OID; the race is detectable only after the call.

Managed asset upload reuses the release signing/account/destination gates. It snapshots bounded regular files using descriptor-relative no-follow opens within the physical worktree before selecting credentials. The upload transport disables curl configuration and inherited proxies, uses the fixed HTTPS GitHub upload endpoint, rejects redirects, and keeps the selected token out of argv. This is not a secrecy classifier: a worktree file may still contain material that must not be published. Review source archives and asset contents separately. Sequential uploads can partially succeed or have uncertain outcomes; Persona never automatically overwrites, deletes, or blindly retries them. See the [managed command restrictions](managed-commands.md#release-asset-upload).

## Safe use

- Start with offline diagnostics and synthetic fixtures.
- Inspect every preview and use disposable repositories for installation/hook tests.
- Keep configuration, backups, tokens and private keys out of source control and public issue reports.
- Treat unsupported commands as unmanaged/blocked, not as implicitly protected. `git fetch --all` preflights every eligible remote's exact destination before transport, but independent runtime transfers are not atomic: earlier remotes may have fetched before a later network failure.
- The earlier limited real-account pilot verified binding, repository metadata reads, and SSH fetch only; release-specific publication evidence must be recorded separately. Production use has not been evaluated. Do not use this release candidate as a security boundary for production publishing.
