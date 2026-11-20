# Configuration

Persona reads a versioned TOML policy. The current write format is v3; legacy v1/v2 files can be read and explicitly migrated. Unknown fields are rejected rather than silently ignored.

## Storage and privacy

By default the policy is `$XDG_CONFIG_HOME/persona/config.toml`, falling back to `$HOME/.config/persona/config.toml`. Persona creates private directories/files, writes atomically, and keeps private backups. `--config PATH` selects a read-only policy for inspection; mutation commands operate only on the default Persona configuration. Runtime/install state uses the XDG state directory.

Do not commit real names/emails, local paths, tokens, passwords, private keys, recovery codes, or credential-store data. Persona stores public-key references and GitHub account binding metadata, not private key or token contents. Use `.invalid` domains and synthetic paths in examples and tests.

## Model

A profile holds reusable Git author/committer identity, optional signing and SSH selectors, named remotes/destinations (`allow` and `deny_destinations`), optional GitHub account/repository policy (`repositories` and `deny_repositories`), optional external HTTPS credential helpers, and per-profile command policies (`[profiles.git.commands]`, `[profiles.github.commands]`, `[profiles.run]`). A scope maps an absolute physical directory root to one profile. The most-specific matching scope is used; scopes do not inherit settings implicitly.

## Minimal synthetic example

```toml
version = 3

[[profiles]]
name = "example"
[profiles.git]
author = { name = "Example Author", email = "author@example.invalid" }
committer = { name = "Example Committer", email = "committer@example.invalid" }

[[scopes]]
name = "example-checkout"
path = "/tmp/persona-example/project"
profile = "example"
```

Scope paths must be absolute, names must be unique and non-empty, every scope must name an existing profile, and at least one profile and scope are required. Real policy paths should point only to directories you intend to manage.

## Signing

Signing is optional. A signing policy names an expected full fingerprint and a path to an exported public key; Persona does not read private key material. OpenPGP public-key files must be public-only exports. SSH signing uses a public key. Keep private signing keys in their native secure location and do not copy them into the repository.

## Remotes, destinations, and publication policy

Named remotes and `[profiles.git.push].destinations` accept exact URLs/paths as well as bounded trailing wildcards such as `https://github.com/OWNER/*`, `git@github.com:OWNER/*`, or `*`. GitHub `repositories` accept `OWNER/REPO`, `OWNER/*`, or `*`. `[profiles.git].deny_destinations` and `[profiles.github].deny_repositories` always take precedence over any allow rule so you can allow an owner namespace while carving out individual repositories.

Push policy defaults preserve strict identity separation (`cross_profile_identity_check = true`, author/committer identity enforcement, optional cryptographic signing checks) without breaking normal Git workflows:

- `upstream_provenance` defaults to `"remote_tracking"` (trusting commits already reachable from `refs/remotes/<remote>/*` tracking refs, while enforcing local profile identity/signing on unpublished commits). Set `upstream_provenance = "pinned"` (default whenever `upstream_baselines` is non-empty) to require explicit pinned commit baselines (`persona baseline update`), or `"off"` to audit every ancestor commit.
- `allow_force_push = false` and `allow_force_with_lease` govern unleased `--force` / `+refspec` vs leased updates; `require_tag_lease_on_create = false` allows creating new remote signed tags without passing `--force-with-lease=refs/tags/TAG:0000...`.
- Local repository execution controls (`strict_repo_hooks`, `strict_git_filters`, `strict_merge_drivers`) default to `false` (and `inherit_git_config` defaults to `true`) so everyday developer hooks and Git LFS filters work normally; enable `strict_* = true` on untrusted repositories.

## Command policies (`git`, `gh`, `run`)

Profiles support allowlist and denylist command filtering across `[profiles.git.commands]`, `[profiles.github.commands]`, and `[profiles.run]`:

```toml
[profiles.git.commands]
mode = "denylist"
deny = ["push --force", "tag.*", "submodule"]

[profiles.github.commands]
mode = "allowlist"
allow = ["pr", "release.create", "release.upload"]
deny = ["pr.merge"]

[profiles.run]
mode = "denylist"
deny = ["curl"]
```

- `mode = "denylist"` (the default when neither `mode` nor `allow` is set) allows day-to-day commands unless matched by `deny`, while still enforcing all identity, signing, destination, credential, and SSH guardrails.
- `mode = "allowlist"` (also the default when legacy `allow = [...]` is set without `mode`) permits only commands matching `allow` and not matched by `deny`. `allow = []` denies every command.
- `deny` rules always take precedence over `allow` rules and accept subcommand prefixes (`fetch` blocks `fetch.all`), trailing wildcards (`tag.*`), and command+flag rules (`push --force`). Command lists never bypass identity, signing, destination, or credential checks. Review the [managed command reference](managed-commands.md) and [security boundaries](security-model.md).

## Migration and rollback

Preview before migration:

```sh
persona config migrate --preview
```

Apply is explicit; Persona creates a private backup. `persona config rollback --backup PRIVATE_BACKUP_PATH` restores a backup created by Persona. Inspect a preview and keep backup paths private.

## SSH transports and external HTTPS credentials

`[profiles.ssh]` remains the primary SSH transport policy. Add one or more `[[profiles.ssh_hosts]]` entries to authorize additional `(host, user, port)` selectors in the same profile; for example, this lets one profile keep a GitHub SSH key policy while adding a separate forge host. A duplicate selector across the primary and additional policies is invalid. Every matched SSH destination still goes through the managed adapter and its exact host, user, port, key fingerprint, and known-hosts checks.

```toml
[profiles.ssh]
host = "github.com"
user = "git"
port = 22
fingerprint = "SHA256:synthetic-fingerprint"
public_key = "/tmp/persona-example/github.pub"
identity_file = "/tmp/persona-example/github.key"
known_hosts_file = "/tmp/persona-example/known_hosts"

[[profiles.ssh_hosts]]
host = "forge.example.invalid"
user = "git"
port = 22
fingerprint = "SHA256:synthetic-fingerprint"
public_key = "/tmp/persona-example/forge.pub"
identity_file = "/tmp/persona-example/forge.key"
known_hosts_file = "/tmp/persona-example/known_hosts"
```

Non-GitHub HTTPS credentials are separately opt-in per host with `[[profiles.https_credentials]]`. Each entry has a `host`, an absolute executable `helper`, and optional argument strings `args`; Persona invokes the helper directly (not through a shell). GitHub hosts, including a profile's bound GitHub host, cannot use this mechanism: those credentials continue to require the enrolled `[profiles.github]` binding. Before invoking an external helper, Persona checks that the requested exact HTTPS repository is allowed by the operation's `fetch_destinations` or `push_destinations` and is not matched by `deny_destinations`. `store` and `erase` remain no-ops.

```toml
[[profiles.https_credentials]]
host = "forge.example.invalid"
helper = "/usr/local/bin/forge-credential-helper"
args = ["--profile", "work"]
```

For command syntax and optional online enrollment, see [CLI reference](cli.md). Enrollment is an explicit online action; offline status/check does not contact GitHub or retrieve a token.
