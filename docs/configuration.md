# Configuration

Persona reads a versioned TOML policy using **schema v4** (`version = 4`). Unknown fields and unsupported versions are rejected rather than silently ignored, with line/column/field parse diagnostics.

## Storage and privacy

By default the policy is `$XDG_CONFIG_HOME/persona/config.toml`, falling back to `$HOME/.config/persona/config.toml`. Persona creates private directories/files (`0700` / `0600`), writes atomically under an exclusive lock, and keeps private backups. `--config PATH` selects a read-only policy for inspection; mutation commands operate only on the default Persona configuration. Runtime/install state uses the XDG state directory.

Do not commit real names/emails, local paths, tokens, passwords, private keys, recovery codes, or credential-store data. Persona stores public-key references and GitHub account binding metadata, not private key or token contents. Use `.invalid` domains and synthetic paths in examples and tests.

## Model

Profiles are defined as named TOML tables under `[profiles.<name>]`. Each profile defines Git author/committer identity (`name`/`email` shorthand when both match, or explicit `author` / `committer`), optional `signing`, `ssh`, `github`, `https`, `git` destinations/push/hardening rules, and command policies (`git.commands`, `github.commands`, `run`).

Directory scopes can be declared inline on a profile (`scopes = ["~/projects"]` or `scopes = [{ name = "custom", path = "~/projects" }]`) or in a top-level `[scopes]` map (`my-scope = { path = "~/projects", profile = "example" }`). Leading `~/` expands deterministically against a validated absolute `$HOME`; relative paths, `~/../` escapes, and `$VAR` shell expansion are rejected. The most-specific matching physical directory scope is selected; directory scopes never inherit settings implicitly.

## Minimal synthetic example

```toml
version = 4

[profiles.example]
scopes = [{ name = "example-checkout", path = "/tmp/persona-example/project" }]
name = "Example Author"
email = "author@example.invalid"
```

Profile and scope names must be unique and non-empty, every scope must reference an existing profile, duplicate scope paths are rejected, and at least one profile and scope are required. Real policy paths should point only to directories you intend to manage.

## Profile inheritance (`extends`)

Profiles can explicitly inherit from another profile via `extends = "<parent>"`:

```toml
version = 4

[profiles.base]
scopes = ["~/work"]
name = "Synthetic Dev"
email = "dev@example.invalid"

[profiles.base.git]
push = ["github.com/example-org/*"]
allow_force_with_lease = true

[profiles.strict-repo]
extends = "base"
scopes = [{ name = "strict-repo", path = "~/work/strict-repo" }]
git.remote = "origin"
git.push = ["git@github.com:example-org/strict-repo.git"]
git.allow_force_with_lease = false
```

- Scalar fields (`name`, `email`, push/hardening booleans, `signing.*`, `ssh.*`, `github.*`) inherit from the parent when omitted and override when set.
- List and map fields (`git.push`, `git.fetch`, `git.deny`, `github.repos`, `github.deny_repos`, `ssh.hosts`, `git.baselines`, `https`) **replace** the parent value when set so child profiles can cleanly narrow permissions.
- `scopes` are never inherited.
- Missing parents and cyclic inheritance graphs fail closed.
- Use `persona config show --resolved` to inspect the fully expanded effective policy.

## Signing

Signing is optional under `[profiles.<name>.signing]`. Provide a full `fingerprint` and `public_key` path (`~/` supported); `format` defaults to `"ssh"` when the fingerprint begins with `SHA256:` and `"openpgp"` otherwise. Persona never reads private key material. OpenPGP public-key files must be public-only exports.

## Remotes, destinations, and publication policy

Under `[profiles.<name>.git]`, `push`, `fetch`, and `deny` accept:

- **Forge shorthands** such as `github.com/OWNER/*`, `github.com/*`, or `github.com/OWNER/REPO` (which expand deterministically to both SSH `git@HOST:...` and HTTPS `https://HOST/...` patterns).
- **Explicit URLs/patterns** such as `git@github.com:OWNER/REPO.git` (SSH-only), `https://github.com/OWNER/*` (HTTPS-only), `file:///...`, or `*`.

`deny` (and `[profiles.<name>.github].deny_repos`) always take precedence over any allow rule. If `fetch` is omitted when `push` is set, fetch reuses the `push` destinations. For multi-remote setups (such as read-only `upstream` plus writable `origin`), define named tables under `[profiles.<name>.git.remotes.<remote>]`:

```toml
[profiles.oss.git.remotes.upstream]
fetch = ["github.com/upstream-org/project"]

[profiles.oss.git.remotes.origin]
fetch = ["github.com/example-user/project"]
push = ["github.com/example-user/project"]
```

Push policy defaults preserve strict identity separation (`cross_profile_identity_check = true`, author/committer identity enforcement, optional cryptographic signing checks) while omitting default fields on write:

- `remote` defaults to `"*"` when `push` is set.
- `upstream_provenance` defaults to `"remote_tracking"` (trusting commits reachable from `refs/remotes/<remote>/*` tracking refs while enforcing local profile identity/signing on unpublished commits). Set `upstream_provenance = "pinned"` (default whenever `baselines` is non-empty) to require pinned commit baselines (`persona baseline update`), or `"off"` to audit every ancestor commit.
- `allow_force_push = false` and `allow_force_with_lease = false` govern opt-in unleased `--force` / `+refspec` vs leased updates (and combine with `[profiles.<name>.git.commands]` rules such as `push.force` and `push.force-with-lease`). Bare `--force-with-lease` and `--force-with-lease=<ref>` automatically resolve the cached remote-tracking OID into an exact lease verified at both primary authorization and the `pre-push` hook; `require_tag_lease_on_create = false` allows creating new remote signed tags without passing `--force-with-lease=refs/tags/TAG:0000...`.
- Local repository execution controls (`strict_repo_hooks`, `strict_git_filters`, `strict_merge_drivers`) default to `false` (and `inherit_git_config` defaults to `true`); enable `strict_* = true` on untrusted repositories.

## Command policies (`git`, `gh`, `run`)

Profiles support allowlist and denylist command filtering across `[profiles.<name>.git.commands]`, `[profiles.<name>.github.commands]`, and `[profiles.<name>.run]`:

```toml
[profiles.example.git.commands]
mode = "denylist"
deny = ["push --force", "tag.*", "submodule"]

[profiles.example.github.commands]
mode = "allowlist"
allow = ["pr", "release.create", "release.upload"]
deny = ["pr.merge"]

[profiles.example.run]
mode = "denylist"
deny = ["curl"]
```

- `mode = "denylist"` (the default when neither `mode` nor `allow` is set) allows day-to-day commands unless matched by `deny`, while still enforcing all identity, signing, destination, credential, and SSH guardrails.
- `mode = "allowlist"` (also the default when `allow = [...]` is set without `mode`) permits only commands matching `allow` and not matched by `deny`. `allow = []` denies every command.
- `deny` rules always take precedence over `allow` rules and accept subcommand prefixes (`fetch` blocks `fetch.all`), trailing wildcards (`tag.*`), and command+flag rules (`push --force`). Review the [managed command reference](managed-commands.md) and [security boundaries](security-model.md).

## SSH transports and external HTTPS credentials

`[profiles.<name>.ssh]` configures managed SSH transport. Provide `host = "github.com"` or `hosts = ["github.com", "forge.example.invalid"]` to share one key across multiple hosts; `user` defaults to `"git"`, `port` defaults to `22`, `known_hosts_file` defaults to `~/.ssh/known_hosts`, and `public_key` defaults to `<identity_file>.pub` when `identity_file` is set. Use `[[profiles.<name>.ssh.extra]]` when an additional host requires a different key, user, port, or `agent_socket`. Duplicate `(host, user, port)` selectors are rejected.

```toml
[profiles.example.ssh]
hosts = ["github.com", "forge.example.invalid"]
fingerprint = "SHA256:synthetic-fingerprint"
identity_file = "/tmp/persona-example/id_ed25519"
known_hosts_file = "/tmp/persona-example/known_hosts"
```

Non-GitHub HTTPS credentials are opt-in per host under `[profiles.<name>.https."<host>"]`. Each entry specifies an absolute `helper` (no shell) and optional `args`. GitHub hosts and the profile's bound GitHub host cannot use this mechanism: those credentials continue to require `[profiles.<name>.github]`.

```toml
[profiles.example.https."forge.example.invalid"]
helper = "/usr/local/bin/forge-credential-helper"
args = ["--profile", "work"]
```

## Validation, inspection, editing, and rollback

```sh
persona config path
persona config validate
persona config show --resolved
persona config edit
persona config rollback --backup PRIVATE_BACKUP_PATH
```

`persona config edit` opens a private `0600` buffer in `$VISUAL`/`$EDITOR`, validates the result before saving, and writes atomically with an automatic backup. For command syntax and optional online enrollment, see [CLI reference](cli.md).
