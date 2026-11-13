# Configuration

Persona reads a versioned TOML policy. The current write format is v3; legacy v1/v2 files can be read and explicitly migrated. Unknown fields are rejected rather than silently ignored.

## Storage and privacy

By default the policy is `$XDG_CONFIG_HOME/persona/config.toml`, falling back to `$HOME/.config/persona/config.toml`. Persona creates private directories/files, writes atomically, and keeps private backups. `--config PATH` selects a read-only policy for inspection; mutation commands operate only on the default Persona configuration. Runtime/install state uses the XDG state directory.

Do not commit real names/emails, local paths, tokens, passwords, private keys, recovery codes, or credential-store data. Persona stores public-key references and GitHub account binding metadata, not private key or token contents. Use `.invalid` domains and synthetic paths in examples and tests.

## Model

A profile holds reusable Git author/committer identity, optional signing and SSH selectors, named remotes/destinations, and optional GitHub account/repository policy. A scope maps an absolute physical directory root to one profile. The most-specific matching scope is used; scopes do not inherit settings implicitly.

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

## Remotes and publication policy

Named remotes have exact fetch and push destination allowlists. A push policy is explicit and controls initial pushes, fast-forwards, annotated/lightweight tags, deletions, and exact-lease rewrites. Defaults are conservative; changing policy records consent, not proof that every transport form is implemented. Review the [managed command reference](managed-commands.md) and [security boundaries](security-model.md).

## Migration and rollback

Preview before migration:

```sh
persona config migrate --preview
```

Apply is explicit; Persona creates a private backup. `persona config rollback --backup PRIVATE_BACKUP_PATH` restores a backup created by Persona. Inspect a preview and keep backup paths private.

For command syntax and optional online enrollment, see [CLI reference](cli.md). Enrollment is an explicit online action; offline status/check does not contact GitHub or retrieve a token.
