# Getting started

This guide uses synthetic identities and local paths. It performs no provider enrollment and does not install adapters or hooks.

## 1. Build and inspect

Install the native prerequisites in [Installation](installation.md), then build and check the binary:

```sh
cargo build --locked --release
./target/release/persona --help
./target/release/persona status
```

`status`, `doctor`, and ordinary `check` diagnostics are offline. They do not test remote access or prove that direct native executables are mediated.

## 2. Set up a private local policy

For an interactive terminal, `setup` can prompt for missing author and committer names/emails. In scripts, pass them explicitly. Choose synthetic values for a disposable example:

```sh
./target/release/persona setup \
  --profile example --scope-name example \
  --scope /absolute/path/to/a/test-checkout \
  --author-name 'Example Author' --author-email 'author@example.invalid' \
  --committer-name 'Example Committer' --committer-email 'committer@example.invalid'
```

Setup writes only Persona's private configuration. It does not activate a profile, edit native Git/SSH/GPG/`gh` settings, or install hooks. The default path is `$XDG_CONFIG_HOME/persona/config.toml` or `$HOME/.config/persona/config.toml`; files/directories are private to the user. See [Configuration](configuration.md).

## 3. Inspect before changing policy

Use `profile list|show|verify`, `scope list|show|verify`, `status`, and `doctor` to inspect local state. Use `--preview` on supported mutations and review the output before applying. A `--config` override is read-only; mutations target Persona's default private configuration.

## 4. Enable integrations only deliberately

Review [managed commands](managed-commands.md) and the [security model](security-model.md). Installing PATH adapters and per-repository hooks are separate, explicit operations; neither is required for offline diagnostics. Set up disposable fixtures first. Never test by pushing to a real repository or enrolling a real account as part of the quick start.

To undo an installation, use the explicit Persona remove/rollback commands documented in [Installation](installation.md). Persona does not silently change shell startup files or global native configuration.
