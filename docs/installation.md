# Installation

Persona is a pre-release. This repository currently provides source and Nix packaging; it does not publish prebuilt executables, a binary cache, or a crates.io package.

## Requirements

- Rust 1.85 or newer to build from source (edition 2024).
- Git, GnuPG, OpenSSH, and GitHub CLI for the integrations you use. Zsh is optional. Test suites additionally use OpenSSL and local SSH server tooling.
- A supported build target: Apple Silicon macOS (`aarch64-darwin`), Linux arm64 (`aarch64-linux`), or Linux x86_64 (`x86_64-linux`). Current target declarations do not replace release-specific validation evidence.

## Build from source

After cloning a published source checkout/tag:

```sh
cargo build --locked --release
./target/release/persona --help
```

For a reproducible local validation run, see [Contributing](../CONTRIBUTING.md). Do not run the release candidate against a production repository without first understanding the command and security boundaries.

## Nix

From a public tagged source revision, build or run the package using its flake reference:

```sh
nix build 'github:yanfsb/persona/vX.Y.Z-rc.N#persona'
./result/bin/persona --help
nix run 'github:yanfsb/persona/vX.Y.Z-rc.N' -- --help
```

Replace the placeholder with a published tag. Home Manager users can add a flake input and pass the package to a module, for example:

```nix
{ pkgs, persona, ... }:
{
  home.packages = [ persona.packages.${pkgs.system}.persona ];
}
```

Pass `persona` through the flake's module arguments (for example with `home-manager.extraSpecialArgs`) when using Home Manager as a flake input. Installing the package alone does not enable adapters, hooks, scopes, or authentication; see the [release procedure](releasing.md#distribution).

A historical release's private-repository token instructions are not valid for anonymous public installation. Never place a token in a flake, lock file, command committed to a script, or issue report.

## Optional PATH adapters and hooks

Persona's adapters are opt-in, independent of building the package. `persona install preview --bin-dir EXISTING_USER_BIN` shows the planned links; `apply` installs them. The directory must already exist and be owned by you. Add it to your PATH yourself. `persona hooks install` separately targets an explicitly selected worktree. See [managed commands](managed-commands.md).

Persona records owned paths and backups, refuses unexpected changes, and supports explicit refresh/remove/rollback. Review each preview and backup path. Never use these commands as an unattended global installer.

## Uninstall and recovery

Use `persona install remove --preview` and then `--apply` to remove unchanged adapters recorded in Persona's private manifest. To restore a saved installation state, use `persona install rollback --backup PRIVATE_BACKUP_PATH --preview`, review it, then apply. Hook removal is explicit: `persona hooks remove --cwd WORKTREE --preview`, then repeat without `--preview` to apply. These commands do not clean up unrelated shell settings or user data.
