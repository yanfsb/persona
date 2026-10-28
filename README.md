# persona

`persona` is a read-only, directory-scoped identity auditor. It reports the
identity expected by a TOML policy and the locally observable Git state. It
does not activate a profile, change Git/SSH/GPG/GitHub configuration, or
replace Git hooks.

## CLI contract

The executable has two subcommands:

```text
persona status --config POLICY [--cwd DIRECTORY] [--format text|json]
persona check  --config POLICY [--cwd DIRECTORY] [--format text|json]
persona check  --config POLICY [--cwd DIRECTORY] --operation push \
  --remote REMOTE --destination EFFECTIVE_URL < pre-push-tuples
```

`check` defaults to the same local audit as `status`. `--json` is an alias for
`--format json`; the two forms cannot be combined. `status` rejects push-only
options. `check --operation status` rejects `--remote` and `--destination`,
and `check --operation push` requires both of them. A missing or malformed
policy, invalid invocation, or other operational error writes an error to
stderr and exits 2.

Text output is intended for people and is not a stable machine-readable
schema. JSON is versioned and has this shape:

```json
{
  "version": 1,
  "status": "PASS|FAIL|UNKNOWN|WARN",
  "findings": [
    {
      "property": "git.author",
      "status": "PASS|FAIL|UNKNOWN|WARN",
      "expected": "...",
      "observed": "...",
      "coverage_reason": "..."
    }
  ]
}
```

`expected` and `observed` are optional and can be absent. Findings are sorted
by property. Exit codes are 0 for PASS, 1 for FAIL, 2 for an error, 3 for
UNKNOWN, and 4 for WARN. The aggregate status uses the most severe finding;
UNKNOWN is intentionally not treated as PASS.

## TOML v1 policy

The parser rejects unknown fields. The complete schema is:

```toml
version = 1

[[scopes]]
name = "synthetic-work"
path = "/tmp/persona-example/project" # absolute path

[scopes.git]
author = { name = "Synthetic Author", email = "author@example.invalid" }
committer = { name = "Synthetic Committer", email = "committer@example.invalid" }

[scopes.git.signing]
fingerprint = "0000000000000000000000000000000000000000"
public_key = "/tmp/persona-example/public-key.asc" # absolute exported public key

[scopes.git.push]
remote = "origin"
destinations = ["file:///tmp/persona-example/remote.git"]
```

`version` must be 1. At least one scope is required; scope names are unique
and non-empty, and scope paths are absolute. Each scope requires non-empty
Git author and committer names and emails. `signing` is optional; when present
its fingerprint is exactly 40 hexadecimal characters and `public_key` is an
absolute path to an ASCII-armored, public-only exported key. Private/secret-key
armor is rejected before import. The public key is validated with a bounded,
show-only GnuPG parse and then imported into a temporary keyring for verification. `push` is optional; when present its remote is
non-empty and its destinations array contains at least one non-empty exact
string. The values above are synthetic placeholders only. Do not put private
keys, tokens, credentials, or real identity/path data in a repository policy.
Do not create a private configuration file as part of installation.

## Push tuple input

`check --operation push` reads stdin in native Git pre-push shape, one update
per line:

```text
local_ref local_oid remote_ref remote_oid
```

The command-line `--remote` is the caller's remote name and
`--destination` is the effective destination reported by the caller. Each OID
must be 40 or 64 hexadecimal characters. The offline audit currently supports
exactly one non-deletion, non-force branch update with both refs under
`refs/heads/`, a non-zero local and remote OID, and locally available complete
objects. It checks the exact remote name and destination against local
`pushurl`/`url` configuration after local `pushInsteadOf`/`insteadOf` rewrites,
then checks every outgoing commit's author and committer. With a signing
policy, every outgoing commit is checked for a signature, validity, and the
configured primary fingerprint.

Empty input, malformed lines, multiple updates, deletions, new branches,
force/non-fast-forward updates, tags and other non-branch refs, missing
objects, shallow or partial repositories, and unsupported annotated-tag
metadata are UNKNOWN rather than PASS. A tuple is caller-supplied data: this
command does not itself receive Git's hook environment and does not prove that
Git used the destination, that credentials work, or that a remote account owns
it.

## Offline guarantees and UNKNOWN boundaries

Normal status/check execution performs no network operation: it does not run
push, fetch, `ls-remote`, `ssh`, `gh`, credential helpers, DNS, or hooks. Git
configuration and locally available objects are inspected through bounded
subprocesses. OpenPGP verification uses only the configured public-key file in
an isolated temporary GnuPG home; the user's GnuPG home, keyring, config,
Keychain, pinentry, and key retrieval are not read. GPG absence, unavailable
keys, incomplete repositories, and values that cannot be observed locally are
UNKNOWN.

SSH and GitHub findings inspect only parent-process environment-variable
presence (`GIT_SSH`, `GIT_SSH_COMMAND`, `SSH_AUTH_SOCK`, `GH_TOKEN`,
`GITHUB_TOKEN`, `GH_HOST`, and `GH_CONFIG_DIR`). `GH_TOKEN` takes precedence
over `GITHUB_TOKEN` in the indicator text. Values and paths are not printed.
Configured remote transport schemes may be reported, but authentication,
credential selection, account ownership, reachability, future commits, and
publication safety remain UNKNOWN. A PASS is evidence only for the individual
property that was checked.

### Git 2.55 and linked worktrees

For Git 2.55, the checker obtains the physical checkout root with
`git rev-parse --show-toplevel` before resolving a scope. A linked worktree is
therefore evaluated by its own checkout directory, not by the common main
worktree directory. Canonical path and most-specific-ancestor matching are
used. This observes Git's current checkout; it does not change worktree
configuration or claim that a different pane/process has the same state.

## Process, hooks, and enforcement limits

There is no daemon, shell activation, global account switch, runtime policy
enforcer, or automatic hook installation. The command is an audit and cannot
block a later `git push`; a pre-push integration would still be a separate
caller and Git may contact a remote before hooks run. Two tmux panes or other
processes can run audits concurrently without shared mutable persona state,
but they share the macOS user, filesystem, credentials, agents, environment
inheritance, and any already-running process. This is not process, Keychain,
network, or anonymity isolation.

## Nix build, use, and rollback

The flake supports only `aarch64-darwin` (Apple Silicon). Its package uses
`Cargo.lock` through `buildRustPackage`, and its checks include release build,
locked Cargo tests, `cargo fmt --check`, and locked Clippy with warnings as
errors. Git and GnuPG are in the package/check environments; the installed
wrapper supplies them to the executable without changing global configuration.
A flake lock file should be committed/updated by the release process before
building in a fresh environment.

Use without installation or global changes:

```sh
nix run .#persona -- status --config /tmp/persona-example/policy.toml
nix build .#persona
./result/bin/persona check --config /tmp/persona-example/policy.toml
nix flake check
```

For an explicit local profile (also leaving global Git, SSH, GPG, and shell
configuration untouched):

```sh
nix profile install --profile ./persona-profile .#persona
./persona-profile/bin/persona --help
nix profile list --profile ./persona-profile
nix profile remove --profile ./persona-profile persona
test -L ./persona-profile && rm ./persona-profile
test -L ./result && rm ./result
```

Rollback is limited to removing that local profile/result; no dotfiles,
repository hooks, global Git settings, authentication state, or network
routing are modified by these commands. Do not run deployment, credential,
network, or authentication probes as part of installation.
