# persona

`persona` is a directory-scoped identity guardrail. The initial `v0.1.0-rc.1`
release validates the documented, bounded managed-command subset on macOS arm64
and Linux arm64/x86_64. This is a release candidate, not a sandbox, anonymity
system, or universal Git/GitHub replacement. Direct native binaries and hostile
same-user processes remain outside its mediation boundary. Read the supported
command surface and limitations in this README and the acceptance matrix at
[`docs/implementation-matrix.md`](docs/implementation-matrix.md) before enabling
managed commands in a real scope.
`setup` prompts for missing author/committer names and emails when attached to
a terminal; non-interactive calls must pass those values explicitly. It writes
only Persona's private configuration and does not activate a profile or change
Git/SSH/GPG/GitHub configuration or hooks. Profile edits accept paired
`--signing-fingerprint`/`--public-key` (and optional `--signing-format openpgp|ssh`),
SSH selector options, and `--push-remote`/repeated
`--push-destination` options. Publication policy can be adjusted explicitly with
`--allow-initial-push`, `--allow-fast-forward`, `--allow-annotated-tags`,
`--allow-lightweight-tags`, `--allow-branch-deletion`, `--allow-tag-deletion`,
and `--allow-force-with-lease` (each takes `true` or `false`). Destructive opts
are off by default; enabling one records consent but does not activate an
unimplemented transport path. Annotated-tag publication requires a signing
policy. Mutations validate before writing, create a private backup, and accept
`--preview` to print the validated v3 result without writing.

## CLI contract

The current CLI supports offline status/check, `doctor`, a transparent
shell-free `run` launcher, non-destructive setup, and explicit configuration
migration. Bare `persona` and `persona status` show compact status; use
`--verbose` or `doctor` for full findings and `--format json` for versioned
JSON. Full findings include `integration.managed_shims` (private installer manifest,
all four owned symlinks, and PATH presence) and `integration.pre_push_hook` (current
worktree's hook manifest/dispatcher/symlink). These checks read no credentials and
do not claim direct native binaries are mediated. `--config` is optional: Persona uses
`$XDG_CONFIG_HOME/persona/config.toml` (or `$HOME/.config/persona/config.toml`)
and refuses an unsafe default config file/directory.

```text
persona setup --profile NAME --scope-name NAME --scope DIRECTORY \
  --author-name NAME --author-email EMAIL \
  --committer-name NAME --committer-email EMAIL
persona
persona status [--config POLICY] [--cwd DIRECTORY] [--verbose|--format json]
persona doctor [--config POLICY] [--cwd DIRECTORY] [--format text|json]
persona run [--config POLICY] [--cwd DIRECTORY] -- PROGRAM [ARG ...]
persona install preview|apply --bin-dir EXISTING_USER_BIN
persona install refresh|remove --preview|--apply
persona install rollback --backup PRIVATE_BACKUP_PATH --preview|--apply
persona shell zsh init|marker
persona check  [--config POLICY] [--cwd DIRECTORY] [--format text|json]
persona check  [--config POLICY] [--cwd DIRECTORY] --operation push \
  --remote REMOTE --destination EFFECTIVE_URL < pre-push-tuples
persona check  [--config POLICY] [--cwd DIRECTORY] --operation tag --tag NAME
persona profile list|show|verify [NAME] [--config POLICY]
persona profile add|update NAME --author-name ... --author-email ... \
  --committer-name ... --committer-email ... [profile policy options] [--preview]
# Repeat after `auth enroll` to authorize GH repository targets:
persona profile update NAME ... --github-repo OWNER/REPO [--github-repo OWNER/REPO]
persona hooks install --config POLICY --cwd WORKTREE [--preview]
persona hooks remove --cwd WORKTREE [--preview]
# SSH selector options (identity file or agent socket is required):
  --ssh-host HOST --ssh-user USER --ssh-port PORT --ssh-fingerprint SHA256:...
  --ssh-public-key ABSOLUTE_PATH --ssh-known-hosts-file ABSOLUTE_PATH
  --ssh-identity-file ABSOLUTE_PATH | --ssh-agent-socket ABSOLUTE_PATH
  --clear-ssh  # profile update only
persona profile remove NAME [--preview]
persona scope list|show|verify [NAME] [--config POLICY]
persona scope add|update NAME DIRECTORY --profile PROFILE [--preview]
persona scope remove NAME [--preview]
persona config migrate [--config POLICY] --preview|--apply
persona config rollback --backup PRIVATE_BACKUP_PATH
persona auth enroll --profile PROFILE [--host github.com] --user GH_USERNAME --confirm-online
persona auth verify --profile PROFILE
persona auth unbind --profile PROFILE [--preview]
persona credential-helper get|store|erase
```

`check` defaults to the same local audit as `status`. `--json` is an alias for
`--format json`; the two forms cannot be combined. `--verbose` is text-only.
`run` directly spawns the requested executable (no implicit shell), preserves
arguments/cwd/stdio and child exit status, and adds temporary Persona `git`/`gh`
PATH shims. `install` manages persistent `git`, `gh`, `ssh`, and Git credential
adapter symlinks in an existing user-owned bin directory. It requires explicit
apply/remove/refresh/rollback actions, stores a private manifest and restore
points, refuses unowned or externally changed paths, and never edits shell
startup files or repository hooks. Interrupted transactions are reconciled by the
next explicit install/refresh/remove/rollback mutation. These checks are not a lock
against a hostile same-user process racing filesystem changes. Add the chosen bin
directory to PATH yourself; use `persona hooks install` separately for explicitly
selected repositories. Optional Zsh users can add `eval "$(persona shell zsh init)"`
to their own startup file and place `$(persona_prompt_marker)` in `PROMPT` (which
requires the user's own `PROMPT_SUBST` setting). The snippet is quiet and
idempotent, composes through Zsh's `add-zsh-hook` arrays (so
other hooks such as direnv remain installed), and `persona_zsh_deactivate` removes
only Persona's hook/functions. `[scope]` means only that the current directory
matches a configured scope; it does not claim every operation is authorized or
protected. No identity is activated and existing processes are unchanged. The Git
shim currently supports safe-pathspec `add` (including `git add .`), scoped
`status`, bounded `diff`/`show`, restricted `rev-parse`, `log`, branch/tag/worktree
listing, `init`, policy-identity
`commit`, exact-destination HTTPS/managed-SSH `fetch`/`clone`, and
fast-forward-only `pull`. SSH fetch/clone use `git-upload-pack`; the bounded
managed push uses `git-receive-pack` only after primary authorization, hook
verification, and destination/path binding through the profile's pinned transport.
The `gh` shim supports explicit allowlisted GitHub.com `repo view|clone|fork|create`,
PR/issue view/list/create, release view/list, typed PR checkout/review/merge, and
repository-scoped constrained REST requests. PR checkout requires a clean worktree,
fetches only `refs/pull/NUMBER/head` through the profile-bound managed remote,
checks the fetched SHA against GitHub metadata, and refuses existing local branches
or active checkout hooks. Reviews use a typed API event and bounded body. Server
merges require a separate profile grant for repository, target base branch, and
strategy; they bind GitHub's merge endpoint to the observed head SHA. Server-created
commits are not represented as locally signed by Persona. Release creation is
allowed only for an already-published, locally verified signed annotated tag whose
remote tag-object OID matches exactly, and the API response must name the requested
tag. Persona sends the audited peeled commit as `target_commitish`, but GitHub
ignores that field when the tag already exists; the binding is the pre/post remote
ref check, not that request field. It never intentionally creates or pushes a tag.
The release endpoint cannot atomically bind the tag name to an OID, so a concurrent
retag/deletion race can only be detected by the post-check and must be reported.
The profile must carry a local account binding and explicit `--github-repo`
allowlist entries. Aliases are normalized only for documented built-in synonyms;
extensions, enterprise hosts, arbitrary API methods/headers/input, destructive
commands, and unknown flags are refused. The selected native account and target
repository are checked before delegation; nested Git must pass its own adapter.
Git rejects ambiguous flags and unsupported operations before transport. Explicit
managed pushes support bounded branch/tag refs and deletions (up to 16 updates;
multiple refs require `--atomic`), with exact lease OIDs required for rewrites,
updates, and deletions. Annotated tags require the configured signature policy;
lightweight tags have a separate explicit opt-in. One authenticated handoff binds
the authorization tuple, config, scope, account, and hook manifest; the hook
compares native advertised refs/OIDs to that plan before the transport proceeds.
Implicit push options, mirror mode, follow-tags, submodule updates, unbounded
refspecs, and force without an exact lease remain blocked. GitHub destinations
additionally require the selected credential to match the enrolled account before
transport. Direct absolute native binaries can bypass PATH mediation, so `run` is
not a sandbox or network confinement. `status` rejects push-only options. `check
--operation status` rejects push/tag arguments; `check --operation push` requires
both `--remote` and `--destination`; and `check --operation tag` requires `--tag
NAME`. Tag verification is local only.
GitHub destinations additionally require the selected credential to match the
enrolled account before transport. Direct absolute native binaries can bypass
PATH mediation, so `run` is not a sandbox or network confinement. `status` rejects push-only
options. `check --operation status` rejects push/tag arguments;
`check --operation push` requires both `--remote` and `--destination`; and
`check --operation tag` requires `--tag NAME`. Tag verification is local only.
Use `check --operation push --online-verified` for an explicit, bounded GitHub
API query of outgoing commits (at most 32 per invocation); missing or false
GitHub verification evidence blocks that decision. Without the flag, host-side
`Verified` remains UNKNOWN and no API request is made. A missing or malformed
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
by property. Diagnostic status exit codes are 0 for PASS, 1 for FAIL, 2 for an
error, 3 for UNKNOWN, and 4 for WARN. `check --operation push` instead emits a
version-2 operation decision and exits 0 only when every operation-required
property has exactly one PASS finding; FAIL, UNKNOWN, WARN, missing, and
ambiguous required evidence block with exit 1. Unrelated UNKNOWN findings stay
visible but do not veto that operation. The decision includes the diagnostic
findings and explicit required-property blockers.

## TOML v3 profiles and scopes

The parser rejects unknown fields. Profiles contain reusable identity policy;
scopes map absolute physical roots to one profile, with no implicit inheritance:

```toml
version = 3

[[profiles]]
name = "synthetic-work"
[profiles.git]
author = { name = "Synthetic Author", email = "author@example.invalid" }
committer = { name = "Synthetic Committer", email = "committer@example.invalid" }

[profiles.git.signing]
fingerprint = "0000000000000000000000000000000000000000"
public_key = "/tmp/persona-example/public-key.asc" # absolute exported public key

[profiles.git.push]
remote = "origin"
destinations = ["file:///tmp/persona-example/remote.git"]

[[profiles.git.remotes]]
name = "origin"
fetch_destinations = ["file:///tmp/persona-example/remote.git"]
push_destinations = ["file:///tmp/persona-example/remote.git"]

[[scopes]]
name = "synthetic-work-checkout"
path = "/tmp/persona-example/project" # absolute path
profile = "synthetic-work"
```

At least one profile and scope are required. Profile and scope names are
unique and non-empty; all scope paths are absolute and each scope references
an existing profile. A profile may be reused by multiple scopes. Each profile
requires non-empty Git author and committer names and emails. `signing` is
optional; it defaults to `format = "openpgp"`, whose fingerprint is exactly 40
hexadecimal characters and whose `public_key` is an absolute path to an
ASCII-armored, public-only export. `format = "ssh"` accepts an OpenSSH public
key and its `SHA256:...` fingerprint. OpenPGP key armor is validated with a
bounded, show-only GnuPG parse and imported into a temporary keyring. SSH
signatures use a temporary allowed-signers file containing only the configured
public key and scope committer email; the verifier is forced on Git's command
line so repository settings cannot replace it. Optional `[profiles.ssh]` binds
an exact host/user/port, public-key fingerprint, strict `known_hosts` file,
and either a private identity path or an explicit agent socket. Persona reads
only the public key and filesystem metadata; it does not read private key
material. The managed SSH command uses `-F none`, disables
proxying/forwarding/multiplexing, and checks destination/key before spawning.
`push` is optional; when present its remote is non-empty and its destinations
array contains at least one non-empty exact string. Optional
`preserve_authors = true` explicitly permits upstream/cherry-picked author
metadata during push audits; the default remains strict local author matching,
and the committer must still match the profile.

Legacy v1 and v2 policy files remain readable. `persona config migrate --config
POLICY --preview` prints a v3 TOML preview to stdout and never modifies the
source. Migration does not grant new publication or server-side merge permissions. v3
profiles may declare exact named remote `fetch_destinations` and `push_destinations`
separately; a publication policy must match its named remote and push destinations.
Legacy push destinations are carried forward conservatively as that remote's
fetch/push destinations. Profiles may also declare explicit
`[profiles.github_merge]` repository/base/strategy allowlists; these are rejected
unless each repository is already in the enrolled profile GitHub repository
allowlist. `gh pr checkout NUMBER --repo OWNER/REPO [--branch NAME]` fetches only that
PR's head ref through the managed remote transport, requires a clean worktree
and unused new local branch, verifies the fetched SHA against GitHub API metadata,
and then creates the branch. `gh pr review NUMBER --repo OWNER/REPO` accepts one
explicit approve/request-changes/comment action; review text is sent as a bounded
API field. `gh pr merge NUMBER --repo OWNER/REPO --squash|--merge|--rebase` is
handled as a typed server-side action: Persona checks the profile strategy and
live base branch, then submits GitHub's merge API with the observed head SHA as a
precondition. The resulting server commit is reported as server-generated, not
locally signed by Persona. Release creation accepts only an existing locally
verified signed annotated tag whose exact tag-object SHA is present on the
allowlisted GitHub repository; it never creates or pushes a tag. The remote tag
is checked both before and after release creation, though concurrent retagging
cannot be made atomic with GitHub's release API. The example values are synthetic placeholders only. Do not put private
keys, tokens, credentials, or real identity/path data in a repository policy.
Default XDG config/state directories are created with owner-only permissions;
configuration writes are atomic, preserve a private backup, and expose CLI
rollback. Mutating commands operate only on Persona's default private XDG
configuration; `--config` overrides are read-only. GitHub enrollment is
explicitly online: `auth enroll --user GH_USERNAME --confirm-online` selects that
named native `gh` account (without changing the global active account) to query a
stable numeric account ID. Legacy bindings without an explicit username selector
remain incomplete until re-enrollment; offline `check` never retrieves a token. Persona stores only that
ID, host, and a keyed HMAC-SHA-256 token fingerprint; it never stores the
credential. `auth verify` compares the selected local native token and makes no
API call. Environment tokens, plaintext `oauth_token` in `gh`'s `hosts.yml`,
unknown stores, and stale/replaced bindings are refused for protected GitHub
pushes. Tests use synthetic `gh` executables and never contact providers.
The Git HTTPS credential-helper command speaks only Git's bounded credential
protocol, returns a native `gh` token only after the exact host/path, allowed
push destination, and enrolled HMAC binding pass, and treats `store`/`erase` as
no-ops. The `persona run` Git shim installs it only for its managed invocation;
do not configure it globally. HTTPS fetch/clone use isolated HOME, native TLS
verification, disabled redirects/proxies/cookies/ambient helpers, and exact
configured destinations. Setup and launcher behavior are local conveniences,
not anonymity or sandbox guarantees.

## Push tuple input

`check --operation push` reads stdin in native Git pre-push shape, one update
per line:

```text
local_ref local_oid remote_ref remote_oid
```

The command-line `--remote` is the caller's remote name and
`--destination` is the effective destination reported by the caller. Each OID
must be 40 or 64 hexadecimal characters. The offline audit now creates a private immutable snapshot of up to 16 requested
ref/OID updates and classifies no-op, initial branch, fast-forward, rewrite,
branch/tag deletion, annotated tag, lightweight tag, and unsupported ref kinds.
First pushes and fast-forwards are policy-enabled by default and still require
complete local object/signature/identity evidence. The combined outgoing graph is capped at
2,048 inspected commit records, refs are checked with native `git check-ref-format`, and commits
shared between ref graphs are inspected once. It checks the exact remote name
and destination against local `pushurl`/`url` configuration after local
`pushInsteadOf`/`insteadOf` rewrites, then checks every outgoing commit's
committer and, unless `preserve_authors` is enabled, author. With a signing
policy, every outgoing commit is checked for a signature, validity, and the
configured primary fingerprint.

Empty input, malformed lines, more than 16 updates, disabled deletions/tags, force/non-fast-forward updates without an exact lease plan, unsupported tag publishing, other non-branch refs, missing objects, and shallow or partial repositories remain blocked (FAIL for explicit policy denial; UNKNOWN when required object/transport evidence is not implemented). Outgoing graphs above 2,048 commits also remain UNKNOWN. A tuple is caller-supplied data: this
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

There is no daemon, shell activation, or global account switch. Hook installation
is explicit and repository-local: `persona hooks install` preserves an existing
regular pre-push hook in Git metadata, chains it only after Persona allows the
update, refuses custom `core.hooksPath` configurations, and supports preview and
removal with conflict checks. The managed PATH adapter authorizes only the documented
single-branch subset before transport; the native pre-push hook is a second
barrier and runs after Git may have contacted the remote. `--no-verify` and
direct native binaries remain documented bypasses, not hidden guarantees. Two
tmux panes or other processes can run adapters concurrently without shared
mutable persona state, but they share the macOS/Linux user, filesystem,
credentials, agents, environment inheritance, and any already-running process.
This is not process, Keychain, network, or anonymity isolation.

## Nix build, use, and rollback

The `v0.1.0-rc.1` flake builds native packages for Apple Silicon macOS
(`aarch64-darwin`), Linux arm64 (`aarch64-linux`), and Linux x86_64
(`x86_64-linux`). The locked Cargo suite, Clippy, formatting, Rust 1.85
compatibility check, and native Nix checks are exercised by CI on those three
runner architectures. Nix's sandbox explicitly skips the local loopback TLS and
SSH-server tests; the same transport fixtures run on the isolated Linux hosts
outside the Nix sandbox. In OrbStack, Nix validation requires
`--option filter-syscalls false` while keeping the build sandbox enabled; this
is an environment workaround, not a project configuration requirement.

The flake uses `Cargo.lock` via `buildRustPackage`. The package wrapper supplies
Git, GnuPG, OpenSSH, and GitHub CLI without modifying global configuration.
Releases provide source archives and checksums; there is no binary cache or
separate prebuilt executable distribution. This repository is private, so Nix needs an authorized GitHub API token to fetch
it. Supply it ephemerally through `NIX_CONFIG` from the existing `gh` login, as
in the commands below. Never write the token into the flake, `flake.lock`, or a
checked-in config; the lock contains only the resolved source revision and NAR
hash.

Run directly without installation or global changes:

```sh
NIX_CONFIG="access-tokens = github.com=$(gh auth token --hostname github.com)" \
  nix run 'github:yanfsb/persona/v0.1.0-rc.1' -- status
NIX_CONFIG="access-tokens = github.com=$(gh auth token --hostname github.com)" \
  nix build 'github:yanfsb/persona/v0.1.0-rc.1#persona'
```

Pin the private release in another flake, for example Home Manager:

Add the input to your existing flake, then pass the package to the Home Manager
module:

```nix
# Existing flake inputs:
inputs.persona.url =
  "git+ssh://git@github.com/yanfsb/persona?ref=v0.1.0-rc.1";

# Existing Home Manager module, with persona passed as a module argument:
{ pkgs, persona, ... }:
{
  home.packages = [ persona.packages.${pkgs.system}.persona ];
}
```

For a flake that defines Home Manager inside nix-darwin, add `persona` to the
flake's `outputs` input arguments and pass
`persona = persona.packages.${system}.persona` through
`home-manager.extraSpecialArgs`. Then import that argument in the package module.
Resolve/update the input intentionally, review the resulting locked revision,
and commit `flake.lock` with the dotfiles change. For this private input, supply
`NIX_CONFIG="access-tokens = github.com=$(gh auth token --hostname github.com)"`
to each Nix invocation that fetches it; this uses the existing authorized
account without storing its token. The lock file contains the source revision
and NAR hash, not credentials. To build without installing it,
use `nix build` and invoke `./result/bin/persona`. Home Manager package
activation alone does not enable Persona shims, repository hooks, profiles, or
authentication. Avoid `persona install`, `persona hooks install`, and credential
enrollment until the target scope/profile has been reviewed and explicitly
configured.

Rollback an explicit local profile/result without changing shell startup files,
repository hooks, authentication state, or network routing:

```sh
nix profile remove --profile ./persona-profile persona
test -L ./persona-profile && rm ./persona-profile
test -L ./result && rm ./result
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
