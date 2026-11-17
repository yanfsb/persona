# Managed command surface

Persona adapters enforce identity separation (author/committer identities, signing, destination allow/deny boundaries, SSH keys, and GitHub credential isolation) while delegating workflow commands through configurable per-profile command policies (`mode = "denylist"` or `"allowlist"`). Global overrides that redirect repository or configuration scope (such as `git -C` outside policy or `-c core.sshCommand=...`) remain refused across all modes. Check `persona --help` and repository tests for exact behavior.

## Git

In default `denylist` mode, everyday local Git operations (`status`, `log`, `diff`, `show`, `add`, `commit`, `switch`, `checkout`, `branch`, `stash`, `merge`, `rebase`, `cherry-pick`, `tag`, `worktree`, etc.) and common flags are permitted unless matched by `[profiles.git.commands].deny`. Identity invariants remain strictly enforced:

- Commit/amend/tag operations inject the profile's expected `author`/`committer` names and emails and configure the profile's OpenPGP/SSH signing key; forging another author on managed `commit` fails closed unless policy allows preservation.
- Network commands (`fetch`, `pull`, `clone`, `push`, `ls-remote`) validate effective destination URLs (supporting exact targets and `OWNER/*` wildcards minus `deny_destinations`), route SSH strictly through Persona's managed SSH adapter, and serve HTTPS credentials strictly for the bound profile account. `git fetch --all` preflights every eligible remote before transferring any data.
- `git push` audits every outgoing commit against the profile's identity, cross-profile leak check (`cross_profile_identity_check`), signing policy, and ref update policy before creating a one-time handoff for the `pre-push` hook. Explicit `--atomic` is supported but not required for multi-ref pushes, and creating new signed annotated tags works without manually passing zero-OID `--force-with-lease` unless `require_tag_lease_on_create = true`.
- By default (`strict_repo_hooks = false`, `strict_git_filters = false`, `strict_merge_drivers = false`, `inherit_git_config = true`), developer hooks such as `pre-commit` and LFS filters run normally without leaking `GH_TOKEN`; set `strict_* = true` on untrusted repositories to block local hooks, filters, or merge drivers before Git runs them.

An optional `[profiles.git.commands]` table configures `mode` (`"denylist"` or `"allowlist"`), `allow`, and `deny` (`persona profile commands --help`). Semantic selectors include `fetch.all`, `branch.list`, `branch.create`, `tag.signed`, `push.force`, `push.delete`, and `config.write`; `deny` always wins over `allow` and supports prefix rules (`fetch` blocks `fetch.all`), wildcards (`tag.*`), and flag rules (`push --force`). Command rules never disable destination, account, identity, signing, or publication checks.

## GitHub CLI (`gh`)

The managed `gh` adapter evaluates `[profiles.github.commands]` (`denylist` by default, or `allowlist` when configured) on GitHub.com while preserving account isolation (`GH_TOKEN` bound strictly to the enrolled account), `deny_repositories` / `repositories` wildcard enforcement (`OWNER/*`, `*`), and enterprise/auth/extension restrictions (`gh auth`, `gh extension`, `gh alias`, and unknown hosts remain blocked). When `--repo` is omitted inside a managed Git checkout, Persona infers `OWNER/REPO` from the checkout's `origin` remote when unambiguous.

Audited high-risk operations retain dedicated preflight and post-flight gates:
- `pr checkout` verifies fetched commits through managed Git transport and refuses unsafe hook execution when `strict_repo_hooks = true` (while never exposing `GH_TOKEN` to hooks).
- `pr review` validates typed review events cleanly before delegation.
- `pr merge` requires an explicit `[profiles.github_merge]` repository/base/strategy grant; the resulting server commit is not represented as locally signed.
- `release create` and `release upload` require an already-published locally verified signed annotated tag, verify the remote tag before/after, and never create or push that tag. The API does not atomically bind tag name to object ID, so a concurrent retag race can only be detected afterward.

### Release asset upload

`persona run -- gh release upload TAG FILE... --repo OWNER/REPO` uploads to an existing release only after the same enrolled-account, repository, publication-destination and signed-annotated-tag checks used by release creation. The remote tag must match the locally audited tag before and after upload. Upload never creates a release or tag.

Supply one to eight explicit regular files within the selected physical Git worktree. Files are read through no-follow directory/file descriptors and snapshotted before credential selection or network activity. Limits are 64 MiB per file and 128 MiB total. Basenames must be unique (case-insensitively), at most 255 ASCII letters/digits or `.`, `_`, `+`, `-`, and cannot be `.`, `..`, or begin with `-`. Symlinks, paths escaping the worktree, directories, stdin, globs, labels and `--clobber` are refused. Review the actual asset contents before publishing; confinement does not establish that a file is safe to disclose.

The uploader requires curl 8.3 or newer, disables curl configuration and inherited proxy settings, and sends snapshotted bytes only to the fixed HTTPS GitHub upload endpoint. All redirects are rejected; the selected token is never placed in command-line arguments. Returned asset IDs, names, sizes, states and supplied SHA-256 digests are validated.

Uploads are sequential and non-transactional. Existing names are refused, assets are never overwritten/deleted, and failed requests are not automatically retried. An error identifies confirmed uploads and any uncertain asset. Inspect the release before retrying only missing assets: a timeout or server failure can leave an uploaded or empty `starter` asset. There is no managed asset deletion/replacement command. Pre/post tag checks detect a retag afterward but cannot prevent the provider's concurrent-retag race. Older/missing curl fails the upload rather than enabling native passthrough. These restrictions do not enable generic `gh api` headers, file inputs, or arbitrary upload URLs.

## Hooks, PATH and shell

`persona run` adds temporary managed Git/gh shims for that invocation; it directly spawns the program without an implicit shell and preserves argv, cwd, stdio and exit status. Persistent adapter links are separately installed into an existing user-owned bin directory. Persona does not edit shell startup files. The optional Zsh prompt hook is visual convenience only.

A pre-push hook is repository-local, separately installed and composable only for supported configurations. It is a second barrier, not a replacement for the pre-transport adapter. `--no-verify`, direct native binaries, another network client, or a hostile same-user process can bypass managed paths; see the [security model](security-model.md).
