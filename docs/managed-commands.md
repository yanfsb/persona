# Managed command surface

Persona adapters intentionally support a bounded grammar. This is a guide to the documented surface, not a promise to emulate every Git or GitHub CLI feature. Check `persona --help` and repository tests for the current exact grammar. Unknown, ambiguous, or unsupported forms are refused in managed scopes.

## Git

The managed Git adapter supports selected local operations including safe-pathspec `add`, scoped `status`, bounded `diff`/`show`, restricted `rev-parse`/`log`, branch/tag/worktree listing, selected local branch/worktree operations, `init`, policy-identity commits, and constrained fetch/clone/pull/push forms. Remote transport is limited to exact configured destinations using managed HTTPS or SSH. Push is bounded by ref count, ref kind, configured policy, available object/signature evidence and, for rewrites/deletions, exact expected remote OIDs. See the [implementation matrix](implementation-matrix.md) and tests before relying on a particular subcommand form.

Unsupported examples include arbitrary helpers/protocols, mirror/follow-tags/submodule modes, implicit or unbounded refspecs, and force updates without an exact lease plan. Some enabled policy options intentionally remain unusable where a complete transport path is not implemented.

## GitHub CLI (`gh`)

The managed `gh` adapter supports an explicit allowlist on GitHub.com, including selected repository and PR/issue/release view/list/create operations, typed PR checkout/review/merge, and constrained repository-scoped REST requests. The profile must bind the selected account and explicitly allowlist a repository for protected operations. Enterprise hosts, extensions, arbitrary methods/headers/inputs and unrecognized commands are refused.

PR checkout requires a clean worktree, fetches a specific PR head through managed transport, checks the fetched commit against API metadata, and refuses branch collisions/hooks that it cannot safely handle. Server-side merges require a separate explicit repository/base/strategy grant; the resulting server commit is not represented as locally signed. Release creation requires an already-published locally verified signed annotated tag, checks the remote tag before/after, and never creates or pushes that tag. The API does not atomically bind tag name to object ID, so a concurrent retag race can only be detected afterward.

## Hooks, PATH and shell

`persona run` adds temporary managed Git/gh shims for that invocation; it directly spawns the program without an implicit shell and preserves argv, cwd, stdio and exit status. Persistent adapter links are separately installed into an existing user-owned bin directory. Persona does not edit shell startup files. The optional Zsh prompt hook is visual convenience only.

A pre-push hook is repository-local, separately installed and composable only for supported configurations. It is a second barrier, not a replacement for the pre-transport adapter. `--no-verify`, direct native binaries, another network client, or a hostile same-user process can bypass managed paths; see the [security model](security-model.md).
