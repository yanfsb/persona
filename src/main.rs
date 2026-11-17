use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use persona::audit::{ExecutablePaths, PushRequest, build_report, build_tag_report};
use persona::authorization::{
    Operation as AuthorizationOperation, OperationDecision, Verdict, authorize,
};
use persona::command_policy::{CommandPolicy, CommandPolicyMode, is_valid_runtime_selector};
use persona::config::{Config, GitPolicy, Identity, Profile, UpstreamProvenanceMode};
use persona::gh_runner::run_managed_gh;
use persona::git::{GitClient, PushTuple};
use persona::git_adapter::{push_authorization_requirements, run_managed_git};
use persona::pre_push::{
    consume_primary_handoff, parse_push_tuples, run_managed_pre_push, validate_primary_handoff,
};
use persona::report::{Report, Status, exit_code};
use persona::runtime::{
    EXIT_ERROR, absolute_path, build_managed_path, gh_executable, git_executable, gpg_executable,
    hook_git_client, load_config, persona_dispatcher_executable, record_invoked_shim_directory,
    resolve_config_path, ssh_executable, ssh_keygen_executable, status_exit_code,
    wait_child_ignoring_sigint,
};
use persona::ssh_adapter::run_managed_ssh;
use persona::storage::{ConfigUpdateLock, PersonaPaths};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const MAX_PUSH_INPUT_BYTES: usize = 1024 * 1024;

const TOP_LEVEL_AFTER_HELP: &str = "\
EXAMPLES:
  persona status
  persona doctor --json
  persona profile list
  persona profile commands my-profile --git-deny push.force --preview
  persona baseline update
  persona run -- git status

DOCUMENTATION:
  Repository & guides: https://github.com/yanfsb/persona (see docs/cli.md)";

#[derive(Parser)]
#[command(
    name = "persona",
    version,
    about = "Directory-scoped Git and GitHub identity guardrail",
    after_help = TOP_LEVEL_AFTER_HELP
)]
struct Cli {
    /// Disable ANSI color codes in terminal output (also respects NO_COLOR).
    #[arg(long, global = true)]
    no_color: bool,
    /// Suppress non-essential confirmation messages.
    #[arg(short, long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Show the resolved Persona scope, profile, and local status for a directory.
    Status(StatusArgs),
    /// Evaluate local status, outgoing Git push updates, or signed tag policy.
    Check(AuditArgs),
    /// Run a verbose offline diagnostic audit of scope, Git, SSH, and shim state.
    Doctor(StatusArgs),
    /// Execute a command with temporary managed Git/GitHub/SSH shims on PATH.
    Run(RunArgs),
    /// Create the initial private Persona configuration and first scope/profile.
    Setup(SetupArgs),
    /// Migrate or roll back Persona's private configuration file.
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// Inspect, create, update, or configure command policies on profiles.
    Profile {
        #[command(subcommand)]
        command: ProfileCommands,
    },
    /// Inspect, add, update, verify, or remove directory scopes.
    Scope {
        #[command(subcommand)]
        command: ScopeCommands,
    },
    /// Enroll, verify, or unbind a profile's GitHub CLI account binding.
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
    /// Serve Git's HTTPS credential-helper protocol for protected repositories.
    CredentialHelper {
        /// Credential helper operation (`get`, `store`, or `erase`).
        action: String,
    },
    /// Install, refresh, or remove the repository-local Persona pre-push hook.
    Hooks {
        #[command(subcommand)]
        command: HookCommands,
    },
    /// Manage pinned upstream commit baselines on the active profile.
    Baseline {
        #[command(subcommand)]
        command: BaselineCommands,
    },
    /// Preview, apply, refresh, remove, or roll back user-owned PATH shims.
    Install {
        #[command(subcommand)]
        command: InstallCommands,
    },
    /// Generate shell prompt hooks or tab-completion scripts.
    Shell {
        #[command(subcommand)]
        command: ShellCommands,
    },
    /// Print shell tab-completion script for bash, zsh, or fish.
    Completions {
        /// Target shell (`bash`, `zsh`, or `fish`).
        #[arg(value_enum)]
        shell: CompletionShell,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
}

#[derive(Subcommand)]
enum BaselineCommands {
    /// Update pinned upstream baselines in the active profile to match current remote-tracking refs.
    Update {
        /// Working directory inside the target Git repository.
        #[arg(long, default_value = ".")]
        cwd: PathBuf,
        /// Preview the updated configuration without writing changes to disk.
        #[arg(long, short = 'n', visible_alias = "dry-run")]
        preview: bool,
    },
}

#[derive(Subcommand)]
enum ShellCommands {
    /// Print optional Zsh prompt integration helpers.
    Zsh {
        #[command(subcommand)]
        command: ZshCommands,
    },
    /// Print shell tab-completion script for bash, zsh, or fish.
    Completions {
        /// Target shell (`bash`, `zsh`, or `fish`).
        #[arg(value_enum)]
        shell: CompletionShell,
    },
}

#[derive(Subcommand)]
enum ZshCommands {
    /// Print the optional Zsh prompt hook for sourcing from your own startup file.
    Init,
    /// Print a fixed marker only when the current directory matches a scope.
    Marker,
}

#[derive(Subcommand)]
enum HookCommands {
    /// Install the Persona pre-push hook into a managed Git worktree.
    Install {
        /// Explicit Persona configuration file path.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Working directory inside the target Git worktree.
        #[arg(long, default_value = ".")]
        cwd: PathBuf,
        /// Preview the hook installation without modifying the worktree.
        #[arg(long, short = 'n', visible_alias = "dry-run")]
        preview: bool,
    },
    /// Refresh an installed pre-push hook to point at this Persona executable.
    Refresh {
        /// Explicit Persona configuration file path.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Working directory inside the target Git worktree.
        #[arg(long, default_value = ".")]
        cwd: PathBuf,
        /// Preview the hook refresh without modifying the worktree.
        #[arg(long, short = 'n', visible_alias = "dry-run")]
        preview: bool,
    },
    /// Remove a Persona-managed pre-push hook and restore any preserved hook.
    Remove {
        /// Working directory inside the target Git worktree.
        #[arg(long, default_value = ".")]
        cwd: PathBuf,
        /// Preview the hook removal without modifying the worktree.
        #[arg(long, short = 'n', visible_alias = "dry-run")]
        preview: bool,
    },
}

#[derive(Subcommand)]
enum InstallCommands {
    /// Show exactly which owned-bin adapters would be created.
    Preview {
        /// Existing user-owned directory to inspect for adapter installation.
        #[arg(long)]
        bin_dir: PathBuf,
    },
    /// Install adapter symlinks into an existing, user-owned bin directory.
    Apply {
        /// Existing user-owned directory where adapter symlinks will be placed.
        #[arg(long)]
        bin_dir: PathBuf,
    },
    /// Point existing owned adapters at this Persona executable.
    Refresh {
        /// Preview the adapter refresh without modifying symlinks.
        #[arg(
            long,
            short = 'n',
            visible_alias = "dry-run",
            conflicts_with = "apply",
            required_unless_present = "apply"
        )]
        preview: bool,
        /// Apply the adapter refresh and update registered worktree hooks.
        #[arg(long, conflicts_with = "preview")]
        apply: bool,
    },
    /// Remove only unchanged adapters recorded in the private manifest.
    Remove {
        /// Preview adapter removal without deleting symlinks.
        #[arg(
            long,
            short = 'n',
            visible_alias = "dry-run",
            conflicts_with = "apply",
            required_unless_present = "apply"
        )]
        preview: bool,
        /// Remove the recorded Persona adapter symlinks.
        #[arg(long, conflicts_with = "preview")]
        apply: bool,
    },
    /// Restore a private installation backup created by an earlier mutation.
    Rollback {
        /// Path to the installation backup file under Persona's state directory.
        #[arg(long)]
        backup: PathBuf,
        /// Preview the rollback without modifying symlinks.
        #[arg(
            long,
            short = 'n',
            visible_alias = "dry-run",
            conflicts_with = "apply",
            required_unless_present = "apply"
        )]
        preview: bool,
        /// Apply the rollback from the specified backup.
        #[arg(long, conflicts_with = "preview")]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Migrate configuration to the v3 schema (preview or apply).
    Migrate {
        /// Explicit configuration file to preview migration for.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Print the v3 TOML preview without modifying the configuration file.
        #[arg(
            long,
            short = 'n',
            visible_alias = "dry-run",
            conflicts_with = "apply",
            required_unless_present = "apply"
        )]
        preview: bool,
        /// Atomically write the migrated v3 configuration to the private config store.
        #[arg(long, conflicts_with = "preview")]
        apply: bool,
    },
    /// Restore a backup created by Persona's private config store.
    Rollback {
        /// Path to the backup file inside Persona's private state backups directory.
        #[arg(long)]
        backup: PathBuf,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum CliCommandMode {
    Allowlist,
    Denylist,
}

impl From<CliCommandMode> for CommandPolicyMode {
    fn from(mode: CliCommandMode) -> Self {
        match mode {
            CliCommandMode::Allowlist => Self::Allowlist,
            CliCommandMode::Denylist => Self::Denylist,
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
enum CliProvenanceMode {
    RemoteTracking,
    Pinned,
    Off,
}

impl From<CliProvenanceMode> for UpstreamProvenanceMode {
    fn from(mode: CliProvenanceMode) -> Self {
        match mode {
            CliProvenanceMode::RemoteTracking => Self::RemoteTracking,
            CliProvenanceMode::Pinned => Self::Pinned,
            CliProvenanceMode::Off => Self::Off,
        }
    }
}

#[derive(Args)]
struct ProfileCommandsArgs {
    /// Profile name to update command policies on.
    name: String,
    /// Command policy mode for managed `git` commands (`denylist` or `allowlist`).
    #[arg(long, value_enum)]
    git_mode: Option<CliCommandMode>,
    /// Allowed `git` command selector or `<selector> <flag>` rule (repeatable).
    #[arg(long = "git-allow")]
    git_allow: Vec<String>,
    /// Denied `git` command selector or `<selector> <flag>` rule (repeatable).
    #[arg(long = "git-deny")]
    git_deny: Vec<String>,
    /// Reset managed `git` command rules back to the default denylist.
    #[arg(long)]
    clear_git: bool,
    /// Command policy mode for managed `gh` commands (`denylist` or `allowlist`).
    #[arg(long, value_enum)]
    gh_mode: Option<CliCommandMode>,
    /// Allowed `gh` command selector or `<selector> <flag>` rule (repeatable).
    #[arg(long = "gh-allow")]
    gh_allow: Vec<String>,
    /// Denied `gh` command selector or `<selector> <flag>` rule (repeatable).
    #[arg(long = "gh-deny")]
    gh_deny: Vec<String>,
    /// Reset managed `gh` command rules back to the default denylist.
    #[arg(long)]
    clear_gh: bool,
    /// Command policy mode for `persona run` commands (`denylist` or `allowlist`).
    #[arg(long, value_enum)]
    run_mode: Option<CliCommandMode>,
    /// Allowed `persona run` program selector or `<selector> <flag>` rule (repeatable).
    #[arg(long = "run-allow")]
    run_allow: Vec<String>,
    /// Denied `persona run` program selector or `<selector> <flag>` rule (repeatable).
    #[arg(long = "run-deny")]
    run_deny: Vec<String>,
    /// Reset `persona run` command rules back to the default denylist.
    #[arg(long)]
    clear_run: bool,
    /// Preview the resulting TOML configuration without writing to disk.
    #[arg(long, short = 'n', visible_alias = "dry-run")]
    preview: bool,
}

#[derive(Subcommand)]
enum ProfileCommands {
    /// List configured profile names.
    List {
        /// Explicit Persona configuration file path.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Output the profile list as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show details and policy summary for a profile.
    Show {
        /// Profile name to inspect.
        name: String,
        /// Explicit Persona configuration file path.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Output the profile details as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify that a profile is structurally valid and report its scope mappings.
    Verify {
        /// Profile name to verify.
        name: String,
        /// Explicit Persona configuration file path.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Add a new reusable identity profile to the private configuration.
    Add(Box<ProfileEditArgs>),
    /// Update an existing reusable identity profile (omitted fields keep current values).
    Update(Box<ProfileEditArgs>),
    /// Configure allowlist/denylist command policies (`git`, `gh`, `run`) on a profile.
    Commands(Box<ProfileCommandsArgs>),
    /// Remove an unused profile from the private configuration.
    Remove {
        /// Profile name to remove.
        name: String,
        /// Preview the removal without modifying the configuration file.
        #[arg(long, short = 'n', visible_alias = "dry-run")]
        preview: bool,
    },
}

#[derive(Subcommand)]
enum ScopeCommands {
    /// List configured directory scopes and their bound profiles.
    List {
        /// Explicit Persona configuration file path.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Output the scope list as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show configured scope details without requiring the directory to exist on disk.
    Show {
        /// Scope name to inspect.
        name: String,
        /// Explicit Persona configuration file path.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Output the scope details as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify that a scope's directory exists on disk and resolves to its canonical root.
    Verify {
        /// Scope name to verify.
        name: String,
        /// Explicit Persona configuration file path.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Bind a directory tree to an existing profile.
    Add {
        /// Unique name for the scope.
        name: String,
        /// Directory path for the scope root.
        path: PathBuf,
        /// Profile name to bind to this scope.
        #[arg(long)]
        profile: String,
        /// Preview the new scope without modifying the configuration file.
        #[arg(long, short = 'n', visible_alias = "dry-run")]
        preview: bool,
    },
    /// Update an existing scope's directory path or bound profile.
    Update {
        /// Existing scope name to update.
        name: String,
        /// Updated directory path for the scope root.
        path: PathBuf,
        /// Updated profile name for this scope.
        #[arg(long)]
        profile: String,
        /// Preview the updated scope without modifying the configuration file.
        #[arg(long, short = 'n', visible_alias = "dry-run")]
        preview: bool,
    },
    /// Remove a directory scope from the private configuration.
    Remove {
        /// Scope name to remove.
        name: String,
        /// Preview the removal without modifying the configuration file.
        #[arg(long, short = 'n', visible_alias = "dry-run")]
        preview: bool,
    },
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Explicitly contact GitHub to bind the currently selected native gh account.
    Enroll {
        /// Profile name to bind the GitHub account to.
        #[arg(long)]
        profile: String,
        /// GitHub hostname (currently `github.com`).
        #[arg(long, default_value = "github.com")]
        host: String,
        /// Expected GitHub username in the native `gh` credential store.
        #[arg(long, required = true)]
        user: String,
        /// Confirm contacting GitHub's API to resolve the stable numeric account ID.
        #[arg(long, required = true)]
        confirm_online: bool,
    },
    /// Compare the local gh token selector to the saved HMAC binding (no API call).
    Verify {
        /// Profile name whose GitHub binding should be verified.
        #[arg(long)]
        profile: String,
        /// Output the verification result as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Remove the GitHub account binding from a profile.
    Unbind {
        /// Profile name to unbind.
        #[arg(long)]
        profile: String,
        /// Preview the unbind operation without writing changes.
        #[arg(long, short = 'n', visible_alias = "dry-run")]
        preview: bool,
    },
}

#[derive(Args)]
struct RunArgs {
    /// Explicit Persona configuration file path.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Working directory in which to resolve the active scope and launch the command.
    #[arg(long, default_value = ".")]
    cwd: PathBuf,
    /// Program and arguments to execute (pass after `--`).
    #[arg(required = true, num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
    argv: Vec<OsString>,
}

#[derive(Args)]
struct ProfileEditArgs {
    /// Profile name.
    name: String,
    /// Expected Git author name (required on `add`; kept if omitted on `update`).
    #[arg(long, help_heading = "Identity")]
    author_name: Option<String>,
    /// Expected Git author email (required on `add`; kept if omitted on `update`).
    #[arg(long, help_heading = "Identity")]
    author_email: Option<String>,
    /// Expected Git committer name (defaults to `--author-name` on `add`; kept on `update`).
    #[arg(long, help_heading = "Identity")]
    committer_name: Option<String>,
    /// Expected Git committer email (defaults to `--author-email` on `add`; kept on `update`).
    #[arg(long, help_heading = "Identity")]
    committer_email: Option<String>,
    /// Authorized signing key fingerprint (40-hex OpenPGP or `SHA256:...` SSH).
    #[arg(long, help_heading = "Signing")]
    signing_fingerprint: Option<String>,
    /// Absolute path to the public key file for offline signature verification.
    #[arg(long, help_heading = "Signing")]
    public_key: Option<PathBuf>,
    /// Cryptographic signing format (`openpgp` or `ssh`).
    #[arg(long, value_parser = ["openpgp", "ssh"], help_heading = "Signing")]
    signing_format: Option<String>,
    /// Remove the signing policy from this profile.
    #[arg(long, help_heading = "Signing")]
    clear_signing: bool,
    /// Authorized Git push remote name (or `*` for any remote matching allowed destinations).
    #[arg(long, help_heading = "Push & Remotes")]
    push_remote: Option<String>,
    /// Allowed push destination URL or pattern such as `git@github.com:OWNER/*` (repeatable).
    #[arg(long = "push-destination", help_heading = "Push & Remotes")]
    push_destinations: Vec<String>,
    /// Exact profile-bound remote: NAME|FETCH_URLS|PUSH_URLS (comma-separated, '-' for none).
    #[arg(
        long = "remote-policy",
        value_name = "NAME|FETCH_URLS|PUSH_URLS",
        help_heading = "Push & Remotes"
    )]
    remote_policies: Vec<String>,
    /// Clear all explicit `[[profiles.git.remotes]]` entries.
    #[arg(
        long,
        conflicts_with = "remote_policies",
        help_heading = "Push & Remotes"
    )]
    clear_remote_policies: bool,
    /// Explicitly denied Git destination URL or wildcard pattern (repeatable).
    #[arg(
        long = "deny-destination",
        conflicts_with = "clear_deny_destinations",
        help_heading = "Push & Remotes"
    )]
    deny_destinations: Vec<String>,
    /// Clear all denied Git destination patterns.
    #[arg(
        long,
        conflicts_with = "deny_destinations",
        help_heading = "Push & Remotes"
    )]
    clear_deny_destinations: bool,
    /// Allow foreign commit authors while still enforcing active committer and signing identity.
    #[arg(
        long,
        conflicts_with = "strict_authors",
        help_heading = "Push & Remotes"
    )]
    preserve_authors: bool,
    /// Require outgoing commit authors to match the active profile's author identity.
    #[arg(
        long,
        conflicts_with = "preserve_authors",
        help_heading = "Push & Remotes"
    )]
    strict_authors: bool,
    /// SSH hostname for managed Git SSH transport (e.g. `github.com`).
    #[arg(long, help_heading = "SSH Transport")]
    ssh_host: Option<String>,
    /// SSH username for managed Git SSH transport (e.g. `git`).
    #[arg(long, help_heading = "SSH Transport")]
    ssh_user: Option<String>,
    /// SSH port for managed Git SSH transport (e.g. `22`).
    #[arg(long, help_heading = "SSH Transport")]
    ssh_port: Option<u16>,
    /// Expected SSH key fingerprint (`SHA256:...`).
    #[arg(long, help_heading = "SSH Transport")]
    ssh_fingerprint: Option<String>,
    /// Absolute path to the SSH public key file.
    #[arg(long, help_heading = "SSH Transport")]
    ssh_public_key: Option<PathBuf>,
    /// Absolute path to the SSH private identity file (`-i`).
    #[arg(long, help_heading = "SSH Transport")]
    ssh_identity_file: Option<PathBuf>,
    /// Absolute path to a dedicated `SSH_AUTH_SOCK` agent socket.
    #[arg(long, help_heading = "SSH Transport")]
    ssh_agent_socket: Option<PathBuf>,
    /// Absolute path to a dedicated `known_hosts` file.
    #[arg(long, help_heading = "SSH Transport")]
    ssh_known_hosts_file: Option<PathBuf>,
    /// Remove the SSH transport policy from this profile.
    #[arg(long, help_heading = "SSH Transport")]
    clear_ssh: bool,
    /// Allowed GitHub repository `OWNER/REPO` or `OWNER/*` pattern for `gh` (repeatable).
    #[arg(long = "github-repo", help_heading = "GitHub")]
    github_repositories: Vec<String>,
    /// Clear the allowed GitHub repository list on the enrolled binding.
    #[arg(long, conflicts_with = "github_repositories", help_heading = "GitHub")]
    clear_github_repositories: bool,
    /// Explicitly denied GitHub repository `OWNER/REPO` or `OWNER/*` pattern (repeatable).
    #[arg(
        long = "deny-github-repo",
        conflicts_with = "clear_deny_github_repositories",
        help_heading = "GitHub"
    )]
    deny_github_repositories: Vec<String>,
    /// Clear all denied GitHub repository patterns.
    #[arg(
        long,
        conflicts_with = "deny_github_repositories",
        help_heading = "GitHub"
    )]
    clear_deny_github_repositories: bool,
    /// Explicit server-side merge grant: OWNER/REPO|BASE_BRANCH|merge|squash|rebase.
    #[arg(
        long = "allow-github-merge",
        value_name = "REPO|BASE|STRATEGY",
        help_heading = "GitHub"
    )]
    github_merge_rules: Vec<String>,
    /// Clear all server-side GitHub merge grants.
    #[arg(long, conflicts_with = "github_merge_rules", help_heading = "GitHub")]
    clear_github_merges: bool,
    /// Command policy mode for managed `git` commands (`denylist` or `allowlist`).
    #[arg(long, value_enum, help_heading = "Command Policies")]
    git_command_mode: Option<CliCommandMode>,
    /// Allowed `git` command selector or `<selector> <flag>` rule (repeatable).
    #[arg(long = "git-allow", help_heading = "Command Policies")]
    git_allow: Vec<String>,
    /// Denied `git` command selector or `<selector> <flag>` rule (repeatable).
    #[arg(long = "git-deny", help_heading = "Command Policies")]
    git_deny: Vec<String>,
    /// Reset managed `git` command rules to default.
    #[arg(long, help_heading = "Command Policies")]
    clear_git_commands: bool,
    /// Command policy mode for managed `gh` commands (`denylist` or `allowlist`).
    #[arg(long, value_enum, help_heading = "Command Policies")]
    gh_command_mode: Option<CliCommandMode>,
    /// Allowed `gh` command selector or `<selector> <flag>` rule (repeatable).
    #[arg(long = "gh-allow", help_heading = "Command Policies")]
    gh_allow: Vec<String>,
    /// Denied `gh` command selector or `<selector> <flag>` rule (repeatable).
    #[arg(long = "gh-deny", help_heading = "Command Policies")]
    gh_deny: Vec<String>,
    /// Reset managed `gh` command rules to default.
    #[arg(long, help_heading = "Command Policies")]
    clear_gh_commands: bool,
    /// Command policy mode for `persona run` (`denylist` or `allowlist`).
    #[arg(long, value_enum, help_heading = "Command Policies")]
    run_command_mode: Option<CliCommandMode>,
    /// Allowed `persona run` program selector or `<selector> <flag>` rule (repeatable).
    #[arg(long = "run-allow", help_heading = "Command Policies")]
    run_allow: Vec<String>,
    /// Denied `persona run` program selector or `<selector> <flag>` rule (repeatable).
    #[arg(long = "run-deny", help_heading = "Command Policies")]
    run_deny: Vec<String>,
    /// Reset `persona run` command rules to default.
    #[arg(long, help_heading = "Command Policies")]
    clear_run_commands: bool,
    /// Allow creating new remote branches on push (`true` or `false`).
    #[arg(long, action = clap::ArgAction::Set, help_heading = "Push & Remotes")]
    allow_initial_push: Option<bool>,
    /// Allow fast-forward branch updates on push (`true` or `false`).
    #[arg(long, action = clap::ArgAction::Set, help_heading = "Push & Remotes")]
    allow_fast_forward: Option<bool>,
    /// Allow pushing signed annotated tags (`true` or `false`).
    #[arg(long, action = clap::ArgAction::Set, help_heading = "Push & Remotes")]
    allow_annotated_tags: Option<bool>,
    /// Allow creating and pushing lightweight tags (`true` or `false`).
    #[arg(long, action = clap::ArgAction::Set, help_heading = "Push & Remotes")]
    allow_lightweight_tags: Option<bool>,
    /// Allow deleting remote branches on push (`true` or `false`).
    #[arg(long, action = clap::ArgAction::Set, help_heading = "Push & Remotes")]
    allow_branch_deletion: Option<bool>,
    /// Allow deleting remote tags on push (`true` or `false`).
    #[arg(long, action = clap::ArgAction::Set, help_heading = "Push & Remotes")]
    allow_tag_deletion: Option<bool>,
    /// Allow `--force-with-lease` branch updates (`true` or `false`).
    #[arg(long, action = clap::ArgAction::Set, help_heading = "Push & Remotes")]
    allow_force_with_lease: Option<bool>,
    /// Allow unleased `--force` push updates (`true` or `false`).
    #[arg(long, action = clap::ArgAction::Set, help_heading = "Push & Remotes")]
    allow_force_push: Option<bool>,
    /// Require an explicit remote ref lease when pushing new tags (`true` or `false`).
    #[arg(long, action = clap::ArgAction::Set, help_heading = "Push & Remotes")]
    require_tag_lease_on_create: Option<bool>,
    /// Upstream commit provenance mode (`remote-tracking`, `pinned`, or `off`).
    #[arg(long, value_enum, help_heading = "Push & Remotes")]
    upstream_provenance: Option<CliProvenanceMode>,
    /// Block checkout mutations when non-Persona repository hooks exist (`true` or `false`).
    #[arg(long, action = clap::ArgAction::Set, help_heading = "Hardening")]
    strict_repo_hooks: Option<bool>,
    /// Block mutations/HTTPS when external Git filter/textconv commands exist (`true` or `false`).
    #[arg(long, action = clap::ArgAction::Set, help_heading = "Hardening")]
    strict_git_filters: Option<bool>,
    /// Block sequenced operations when custom merge drivers exist (`true` or `false`).
    #[arg(long, action = clap::ArgAction::Set, help_heading = "Hardening")]
    strict_merge_drivers: Option<bool>,
    /// Inherit global/user Git config for local non-network commands (`true` or `false`).
    #[arg(long, action = clap::ArgAction::Set, help_heading = "Hardening")]
    inherit_git_config: Option<bool>,
    /// Block commits/pushes authored or committed by another Persona profile's email (`true` or `false`).
    #[arg(long, action = clap::ArgAction::Set, help_heading = "Hardening")]
    cross_profile_identity_check: Option<bool>,
    /// Pinned upstream baseline `<DESTINATION>|<refs/remotes/REMOTE/BRANCH>=<OID>` (repeatable).
    #[arg(
        long = "upstream-baseline",
        conflicts_with = "clear_upstream_baselines",
        help_heading = "Push & Remotes"
    )]
    upstream_baselines: Vec<String>,
    /// Clear all pinned upstream baselines on this profile.
    #[arg(
        long,
        conflicts_with = "upstream_baselines",
        help_heading = "Push & Remotes"
    )]
    clear_upstream_baselines: bool,
    /// Preview the resulting TOML configuration without writing to disk.
    #[arg(long, short = 'n', visible_alias = "dry-run")]
    preview: bool,
}

#[derive(Args)]
struct SetupArgs {
    /// Initial profile name to create.
    #[arg(long, default_value = "default")]
    profile: String,
    /// Initial directory scope name to create.
    #[arg(long, default_value = "default")]
    scope_name: String,
    /// Directory path to bind to the initial scope.
    #[arg(long, default_value = ".")]
    scope: PathBuf,
    /// Git author name for the initial profile.
    #[arg(long)]
    author_name: Option<String>,
    /// Git author email for the initial profile.
    #[arg(long)]
    author_email: Option<String>,
    /// Git committer name (defaults to `--author-name` if omitted).
    #[arg(long)]
    committer_name: Option<String>,
    /// Git committer email (defaults to `--author-email` if omitted).
    #[arg(long)]
    committer_email: Option<String>,
    /// Do not prompt on stdin; fail if required options are missing.
    #[arg(long)]
    no_input: bool,
}

#[derive(Args)]
struct StatusArgs {
    /// Explicit Persona configuration file path (also respects PERSONA_CONFIG_PATH).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Directory to inspect.
    #[arg(long, default_value = ".")]
    cwd: PathBuf,
    /// Output format (`text` or `json`).
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    /// Alias for `--format json`.
    #[arg(long, conflicts_with = "format")]
    json: bool,
    /// Print per-property offline diagnostic findings.
    #[arg(long)]
    verbose: bool,
    /// Exit non-zero (3 or 4) even when only informational offline indicators are UNKNOWN/WARN.
    #[arg(long)]
    strict: bool,
    #[arg(long, value_enum, hide = true)]
    operation: Option<Operation>,
    #[arg(long, hide = true)]
    remote: Option<String>,
    #[arg(long, hide = true, conflicts_with = "destination_stdin")]
    destination: Option<String>,
    #[arg(long, hide = true, conflicts_with = "destination")]
    destination_stdin: bool,
    #[arg(long, hide = true)]
    primary_handoff: Option<PathBuf>,
    #[arg(long, hide = true)]
    tag: Option<String>,
    #[arg(long, hide = true)]
    online_verified: bool,
}

#[derive(Args)]
struct AuditArgs {
    /// Explicit Persona configuration file path (also respects PERSONA_CONFIG_PATH).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Directory or Git worktree to inspect.
    #[arg(long, default_value = ".")]
    cwd: PathBuf,
    /// Output format (`text` or `json`).
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    /// Alias for `--format json`.
    #[arg(long, conflicts_with = "format")]
    json: bool,
    /// Print per-property offline diagnostic findings in text mode.
    #[arg(long)]
    verbose: bool,
    /// Exit non-zero (3 or 4) even when only informational offline indicators are UNKNOWN/WARN.
    #[arg(long)]
    strict: bool,
    /// Audit operation to perform (`status`, `push`, or `tag`).
    #[arg(long, value_enum)]
    operation: Option<Operation>,
    /// Remote name for `--operation push`.
    #[arg(long)]
    remote: Option<String>,
    /// Effective remote destination URL for `--operation push`.
    #[arg(long, conflicts_with = "destination_stdin")]
    destination: Option<String>,
    #[arg(long, hide = true, conflicts_with = "destination")]
    destination_stdin: bool,
    #[arg(long, hide = true)]
    primary_handoff: Option<PathBuf>,
    /// Annotated tag name to verify for `--operation tag`.
    #[arg(long)]
    tag: Option<String>,
    /// Explicitly query GitHub's commit verification status for outgoing commits.
    #[arg(long)]
    online_verified: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Operation {
    Status,
    Push,
    Tag,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

static NO_COLOR_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static QUIET_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn env_disables_color() -> bool {
    NO_COLOR_REQUESTED.load(std::sync::atomic::Ordering::Relaxed)
        || std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty())
        || std::env::var("TERM").is_ok_and(|term| term == "dumb")
        || std::env::var("CLICOLOR").is_ok_and(|value| value == "0")
}

fn stdout_color_enabled() -> bool {
    !env_disables_color() && std::io::stdout().is_terminal()
}

fn stderr_color_enabled() -> bool {
    !env_disables_color() && std::io::stderr().is_terminal()
}

fn is_quiet() -> bool {
    QUIET_REQUESTED.load(std::sync::atomic::Ordering::Relaxed)
}

fn style_status(text: &str, status: Status, color: bool) -> String {
    if !color {
        return text.to_owned();
    }
    let code = match status {
        Status::Pass => "\x1b[32m",
        Status::Warn => "\x1b[33m",
        Status::Unknown => "\x1b[36m",
        Status::Fail => "\x1b[31m",
    };
    format!("{code}{text}\x1b[0m")
}

fn style_verdict(allowed: bool, color: bool) -> &'static str {
    match (allowed, color) {
        (true, false) => "ALLOW",
        (false, false) => "BLOCK",
        (true, true) => "\x1b[32mALLOW\x1b[0m",
        (false, true) => "\x1b[31mBLOCK\x1b[0m",
    }
}

fn main() -> ExitCode {
    if let Some(exit) = managed_shim_dispatch() {
        return exit;
    }
    let cli = Cli::parse();
    NO_COLOR_REQUESTED.store(cli.no_color, std::sync::atomic::Ordering::Relaxed);
    QUIET_REQUESTED.store(cli.quiet, std::sync::atomic::Ordering::Relaxed);
    let result = (|| -> Result<u8, String> {
        match cli.command {
            None => {
                let config = resolve_config_path(None)?;
                show_status(
                    &config,
                    Path::new("."),
                    OutputFormat::Text,
                    false,
                    false,
                    None,
                    None,
                    false,
                )
            }
            Some(Commands::Status(args)) => {
                if args.operation.is_some()
                    || args.remote.is_some()
                    || args.destination.is_some()
                    || args.destination_stdin
                    || args.primary_handoff.is_some()
                    || args.tag.is_some()
                    || args.online_verified
                {
                    return Err(
                        "--operation, --remote, --destination and --tag are only valid for check"
                            .to_owned(),
                    );
                }
                let config = resolve_config_path(args.config.as_deref())?;
                show_status(
                    &config,
                    &args.cwd,
                    status_output_format(&args),
                    args.verbose,
                    args.strict,
                    None,
                    None,
                    false,
                )
            }
            Some(Commands::Check(args)) => {
                let format = output_format(&args);
                let operation = args.operation.unwrap_or(Operation::Status);
                match operation {
                    Operation::Status
                        if args.remote.is_some()
                            || args.destination.is_some()
                            || args.destination_stdin
                            || args.primary_handoff.is_some()
                            || args.tag.is_some()
                            || args.online_verified =>
                    {
                        Err(
                            "--remote/--destination require --operation push; --tag requires --operation tag"
                                .to_owned(),
                        )
                    }
                    Operation::Status => {
                        let config = resolve_config_path(args.config.as_deref())?;
                        show_status(
                            &config,
                            &args.cwd,
                            format,
                            args.verbose,
                            args.strict,
                            None,
                            None,
                            false,
                        )
                    }
                    Operation::Push if args.tag.is_some() => {
                        Err("--tag cannot be combined with --operation push".to_owned())
                    }
                    Operation::Push => {
                        let remote = args.remote.ok_or_else(|| {
                            "--remote is required with --operation push".to_owned()
                        })?;
                        let (destination, tuples) = if args.destination_stdin {
                            read_push_request_stdin()?
                        } else {
                            let destination = args.destination.ok_or_else(|| {
                                "--destination or --destination-stdin is required with --operation push"
                                    .to_owned()
                            })?;
                            (destination, read_push_tuples()?)
                        };
                        let config = resolve_config_path(args.config.as_deref())?;
                        let current = std::env::current_dir()
                            .map_err(|_| "cannot resolve check working directory".to_owned())?;
                        let config = absolute_path(&config, &current);
                        let directory = absolute_path(&args.cwd, &current);
                        let mut request = PushRequest {
                            remote,
                            destination,
                            tuples,
                            leases: Vec::new(),
                            allow_unleased_force: false,
                        };
                        let primary_handoff = args.primary_handoff;
                        let validated_handoff = primary_handoff
                            .as_deref()
                            .map(|path| {
                                validate_primary_handoff(path, &config, &directory, &mut request)
                            })
                            .transpose()?;
                        let handoff_binding = validated_handoff
                            .as_ref()
                            .and_then(|handoff| handoff.github_binding.clone());
                        let exit = show_status(
                            &config,
                            &directory,
                            format,
                            args.verbose,
                            args.strict,
                            Some(request),
                            handoff_binding,
                            args.online_verified,
                        )?;
                        if exit == 0 {
                            if let Some(path) = primary_handoff {
                                consume_primary_handoff(&path)?;
                            }
                        }
                        Ok(exit)
                    }
                    Operation::Tag
                        if args.remote.is_some()
                            || args.destination.is_some()
                            || args.destination_stdin
                            || args.primary_handoff.is_some()
                            || args.online_verified =>
                    {
                        Err("--remote/--destination cannot be combined with --operation tag"
                            .to_owned())
                    }
                    Operation::Tag => {
                        let tag = args
                            .tag
                            .ok_or_else(|| "--tag is required with --operation tag".to_owned())?;
                        let config = resolve_config_path(args.config.as_deref())?;
                        show_tag(&config, &args.cwd, &tag, format)
                    }
                }
            }
            Some(Commands::Doctor(args)) => {
                if args.operation.is_some()
                    || args.remote.is_some()
                    || args.destination.is_some()
                    || args.destination_stdin
                    || args.primary_handoff.is_some()
                    || args.tag.is_some()
                    || args.online_verified
                {
                    return Err("doctor does not accept operation, push or tag options".to_owned());
                }
                let config = resolve_config_path(args.config.as_deref())?;
                show_status(
                    &config,
                    &args.cwd,
                    status_output_format(&args),
                    true,
                    args.strict,
                    None,
                    None,
                    false,
                )
            }
            Some(Commands::Run(args)) => run_launcher(args),
            Some(Commands::Setup(args)) => setup(args),
            Some(Commands::CredentialHelper { action }) => git_credential_helper(&action),
            Some(Commands::Hooks { command }) => hooks_command(command),
            Some(Commands::Baseline { command }) => baseline_command(command),
            Some(Commands::Install { command }) => installer_command(command),
            Some(Commands::Shell { command }) => shell_command(command),
            Some(Commands::Completions { shell }) => {
                print_completions(shell);
                Ok(0)
            }
            Some(Commands::Config { command }) => match command {
                ConfigCommands::Migrate {
                    config,
                    preview: _,
                    apply,
                } if apply => {
                    if config.is_some() {
                        return Err("--config cannot be combined with --apply; migration writes only the private XDG config".to_owned());
                    }
                    apply_config_migration()
                }
                ConfigCommands::Migrate {
                    config,
                    preview: _,
                    apply: _,
                } => {
                    let config = resolve_config_path(config.as_deref())?;
                    preview_config_migration(&config)
                }
                ConfigCommands::Rollback { backup } => rollback_config(&backup),
            },
            Some(Commands::Profile { command }) => profile_command(command),
            Some(Commands::Scope { command }) => scope_command(command),
            Some(Commands::Auth { command }) => auth_command(command),
        }
    })();

    match result {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            if stderr_color_enabled() {
                eprintln!("\x1b[31merror:\x1b[0m {message}");
            } else {
                eprintln!("error: {message}");
            }
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn managed_shim_dispatch() -> Option<ExitCode> {
    let argv0 = std::env::args_os().next()?;
    let name = Path::new(&argv0).file_name()?.to_str()?;
    if matches!(name, "git" | "gh" | "ssh" | "git-credential-persona") {
        record_invoked_shim_directory(&argv0);
    }
    match name {
        "pre-push" => Some(match run_managed_pre_push() {
            Ok(code) => ExitCode::from(code),
            Err(message) => {
                eprintln!("Persona pre-push blocked: {message}");
                ExitCode::from(1)
            }
        }),
        "ssh" => Some(match run_managed_ssh() {
            Ok(code) => ExitCode::from(code),
            Err(message) => {
                eprintln!("Persona blocked SSH: {message}");
                ExitCode::from(126)
            }
        }),
        "git-credential-persona" => {
            let action = std::env::args().nth(1).unwrap_or_default();
            Some(match git_credential_helper(&action) {
                Ok(code) => ExitCode::from(code),
                Err(message) => {
                    eprintln!("Persona Git credential helper denied request: {message}");
                    ExitCode::from(EXIT_ERROR)
                }
            })
        }
        "git" => Some(match run_managed_git() {
            Ok(code) => ExitCode::from(code),
            Err(message) => {
                eprintln!("Persona blocked Git: {message}");
                ExitCode::from(126)
            }
        }),
        "gh" => Some(match run_managed_gh() {
            Ok(code) => ExitCode::from(code),
            Err(message) => {
                eprintln!("Persona blocked GitHub CLI: {message}");
                ExitCode::from(126)
            }
        }),
        _ => None,
    }
}

fn status_output_format(args: &StatusArgs) -> OutputFormat {
    if args.json {
        OutputFormat::Json
    } else {
        args.format
    }
}

fn output_format(args: &AuditArgs) -> OutputFormat {
    if args.json {
        OutputFormat::Json
    } else {
        args.format
    }
}

fn read_push_tuples() -> Result<Vec<PushTuple>, String> {
    let mut input = String::new();
    std::io::stdin()
        .take((MAX_PUSH_INPUT_BYTES + 1) as u64)
        .read_to_string(&mut input)
        .map_err(|error| format!("cannot read push update tuples: {error}"))?;
    parse_push_tuples(&input)
}

fn read_push_request_stdin() -> Result<(String, Vec<PushTuple>), String> {
    let mut input = Vec::new();
    std::io::stdin()
        .take((MAX_PUSH_INPUT_BYTES + 65_537) as u64)
        .read_to_end(&mut input)
        .map_err(|_| "cannot read framed push request from stdin".to_owned())?;
    if input.len() > MAX_PUSH_INPUT_BYTES + 65_536 {
        return Err("framed push request exceeds the input limit".to_owned());
    }
    let separator = input
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| "framed push request is missing its NUL separator".to_owned())?;
    let destination = std::str::from_utf8(&input[..separator])
        .map_err(|_| "framed push destination is not UTF-8".to_owned())?
        .to_owned();
    if destination.is_empty() || destination.len() > 65_536 {
        return Err("framed push destination is empty or oversized".to_owned());
    }
    let tuples = std::str::from_utf8(&input[separator + 1..])
        .map_err(|_| "framed push tuples are not UTF-8".to_owned())?;
    Ok((destination, parse_push_tuples(tuples)?))
}

fn shell_command(command: ShellCommands) -> Result<u8, String> {
    match command {
        ShellCommands::Zsh {
            command: ZshCommands::Init,
        } => {
            print!("{}", include_str!("../shell/persona.zsh"));
            Ok(0)
        }
        ShellCommands::Zsh {
            command: ZshCommands::Marker,
        } => {
            let cwd = std::env::current_dir()
                .map_err(|_| "cannot resolve current directory for shell marker".to_owned())?;
            let config_path = resolve_config_path(None)?;
            let config = Config::load(&config_path)
                .map_err(|error| format!("cannot load Persona config: {error}"))?;
            let selected = persona::context::resolve_context(&cwd, &config.scopes())
                .map_err(|_| "cannot resolve Persona scope for shell marker".to_owned())?;
            if selected.is_some() {
                print!("[scope]");
            }
            Ok(0)
        }
        ShellCommands::Completions { shell } => {
            print_completions(shell);
            Ok(0)
        }
    }
}

fn print_completions(shell: CompletionShell) {
    let cmd = Cli::command();
    let top_subcommands: Vec<&str> = cmd
        .get_subcommands()
        .filter(|sub| !sub.is_hide_set())
        .map(|sub| sub.get_name())
        .collect();
    let top_list = top_subcommands.join(" ");
    match shell {
        CompletionShell::Bash => {
            println!(
                r#"_persona_completions() {{
    local cur prev words cword
    COMPREPLY=()
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    if [[ ${{COMP_CWORD}} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "{top_list} --help --version --no-color --quiet" -- "$cur") )
        return 0
    fi
    case "${{COMP_WORDS[1]}}" in
        profile)
            COMPREPLY=( $(compgen -W "list show verify add update commands remove --help" -- "$cur") )
            ;;
        scope)
            COMPREPLY=( $(compgen -W "list show verify add update remove --help" -- "$cur") )
            ;;
        auth)
            COMPREPLY=( $(compgen -W "enroll verify unbind --help" -- "$cur") )
            ;;
        hooks)
            COMPREPLY=( $(compgen -W "install refresh remove --help" -- "$cur") )
            ;;
        install)
            COMPREPLY=( $(compgen -W "preview apply refresh remove rollback --help" -- "$cur") )
            ;;
        config)
            COMPREPLY=( $(compgen -W "migrate rollback --help" -- "$cur") )
            ;;
        baseline)
            COMPREPLY=( $(compgen -W "update --help" -- "$cur") )
            ;;
        shell)
            COMPREPLY=( $(compgen -W "zsh completions --help" -- "$cur") )
            ;;
        completions)
            COMPREPLY=( $(compgen -W "bash zsh fish --help" -- "$cur") )
            ;;
        status|doctor|check)
            COMPREPLY=( $(compgen -W "--config --cwd --format --json --verbose --strict --help" -- "$cur") )
            ;;
    esac
}}
complete -F _persona_completions persona"#
            );
        }
        CompletionShell::Zsh => {
            println!(
                r#"#compdef persona
_persona() {{
    local -a commands
    commands=(
        'status:Show the resolved Persona scope, profile, and local status'
        'check:Evaluate local status, outgoing push updates, or signed tag policy'
        'doctor:Run a verbose offline diagnostic audit'
        'run:Execute a command with temporary managed shims on PATH'
        'setup:Create the initial private Persona configuration'
        'config:Migrate or roll back Persona configuration'
        'profile:Inspect, create, update, or configure profiles'
        'scope:Inspect, add, update, verify, or remove directory scopes'
        'auth:Enroll, verify, or unbind a GitHub CLI account binding'
        'hooks:Install, refresh, or remove the pre-push hook'
        'baseline:Manage pinned upstream commit baselines'
        'install:Preview or manage user-owned PATH shims'
        'shell:Generate shell prompt hooks or tab-completion scripts'
        'completions:Print shell tab-completion script'
    )
    if (( CURRENT == 2 )); then
        _describe -t commands 'persona command' commands
        return
    fi
    case "${{words[2]}}" in
        profile)
            local -a sub=('list' 'show' 'verify' 'add' 'update' 'commands' 'remove')
            _describe -t subcommands 'profile command' sub
            ;;
        scope)
            local -a sub=('list' 'show' 'verify' 'add' 'update' 'remove')
            _describe -t subcommands 'scope command' sub
            ;;
        auth)
            local -a sub=('enroll' 'verify' 'unbind')
            _describe -t subcommands 'auth command' sub
            ;;
        hooks)
            local -a sub=('install' 'refresh' 'remove')
            _describe -t subcommands 'hooks command' sub
            ;;
        install)
            local -a sub=('preview' 'apply' 'refresh' 'remove' 'rollback')
            _describe -t subcommands 'install command' sub
            ;;
        config)
            local -a sub=('migrate' 'rollback')
            _describe -t subcommands 'config command' sub
            ;;
        baseline)
            local -a sub=('update')
            _describe -t subcommands 'baseline command' sub
            ;;
        shell)
            local -a sub=('zsh' 'completions')
            _describe -t subcommands 'shell command' sub
            ;;
        completions)
            local -a sub=('bash' 'zsh' 'fish')
            _describe -t subcommands 'shell' sub
            ;;
    esac
}}
compdef _persona persona"#
            );
        }
        CompletionShell::Fish => {
            for sub in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
                let name = sub.get_name();
                let about = sub.get_about().map(ToString::to_string).unwrap_or_default();
                println!(
                    "complete -c persona -n '__fish_use_subcommand' -a '{name}' -d '{}'",
                    about.replace('\'', "\\'")
                );
            }
            println!(
                "complete -c persona -n '__fish_seen_subcommand_from profile' -a 'list show verify add update commands remove'"
            );
            println!(
                "complete -c persona -n '__fish_seen_subcommand_from scope' -a 'list show verify add update remove'"
            );
            println!(
                "complete -c persona -n '__fish_seen_subcommand_from auth' -a 'enroll verify unbind'"
            );
            println!(
                "complete -c persona -n '__fish_seen_subcommand_from hooks' -a 'install refresh remove'"
            );
            println!(
                "complete -c persona -n '__fish_seen_subcommand_from install' -a 'preview apply refresh remove rollback'"
            );
            println!(
                "complete -c persona -n '__fish_seen_subcommand_from completions' -a 'bash zsh fish'"
            );
        }
    }
}

fn installer_command(command: InstallCommands) -> Result<u8, String> {
    use persona::installer;

    let preview_only = matches!(
        &command,
        InstallCommands::Preview { .. }
            | InstallCommands::Refresh { preview: true, .. }
            | InstallCommands::Remove { preview: true, .. }
            | InstallCommands::Rollback { preview: true, .. }
    );
    let result = match command {
        InstallCommands::Preview { bin_dir } => {
            println!(
                "Preview: {}",
                installer::preview_install(&bin_dir, &persona_dispatcher_executable()?)?
            );
            None
        }
        InstallCommands::Apply { bin_dir } => {
            installer::apply_install(&bin_dir, &persona_dispatcher_executable()?)?
        }
        InstallCommands::Refresh { preview, apply } => {
            if preview {
                println!("Preview: {}", installer::preview_refresh()?);
                None
            } else if apply {
                let backup = installer::refresh()?;
                if let (Ok(paths), Ok((_home, git)), Ok(executable)) = (
                    PersonaPaths::discover(),
                    hook_git_client(),
                    persona_dispatcher_executable(),
                ) {
                    for line in persona::hooks::refresh_registered_hooks(
                        &paths.state_dir,
                        &git,
                        &executable,
                    ) {
                        if !is_quiet() {
                            println!("{line}");
                        }
                    }
                }
                backup
            } else {
                return Err("choose exactly one of --preview or --apply".to_owned());
            }
        }
        InstallCommands::Remove { preview, apply } => {
            if preview {
                println!("Preview: {}", installer::preview_remove()?);
                None
            } else if apply {
                installer::remove()?
            } else {
                return Err("choose exactly one of --preview or --apply".to_owned());
            }
        }
        InstallCommands::Rollback {
            backup,
            preview,
            apply,
        } => {
            if preview {
                println!("Preview: {}", installer::preview_rollback(&backup)?);
                None
            } else if apply {
                installer::rollback(&backup)?;
                None
            } else {
                return Err("choose exactly one of --preview or --apply".to_owned());
            }
        }
    };
    if !is_quiet() {
        if let Some(backup) = result {
            println!("Backup: {}", backup.display());
        }
        if !preview_only {
            println!("Installation operation complete.");
        }
    }
    Ok(0)
}

fn hooks_command(command: HookCommands) -> Result<u8, String> {
    let cwd = match &command {
        HookCommands::Install { cwd, .. }
        | HookCommands::Refresh { cwd, .. }
        | HookCommands::Remove { cwd, .. } => cwd,
    };
    let cwd = std::fs::canonicalize(cwd)
        .map_err(|_| "hook command working directory must exist".to_owned())?;
    let (_home, git) = hook_git_client()?;
    let root = git
        .checkout_root(&cwd)
        .map_err(|_| "hook management requires an existing Git worktree".to_owned())?;
    let paths = persona::hooks::resolve_paths(&git, &root)?;
    let message = match command {
        HookCommands::Install {
            config, preview, ..
        } => {
            let config_path = resolve_config_path(config.as_deref())?;
            let config = Config::load(&config_path)
                .map_err(|error| format!("cannot load Persona config: {error}"))?;
            let selected = persona::context::resolve_context(&root, &config.scopes())
                .map_err(|_| "cannot resolve Persona policy for hook install".to_owned())?
                .ok_or_else(|| "hook installation requires a managed scope".to_owned())?;
            let policy = config
                .policies()
                .iter()
                .find(|policy| policy.name == selected.name)
                .ok_or_else(|| "managed scope has no Git policy".to_owned())?;
            if policy.git.push.is_none() {
                return Err("pre-push hook requires an explicit push policy".to_owned());
            }
            let message = persona::hooks::install(
                &paths,
                &config_path,
                &persona_dispatcher_executable()?,
                preview,
            )?;
            if !preview {
                if let Ok(persona_paths) = PersonaPaths::discover() {
                    let _ = persona::hooks::register_hook_worktree(&persona_paths.state_dir, &root);
                }
            }
            message
        }
        HookCommands::Refresh {
            config, preview, ..
        } => {
            let resolved_config = config
                .as_deref()
                .map(|path| resolve_config_path(Some(path)))
                .transpose()?;
            let message = persona::hooks::refresh(
                &paths,
                resolved_config.as_deref(),
                &persona_dispatcher_executable()?,
                preview,
            )?;
            if !preview {
                if let Ok(persona_paths) = PersonaPaths::discover() {
                    let _ = persona::hooks::register_hook_worktree(&persona_paths.state_dir, &root);
                }
            }
            message
        }
        HookCommands::Remove { preview, .. } => {
            let message = persona::hooks::uninstall(&paths, preview)?;
            if !preview {
                if let Ok(persona_paths) = PersonaPaths::discover() {
                    let _ =
                        persona::hooks::unregister_hook_worktree(&persona_paths.state_dir, &root);
                }
            }
            message
        }
    };
    if !is_quiet() {
        println!("{message}");
    }
    Ok(0)
}

fn run_launcher(args: RunArgs) -> Result<u8, String> {
    if args.argv.is_empty() {
        return Err("persona run requires a program after `--`".to_owned());
    }
    let program = Path::new(&args.argv[0]);
    if matches!(
        program.file_name().and_then(|name| name.to_str()),
        Some("git" | "gh")
    ) && program.components().count() > 1
    {
        return Err(
            "run refuses an explicit Git/GitHub CLI binary path; invoke the managed PATH command"
                .to_owned(),
        );
    }
    let config_path = resolve_config_path(args.config.as_deref())?;
    let current = std::env::current_dir()
        .map_err(|error| format!("cannot determine current directory: {error}"))?;
    let config_path = absolute_path(&config_path, &current);
    let directory = absolute_path(&args.cwd, &current);
    let config = Config::load(&config_path).map_err(|error| error.to_string())?;
    let executables = ExecutablePaths {
        git: git_executable(),
        gpg: gpg_executable(),
        ssh_keygen: ssh_keygen_executable(),
    };
    let (report, selected) = build_report(&config, &directory, None, &executables)?;
    let decision = authorize(
        AuthorizationOperation::Run,
        vec!["scope".to_owned(), "policy.profile".to_owned()],
        report.findings,
    );
    if !decision.is_allowed() {
        eprintln!("persona run blocked: required scope/profile evidence is incomplete");
        for blocker in decision.blockers {
            eprintln!("{}: {}", blocker.property, blocker.reason);
        }
        return Ok(1);
    }
    if let Some(scope) = &selected {
        if let Some(policy) = config
            .policies()
            .iter()
            .find(|item| item.name == scope.name)
        {
            if let Some(profile) = config
                .profiles()
                .iter()
                .find(|item| item.name == policy.profile)
            {
                let raw_name = program
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("");
                let program_selector = raw_name.to_ascii_lowercase();
                let flag_storage = args.argv[1..]
                    .iter()
                    .filter_map(|arg| arg.to_str())
                    .filter(|arg| arg.starts_with('-') && *arg != "--")
                    .collect::<Vec<_>>();
                let selector = format!("run.{program_selector}");
                if is_valid_runtime_selector(&program_selector) {
                    if let Err(denial) = profile.run.evaluate(
                        &[selector.as_str(), program_selector.as_str()],
                        &flag_storage,
                    ) {
                        return Err(denial.describe("run", raw_name));
                    }
                } else if profile.run.effective_mode() == CommandPolicyMode::Allowlist {
                    return Err(format!(
                        "run operation `{raw_name}` is not permitted by the selected profile's allowlist"
                    ));
                }
            }
        }
    }

    let executable = persona_dispatcher_executable()?;
    let native_git = git_executable();
    if !native_git.is_absolute() || !native_git.is_file() {
        return Err("Persona requires an absolute, existing native Git executable".to_owned());
    }
    let shims = tempfile::tempdir()
        .map_err(|error| format!("cannot create temporary managed PATH: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        for name in ["git", "gh", "git-credential-persona", "ssh"] {
            symlink(&executable, shims.path().join(name))
                .map_err(|error| format!("cannot install temporary {name} adapter: {error}"))?;
        }
    }
    let path = build_managed_path(shims.path())?;
    let mut child = Command::new(&args.argv[0]);
    child
        .args(&args.argv[1..])
        .current_dir(&directory)
        .env("PATH", path)
        .env("PERSONA_CONFIG_PATH", &config_path)
        .env("PERSONA_SHIM_DIR", shims.path())
        .env("PERSONA_GIT", &native_git);
    if let Some(gh) = gh_executable() {
        child.env("PERSONA_GH", gh);
    }
    if let Some(ssh) = ssh_executable() {
        child.env("PERSONA_SSH", ssh);
    }
    if let Some(ssh_keygen) = ssh_keygen_executable() {
        child.env("PERSONA_SSH_KEYGEN", ssh_keygen);
    }
    let status = wait_child_ignoring_sigint(&mut child)
        .map_err(|error| format!("cannot launch requested program: {error}"))?;
    Ok(status_exit_code(status))
}

fn integration_coverage_findings(directory: &Path) -> Vec<persona::report::Finding> {
    let installation = persona::installer::coverage_state();
    let installation_finding = match installation {
        "active" => persona::report::Finding::pass(
            "integration.managed_shims",
            "four owned Persona shims are installed",
            "active",
            "private install manifest and all four shim symlinks were verified without credential lookup",
        ),
        "shadowed" => persona::report::Finding::status(
            "integration.managed_shims",
            Status::Fail,
            Some("first executable for each shim is Persona".to_owned()),
            Some("one or more earlier PATH entries shadow a Persona shim".to_owned()),
            "installed shims are not the first executable resolved by PATH",
        ),
        "installed-not-on-path" => persona::report::Finding::status(
            "integration.managed_shims",
            Status::Warn,
            Some("active".to_owned()),
            Some("installed-not-on-path".to_owned()),
            "owned shims are intact but their directory is not present in PATH",
        ),
        "incomplete" => persona::report::Finding::status(
            "integration.managed_shims",
            Status::Fail,
            Some("active".to_owned()),
            Some("incomplete".to_owned()),
            "the private install manifest or one or more owned shim links failed verification",
        ),
        "absent" => persona::report::Finding::status(
            "integration.managed_shims",
            Status::Unknown,
            Some("active".to_owned()),
            Some("absent".to_owned()),
            "persistent PATH mediation is not installed; `persona run` still uses temporary managed shims",
        ),
        _ => persona::report::Finding::status(
            "integration.managed_shims",
            Status::Unknown,
            Some("active".to_owned()),
            None,
            "installation state could not be verified without reading credentials",
        ),
    };
    let git = GitClient::new(git_executable(), persona::git::safe_environment());
    let hook_finding = match git.checkout_root(directory) {
        Err(_) => persona::report::Finding::status(
            "integration.pre_push_hook",
            Status::Unknown,
            None,
            Some("not-a-worktree".to_owned()),
            "no repository hook applies in this directory",
        ),
        Ok(root) => match persona::hooks::resolve_paths(&git, &root) {
            Err(_) => persona::report::Finding::status(
                "integration.pre_push_hook",
                Status::Fail,
                Some("Persona hook installed".to_owned()),
                Some("custom-or-unsafe-hooksPath".to_owned()),
                "hook coverage is blocked by an unverified or custom Git hook path",
            ),
            Ok(paths) => match std::fs::symlink_metadata(&paths.manifest) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    persona::report::Finding::status(
                        "integration.pre_push_hook",
                        Status::Unknown,
                        Some("Persona hook installed".to_owned()),
                        Some("absent".to_owned()),
                        "pre-push hook is not installed in this worktree",
                    )
                }
                Err(_) => persona::report::Finding::status(
                    "integration.pre_push_hook",
                    Status::Unknown,
                    Some("Persona hook installed".to_owned()),
                    None,
                    "hook manifest state could not be inspected",
                ),
                Ok(_) => match persona::hooks::load_manifest(&paths) {
                    Ok(manifest)
                        if persona_dispatcher_executable().is_ok_and(|executable| {
                            manifest.persona_executable() == executable
                        }) && persona::hooks::verify_installed_hook(&paths, &manifest)
                            .is_ok() =>
                    {
                        persona::report::Finding::pass(
                            "integration.pre_push_hook",
                            "Persona pre-push hook verified",
                            "active",
                            "hook manifest, dispatcher target, and repository hook symlink were verified",
                        )
                    }
                    _ => persona::report::Finding::status(
                        "integration.pre_push_hook",
                        Status::Fail,
                        Some("Persona hook installed".to_owned()),
                        Some("modified-or-invalid".to_owned()),
                        "installed hook state did not match the private manifest and current Persona dispatcher",
                    ),
                },
            },
        },
    };
    vec![installation_finding, hook_finding]
}

#[allow(clippy::too_many_arguments)]
fn show_status(
    config_path: &Path,
    directory: &Path,
    format: OutputFormat,
    verbose: bool,
    strict: bool,
    push: Option<PushRequest>,
    handoff_binding: Option<persona::push_handoff::HandoffGithubBinding>,
    online_verified: bool,
) -> Result<u8, String> {
    let current_directory = std::env::current_dir()
        .map_err(|error| format!("cannot determine current directory: {error}"))?;
    let config_path = absolute_path(config_path, &current_directory);
    let directory = absolute_path(directory, &current_directory);
    let config = Config::load(&config_path).map_err(|error| error.to_string())?;
    let executables = ExecutablePaths {
        git: git_executable(),
        gpg: gpg_executable(),
        ssh_keygen: ssh_keygen_executable(),
    };
    let (initial_report, selected) =
        build_report(&config, &directory, push.as_ref(), &executables)?;
    let selected_policy = selected.as_ref().and_then(|scope| {
        config
            .policies()
            .iter()
            .find(|policy| policy.name == scope.name)
    });
    let selected_profile = selected_policy.and_then(|policy| {
        config
            .profiles()
            .iter()
            .find(|profile| profile.name == policy.profile)
    });
    let mut online_findings = Vec::new();
    let mut online_binding_verified = false;
    if online_verified {
        let request = push
            .as_ref()
            .ok_or_else(|| "--online-verified requires --operation push".to_owned())?;
        let host = persona::credential::destination_host(&request.destination)
            .ok_or_else(|| "online Verified requires a recognized GitHub destination".to_owned())?;
        let repository = persona::gh_adapter::repository_from_destination(&request.destination)
            .ok_or_else(|| {
                "online Verified requires an exact GitHub.com repository destination".to_owned()
            })?;
        let profile = selected_profile
            .ok_or_else(|| "online Verified requires a selected profile".to_owned())?;
        let binding = profile.github.as_ref().ok_or_else(|| {
            "online Verified requires an enrolled GitHub account binding".to_owned()
        })?;
        let local_required = push_authorization_requirements(
            request,
            selected_policy.is_some_and(|policy| policy.git.signing.is_some()),
        );
        let local_authorized = authorize(
            AuthorizationOperation::GitPush,
            local_required,
            initial_report.findings.clone(),
        )
        .is_allowed();
        if host != binding.host || !binding.permits_repository(&repository) {
            online_findings.push(persona::report::Finding::status(
                "github.commit.verified", Status::Fail, Some("bound allowlisted GitHub repository".to_owned()), Some(repository.clone()),
                "online Verified target does not match the enrolled profile binding and repository allowlist",
            ));
        } else if !local_authorized {
            online_findings.push(persona::report::Finding::status(
                "github.commit.verified", Status::Unknown, Some("locally authorized publication".to_owned()), None,
                "online Verified was not queried because local publication evidence is incomplete or blocked",
            ));
        } else {
            let gh = gh_executable().ok_or_else(|| {
                "native gh is unavailable for explicit online verification".to_owned()
            })?;
            let paths = PersonaPaths::discover().map_err(|_| {
                "cannot resolve private Persona state for online verification".to_owned()
            })?;
            let selector =
                persona::credential::GithubSelector::discover(gh, binding.host.clone(), paths)
                    .map_err(|_| {
                        "cannot safely inspect the selected GitHub account for online verification"
                            .to_owned()
                    })?;
            match selector.token_for_binding(binding) {
                Ok(Some(token)) => {
                    online_binding_verified = true;
                    let git = GitClient::new(git_executable(), persona::git::safe_environment());
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
                    match git.outgoing_commit_oids_many(&directory, &request.tuples, deadline) {
                        Ok(oids) if !oids.is_empty() && oids.len() <= 32 => {
                            let mut verified = 0usize;
                            let mut unverified = 0usize;
                            let mut unavailable = 0usize;
                            for oid in &oids {
                                match selector.commit_is_verified(&token, &repository, oid) {
                                    Ok(true) => verified += 1,
                                    Ok(false) => unverified += 1,
                                    Err(_) => unavailable += 1,
                                }
                            }
                            let status = if unverified > 0 { Status::Fail } else if unavailable > 0 { Status::Unknown } else { Status::Pass };
                            online_findings.push(persona::report::Finding::status(
                                "github.commit.verified", status, Some(format!("all {} outgoing commits Verified", oids.len())),
                                Some(format!("verified={verified}, unverified={unverified}, unavailable={unavailable}")),
                                "GitHub's online commit verification status was queried for every bounded outgoing commit",
                            ));
                        }
                        Ok(_) => online_findings.push(persona::report::Finding::status(
                            "github.commit.verified", Status::Unknown, Some("1..32 bounded outgoing commits".to_owned()), None,
                            "no outgoing commits or too many commits for the bounded online verification operation",
                        )),
                        Err(_) => online_findings.push(persona::report::Finding::status(
                            "github.commit.verified", Status::Unknown, Some("complete bounded outgoing commit graph".to_owned()), None,
                            "outgoing commit IDs could not be enumerated safely",
                        )),
                    }
                }
                Ok(None) => online_findings.push(persona::report::Finding::status(
                    "github.commit.verified",
                    Status::Fail,
                    Some(binding.account_id.clone()),
                    None,
                    "selected native GitHub credential does not match the enrolled account binding",
                )),
                Err(_) => online_findings.push(persona::report::Finding::status(
                    "github.commit.verified",
                    Status::Unknown,
                    Some(binding.account_id.clone()),
                    None,
                    "selected native GitHub credential could not be verified locally",
                )),
            }
        }
    }
    let destination_host = push
        .as_ref()
        .and_then(|request| persona::credential::destination_host(&request.destination));
    let github_operation = destination_host.as_ref().is_some_and(|host| {
        persona::credential::is_known_github_host(host)
            || selected_profile.is_some_and(|profile| profile.github.is_some())
    });
    let mut findings = initial_report.findings.clone();
    findings.extend(online_findings);
    findings.extend(integration_coverage_findings(&directory));
    if github_operation {
        let binding = selected_profile.and_then(|profile| profile.github.as_ref());
        let finding = match (destination_host.as_deref(), binding) {
            (Some(host), Some(binding)) if binding.host != host => {
                persona::report::Finding::status(
                    "github.credential.binding",
                    Status::Fail,
                    Some(binding.host.clone()),
                    Some(host.to_owned()),
                    "bound GitHub host does not match the effective push destination",
                )
            }
            (_, Some(binding))
                if handoff_binding.as_ref().is_some_and(|evidence| {
                    evidence.host == binding.host && evidence.account_id == binding.account_id
                }) =>
            {
                persona::report::Finding::pass(
                    "github.credential.binding",
                    binding.account_id.clone(),
                    binding.account_id.clone(),
                    "authenticated primary authorization handoff matches the enrolled GitHub account; no token was read at the hook barrier",
                )
            }
            (_, Some(binding)) if online_binding_verified => persona::report::Finding::pass(
                "github.credential.binding",
                binding.account_id.clone(),
                binding.account_id.clone(),
                "explicit online verification used a transient credential matching the enrolled account",
            ),
            (_, Some(binding)) => persona::report::Finding::status(
                "github.credential.binding",
                Status::Unknown,
                Some(binding.account_id.clone()),
                None,
                "offline diagnostic does not query native credentials; run `persona auth verify` or use the managed operation",
            ),
            _ => persona::report::Finding::status(
                "github.credential.binding",
                Status::Unknown,
                None,
                None,
                "no enrolled stable account binding exists for this GitHub destination",
            ),
        };
        findings.push(finding);
    }
    let mut report = Report::new(findings);
    if strict {
        report.status = report.strict_status();
    }
    let decision = push.as_ref().map(|_| {
        let mut required = vec![
            "scope".to_owned(),
            "policy.profile".to_owned(),
            "git.worktree".to_owned(),
            "git.push.destination".to_owned(),
            "git.push.updates".to_owned(),
            "git.push.author".to_owned(),
            "git.push.committer".to_owned(),
        ];
        if push.as_ref().is_some_and(|request| {
            request.tuples.iter().any(|tuple| {
                tuple.remote_ref.starts_with("refs/tags/") && tuple.local_ref != "(delete)"
            })
        }) {
            required.push("git.push.tag_signature".to_owned());
        }
        if selected_policy.is_some_and(|policy| policy.git.signing.is_some()) {
            required.extend([
                "git.push.signature.present".to_owned(),
                "git.push.signature.valid".to_owned(),
                "git.push.signature.fingerprint".to_owned(),
            ]);
        }
        if github_operation {
            required.push("github.credential.binding".to_owned());
        }
        if online_verified {
            required.push("github.commit.verified".to_owned());
        }
        authorize(
            AuthorizationOperation::GitPush,
            required,
            report.findings.clone(),
        )
    });

    match format {
        OutputFormat::Text => print_text(
            &config,
            selected.as_ref(),
            &report,
            decision.as_ref(),
            verbose,
        ),
        OutputFormat::Json => {
            let json = match decision.as_ref() {
                Some(decision) => serde_json::to_string_pretty(decision),
                None => serde_json::to_string_pretty(&report),
            }
            .map_err(|error| format!("cannot encode report: {error}"))?;
            println!("{json}");
        }
    }
    Ok(match decision {
        Some(decision) if decision.verdict == Verdict::Block => 1,
        Some(_) => 0,
        None => exit_code(report.status),
    })
}

fn show_tag(
    config_path: &Path,
    directory: &Path,
    tag: &str,
    format: OutputFormat,
) -> Result<u8, String> {
    let current = std::env::current_dir()
        .map_err(|error| format!("cannot determine current directory: {error}"))?;
    let config_path = absolute_path(config_path, &current);
    let directory = absolute_path(directory, &current);
    let config = Config::load(&config_path).map_err(|error| error.to_string())?;
    let executables = ExecutablePaths {
        git: git_executable(),
        gpg: gpg_executable(),
        ssh_keygen: ssh_keygen_executable(),
    };
    let (report, selected) = build_tag_report(&config, &directory, tag, &executables)?;
    let decision = authorize(
        AuthorizationOperation::GitTagVerification,
        vec![
            "scope".to_owned(),
            "policy.profile".to_owned(),
            "git.worktree".to_owned(),
            "git.tag.signing.config".to_owned(),
            "git.tag.signature.present".to_owned(),
            "git.tag.signature.valid".to_owned(),
            "git.tag.signature.fingerprint".to_owned(),
        ],
        report.findings.clone(),
    );
    match format {
        OutputFormat::Text => {
            print_text(&config, selected.as_ref(), &report, Some(&decision), true)
        }
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&decision)
                .map_err(|error| format!("cannot encode tag decision: {error}"))?
        ),
    }
    Ok(if decision.is_allowed() { 0 } else { 1 })
}

fn print_text(
    config: &Config,
    selected: Option<&persona::Scope>,
    report: &Report,
    decision: Option<&OperationDecision>,
    verbose: bool,
) {
    let color = stdout_color_enabled();
    if !verbose {
        let scope = selected
            .map(|scope| scope.name.as_str())
            .unwrap_or("unmanaged");
        let status_label = style_status(&format!("{:?}", report.status), report.status, color);
        println!("Persona: {scope} — {status_label}");
        if let Some(scope) = selected {
            if let Some(policy) = config
                .policies()
                .iter()
                .find(|policy| policy.name == scope.name)
            {
                println!("profile: {}", policy.profile);
            }
        }
        if let Some(decision) = decision {
            println!(
                "authorization: {}",
                style_verdict(decision.is_allowed(), color)
            );
            for blocker in &decision.blockers {
                println!("blocked {}: {}", blocker.property, blocker.reason);
            }
            if !is_quiet() {
                println!("Use `--verbose` for all findings.");
            }
        } else if !is_quiet() {
            println!("Use `persona doctor` or `--verbose` for offline findings.");
        }
        return;
    }
    match selected {
        Some(scope) => {
            println!("scope: {}", scope.name);
            println!("scope root: {}", scope.root.display());
            if let Some(policy) = config
                .policies()
                .iter()
                .find(|policy| policy.name == scope.name)
            {
                println!("profile: {}", policy.profile);
                println!(
                    "expected author: {} <{}>",
                    policy.git.author.name, policy.git.author.email
                );
                println!(
                    "expected committer: {} <{}>",
                    policy.git.committer.name, policy.git.committer.email
                );
            }
        }
        None => {
            println!("scope: unmanaged");
            println!("identity: no identity assumed");
        }
    }
    let result_upper = format!("{:?}", report.status).to_uppercase();
    println!(
        "result: {}",
        style_status(&result_upper, report.status, color)
    );
    if let Some(decision) = decision {
        println!(
            "authorization: {} ({:?})",
            style_verdict(decision.is_allowed(), color),
            decision.operation
        );
        for blocker in &decision.blockers {
            println!("blocked {}: {}", blocker.property, blocker.reason);
        }
    }
    println!("coverage: per-property offline findings");
    let worktree_checked = report
        .findings
        .iter()
        .any(|finding| finding.property == "git.worktree" && finding.status == Status::Pass);
    let identity_checked = report.findings.iter().any(|finding| {
        (finding.property == "git.author" || finding.property == "git.committer")
            && finding.observed.is_some()
    });
    match (worktree_checked, identity_checked) {
        (true, true) => println!("Git worktree and effective identity checked offline"),
        (true, false) => println!("Git worktree checked offline; effective identity unknown"),
        _ => println!("Git worktree and identity not checked"),
    }
    println!(
        "SSH/gh indicators and remote transport were inspected offline; authentication and publication remain unknown"
    );
    let mut details = String::new();
    for finding in &report.findings {
        let status_str = style_status(&format!("{:?}", finding.status), finding.status, color);
        let _ = write!(
            details,
            "finding {}: {status_str} ({}), ",
            finding.property, finding.coverage_reason
        );
        if let Some(expected) = &finding.expected {
            let _ = write!(details, "expected={expected}, ");
        }
        if let Some(observed) = &finding.observed {
            let _ = write!(details, "observed={observed}, ");
        }
        let _ = writeln!(details);
    }
    print!("{details}");
}

fn setup(args: SetupArgs) -> Result<u8, String> {
    let paths = PersonaPaths::discover()
        .map_err(|error| format!("cannot resolve Persona paths: {error}"))?;
    paths
        .validate_private_config()
        .map_err(|error| format!("unsafe private configuration: {error}"))?;
    if paths.config_file.exists() {
        return Err("Persona is already configured; refusing to overwrite it".to_owned());
    }
    let current = std::env::current_dir()
        .map_err(|error| format!("cannot determine current directory: {error}"))?;
    let scope_root = physical_scope_root(&absolute_path(&args.scope, &current))?;
    let author_name = setup_value(args.author_name, "Author name", args.no_input, None)?;
    let author_email = setup_value(args.author_email, "Author email", args.no_input, None)?;
    let committer_name = setup_value(
        args.committer_name,
        "Committer name",
        args.no_input,
        Some(&author_name),
    )?;
    let committer_email = setup_value(
        args.committer_email,
        "Committer email",
        args.no_input,
        Some(&author_email),
    )?;
    let profile = Profile {
        name: args.profile.clone(),
        github: None,
        ssh: None,
        github_merge: None,
        run: CommandPolicy::default(),
        git: GitPolicy {
            author: Identity {
                name: author_name,
                email: author_email,
            },
            committer: Identity {
                name: committer_name,
                email: committer_email,
            },
            signing: None,
            push: None,
            remotes: Vec::new(),
            deny_destinations: Vec::new(),
            commands: CommandPolicy::default(),
            strict_repo_hooks: false,
            strict_git_filters: false,
            strict_merge_drivers: false,
            inherit_git_config: true,
            cross_profile_identity_check: true,
        },
    };
    let config = Config::single_scope(profile, args.scope_name, scope_root)
        .map_err(|error| format!("invalid initial profile/scope: {error}"))?;
    let contents = config
        .to_v3_toml()
        .map_err(|error| format!("cannot encode initial configuration: {error}"))?;
    paths
        .ensure_private_directories()
        .map_err(|error| format!("cannot prepare private Persona paths: {error}"))?;
    paths
        .create_config(contents.as_bytes())
        .map_err(|error| format!("cannot securely create Persona configuration: {error}"))?;
    if !is_quiet() {
        println!(
            "Created private Persona configuration at {}",
            paths.config_file.display()
        );
        println!("No Git, SSH, GPG, GitHub, or credential settings were changed.");
        println!(
            "Next steps: run `persona doctor`, `persona profile show {}`, or `persona auth enroll --profile {} --user <GH_USER> --confirm-online`.",
            args.profile, args.profile
        );
    }
    Ok(0)
}

fn setup_value(
    value: Option<String>,
    label: &str,
    no_input: bool,
    default: Option<&str>,
) -> Result<String, String> {
    if let Some(value) = value {
        if value.trim().is_empty() {
            return Err(format!("{label} cannot be empty"));
        }
        return Ok(value);
    }
    if no_input || !std::io::stdin().is_terminal() {
        if let Some(default) = default {
            return Ok(default.to_owned());
        }
        return Err(format!(
            "{label} is required; supply its --{} flag or run setup interactively",
            label.to_ascii_lowercase().replace(' ', "-")
        ));
    }
    if let Some(default) = default {
        print!("{label} [{default}]: ");
    } else {
        print!("{label}: ");
    }
    std::io::Write::flush(&mut std::io::stdout())
        .map_err(|error| format!("cannot write setup prompt: {error}"))?;
    let mut value = String::new();
    std::io::stdin()
        .read_line(&mut value)
        .map_err(|error| format!("cannot read setup input: {error}"))?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        if let Some(default) = default {
            return Ok(default.to_owned());
        }
        return Err(format!("{label} cannot be empty"));
    }
    Ok(value)
}

fn physical_scope_root(path: &Path) -> Result<PathBuf, String> {
    let canonical = persona::paths::canonical_directory(path)
        .map_err(|error| format!("invalid scope directory: {error}"))?;
    let git = GitClient::new(git_executable(), Vec::new());
    match git.checkout_root(&canonical) {
        Ok(root) => Ok(root),
        Err(persona::git::GitError::CommandFailed(_)) => Ok(canonical),
        Err(error) => Err(format!("cannot identify physical worktree root: {error:?}")),
    }
}

fn preview_config_migration(config_path: &Path) -> Result<u8, String> {
    let config = Config::load(config_path).map_err(|error| error.to_string())?;
    let preview = config
        .to_v3_toml()
        .map_err(|error| format!("cannot migrate configuration: {error}"))?;
    print!("{preview}");
    Ok(0)
}

fn apply_config_migration() -> Result<u8, String> {
    let paths = PersonaPaths::discover()
        .map_err(|error| format!("cannot resolve Persona paths: {error}"))?;
    let _update_lock = paths
        .lock_config_update()
        .map_err(|error| format!("cannot lock private configuration for migration: {error}"))?;
    paths
        .validate_private_config()
        .map_err(|error| format!("unsafe private configuration: {error}"))?;
    let config = Config::load(&paths.config_file)
        .map_err(|error| format!("cannot load private configuration: {error}"))?;
    if config.version() == 3 {
        return Err("configuration is already version 3".to_owned());
    }
    let contents = config
        .to_v3_toml()
        .map_err(|error| format!("cannot migrate configuration: {error}"))?;
    let backup = paths
        .write_config(contents.as_bytes())
        .map_err(|error| format!("cannot atomically migrate configuration: {error}"))?;
    if !is_quiet() {
        println!("Migrated private configuration to v3.");
        if let Some(backup) = backup {
            println!("Backup: {}", backup.display());
        }
    }
    Ok(0)
}

fn rollback_config(backup: &Path) -> Result<u8, String> {
    let paths = PersonaPaths::discover()
        .map_err(|error| format!("cannot resolve Persona paths: {error}"))?;
    let _update_lock = paths
        .lock_config_update()
        .map_err(|error| format!("cannot lock private configuration for rollback: {error}"))?;
    let previous = paths
        .rollback(backup)
        .map_err(|error| format!("cannot roll back configuration: {error}"))?;
    if !is_quiet() {
        println!("Restored configuration from {}.", backup.display());
        if let Some(previous) = previous {
            println!(
                "The replaced configuration was backed up to {}.",
                previous.display()
            );
        }
    }
    Ok(0)
}

fn git_credential_helper(action: &str) -> Result<u8, String> {
    if !matches!(action, "get" | "store" | "erase") {
        return Err("unsupported Git credential-helper operation".to_owned());
    }
    let input = read_credential_helper_input()?;
    if matches!(action, "store" | "erase") {
        return Ok(0);
    }
    persona::git_https::parse_credential_request(input.expose())
        .map_err(|_| "invalid Git HTTPS credential request".to_owned())?;

    let configured_path = std::env::var_os("PERSONA_CONFIG_PATH").map(PathBuf::from);
    let config = persona::runtime::load_config(configured_path.as_deref())?;
    let cwd = std::env::current_dir().map_err(|_| "cannot resolve current directory".to_owned())?;
    let physical = physical_scope_root(&cwd)?;
    let selected = persona::context::resolve_context(&physical, &config.scopes())
        .map_err(|_| "cannot resolve Persona scope".to_owned())?
        .ok_or_else(|| "Git HTTPS credentials require a managed Persona scope".to_owned())?;
    let policy = config
        .policies()
        .iter()
        .find(|policy| policy.name == selected.name)
        .ok_or_else(|| "managed Persona scope has no policy".to_owned())?;
    let profile = config
        .profiles()
        .iter()
        .find(|profile| profile.name == policy.profile)
        .ok_or_else(|| "managed Persona profile is unavailable".to_owned())?;
    let binding = profile
        .github
        .as_ref()
        .ok_or_else(|| "managed Persona profile has no GitHub credential binding".to_owned())?;
    let direction = match std::env::var("PERSONA_GIT_CREDENTIAL_DIRECTION").as_deref() {
        Ok("fetch") => "fetch",
        Ok("push") | Err(_) => "push",
        _ => return Err("unsupported managed Git credential direction".to_owned()),
    };
    let requested_remote = std::env::var("PERSONA_GIT_CREDENTIAL_REMOTE").ok();
    let allowed_destinations = if direction == "push" {
        if let Some(remote) = requested_remote.as_deref() {
            policy
                .git
                .configured_push_destinations(remote)
                .map(ToOwned::to_owned)
        } else {
            None
        }
        .or_else(|| {
            policy
                .git
                .push
                .as_ref()
                .map(|push| push.destinations.clone())
        })
        .ok_or_else(|| "managed Persona profile has no allowed push destinations".to_owned())?
    } else if let Some(remote) = requested_remote.as_deref() {
        policy
            .git
            .configured_fetch_destinations(remote)
            .ok_or_else(|| format!("managed Persona profile has no fetch policy for `{remote}`"))?
            .to_vec()
    } else if !profile.git.remotes.is_empty() {
        let mut destinations = profile
            .git
            .remotes
            .iter()
            .flat_map(|remote| remote.fetch_destinations.iter().cloned())
            .collect::<Vec<_>>();
        destinations.sort();
        destinations.dedup();
        destinations
    } else {
        policy
            .git
            .push
            .as_ref()
            .map(|push| push.destinations.clone())
            .unwrap_or_default()
    };
    if allowed_destinations.is_empty() {
        return Err("managed Persona profile has no allowed HTTPS destinations".to_owned());
    }
    let gh = gh_executable().ok_or_else(|| "GitHub CLI is unavailable".to_owned())?;
    let paths =
        PersonaPaths::discover().map_err(|_| "cannot resolve Persona private state".to_owned())?;
    let selector = persona::credential::GithubSelector::discover(gh, binding.host.clone(), paths)
        .map_err(|_| "cannot inspect native GitHub credential selector".to_owned())?;
    let mut output = std::io::stdout().lock();
    persona::git_https::handle_credential_helper_with_denies(
        action,
        input.expose(),
        binding,
        &allowed_destinations,
        &policy.git.deny_destinations,
        &selector,
        &mut output,
    )
    .map_err(|_| "Git HTTPS credential request denied".to_owned())?;
    output
        .flush()
        .map_err(|_| "cannot write Git credential response".to_owned())?;
    Ok(0)
}

fn read_credential_helper_input() -> Result<persona::credential::Secret, String> {
    const INPUT_LIMIT: u64 = 8 * 1024 + 1;
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(INPUT_LIMIT)
        .read_to_end(&mut input)
        .map_err(|_| "cannot read Git credential request".to_owned())?;
    if input.len() > INPUT_LIMIT as usize - 1 {
        input.fill(0);
        return Err("Git credential request exceeds the size limit".to_owned());
    }
    Ok(persona::credential::Secret::new(input))
}

fn command_policy_summary(policy: &CommandPolicy) -> String {
    let mode = match policy.effective_mode() {
        CommandPolicyMode::Allowlist => "allowlist",
        CommandPolicyMode::Denylist => "denylist",
    };
    let allow = policy.allow.as_ref().map_or(0, Vec::len);
    let deny = policy.deny.len();
    format!("mode={mode} (allow={allow}, deny={deny})")
}

fn update_command_policy(
    existing: &CommandPolicy,
    clear: bool,
    mode: Option<CliCommandMode>,
    allow: Vec<String>,
    deny: Vec<String>,
) -> Result<CommandPolicy, String> {
    if clear {
        if mode.is_some() || !allow.is_empty() || !deny.is_empty() {
            return Err(
                "command clear flag cannot be combined with allow, deny, or mode options"
                    .to_owned(),
            );
        }
        return Ok(CommandPolicy::default());
    }
    let mut updated = existing.clone();
    if let Some(mode) = mode {
        updated.mode = Some(mode.into());
    }
    if !allow.is_empty() {
        updated.allow = Some(allow);
    }
    if !deny.is_empty() {
        updated.deny = deny;
    }
    Ok(updated)
}

fn baseline_command(command: BaselineCommands) -> Result<u8, String> {
    match command {
        BaselineCommands::Update { cwd, preview } => {
            let cwd = std::fs::canonicalize(&cwd)
                .map_err(|_| "baseline working directory must exist".to_owned())?;
            let (_home, git) = hook_git_client()?;
            let root = git
                .checkout_root(&cwd)
                .map_err(|_| "baseline update requires an existing Git worktree".to_owned())?;
            let (paths, update_lock, mut config) = load_private_config_for_update()?;
            let selected = persona::context::resolve_context(&root, &config.scopes())
                .map_err(|_| "cannot resolve Persona scope for baseline update".to_owned())?
                .ok_or_else(|| "baseline update requires a managed scope".to_owned())?;
            let policy = config
                .policies()
                .iter()
                .find(|policy| policy.name == selected.name)
                .ok_or_else(|| "managed scope has no Git policy".to_owned())?;
            let mut updated = config
                .profiles()
                .iter()
                .find(|profile| profile.name == policy.profile)
                .cloned()
                .ok_or_else(|| "active profile does not exist".to_owned())?;
            let remotes = {
                let push = updated
                    .git
                    .push
                    .as_ref()
                    .ok_or_else(|| "active profile has no push policy".to_owned())?;
                if push.remote == "*" {
                    git.configured_remotes(&root)
                        .map_err(|_| "cannot inspect Git remotes for baseline update".to_owned())?
                } else {
                    vec![push.remote.clone()]
                }
            };
            let mut repo_tracking = Vec::new();
            for remote in &remotes {
                let Ok(destinations) = git.effective_push_destinations(&root, remote) else {
                    continue;
                };
                let allowed_destinations: Vec<String> = destinations
                    .into_iter()
                    .filter(|destination| updated.git.permits_push_destination(remote, destination))
                    .collect();
                if allowed_destinations.is_empty() {
                    continue;
                }
                let refs = git
                    .remote_tracking_refs(&root, remote)
                    .map_err(|_| format!("cannot inspect tracking refs for remote `{remote}`"))?;
                let filtered_refs: Vec<(String, String)> = refs
                    .into_iter()
                    .filter(|(tracking_ref, _)| !tracking_ref.ends_with("/HEAD"))
                    .collect();
                if !filtered_refs.is_empty() {
                    repo_tracking.push((allowed_destinations, filtered_refs));
                }
            }
            if repo_tracking.is_empty() {
                return Err(
                    "no permitted remote push destination with tracking refs found in this worktree"
                        .to_owned(),
                );
            }
            let push = updated
                .git
                .push
                .as_mut()
                .ok_or_else(|| "active profile has no push policy".to_owned())?;
            let mut touched = 0usize;
            for baseline in &mut push.upstream_baselines {
                for (destinations, refs) in &repo_tracking {
                    if destinations
                        .iter()
                        .any(|dest| dest == &baseline.destination)
                    {
                        if let Some((_, oid)) = refs
                            .iter()
                            .find(|(tracking_ref, _)| tracking_ref == &baseline.tracking_ref)
                        {
                            baseline.oid = oid.clone();
                            if !is_quiet() {
                                println!(
                                    "Updated baseline: {} {} -> {}",
                                    baseline.destination, baseline.tracking_ref, baseline.oid
                                );
                            }
                            touched += 1;
                        }
                    }
                }
            }
            if touched == 0 {
                for (destinations, refs) in repo_tracking {
                    let destination = destinations[0].clone();
                    for (tracking_ref, oid) in refs {
                        if !is_quiet() {
                            println!("Pinned baseline: {destination} {tracking_ref} -> {oid}");
                        }
                        push.upstream_baselines
                            .push(persona::config::UpstreamBaseline {
                                destination: destination.clone(),
                                tracking_ref,
                                oid,
                            });
                        touched += 1;
                    }
                }
            }
            if touched == 0 {
                return Err("no remote-tracking refs found to update".to_owned());
            }
            config
                .update_profile(updated)
                .map_err(|error| format!("cannot update upstream baselines: {error}"))?;
            persist_private_config(&paths, &update_lock, &config, preview)
        }
    }
}

fn profile_command(command: ProfileCommands) -> Result<u8, String> {
    match command {
        ProfileCommands::List { config, json } => {
            let config = load_config(config.as_deref())?;
            if json {
                let names: Vec<&str> = config
                    .profiles()
                    .iter()
                    .map(|profile| profile.name.as_str())
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&names)
                        .map_err(|error| format!("cannot encode profile list: {error}"))?
                );
            } else {
                for profile in config.profiles() {
                    println!("{}", profile.name);
                }
            }
            Ok(0)
        }
        ProfileCommands::Show { name, config, json } => {
            let config = load_config(config.as_deref())?;
            let profile = config
                .profiles()
                .iter()
                .find(|profile| profile.name == name)
                .ok_or_else(|| format!("profile `{name}` does not exist"))?;
            if json {
                let payload = serde_json::json!({
                    "name": profile.name,
                    "author": {
                        "name": profile.git.author.name,
                        "email": profile.git.author.email,
                    },
                    "committer": {
                        "name": profile.git.committer.name,
                        "email": profile.git.committer.email,
                    },
                    "signing_configured": profile.git.signing.is_some(),
                    "push_configured": profile.git.push.is_some(),
                    "ssh_configured": profile.ssh.is_some(),
                    "github_configured": profile.github.is_some(),
                    "git_commands": {
                        "mode": match profile.git.commands.effective_mode() {
                            CommandPolicyMode::Allowlist => "allowlist",
                            CommandPolicyMode::Denylist => "denylist",
                        },
                        "allow": profile.git.commands.allow,
                        "deny": profile.git.commands.deny,
                    },
                    "run_commands": {
                        "mode": match profile.run.effective_mode() {
                            CommandPolicyMode::Allowlist => "allowlist",
                            CommandPolicyMode::Denylist => "denylist",
                        },
                        "allow": profile.run.allow,
                        "deny": profile.run.deny,
                    },
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .map_err(|error| format!("cannot encode profile details: {error}"))?
                );
                return Ok(0);
            }
            println!("profile: {}", profile.name);
            println!(
                "author: {} <{}>",
                profile.git.author.name, profile.git.author.email
            );
            println!(
                "committer: {} <{}>",
                profile.git.committer.name, profile.git.committer.email
            );
            println!(
                "signing policy: {}",
                if profile.git.signing.is_some() {
                    "configured"
                } else {
                    "not configured"
                }
            );
            println!(
                "push policy: {}",
                if profile.git.push.is_some() {
                    "configured"
                } else {
                    "not configured"
                }
            );
            if let Some(push) = &profile.git.push {
                println!(
                    "upstream provenance: {:?}",
                    push.effective_upstream_provenance()
                );
                println!(
                    "pinned upstream baselines: {}",
                    push.upstream_baselines.len()
                );
                for baseline in &push.upstream_baselines {
                    println!(
                        "upstream baseline: {} {}",
                        baseline.tracking_ref, baseline.oid
                    );
                }
            }
            if !profile.git.deny_destinations.is_empty() {
                println!(
                    "denied git destinations: {}",
                    profile.git.deny_destinations.join(", ")
                );
            }
            println!(
                "git commands: {}",
                command_policy_summary(&profile.git.commands)
            );
            println!(
                "GitHub account binding: {}",
                profile.github.as_ref().map_or("not configured", |binding| {
                    if binding.account_selector.is_none() {
                        "incomplete; re-enroll with an explicit native gh username"
                    } else if binding.repositories.is_empty() {
                        "configured; no GH repository allowlist"
                    } else {
                        "configured; explicit GH repository allowlist"
                    }
                })
            );
            if let Some(binding) = &profile.github {
                for repository in &binding.repositories {
                    println!("GitHub repository: {repository}");
                }
                for denied in &binding.deny_repositories {
                    println!("GitHub denied repository: {denied}");
                }
                println!("gh commands: {}", command_policy_summary(&binding.commands));
            }
            println!("run commands: {}", command_policy_summary(&profile.run));
            println!(
                "SSH transport policy: {}",
                if profile.ssh.is_some() {
                    "configured"
                } else {
                    "not configured"
                }
            );
            Ok(0)
        }
        ProfileCommands::Verify { name, config } => {
            let config = load_config(config.as_deref())?;
            let profile = config
                .profiles()
                .iter()
                .find(|profile| profile.name == name)
                .ok_or_else(|| format!("profile `{name}` does not exist"))?;
            let mappings = config
                .policies()
                .iter()
                .filter(|scope| scope.profile == profile.name)
                .count();
            println!(
                "profile `{}` is structurally valid and explicitly mapped by {mappings} scope(s)",
                profile.name
            );
            Ok(0)
        }
        ProfileCommands::Add(args) => {
            let (paths, update_lock, mut config) = load_private_config_for_update()?;
            let preview = args.preview;
            let profile = profile_from_args(*args, None)?;
            config
                .add_profile(profile)
                .map_err(|error| format!("cannot add profile: {error}"))?;
            persist_private_config(&paths, &update_lock, &config, preview)
        }
        ProfileCommands::Update(args) => {
            let (paths, update_lock, mut config) = load_private_config_for_update()?;
            let existing = config
                .profiles()
                .iter()
                .find(|profile| profile.name == args.name)
                .ok_or_else(|| format!("profile `{}` does not exist", args.name))?;
            let existing = existing.clone();
            let preview = args.preview;
            let profile = profile_from_args(*args, Some(&existing))?;
            config
                .update_profile(profile)
                .map_err(|error| format!("cannot update profile: {error}"))?;
            persist_private_config(&paths, &update_lock, &config, preview)
        }
        ProfileCommands::Commands(args) => {
            if !args.clear_git
                && args.git_mode.is_none()
                && args.git_allow.is_empty()
                && args.git_deny.is_empty()
                && !args.clear_gh
                && args.gh_mode.is_none()
                && args.gh_allow.is_empty()
                && args.gh_deny.is_empty()
                && !args.clear_run
                && args.run_mode.is_none()
                && args.run_allow.is_empty()
                && args.run_deny.is_empty()
            {
                return Err(
                    "profile commands requires at least one `--git-*`, `--gh-*`, or `--run-*` option"
                        .to_owned(),
                );
            }
            let (paths, update_lock, mut config) = load_private_config_for_update()?;
            let mut updated = config
                .profiles()
                .iter()
                .find(|profile| profile.name == args.name)
                .cloned()
                .ok_or_else(|| format!("profile `{}` does not exist", args.name))?;
            let preview = args.preview;
            updated.git.commands = update_command_policy(
                &updated.git.commands,
                args.clear_git,
                args.git_mode,
                args.git_allow,
                args.git_deny,
            )?;
            if args.clear_gh
                || args.gh_mode.is_some()
                || !args.gh_allow.is_empty()
                || !args.gh_deny.is_empty()
            {
                let binding = updated.github.as_mut().ok_or_else(|| {
                    "enroll the profile with `persona auth enroll` before configuring GitHub command policies".to_owned()
                })?;
                binding.commands = update_command_policy(
                    &binding.commands,
                    args.clear_gh,
                    args.gh_mode,
                    args.gh_allow,
                    args.gh_deny,
                )?;
            }
            updated.run = update_command_policy(
                &updated.run,
                args.clear_run,
                args.run_mode,
                args.run_allow,
                args.run_deny,
            )?;
            config
                .update_profile(updated)
                .map_err(|error| format!("cannot update profile command policy: {error}"))?;
            persist_private_config(&paths, &update_lock, &config, preview)
        }
        ProfileCommands::Remove { name, preview } => {
            let (paths, update_lock, mut config) = load_private_config_for_update()?;
            config
                .remove_profile(&name)
                .map_err(|error| format!("cannot remove profile: {error}"))?;
            persist_private_config(&paths, &update_lock, &config, preview)
        }
    }
}

fn profile_from_args(args: ProfileEditArgs, existing: Option<&Profile>) -> Result<Profile, String> {
    let author_name = match (args.author_name, existing) {
        (Some(name), _) => name,
        (None, Some(profile)) => profile.git.author.name.clone(),
        (None, None) => return Err("--author-name is required when adding a profile".to_owned()),
    };
    let author_email = match (args.author_email, existing) {
        (Some(email), _) => email,
        (None, Some(profile)) => profile.git.author.email.clone(),
        (None, None) => return Err("--author-email is required when adding a profile".to_owned()),
    };
    let committer_name = match (args.committer_name, existing) {
        (Some(name), _) => name,
        (None, Some(profile)) => profile.git.committer.name.clone(),
        (None, None) => author_name.clone(),
    };
    let committer_email = match (args.committer_email, existing) {
        (Some(email), _) => email,
        (None, Some(profile)) => profile.git.committer.email.clone(),
        (None, None) => author_email.clone(),
    };

    let signing = if args.clear_signing {
        if args.signing_fingerprint.is_some()
            || args.public_key.is_some()
            || args.signing_format.is_some()
        {
            return Err("--clear-signing cannot be combined with signing options".to_owned());
        }
        None
    } else {
        match (
            args.signing_fingerprint,
            args.public_key,
            existing.and_then(|profile| profile.git.signing.as_ref()),
        ) {
            (Some(fingerprint), Some(public_key), prev) => Some(persona::config::SigningPolicy {
                fingerprint,
                format: match args.signing_format.as_deref() {
                    Some("openpgp") => persona::config::SigningFormat::OpenPgp,
                    Some("ssh") => persona::config::SigningFormat::Ssh,
                    Some(_) => return Err("--signing-format must be `openpgp` or `ssh`".to_owned()),
                    None => prev.map_or(persona::config::SigningFormat::OpenPgp, |s| s.format),
                },
                public_key,
            }),
            (Some(fingerprint), None, Some(prev)) => Some(persona::config::SigningPolicy {
                fingerprint,
                format: match args.signing_format.as_deref() {
                    Some("openpgp") => persona::config::SigningFormat::OpenPgp,
                    Some("ssh") => persona::config::SigningFormat::Ssh,
                    Some(_) => return Err("--signing-format must be `openpgp` or `ssh`".to_owned()),
                    None => prev.format,
                },
                public_key: prev.public_key.clone(),
            }),
            (None, Some(public_key), Some(prev)) => Some(persona::config::SigningPolicy {
                fingerprint: prev.fingerprint.clone(),
                format: match args.signing_format.as_deref() {
                    Some("openpgp") => persona::config::SigningFormat::OpenPgp,
                    Some("ssh") => persona::config::SigningFormat::Ssh,
                    Some(_) => return Err("--signing-format must be `openpgp` or `ssh`".to_owned()),
                    None => prev.format,
                },
                public_key,
            }),
            (None, None, Some(prev)) if args.signing_format.is_some() => {
                Some(persona::config::SigningPolicy {
                    fingerprint: prev.fingerprint.clone(),
                    format: match args.signing_format.as_deref() {
                        Some("openpgp") => persona::config::SigningFormat::OpenPgp,
                        Some("ssh") => persona::config::SigningFormat::Ssh,
                        _ => return Err("--signing-format must be `openpgp` or `ssh`".to_owned()),
                    },
                    public_key: prev.public_key.clone(),
                })
            }
            (None, None, prev) if args.signing_format.is_none() => prev.cloned(),
            (None, None, None) => {
                return Err(
                    "--signing-format requires --signing-fingerprint and --public-key".to_owned(),
                );
            }
            _ => {
                return Err(
                    "--signing-fingerprint and --public-key must be supplied together".to_owned(),
                );
            }
        }
    };
    let push = match (args.push_remote, args.push_destinations.is_empty()) {
        (Some(remote), false) => {
            let mut push = existing
                .and_then(|profile| profile.git.push.clone())
                .unwrap_or_default();
            push.remote = remote;
            push.destinations = args.push_destinations;
            if args.preserve_authors {
                push.preserve_authors = true;
            } else if args.strict_authors {
                push.preserve_authors = false;
            }
            Some(push)
        }
        (None, true) => {
            let mut push = existing.and_then(|profile| profile.git.push.clone());
            if args.preserve_authors || args.strict_authors {
                let Some(policy) = push.as_mut() else {
                    return Err(
                        "author-preservation options require an existing push policy".to_owned(),
                    );
                };
                policy.preserve_authors = args.preserve_authors;
            }
            push
        }
        _ => {
            return Err(
                "--push-remote and at least one --push-destination must be supplied together"
                    .to_owned(),
            );
        }
    };
    let publication_options_supplied = args.allow_initial_push.is_some()
        || args.allow_fast_forward.is_some()
        || args.allow_annotated_tags.is_some()
        || args.allow_lightweight_tags.is_some()
        || args.allow_branch_deletion.is_some()
        || args.allow_tag_deletion.is_some()
        || args.allow_force_with_lease.is_some()
        || args.allow_force_push.is_some()
        || args.require_tag_lease_on_create.is_some()
        || args.upstream_provenance.is_some()
        || !args.upstream_baselines.is_empty()
        || args.clear_upstream_baselines;
    let push = if publication_options_supplied {
        let Some(mut policy) = push else {
            return Err("publication policy options require an existing push policy".to_owned());
        };
        if let Some(value) = args.allow_initial_push {
            policy.allow_initial_push = value;
        }
        if let Some(value) = args.allow_fast_forward {
            policy.allow_fast_forward = value;
        }
        if let Some(value) = args.allow_annotated_tags {
            policy.allow_annotated_tags = value;
        }
        if let Some(value) = args.allow_lightweight_tags {
            policy.allow_lightweight_tags = value;
        }
        if let Some(value) = args.allow_branch_deletion {
            policy.allow_branch_deletion = value;
        }
        if let Some(value) = args.allow_tag_deletion {
            policy.allow_tag_deletion = value;
        }
        if let Some(value) = args.allow_force_with_lease {
            policy.allow_force_with_lease = value;
        }
        if let Some(value) = args.allow_force_push {
            policy.allow_force_push = value;
        }
        if let Some(value) = args.require_tag_lease_on_create {
            policy.require_tag_lease_on_create = value;
        }
        if let Some(mode) = args.upstream_provenance {
            policy.upstream_provenance = Some(mode.into());
        }
        if args.clear_upstream_baselines {
            policy.upstream_baselines.clear();
        } else if !args.upstream_baselines.is_empty() {
            policy.upstream_baselines = args
                .upstream_baselines
                .iter()
                .map(|entry| {
                    let (destination, reference_and_oid) = entry.split_once('|').ok_or_else(|| {
                        "--upstream-baseline must be <DESTINATION>|<refs/remotes/REMOTE/BRANCH>=<OID>".to_owned()
                    })?;
                    let (tracking_ref, oid) = reference_and_oid.split_once('=').ok_or_else(|| {
                        "--upstream-baseline must include an exact object ID".to_owned()
                    })?;
                    Ok(persona::config::UpstreamBaseline {
                        destination: destination.to_owned(),
                        tracking_ref: tracking_ref.to_owned(),
                        oid: oid.to_ascii_lowercase(),
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
        }
        Some(policy)
    } else {
        push
    };
    let ssh_options_supplied = args.ssh_host.is_some()
        || args.ssh_user.is_some()
        || args.ssh_port.is_some()
        || args.ssh_fingerprint.is_some()
        || args.ssh_public_key.is_some()
        || args.ssh_identity_file.is_some()
        || args.ssh_agent_socket.is_some()
        || args.ssh_known_hosts_file.is_some();
    let ssh = if args.clear_ssh {
        if ssh_options_supplied {
            return Err("--clear-ssh cannot be combined with SSH options".to_owned());
        }
        None
    } else if !ssh_options_supplied {
        existing.and_then(|profile| profile.ssh.clone())
    } else {
        let prev_ssh = existing.and_then(|profile| profile.ssh.as_ref());
        Some(persona::config::SshPolicy {
            host: args
                .ssh_host
                .or_else(|| prev_ssh.map(|s| s.host.clone()))
                .ok_or_else(|| "--ssh-host required for SSH policy".to_owned())?,
            user: args
                .ssh_user
                .or_else(|| prev_ssh.map(|s| s.user.clone()))
                .ok_or_else(|| "--ssh-user required for SSH policy".to_owned())?,
            port: args
                .ssh_port
                .or_else(|| prev_ssh.map(|s| s.port))
                .ok_or_else(|| "--ssh-port required for SSH policy".to_owned())?,
            fingerprint: args
                .ssh_fingerprint
                .or_else(|| prev_ssh.map(|s| s.fingerprint.clone()))
                .ok_or_else(|| "--ssh-fingerprint required for SSH policy".to_owned())?,
            public_key: args
                .ssh_public_key
                .or_else(|| prev_ssh.map(|s| s.public_key.clone()))
                .ok_or_else(|| "--ssh-public-key required for SSH policy".to_owned())?,
            identity_file: args
                .ssh_identity_file
                .or_else(|| prev_ssh.and_then(|s| s.identity_file.clone())),
            agent_socket: args
                .ssh_agent_socket
                .or_else(|| prev_ssh.and_then(|s| s.agent_socket.clone())),
            known_hosts_file: args
                .ssh_known_hosts_file
                .or_else(|| prev_ssh.map(|s| s.known_hosts_file.clone()))
                .ok_or_else(|| "--ssh-known-hosts-file required for SSH policy".to_owned())?,
        })
    };
    let remotes = if args.clear_remote_policies {
        Vec::new()
    } else if !args.remote_policies.is_empty() {
        args.remote_policies
            .iter()
            .map(|entry| {
                let mut fields = entry.split('|');
                let name = fields
                    .next()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        "--remote-policy must be NAME|FETCH_URLS|PUSH_URLS".to_owned()
                    })?;
                let fetch = fields.next().ok_or_else(|| {
                    "--remote-policy must be NAME|FETCH_URLS|PUSH_URLS".to_owned()
                })?;
                let push = fields.next().ok_or_else(|| {
                    "--remote-policy must be NAME|FETCH_URLS|PUSH_URLS".to_owned()
                })?;
                if fields.next().is_some() {
                    return Err(
                        "--remote-policy accepts exactly three pipe-delimited fields".to_owned(),
                    );
                }
                let parse_destinations = |value: &str| -> Result<Vec<String>, String> {
                    if value == "-" {
                        return Ok(Vec::new());
                    }
                    let values = value.split(',').map(str::to_owned).collect::<Vec<_>>();
                    if values.iter().any(String::is_empty) {
                        return Err("remote destination list contains an empty item".to_owned());
                    }
                    Ok(values)
                };
                Ok(persona::config::RemotePolicy {
                    name: name.to_owned(),
                    fetch_destinations: parse_destinations(fetch)?,
                    push_destinations: parse_destinations(push)?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?
    } else {
        existing.map_or_else(Vec::new, |profile| profile.git.remotes.clone())
    };
    let github_merge = if args.clear_github_merges {
        None
    } else if !args.github_merge_rules.is_empty() {
        let mut rules: std::collections::BTreeMap<
            String,
            (Vec<String>, Vec<persona::config::MergeStrategy>),
        > = std::collections::BTreeMap::new();
        for entry in &args.github_merge_rules {
            let mut fields = entry.split('|');
            let repository = fields
                .next()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "--allow-github-merge must be REPO|BASE|STRATEGY".to_owned())?;
            let base = fields
                .next()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "--allow-github-merge must be REPO|BASE|STRATEGY".to_owned())?;
            let strategy = match fields.next() {
                Some("merge") => persona::config::MergeStrategy::Merge,
                Some("squash") => persona::config::MergeStrategy::Squash,
                Some("rebase") => persona::config::MergeStrategy::Rebase,
                _ => {
                    return Err("GitHub merge strategy must be merge, squash, or rebase".to_owned());
                }
            };
            if fields.next().is_some() {
                return Err("--allow-github-merge accepts exactly three fields".to_owned());
            }
            let entry = rules.entry(repository.to_owned()).or_default();
            entry.0.push(base.to_owned());
            if !entry.1.contains(&strategy) {
                entry.1.push(strategy);
            }
        }
        Some(persona::config::GitHubMergePolicy {
            repositories: rules
                .into_iter()
                .map(|(repository, (base_branches, strategies))| {
                    persona::config::GitHubMergeRepository {
                        repository,
                        base_branches,
                        strategies,
                    }
                })
                .collect(),
        })
    } else {
        existing.and_then(|profile| profile.github_merge.clone())
    };

    let github_command_update = args.clear_gh_commands
        || args.gh_command_mode.is_some()
        || !args.gh_allow.is_empty()
        || !args.gh_deny.is_empty();
    let mut github = if args.clear_github_repositories {
        let mut binding = existing
            .and_then(|profile| profile.github.clone())
            .ok_or_else(|| {
                "--clear-github-repositories requires an enrolled GitHub binding".to_owned()
            })?;
        binding.repositories.clear();
        Some(binding)
    } else if !args.github_repositories.is_empty() {
        let mut binding = existing
            .and_then(|profile| profile.github.clone())
            .ok_or_else(|| {
                "enroll the profile with `persona auth enroll` before adding GitHub repositories"
                    .to_owned()
            })?;
        binding.repositories = args
            .github_repositories
            .iter()
            .map(|repository| persona::destination::normalize_repository_pattern(repository))
            .collect::<Result<Vec<_>, _>>()?;
        Some(binding)
    } else {
        existing.and_then(|profile| profile.github.clone())
    };
    if args.clear_deny_github_repositories
        || !args.deny_github_repositories.is_empty()
        || github_command_update
    {
        let binding = github.as_mut().ok_or_else(|| {
            "enroll the profile with `persona auth enroll` before configuring GitHub repository or command rules".to_owned()
        })?;
        if args.clear_deny_github_repositories {
            binding.deny_repositories.clear();
        } else if !args.deny_github_repositories.is_empty() {
            binding.deny_repositories = args
                .deny_github_repositories
                .iter()
                .map(|repository| persona::destination::normalize_repository_pattern(repository))
                .collect::<Result<Vec<_>, _>>()?;
        }
        binding.commands = update_command_policy(
            &binding.commands,
            args.clear_gh_commands,
            args.gh_command_mode,
            args.gh_allow,
            args.gh_deny,
        )?;
    }
    let deny_destinations = if args.clear_deny_destinations {
        Vec::new()
    } else if !args.deny_destinations.is_empty() {
        args.deny_destinations
    } else {
        existing.map_or_else(Vec::new, |profile| profile.git.deny_destinations.clone())
    };
    let git_commands = update_command_policy(
        &existing
            .map(|profile| profile.git.commands.clone())
            .unwrap_or_default(),
        args.clear_git_commands,
        args.git_command_mode,
        args.git_allow,
        args.git_deny,
    )?;
    let run = update_command_policy(
        &existing
            .map(|profile| profile.run.clone())
            .unwrap_or_default(),
        args.clear_run_commands,
        args.run_command_mode,
        args.run_allow,
        args.run_deny,
    )?;
    Ok(Profile {
        name: args.name,
        github,
        ssh,
        github_merge,
        run,
        git: GitPolicy {
            author: Identity {
                name: author_name,
                email: author_email,
            },
            committer: Identity {
                name: committer_name,
                email: committer_email,
            },
            signing,
            push,
            remotes,
            deny_destinations,
            commands: git_commands,
            strict_repo_hooks: args
                .strict_repo_hooks
                .unwrap_or_else(|| existing.is_some_and(|profile| profile.git.strict_repo_hooks)),
            strict_git_filters: args
                .strict_git_filters
                .unwrap_or_else(|| existing.is_some_and(|profile| profile.git.strict_git_filters)),
            strict_merge_drivers: args.strict_merge_drivers.unwrap_or_else(|| {
                existing.is_some_and(|profile| profile.git.strict_merge_drivers)
            }),
            inherit_git_config: args
                .inherit_git_config
                .unwrap_or_else(|| existing.is_none_or(|profile| profile.git.inherit_git_config)),
            cross_profile_identity_check: args.cross_profile_identity_check.unwrap_or_else(|| {
                existing.is_none_or(|profile| profile.git.cross_profile_identity_check)
            }),
        },
    })
}

fn scope_command(command: ScopeCommands) -> Result<u8, String> {
    match command {
        ScopeCommands::List { config, json } => {
            let config = load_config(config.as_deref())?;
            if json {
                let items: Vec<serde_json::Value> = config
                    .policies()
                    .iter()
                    .map(|scope| {
                        serde_json::json!({
                            "name": scope.name,
                            "path": scope.path,
                            "profile": scope.profile,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&items)
                        .map_err(|error| format!("cannot encode scope list: {error}"))?
                );
            } else {
                for scope in config.policies() {
                    println!(
                        "{}\t{}\t{}",
                        scope.name,
                        scope.path.display(),
                        scope.profile
                    );
                }
            }
            Ok(0)
        }
        ScopeCommands::Show { name, config, json } => {
            let config = load_config(config.as_deref())?;
            let scope = config
                .policies()
                .iter()
                .find(|scope| scope.name == name)
                .ok_or_else(|| format!("scope `{name}` does not exist"))?;
            if json {
                let payload = serde_json::json!({
                    "name": scope.name,
                    "path": scope.path,
                    "profile": scope.profile,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .map_err(|error| format!("cannot encode scope details: {error}"))?
                );
            } else {
                println!("scope: {}", scope.name);
                println!("path: {}", scope.path.display());
                println!("profile: {}", scope.profile);
            }
            Ok(0)
        }
        ScopeCommands::Verify { name, config } => {
            let config = load_config(config.as_deref())?;
            let scope = config
                .policies()
                .iter()
                .find(|scope| scope.name == name)
                .ok_or_else(|| format!("scope `{name}` does not exist"))?;
            let actual = physical_scope_root(&scope.path)?;
            if actual != scope.path {
                return Err(format!(
                    "scope `{name}` resolves to a different physical worktree root"
                ));
            }
            println!("scope: {}", scope.name);
            println!("path: {}", scope.path.display());
            println!("profile: {}", scope.profile);
            Ok(0)
        }
        ScopeCommands::Add {
            name,
            path,
            profile,
            preview,
        } => {
            let (paths, update_lock, mut config) = load_private_config_for_update()?;
            let current = std::env::current_dir()
                .map_err(|error| format!("cannot determine current directory: {error}"))?;
            let root = physical_scope_root(&absolute_path(&path, &current))?;
            config
                .add_scope(name, root, &profile)
                .map_err(|error| format!("cannot add scope: {error}"))?;
            persist_private_config(&paths, &update_lock, &config, preview)
        }
        ScopeCommands::Update {
            name,
            path,
            profile,
            preview,
        } => {
            let (paths, update_lock, mut config) = load_private_config_for_update()?;
            let current = std::env::current_dir()
                .map_err(|error| format!("cannot determine current directory: {error}"))?;
            let root = physical_scope_root(&absolute_path(&path, &current))?;
            config
                .update_scope(&name, root, &profile)
                .map_err(|error| format!("cannot update scope: {error}"))?;
            persist_private_config(&paths, &update_lock, &config, preview)
        }
        ScopeCommands::Remove { name, preview } => {
            let (paths, update_lock, mut config) = load_private_config_for_update()?;
            config
                .remove_scope(&name)
                .map_err(|error| format!("cannot remove scope: {error}"))?;
            persist_private_config(&paths, &update_lock, &config, preview)
        }
    }
}

fn auth_command(command: AuthCommands) -> Result<u8, String> {
    match command {
        AuthCommands::Enroll {
            profile,
            host,
            user,
            confirm_online,
        } => {
            let paths = PersonaPaths::discover()
                .map_err(|error| format!("cannot resolve Persona paths: {error}"))?;
            paths
                .validate_private_config()
                .map_err(|error| format!("unsafe private configuration: {error}"))?;
            let config = Config::load(&paths.config_file)
                .map_err(|error| format!("cannot load private configuration: {error}"))?;
            if !config.profiles().iter().any(|item| item.name == profile) {
                return Err(format!("profile `{profile}` does not exist"));
            }
            let gh = gh_executable().ok_or_else(|| {
                "cannot find gh; set PERSONA_GH to an absolute gh executable".to_owned()
            })?;
            let selector = persona::credential::GithubSelector::discover(gh, host.clone(), paths)
                .map_err(|error| {
                format!("cannot safely select native GitHub credentials: {error}")
            })?;
            let binding = selector
                .enroll(confirm_online, &user)
                .map_err(|error| format!("GitHub enrollment failed: {error}"))?;
            let (paths, update_lock, mut config) = load_private_config_for_update()?;
            let mut updated = config
                .profiles()
                .iter()
                .find(|item| item.name == profile)
                .cloned()
                .ok_or_else(|| format!("profile `{profile}` was removed during enrollment"))?;
            updated.github = Some(binding.clone());
            config
                .update_profile(updated)
                .map_err(|error| format!("cannot bind GitHub account: {error}"))?;
            persist_private_config(&paths, &update_lock, &config, false)?;
            if !is_quiet() {
                println!(
                    "Bound stable GitHub account ID {} on {} to profile `{}`.",
                    binding.account_id, binding.host, profile
                );
                println!(
                    "The native token was not stored by Persona; only a keyed non-reversible fingerprint was saved."
                );
            }
            Ok(0)
        }
        AuthCommands::Verify { profile, json } => {
            let config = load_private_config()?;
            let profile_config = config
                .profiles()
                .iter()
                .find(|item| item.name == profile)
                .ok_or_else(|| format!("profile `{profile}` does not exist"))?;
            let binding = profile_config
                .github
                .as_ref()
                .ok_or_else(|| format!("profile `{profile}` has no GitHub enrollment binding"))?;
            let gh = gh_executable().ok_or_else(|| {
                "cannot find gh; set PERSONA_GH to an absolute gh executable".to_owned()
            })?;
            let paths = PersonaPaths::discover()
                .map_err(|error| format!("cannot resolve Persona paths: {error}"))?;
            let selector =
                persona::credential::GithubSelector::discover(gh, binding.host.clone(), paths)
                    .map_err(|error| {
                        format!("cannot safely select native GitHub credentials: {error}")
                    })?;
            match selector.matches_selected_account(binding) {
                Ok(true) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "status": "PASS",
                                "profile": profile,
                                "host": binding.host,
                                "account_id": binding.account_id,
                            }))
                            .map_err(|error| format!("cannot encode auth verification: {error}"))?
                        );
                    } else {
                        println!(
                            "Selected native credential matches bound account ID {} on {}.",
                            binding.account_id, binding.host
                        );
                    }
                    Ok(0)
                }
                Ok(false) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "status": "BLOCK",
                                "profile": profile,
                                "host": binding.host,
                                "account_id": binding.account_id,
                            }))
                            .map_err(|error| format!("cannot encode auth verification: {error}"))?
                        );
                    } else {
                        println!(
                            "BLOCK: selected native credential does not match profile `{profile}`."
                        );
                    }
                    Ok(1)
                }
                Err(error) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "status": "UNKNOWN",
                                "profile": profile,
                                "error": error.to_string(),
                            }))
                            .map_err(|error| format!("cannot encode auth verification: {error}"))?
                        );
                    } else {
                        println!("UNKNOWN: cannot verify selected native credential ({error}).");
                    }
                    Ok(1)
                }
            }
        }
        AuthCommands::Unbind { profile, preview } => {
            let (paths, update_lock, mut config) = load_private_config_for_update()?;
            let mut profile_config = config
                .profiles()
                .iter()
                .find(|item| item.name == profile)
                .cloned()
                .ok_or_else(|| format!("profile `{profile}` does not exist"))?;
            if profile_config.github.is_none() {
                return Err(format!("profile `{profile}` has no GitHub binding"));
            }
            profile_config.github = None;
            config
                .update_profile(profile_config)
                .map_err(|error| format!("cannot remove GitHub binding: {error}"))?;
            persist_private_config(&paths, &update_lock, &config, preview)
        }
    }
}

fn load_private_config() -> Result<Config, String> {
    let paths = PersonaPaths::discover()
        .map_err(|error| format!("cannot resolve Persona paths: {error}"))?;
    paths
        .validate_private_config()
        .map_err(|error| format!("unsafe private configuration: {error}"))?;
    Config::load(&paths.config_file)
        .map_err(|error| format!("cannot load private configuration: {error}"))
}

fn load_private_config_for_update() -> Result<(PersonaPaths, ConfigUpdateLock, Config), String> {
    let paths = PersonaPaths::discover()
        .map_err(|error| format!("cannot resolve Persona paths: {error}"))?;
    let update_lock = paths
        .lock_config_update()
        .map_err(|error| format!("cannot lock private configuration for update: {error}"))?;
    paths
        .validate_private_config()
        .map_err(|error| format!("unsafe private configuration: {error}"))?;
    let config = Config::load(&paths.config_file)
        .map_err(|error| format!("cannot load private configuration: {error}"))?;
    Ok((paths, update_lock, config))
}

fn persist_private_config(
    paths: &PersonaPaths,
    _update_lock: &ConfigUpdateLock,
    config: &Config,
    preview: bool,
) -> Result<u8, String> {
    paths
        .validate_private_config()
        .map_err(|error| format!("unsafe private configuration: {error}"))?;
    let contents = config
        .to_v3_toml()
        .map_err(|error| format!("cannot serialize configuration: {error}"))?;
    Config::parse(&contents).map_err(|error| format!("refusing invalid configuration: {error}"))?;
    if preview {
        if !is_quiet() {
            println!("Preview only; no configuration was written.");
        }
        print!("{contents}");
        return Ok(0);
    }
    let backup = paths
        .write_config(contents.as_bytes())
        .map_err(|error| format!("cannot atomically write configuration: {error}"))?;
    if !is_quiet() {
        println!("Updated private Persona configuration.");
        if let Some(backup) = backup {
            println!("Backup: {}", backup.display());
        }
    }
    Ok(0)
}

#[cfg(test)]
mod managed_git_argument_tests {
    use persona::git_adapter::managed_fetch_safety_arguments;
    use std::ffi::OsString;

    #[test]
    fn managed_fetch_explicitly_disables_unpreflighted_remote_side_effects() {
        assert_eq!(
            managed_fetch_safety_arguments(&[]),
            ["--no-prune", "--no-prune-tags", "--no-recurse-submodules"]
        );
        assert_eq!(
            managed_fetch_safety_arguments(&[OsString::from("--prune")]),
            ["--no-prune-tags", "--no-recurse-submodules"]
        );
    }
}
