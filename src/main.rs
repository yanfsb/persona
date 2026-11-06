use clap::{Args, Parser, Subcommand, ValueEnum};
use persona::audit::{ExecutablePaths, PushRequest, build_report, build_tag_report};
use persona::authorization::{
    Operation as AuthorizationOperation, OperationDecision, Verdict, authorize,
};
use persona::config::{Config, GitPolicy, Identity, Profile};
use persona::git::{GitClient, PushTuple};
use persona::report::{Report, Status, exit_code};
use persona::storage::PersonaPaths;
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::OnceLock;

static INVOKED_SHIM_DIRECTORY: OnceLock<PathBuf> = OnceLock::new();

const EXIT_ERROR: u8 = 2;
const MAX_PUSH_INPUT_BYTES: usize = 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "persona",
    version,
    about = "Directory-scoped identity guardrail"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Status(AuditArgs),
    Check(AuditArgs),
    Doctor(AuditArgs),
    Run(RunArgs),
    Setup(SetupArgs),
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    Profile {
        #[command(subcommand)]
        command: ProfileCommands,
    },
    Scope {
        #[command(subcommand)]
        command: ScopeCommands,
    },
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
    /// Serve Git's HTTPS credential-helper protocol for protected repositories.
    CredentialHelper {
        action: String,
    },
    Hooks {
        #[command(subcommand)]
        command: HookCommands,
    },
    Install {
        #[command(subcommand)]
        command: InstallCommands,
    },
    Shell {
        #[command(subcommand)]
        command: ShellCommands,
    },
}

#[derive(Subcommand)]
enum ShellCommands {
    Zsh {
        #[command(subcommand)]
        command: ZshCommands,
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
    Install {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, default_value = ".")]
        cwd: PathBuf,
        #[arg(long)]
        preview: bool,
    },
    Remove {
        #[arg(long, default_value = ".")]
        cwd: PathBuf,
        #[arg(long)]
        preview: bool,
    },
}

#[derive(Subcommand)]
enum InstallCommands {
    /// Show exactly which owned-bin adapters would be created.
    Preview {
        #[arg(long)]
        bin_dir: PathBuf,
    },
    /// Install adapter symlinks into an existing, user-owned bin directory.
    Apply {
        #[arg(long)]
        bin_dir: PathBuf,
    },
    /// Point existing owned adapters at this Persona executable.
    Refresh {
        #[arg(long, conflicts_with = "apply", required_unless_present = "apply")]
        preview: bool,
        #[arg(long, conflicts_with = "preview")]
        apply: bool,
    },
    /// Remove only unchanged adapters recorded in the private manifest.
    Remove {
        #[arg(long, conflicts_with = "apply", required_unless_present = "apply")]
        preview: bool,
        #[arg(long, conflicts_with = "preview")]
        apply: bool,
    },
    /// Restore a private installation backup created by an earlier mutation.
    Rollback {
        #[arg(long)]
        backup: PathBuf,
        #[arg(long, conflicts_with = "apply", required_unless_present = "apply")]
        preview: bool,
        #[arg(long, conflicts_with = "preview")]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Print a v2 migration preview without modifying the source file.
    Migrate {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, conflicts_with = "apply", required_unless_present = "apply")]
        preview: bool,
        #[arg(long, conflicts_with = "preview")]
        apply: bool,
    },
    /// Restore a backup created by Persona's private config store.
    Rollback {
        #[arg(long)]
        backup: PathBuf,
    },
}

#[derive(Subcommand)]
enum ProfileCommands {
    List {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Show {
        name: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Verify {
        name: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Add(Box<ProfileEditArgs>),
    Update(Box<ProfileEditArgs>),
    Remove {
        name: String,
        #[arg(long)]
        preview: bool,
    },
}

#[derive(Subcommand)]
enum ScopeCommands {
    List {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Show {
        name: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Verify {
        name: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Add {
        name: String,
        path: PathBuf,
        #[arg(long)]
        profile: String,
        #[arg(long)]
        preview: bool,
    },
    Update {
        name: String,
        path: PathBuf,
        #[arg(long)]
        profile: String,
        #[arg(long)]
        preview: bool,
    },
    Remove {
        name: String,
        #[arg(long)]
        preview: bool,
    },
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Explicitly contact GitHub to bind the currently selected native gh account.
    Enroll {
        #[arg(long)]
        profile: String,
        #[arg(long, default_value = "github.com")]
        host: String,
        #[arg(long, required = true)]
        user: String,
        #[arg(long, required = true)]
        confirm_online: bool,
    },
    /// Compare the local gh token selector to the saved HMAC binding (no API call).
    Verify {
        #[arg(long)]
        profile: String,
    },
    Unbind {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        preview: bool,
    },
}

#[derive(Args)]
struct RunArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value = ".")]
    cwd: PathBuf,
    #[arg(required = true, num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
    argv: Vec<OsString>,
}

#[derive(Args)]
struct ProfileEditArgs {
    name: String,
    #[arg(long)]
    author_name: String,
    #[arg(long)]
    author_email: String,
    #[arg(long)]
    committer_name: String,
    #[arg(long)]
    committer_email: String,
    #[arg(long)]
    signing_fingerprint: Option<String>,
    #[arg(long)]
    public_key: Option<PathBuf>,
    #[arg(long, value_parser = ["openpgp", "ssh"])]
    signing_format: Option<String>,
    #[arg(long)]
    push_remote: Option<String>,
    #[arg(long)]
    ssh_host: Option<String>,
    #[arg(long)]
    ssh_user: Option<String>,
    #[arg(long)]
    ssh_port: Option<u16>,
    #[arg(long)]
    ssh_fingerprint: Option<String>,
    #[arg(long)]
    ssh_public_key: Option<PathBuf>,
    #[arg(long)]
    ssh_identity_file: Option<PathBuf>,
    #[arg(long)]
    ssh_agent_socket: Option<PathBuf>,
    #[arg(long)]
    ssh_known_hosts_file: Option<PathBuf>,
    #[arg(long)]
    clear_ssh: bool,
    #[arg(long = "push-destination")]
    push_destinations: Vec<String>,
    #[arg(long = "github-repo")]
    github_repositories: Vec<String>,
    /// Exact profile-bound remote: NAME|FETCH_URLS|PUSH_URLS (comma-separated, '-' for none).
    #[arg(long = "remote-policy", value_name = "NAME|FETCH_URLS|PUSH_URLS")]
    remote_policies: Vec<String>,
    #[arg(long, conflicts_with = "remote_policies")]
    clear_remote_policies: bool,
    /// Explicit server-side merge grant: OWNER/REPO|BASE_BRANCH|merge|squash|rebase.
    #[arg(long = "allow-github-merge", value_name = "REPO|BASE|STRATEGY")]
    github_merge_rules: Vec<String>,
    #[arg(long, conflicts_with = "github_merge_rules")]
    clear_github_merges: bool,
    #[arg(long, conflicts_with = "github_repositories")]
    clear_github_repositories: bool,
    #[arg(long, conflicts_with = "strict_authors")]
    preserve_authors: bool,
    #[arg(long, conflicts_with = "preserve_authors")]
    strict_authors: bool,
    #[arg(long, action = clap::ArgAction::Set)]
    allow_initial_push: Option<bool>,
    #[arg(long, action = clap::ArgAction::Set)]
    allow_fast_forward: Option<bool>,
    #[arg(long, action = clap::ArgAction::Set)]
    allow_annotated_tags: Option<bool>,
    #[arg(long, action = clap::ArgAction::Set)]
    allow_lightweight_tags: Option<bool>,
    #[arg(long, action = clap::ArgAction::Set)]
    allow_branch_deletion: Option<bool>,
    #[arg(long, action = clap::ArgAction::Set)]
    allow_tag_deletion: Option<bool>,
    #[arg(long, action = clap::ArgAction::Set)]
    allow_force_with_lease: Option<bool>,
    #[arg(
        long = "upstream-baseline",
        conflicts_with = "clear_upstream_baselines"
    )]
    upstream_baselines: Vec<String>,
    #[arg(long, conflicts_with = "upstream_baselines")]
    clear_upstream_baselines: bool,
    #[arg(long)]
    preview: bool,
}

#[derive(Args)]
struct SetupArgs {
    #[arg(long, default_value = "default")]
    profile: String,
    #[arg(long, default_value = "default")]
    scope_name: String,
    #[arg(long, default_value = ".")]
    scope: PathBuf,
    #[arg(long)]
    author_name: Option<String>,
    #[arg(long)]
    author_email: Option<String>,
    #[arg(long)]
    committer_name: Option<String>,
    #[arg(long)]
    committer_email: Option<String>,
}

#[derive(Args)]
struct AuditArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value = ".")]
    cwd: PathBuf,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    /// Alias for --format json.
    #[arg(long, conflicts_with = "format")]
    json: bool,
    #[arg(long, conflicts_with_all = ["json", "format"])]
    verbose: bool,
    #[arg(long, value_enum)]
    operation: Option<Operation>,
    #[arg(long)]
    remote: Option<String>,
    #[arg(long, conflicts_with = "destination_stdin")]
    destination: Option<String>,
    #[arg(long, hide = true, conflicts_with = "destination")]
    destination_stdin: bool,
    #[arg(long, hide = true)]
    primary_handoff: Option<PathBuf>,
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

fn main() -> ExitCode {
    if let Some(exit) = managed_shim_dispatch() {
        return exit;
    }
    let cli = Cli::parse();
    let result = (|| -> Result<u8, String> {
        match cli.command {
            None => {
                let config = resolve_config_path(None)?;
                show_status(
                    &config,
                    Path::new("."),
                    OutputFormat::Text,
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
                    output_format(&args),
                    args.verbose,
                    None,
                    None,
                    false,
                )
            }
            Some(Commands::Check(args)) => {
                let format = output_format(&args);
                let operation = args.operation.unwrap_or(Operation::Status);
                match operation {
                    Operation::Status if args.remote.is_some() || args.destination.is_some() || args.destination_stdin || args.primary_handoff.is_some() || args.tag.is_some() || args.online_verified => {
                        Err("--remote/--destination require --operation push; --tag requires --operation tag".to_owned())
                    }
                    Operation::Status => {
                        let config = resolve_config_path(args.config.as_deref())?;
                        show_status(&config, &args.cwd, format, args.verbose, None, None, false)
                    }
                    Operation::Push if args.tag.is_some() => Err("--tag cannot be combined with --operation push".to_owned()),
                    Operation::Push => {
                        let remote = args.remote.ok_or_else(|| {
                            "--remote is required with --operation push".to_owned()
                        })?;
                        let (destination, tuples) = if args.destination_stdin {
                            read_push_request_stdin()?
                        } else {
                            let destination = args.destination.ok_or_else(|| {
                                "--destination or --destination-stdin is required with --operation push".to_owned()
                            })?;
                            (destination, read_push_tuples()?)
                        };
                        let config = resolve_config_path(args.config.as_deref())?;
                        let current = std::env::current_dir().map_err(|_| "cannot resolve check working directory".to_owned())?;
                        let config = absolute_path(&config, &current);
                        let directory = absolute_path(&args.cwd, &current);
                        let mut request = PushRequest { remote, destination, tuples, leases: Vec::new() };
                        let primary_handoff = args.primary_handoff;
                        let handoff_binding = primary_handoff.as_deref().map(|path| {
                            validate_primary_handoff(path, &config, &directory, &mut request)
                        }).transpose()?.flatten();
                        let exit = show_status(&config, &directory, format, args.verbose, Some(request), handoff_binding, args.online_verified)?;
                        if exit == 0 {
                            if let Some(path) = primary_handoff {
                                consume_primary_handoff(&path)?;
                            }
                        }
                        Ok(exit)
                    }
                    Operation::Tag if args.remote.is_some() || args.destination.is_some() || args.destination_stdin || args.primary_handoff.is_some() || args.online_verified => Err("--remote/--destination cannot be combined with --operation tag".to_owned()),
                    Operation::Tag => {
                        let tag = args.tag.ok_or_else(|| "--tag is required with --operation tag".to_owned())?;
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
                    output_format(&args),
                    true,
                    None,
                    None,
                    false,
                )
            }
            Some(Commands::Run(args)) => run_launcher(args),
            Some(Commands::Setup(args)) => setup(args),
            Some(Commands::CredentialHelper { action }) => git_credential_helper(&action),
            Some(Commands::Hooks { command }) => hooks_command(command),
            Some(Commands::Install { command }) => installer_command(command),
            Some(Commands::Shell { command }) => shell_command(command),
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
            eprintln!("error: {message}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn managed_shim_dispatch() -> Option<ExitCode> {
    let argv0 = std::env::args_os().next()?;
    let name = Path::new(&argv0).file_name()?.to_str()?;
    if matches!(name, "git" | "gh" | "ssh" | "git-credential-persona")
        && std::env::var_os("PERSONA_SHIM_DIR").is_none()
    {
        if let Some(directory) = infer_shim_directory(&argv0) {
            let _ = INVOKED_SHIM_DIRECTORY.set(directory);
        }
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

fn persona_dispatcher_executable() -> Result<PathBuf, String> {
    let path = match std::env::var_os("PERSONA_INSTALL_EXECUTABLE") {
        Some(path) => PathBuf::from(path),
        None => {
            std::env::current_exe().map_err(|_| "cannot resolve Persona executable".to_owned())?
        }
    };
    if !path.is_absolute() || !path.is_file() {
        return Err("Persona dispatcher executable is not an absolute existing file".to_owned());
    }
    std::fs::canonicalize(path).map_err(|_| "cannot canonicalize Persona dispatcher".to_owned())
}

fn infer_shim_directory(argv0: &OsStr) -> Option<PathBuf> {
    let current = persona_dispatcher_executable().ok()?;
    let invoked = PathBuf::from(argv0);
    let candidates = if invoked.components().count() > 1 || invoked.is_absolute() {
        vec![invoked]
    } else {
        std::env::split_paths(&std::env::var_os("PATH")?)
            .map(|directory| directory.join(&invoked))
            .collect()
    };
    candidates.into_iter().find_map(|candidate| {
        (std::fs::canonicalize(&candidate).ok()? == current)
            .then(|| std::fs::canonicalize(candidate.parent()?).ok())
            .flatten()
    })
}

fn validate_managed_shim_directory() -> Result<PathBuf, String> {
    let path = std::env::var_os("PERSONA_SHIM_DIR")
        .map(PathBuf::from)
        .or_else(|| INVOKED_SHIM_DIRECTORY.get().cloned())
        .filter(|path| path.is_absolute())
        .ok_or_else(|| "managed Persona shim directory is unavailable".to_owned())?;
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|_| "managed Persona shim directory is missing".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("managed Persona shim directory is not a real directory".to_owned());
    }
    #[cfg(unix)]
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
        return Err(
            "managed Persona shim directory has unsafe ownership or permissions".to_owned(),
        );
    }
    let directory = std::fs::canonicalize(&path)
        .map_err(|_| "managed Persona shim directory cannot be canonicalized".to_owned())?;
    let executable = persona_dispatcher_executable()?;
    for name in ["git", "gh", "ssh", "git-credential-persona"] {
        let shim = directory.join(name);
        let metadata = std::fs::symlink_metadata(&shim)
            .map_err(|_| format!("managed Persona shim is missing: {name}"))?;
        if !metadata.file_type().is_symlink()
            || std::fs::canonicalize(&shim).ok().as_ref() != Some(&executable)
        {
            return Err(format!("managed Persona shim target is unexpected: {name}"));
        }
    }
    Ok(directory)
}

fn run_managed_gh() -> Result<u8, String> {
    let shim_directory = validate_managed_shim_directory()?;
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let request = persona::gh_adapter::parse(&arguments)?;
    let native_gh = gh_executable()
        .ok_or_else(|| "an absolute native GitHub CLI executable is required".to_owned())?;
    if !native_gh.is_absolute() || !native_gh.is_file() {
        return Err("native GitHub CLI executable is unavailable".to_owned());
    }
    for variable in [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "GH_HOST",
        "GH_CONFIG_DIR",
        "GH_REPO",
    ] {
        if std::env::var_os(variable).is_some() {
            return Err(format!(
                "inherited {variable} override is not permitted for managed gh"
            ));
        }
    }
    for variable in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
    ] {
        if std::env::var_os(variable).is_some() {
            return Err(format!(
                "inherited {variable} override makes the GitHub operation ambiguous"
            ));
        }
    }

    let cwd = std::env::current_dir()
        .map_err(|_| "cannot resolve the GitHub operation directory".to_owned())?;
    let config_path = match std::env::var_os("PERSONA_CONFIG_PATH") {
        Some(path) => PathBuf::from(path),
        None => resolve_config_path(None)?,
    };
    let config_path = absolute_path(&config_path, &cwd);
    let config = Config::load(&config_path).map_err(|error| format!("{error:?}"))?;
    let target_directory = request.clone_directory.as_ref().map(|clone_directory| {
        if clone_directory.is_absolute() {
            clone_directory.clone()
        } else {
            cwd.join(clone_directory)
        }
    });
    if target_directory
        .as_ref()
        .is_some_and(|target| target.exists() || std::fs::symlink_metadata(target).is_ok())
    {
        return Err("gh repo clone target already exists".to_owned());
    }
    let selected_scope = persona::context::resolve_operation_context(
        &cwd,
        target_directory.as_deref(),
        &config.scopes(),
    )
    .map_err(|_| "cannot resolve the physical GitHub operation scope".to_owned())?
    .ok_or_else(|| {
        if target_directory.is_some() {
            "gh repo clone target is outside every configured Persona scope".to_owned()
        } else {
            "gh is blocked outside a configured Persona scope".to_owned()
        }
    })?;
    let policy = config
        .policies()
        .iter()
        .find(|policy| policy.name == selected_scope.name)
        .ok_or_else(|| "selected GitHub scope policy is unavailable".to_owned())?;
    let profile = config
        .profiles()
        .iter()
        .find(|profile| profile.name == policy.profile)
        .ok_or_else(|| "selected GitHub profile is unavailable".to_owned())?;
    let binding = profile
        .github
        .as_ref()
        .ok_or_else(|| "selected profile has no enrolled GitHub account binding".to_owned())?;
    if binding.host != "github.com" {
        return Err("managed gh supports only the explicitly bound github.com host".to_owned());
    }

    let allowed_repositories = binding
        .repositories
        .iter()
        .map(|repository| persona::gh_adapter::normalize_repository(repository))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    if allowed_repositories.is_empty()
        || request
            .repositories
            .iter()
            .any(|repository| !allowed_repositories.contains(repository))
    {
        return Err(
            "GitHub repository target is not in the selected profile's explicit allowlist"
                .to_owned(),
        );
    }
    let audited_release_tag_oid = if let Some(release) = &request.release {
        if !profile.github.as_ref().is_some_and(|binding| {
            binding.repositories.iter().any(|repository| {
                persona::gh_adapter::normalize_repository(repository)
                    .is_ok_and(|value| value == release.repository)
            })
        }) {
            return Err("release repository is not in the enrolled profile allowlist".to_owned());
        }
        let push = profile.git.push.as_ref().ok_or_else(|| {
            "release creation requires an explicit signed-tag publication policy".to_owned()
        })?;
        if !push.allow_annotated_tags || profile.git.signing.is_none() {
            return Err(
                "release creation requires explicit annotated-tag publication and signing policy"
                    .to_owned(),
            );
        }
        let has_destination = configured_push_destinations(profile, &push.remote)
            .unwrap_or(&[])
            .iter()
            .any(|destination| {
                persona::gh_adapter::repository_from_destination(destination).as_deref()
                    == Some(release.repository.as_str())
            });
        if !has_destination {
            return Err(
                "release repository has no matching profile-bound publication destination"
                    .to_owned(),
            );
        }
        let executables = ExecutablePaths {
            git: git_executable(),
            gpg: gpg_executable(),
            ssh_keygen: ssh_keygen_executable(),
        };
        let (tag_report, _) = build_tag_report(&config, &cwd, &release.tag, &executables)?;
        let tag_decision = authorize(
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
            tag_report.findings,
        );
        if !tag_decision.is_allowed() {
            return Err("release tag failed local profile signature and scope audit".to_owned());
        }
        let git = GitClient::new(git_executable(), persona::git::safe_environment());
        let reference = format!("refs/tags/{}", release.tag);
        let oid = git
            .resolve_object_oid(&cwd, &reference)
            .map_err(|_| "release tag object is unavailable".to_owned())?;
        if git
            .object_type(&cwd, &oid)
            .map_err(|_| "cannot inspect release tag object".to_owned())?
            != "tag"
        {
            return Err(
                "release creation accepts only an existing signed annotated tag".to_owned(),
            );
        }
        let commit_oid = git.tag_commit_target_oid(&cwd, &oid).map_err(|_| {
            "release tag does not resolve through a valid annotated-tag chain to a commit"
                .to_owned()
        })?;
        Some((oid, commit_oid))
    } else {
        None
    };
    let checkout_plan = if let Some(checkout) = &request.checkout {
        let git = GitClient::new(git_executable(), persona::git::safe_environment());
        let root = git
            .checkout_root(&cwd)
            .map_err(|_| "PR checkout requires an existing managed Git worktree".to_owned())?;
        if !git
            .worktree_is_clean(&root)
            .map_err(|_| "cannot verify clean worktree before PR checkout".to_owned())?
        {
            return Err("PR checkout requires a clean worktree".to_owned());
        }
        let branch = checkout
            .branch
            .clone()
            .unwrap_or_else(|| format!("pr-{}", checkout.pull_number));
        let branch_ref = format!("refs/heads/{branch}");
        if !git
            .valid_refname(&root, &branch_ref)
            .map_err(|_| "cannot validate PR checkout branch".to_owned())?
        {
            return Err("PR checkout branch name is invalid".to_owned());
        }
        if git
            .optional_commit_oid(&root, &branch_ref)
            .map_err(|_| "cannot inspect existing PR checkout branch".to_owned())?
            .is_some()
        {
            return Err("PR checkout refuses to overwrite an existing local branch".to_owned());
        }
        let candidates = profile
            .git
            .remotes
            .iter()
            .filter(|remote| {
                remote.fetch_destinations.iter().any(|destination| {
                    persona::gh_adapter::repository_from_destination(destination).as_deref()
                        == Some(checkout.repository.as_str())
                })
            })
            .map(|remote| remote.name.clone())
            .collect::<Vec<_>>();
        let remote = if candidates.is_empty() && profile.git.remotes.is_empty() {
            profile
                .git
                .push
                .as_ref()
                .filter(|push| {
                    push.destinations.iter().any(|destination| {
                        persona::gh_adapter::repository_from_destination(destination).as_deref()
                            == Some(checkout.repository.as_str())
                    })
                })
                .map(|push| vec![push.remote.clone()])
                .unwrap_or_default()
        } else {
            candidates
        };
        if remote.len() != 1 {
            return Err(
                "PR checkout requires exactly one profile-bound fetch remote for the repository"
                    .to_owned(),
            );
        }
        Some((root, remote[0].clone(), branch))
    } else {
        None
    };
    let merge_rule = if let Some(merge) = &request.merge {
        let policy = profile.github_merge.as_ref().ok_or_else(|| {
            "server-side merge requires an explicit profile GitHub merge policy".to_owned()
        })?;
        let rule = policy
            .repositories
            .iter()
            .find(|rule| rule.repository == merge.repository)
            .ok_or_else(|| {
                "server-side merge repository is not authorized by this profile".to_owned()
            })?;
        if !rule.strategies.contains(&merge.strategy) {
            return Err("server-side merge strategy is not authorized by this profile".to_owned());
        }
        Some(rule)
    } else {
        None
    };
    let _operation_kind = request.operation;

    let paths =
        PersonaPaths::discover().map_err(|_| "cannot resolve private Persona state".to_owned())?;
    let selector = persona::credential::GithubSelector::discover(
        native_gh.clone(),
        binding.host.clone(),
        paths,
    )
    .map_err(|_| "cannot safely resolve the native GitHub credential selector".to_owned())?;
    let selected_token = selector
        .token_for_binding(binding)
        .map_err(|_| "cannot safely verify the selected native GitHub account".to_owned())?
        .ok_or_else(|| {
            "selected native GitHub credential does not match the enrolled account binding"
                .to_owned()
        })?;
    if let (Some(merge), Some(rule)) = (&request.merge, merge_rule) {
        let (base_branch, expected_head) = selector
            .pull_request_merge_context(&selected_token, &merge.repository, merge.pull_number)
            .map_err(|_| "cannot safely verify the pull request base and head".to_owned())?;
        if !rule.base_branches.contains(&base_branch) {
            return Err(
                "pull request base branch is not authorized for server-side merging".to_owned(),
            );
        }
        let merge_sha = selector
            .merge_pull_request(
                &selected_token,
                &merge.repository,
                merge.pull_number,
                merge.strategy,
                &expected_head,
            )
            .map_err(|_| "GitHub refused the policy-bound server-side merge".to_owned())?;
        println!(
            "Merged {}#{} using {:?}; GitHub created server-side commit {merge_sha} (not locally signed by Persona).",
            merge.repository, merge.pull_number, merge.strategy
        );
        return Ok(0);
    }
    if let (Some(checkout), Some((root, remote, branch))) =
        (&request.checkout, checkout_plan.as_ref())
    {
        let (expected_head, _head_ref) = selector
            .pull_request_checkout_context(
                &selected_token,
                &checkout.repository,
                checkout.pull_number,
            )
            .map_err(|_| "cannot retrieve allowlisted pull request head metadata".to_owned())?;
        let shim_git = shim_directory.join("git");
        let home_dir = std::env::var_os("HOME")
            .ok_or_else(|| "HOME is required for managed Git".to_owned())?;
        let managed_path = std::env::join_paths([
            shim_directory.clone(),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
        ])
        .map_err(|_| "cannot construct managed Git path".to_owned())?;
        let run_git = |args: &[&str]| -> Result<std::process::ExitStatus, String> {
            let mut command = Command::new(&shim_git);
            command
                .args(args)
                .current_dir(root)
                .env_clear()
                .env("HOME", &home_dir)
                .env("PATH", &managed_path)
                .env("PERSONA_SHIM_DIR", &shim_directory)
                .env("PERSONA_GH", &native_gh)
                .env("PERSONA_GIT", git_executable())
                .env("PERSONA_GH_AUTHORIZED", "1")
                .env("PERSONA_CONFIG_PATH", &config_path)
                .env("GH_PROMPT_DISABLED", "1")
                .env("GIT_TERMINAL_PROMPT", "0")
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
            for variable in ["XDG_CONFIG_HOME", "XDG_STATE_HOME"] {
                if let Some(value) = std::env::var_os(variable) {
                    command.env(variable, value);
                }
            }
            command
                .status()
                .map_err(|_| "cannot start managed Git for PR checkout".to_owned())
        };
        let pr_ref = format!("refs/pull/{}/head", checkout.pull_number);
        let fetch_args = ["fetch", remote.as_str(), pr_ref.as_str()];
        let fetch_status = run_git(&fetch_args)?;
        if !fetch_status.success() {
            return Ok(status_exit_code(fetch_status));
        }
        let git = GitClient::new(git_executable(), persona::git::safe_environment());
        let fetched_head = git
            .resolve_commit_oid(root, "FETCH_HEAD")
            .map_err(|_| "fetched PR head is not a complete local commit".to_owned())?;
        if fetched_head != expected_head {
            return Err("pull request head changed between GitHub metadata and managed fetch; no branch was created".to_owned());
        }
        let switch_args = ["switch", "--create", branch.as_str(), fetched_head.as_str()];
        let switch_status = run_git(&switch_args)?;
        if !switch_status.success() {
            return Ok(status_exit_code(switch_status));
        }
        println!(
            "Checked out {}#{} as local branch {branch} at {fetched_head}.",
            checkout.repository, checkout.pull_number
        );
        return Ok(0);
    }
    if let Some(review) = &request.review {
        let review_id = selector
            .submit_pull_request_review(
                &selected_token,
                &review.repository,
                review.pull_number,
                review.event,
                review.body.as_deref(),
            )
            .map_err(|_| "GitHub refused the typed pull-request review".to_owned())?;
        println!(
            "Submitted {:?} review {review_id} for {}#{}.",
            review.event, review.repository, review.pull_number
        );
        return Ok(0);
    }
    if let (Some(release), Some((local_tag_oid, local_tag_commit_oid))) =
        (&request.release, audited_release_tag_oid.as_ref())
    {
        let remote_tag_oid = selector.tag_ref_oid(&selected_token, &release.repository, &release.tag)
            .map_err(|_| "release tag is not present as an annotated tag on the allowlisted GitHub repository".to_owned())?;
        if remote_tag_oid != *local_tag_oid {
            return Err(
                "remote GitHub tag object differs from the locally audited signed tag".to_owned(),
            );
        }
        let release_id = selector
            .create_release(&selected_token, release, local_tag_commit_oid)
            .map_err(|_| "GitHub refused the audited-tag release creation request".to_owned())?;
        let after_tag_oid = selector
            .tag_ref_oid(&selected_token, &release.repository, &release.tag)
            .map_err(|_| {
                "release was created but post-publication tag verification failed".to_owned()
            })?;
        if after_tag_oid != *local_tag_oid {
            return Err("release was created while its remote tag changed concurrently; inspect GitHub before proceeding".to_owned());
        }
        println!(
            "Created GitHub release {release_id} for existing locally audited signed tag {}:{}; no tag was created or pushed by Persona.",
            release.repository, release.tag
        );
        return Ok(0);
    }
    let token = std::str::from_utf8(selected_token.expose())
        .map_err(|_| "selected native GitHub credential is not valid UTF-8".to_owned())?;

    let mut path_entries = vec![shim_directory.clone()];
    if let Some(path) = std::env::var_os("PATH") {
        path_entries.extend(std::env::split_paths(&path));
    }
    let managed_path = std::env::join_paths(path_entries)
        .map_err(|error| format!("cannot construct managed gh PATH: {error}"))?;

    let mut command = Command::new(&native_gh);
    command
        .args(&request.arguments)
        .current_dir(&cwd)
        .env_clear()
        .env("GH_PROMPT_DISABLED", "1")
        .env("GH_NO_UPDATE_NOTIFIER", "1")
        .env("GH_PAGER", "cat")
        .env("GH_TOKEN", token)
        .env("PATH", managed_path)
        .env("PERSONA_SHIM_DIR", &shim_directory)
        .env("PERSONA_GH_AUTHORIZED", "1")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for variable in [
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_STATE_HOME",
        "PERSONA_CONFIG_PATH",
    ] {
        if let Some(value) = std::env::var_os(variable) {
            command.env(variable, value);
        }
    }
    command.env("PERSONA_GH", &native_gh);
    command.env("PERSONA_GIT", git_executable());
    let status = command
        .status()
        .map_err(|_| "cannot launch the validated native GitHub CLI operation".to_owned())?;
    Ok(status_exit_code(status))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedGitOperation {
    Status,
    Diff,
    Show,
    Add,
    Restore,
    Rm,
    RemoteAdd,
    Init,
    Commit,
    Log,
    BranchList,
    BranchCreate,
    Switch,
    Checkout,
    Merge,
    CherryPick,
    Rebase,
    WorktreeList,
    WorktreeAdd,
    TagList,
    SignedTag,
    LightweightTag,
    Fetch,
    Pull,
    Push,
    Clone,
    RevParse,
}

impl ManagedGitOperation {
    fn name(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Diff => "diff",
            Self::Show => "show",
            Self::Add => "add",
            Self::Restore => "restore",
            Self::Rm => "rm",
            Self::RemoteAdd => "remote",
            Self::Init => "init",
            Self::Commit => "commit",
            Self::Log => "log",
            Self::BranchList | Self::BranchCreate => "branch",
            Self::Switch => "switch",
            Self::Checkout => "checkout",
            Self::Merge => "merge",
            Self::CherryPick => "cherry-pick",
            Self::Rebase => "rebase",
            Self::WorktreeList | Self::WorktreeAdd => "worktree",
            Self::TagList | Self::SignedTag | Self::LightweightTag => "tag",
            Self::Fetch => "fetch",
            Self::Pull => "pull",
            Self::Push => "push",
            Self::Clone => "clone",
            Self::RevParse => "rev-parse",
        }
    }
}

fn resolve_managed_git_operation(arguments: &[OsString]) -> Result<ManagedGitOperation, String> {
    let command = arguments
        .first()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "missing Git subcommand".to_owned())?;
    let args = &arguments[1..];
    let operation = match command {
        "status" if safe_status_arguments(args) => ManagedGitOperation::Status,
        "diff" if safe_diff_arguments(args) => ManagedGitOperation::Diff,
        "show" if safe_show_arguments(args) => ManagedGitOperation::Show,
        "add" if safe_add_arguments(args) => ManagedGitOperation::Add,
        "restore" if safe_restore_arguments(args) => ManagedGitOperation::Restore,
        "rm" if safe_rm_arguments(args) => ManagedGitOperation::Rm,
        "remote" if safe_remote_add_arguments(args) => ManagedGitOperation::RemoteAdd,
        "init"
            if args
                .iter()
                .all(|argument| matches!(argument.to_str(), Some("-q" | "--quiet"))) =>
        {
            ManagedGitOperation::Init
        }
        "commit" if safe_commit_arguments(args) => ManagedGitOperation::Commit,
        "log" if safe_log_arguments(args) => ManagedGitOperation::Log,
        "branch" if args == [OsString::from("--list")] => ManagedGitOperation::BranchList,
        "branch" if safe_branch_create_arguments(args) => ManagedGitOperation::BranchCreate,
        "switch" if safe_switch_arguments(args) => ManagedGitOperation::Switch,
        "checkout" if safe_checkout_arguments(args) => ManagedGitOperation::Checkout,
        "merge" if safe_merge_arguments(args) => ManagedGitOperation::Merge,
        "cherry-pick" if safe_cherry_pick_arguments(args) => ManagedGitOperation::CherryPick,
        "rebase" if safe_rebase_arguments(args) => ManagedGitOperation::Rebase,
        "worktree" if args == [OsString::from("list"), OsString::from("--porcelain")] => {
            ManagedGitOperation::WorktreeList
        }
        "worktree" if safe_worktree_add_arguments(args) => ManagedGitOperation::WorktreeAdd,
        "tag" if args == [OsString::from("--list")] => ManagedGitOperation::TagList,
        "tag" if safe_signed_tag_arguments(args) => ManagedGitOperation::SignedTag,
        "tag" if safe_lightweight_tag_arguments(args) => ManagedGitOperation::LightweightTag,
        "fetch" if safe_fetch_arguments(args) => ManagedGitOperation::Fetch,
        "pull" if safe_fetch_arguments(args) => ManagedGitOperation::Pull,
        "push" if safe_push_arguments(args) => ManagedGitOperation::Push,
        "clone" if safe_clone_arguments(args) => ManagedGitOperation::Clone,
        "rev-parse"
            if args.iter().all(|argument| {
                matches!(
                    argument.to_str(),
                    Some("--show-toplevel" | "--show-prefix" | "--is-inside-work-tree")
                )
            }) =>
        {
            ManagedGitOperation::RevParse
        }
        "submodule" => {
            return Err("submodule operations are blocked by the managed Git adapter".to_owned());
        }
        _ => {
            return Err(
                "Git subcommand or argument form is outside the currently supported safe grammar"
                    .to_owned(),
            );
        }
    };
    Ok(operation)
}

fn run_managed_git() -> Result<u8, String> {
    let current_directory = std::env::current_dir()
        .map_err(|error| format!("cannot determine Git working directory: {error}"))?;
    let invocation = persona::git_command::GitInvocation::parse(std::env::args_os().skip(1))
        .map_err(|error| match error {
            persona::git_command::ParseError::MissingDirectory => {
                "Git -C requires a directory".to_owned()
            }
            persona::git_command::ParseError::UnsupportedGlobalOption => {
                "unsupported Git global option; configuration and repository redirects are blocked"
                    .to_owned()
            }
            persona::git_command::ParseError::MissingSubcommand => {
                "missing Git subcommand".to_owned()
            }
        })?;
    let directory = invocation
        .resolve_directory(&current_directory)
        .map_err(|_| "Git -C directory is missing or inaccessible".to_owned())?;
    let operation = resolve_managed_git_operation(&invocation.arguments)?;
    let command = operation.name();
    let global_arguments = invocation.global_arguments;
    let mut git_arguments = invocation.arguments;

    let config_path = match std::env::var_os("PERSONA_CONFIG_PATH") {
        Some(path) => {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err("PERSONA_CONFIG_PATH must be absolute for managed Git".to_owned());
            }
            path
        }
        None => resolve_config_path(None)?,
    };
    let config =
        Config::load(&config_path).map_err(|error| format!("cannot load policy: {error:?}"))?;
    let config_digest_at_load = sha256_file(&config_path)?;
    let native_git = git_executable();
    if !native_git.is_absolute() || !native_git.is_file() {
        return Err("Persona requires an absolute, existing native Git executable".to_owned());
    }
    let home =
        tempfile::tempdir().map_err(|error| format!("cannot create isolated Git HOME: {error}"))?;
    let preflight_environment = vec![
        (OsString::from("HOME"), home.path().as_os_str().to_owned()),
        (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
        (
            OsString::from("GIT_CONFIG_SYSTEM"),
            OsString::from("/dev/null"),
        ),
        (
            OsString::from("GIT_CONFIG_GLOBAL"),
            OsString::from("/dev/null"),
        ),
        (OsString::from("GIT_TERMINAL_PROMPT"), OsString::from("0")),
    ];
    let git_client = GitClient::new(native_git.clone(), preflight_environment.clone());
    let worktree_add = operation == ManagedGitOperation::WorktreeAdd;
    let checkout_mutation = matches!(
        operation,
        ManagedGitOperation::WorktreeAdd
            | ManagedGitOperation::Restore
            | ManagedGitOperation::Switch
            | ManagedGitOperation::Checkout
            | ManagedGitOperation::Merge
            | ManagedGitOperation::CherryPick
            | ManagedGitOperation::Rebase
    );
    if (operation == ManagedGitOperation::Add || checkout_mutation)
        && git_client
            .has_external_filter_config(&directory)
            .map_err(|_| {
                "cannot inspect Git filter configuration before local mutation".to_owned()
            })?
    {
        return Err(
            "local mutation is blocked because repository Git filters may execute external programs"
                .to_owned(),
        );
    }
    if checkout_mutation {
        if git_client
            .has_custom_hooks_path(&directory)
            .map_err(|_| "cannot inspect hooks configuration before checkout mutation".to_owned())?
        {
            return Err(
                "checkout mutation is blocked while a custom hooksPath is configured".to_owned(),
            );
        }
        let hooks = git_client
            .git_path(&directory, "hooks")
            .map_err(|_| "cannot resolve repository hooks before checkout mutation".to_owned())?;
        let has_active_hook = std::fs::read_dir(hooks)
            .map_err(|_| "cannot inspect repository hooks before checkout mutation".to_owned())?
            .filter_map(Result::ok)
            .any(|entry| {
                let name = entry.file_name();
                !name.to_string_lossy().ends_with(".sample") && name != "pre-push"
            });
        if has_active_hook {
            return Err(
                "checkout mutation is blocked while repository hooks are installed".to_owned(),
            );
        }
    }
    let target_operation = matches!(
        operation,
        ManagedGitOperation::Clone | ManagedGitOperation::WorktreeAdd
    );
    let selection_directory = if target_operation {
        let target_index = if operation == ManagedGitOperation::Clone {
            2
        } else {
            3
        };
        let target = git_arguments
            .get(target_index)
            .and_then(|value| value.to_str())
            .ok_or_else(|| "Git operation requires an explicit destination directory".to_owned())?;
        let target = PathBuf::from(target);
        if target.is_absolute() {
            target
        } else {
            directory.join(target)
        }
    } else {
        match git_client.checkout_root(&directory) {
            Ok(root) => root,
            Err(_) if operation == ManagedGitOperation::Init => directory.clone(),
            Err(_) => {
                return Err("Git command requires a working tree in a managed scope".to_owned());
            }
        }
    };
    let selected_scope = if target_operation {
        persona::context::resolve_target_context(&selection_directory, &config.scopes())
    } else {
        persona::context::resolve_context(&selection_directory, &config.scopes())
    }
    .map_err(|_| "cannot resolve managed Git scope".to_owned())?
    .ok_or_else(|| "no managed Persona scope applies to this Git directory".to_owned())?;
    let selected_policy = config
        .policies()
        .iter()
        .find(|policy| policy.name == selected_scope.name)
        .ok_or_else(|| "no managed Git policy applies to this directory".to_owned())?;
    let profile = config
        .profiles()
        .iter()
        .find(|profile| profile.name == selected_policy.profile)
        .ok_or_else(|| "managed Git profile is unavailable".to_owned())?;
    let gh_parent_authorized = match std::env::var_os("PERSONA_GH_AUTHORIZED") {
        Some(marker) if marker == "1" => {
            if [
                "GITHUB_TOKEN",
                "GH_ENTERPRISE_TOKEN",
                "GITHUB_ENTERPRISE_TOKEN",
                "GH_HOST",
                "GH_CONFIG_DIR",
            ]
            .iter()
            .any(|variable| std::env::var_os(variable).is_some())
            {
                return Err(
                    "managed gh child has conflicting inherited GitHub selectors".to_owned(),
                );
            }
            let binding = profile
                .github
                .as_ref()
                .ok_or_else(|| "managed gh child profile has no account binding".to_owned())?;
            let gh = gh_executable()
                .ok_or_else(|| "native gh is unavailable for nested Git binding".to_owned())?;
            let paths = PersonaPaths::discover()
                .map_err(|_| "cannot resolve private Persona state for nested Git".to_owned())?;
            let selector =
                persona::credential::GithubSelector::discover(gh, binding.host.clone(), paths)
                    .map_err(|_| "cannot resolve nested GitHub account binding".to_owned())?;
            if let Some(token) = std::env::var_os("GH_TOKEN") {
                let token = token
                    .to_str()
                    .filter(|token| {
                        !token.is_empty() && token.len() <= 16 * 1024 && token.is_ascii()
                    })
                    .ok_or_else(|| "managed gh child credential is malformed".to_owned())?;
                if !selector
                    .token_matches_binding(binding, token.as_bytes())
                    .map_err(|_| "cannot compare nested GitHub account binding".to_owned())?
                {
                    return Err(
                        "managed gh child credential does not match its enrolled account"
                            .to_owned(),
                    );
                }
            } else {
                let token = selector
                    .token_for_binding(binding)
                    .map_err(|_| "cannot select nested GitHub account binding".to_owned())?;
                if token.is_none() {
                    return Err(
                        "selected GitHub credential does not match the enrolled account".to_owned(),
                    );
                }
            }
            true
        }
        Some(_) => return Err("unrecognized managed gh child marker".to_owned()),
        None => false,
    };
    let inherited_github_tokens_present = [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
    ]
    .iter()
    .any(|variable| std::env::var_os(variable).is_some());
    if matches!(command, "fetch" | "pull" | "push" | "clone")
        && inherited_github_tokens_present
        && !gh_parent_authorized
    {
        return Err(
            "inherited GitHub token override is not permitted for managed Git transport".to_owned(),
        );
    }
    let mut managed_destination = None;
    let mut use_managed_ssh = false;
    let mut managed_push_request = None;
    let mut push_handoff_file = None;
    let mut expected_ssh_push_path = None;
    if worktree_add {
        let source_root = git_client
            .checkout_root(&directory)
            .map_err(|_| "worktree creation requires an existing Git worktree".to_owned())?;
        persona::context::resolve_context(&source_root, &config.scopes())
            .map_err(|_| "cannot resolve source worktree scope".to_owned())?
            .ok_or_else(|| "worktree source must also be in a managed scope".to_owned())?;
        if selection_directory.exists() || std::fs::symlink_metadata(&selection_directory).is_ok() {
            return Err("worktree destination already exists".to_owned());
        }
        let parent = selection_directory
            .parent()
            .ok_or_else(|| "worktree destination has no parent".to_owned())?;
        let parent = std::fs::canonicalize(parent)
            .map_err(|_| "worktree destination parent must already exist".to_owned())?;
        let name = selection_directory
            .file_name()
            .ok_or_else(|| "worktree destination has no final path component".to_owned())?;
        if !parent.join(name).starts_with(&selected_scope.root) {
            return Err("worktree destination is outside the selected Persona scope".to_owned());
        }
    }
    if command == "remote" && safe_remote_add_arguments(&git_arguments[1..]) {
        let remote = git_arguments[2]
            .to_str()
            .ok_or_else(|| "remote name must be valid UTF-8".to_owned())?;
        let destination = git_arguments[3]
            .to_str()
            .ok_or_else(|| "remote destination must be valid UTF-8".to_owned())?;
        let allowed = configured_fetch_destinations(profile, remote)
            .into_iter()
            .flatten()
            .any(|item| item == destination)
            || configured_push_destinations(profile, remote)
                .into_iter()
                .flatten()
                .any(|item| item == destination);
        if !allowed {
            return Err("remote name or destination is not authorized by this profile".to_owned());
        }
        if !is_supported_https_destination(destination) {
            validate_managed_ssh_destination(profile.ssh.as_ref(), destination, "git-upload-pack")
                .map_err(|reason| {
                    format!("remote destination has no managed SSH policy: {reason}")
                })?;
        }
    }
    let signed_tag_create = operation == ManagedGitOperation::SignedTag;
    let lightweight_tag_create = operation == ManagedGitOperation::LightweightTag;
    let tag_create = signed_tag_create || lightweight_tag_create;
    if signed_tag_create && selected_policy.git.signing.is_none() {
        return Err("annotated tag creation requires an explicit signing policy".to_owned());
    }
    if lightweight_tag_create
        && !selected_policy
            .git
            .push
            .as_ref()
            .is_some_and(|push| push.allow_lightweight_tags)
    {
        return Err("lightweight tag creation requires an explicit policy opt-in".to_owned());
    }
    if tag_create {
        let name_index = if signed_tag_create { 4 } else { 2 };
        let name = git_arguments[name_index]
            .to_str()
            .ok_or_else(|| "tag name must be valid UTF-8".to_owned())?;
        let refname = format!("refs/tags/{name}");
        if !git_client
            .valid_refname(&directory, &refname)
            .map_err(|_| "cannot validate tag refname".to_owned())?
        {
            return Err("tag name is invalid".to_owned());
        }
    }
    if operation == ManagedGitOperation::BranchCreate {
        let branch = git_arguments[1]
            .to_str()
            .ok_or_else(|| "branch name must be valid UTF-8".to_owned())?;
        let refname = format!("refs/heads/{branch}");
        let checked = git_client
            .valid_refname(&directory, &refname)
            .map_err(|_| "cannot safely validate Git branch name".to_owned())?;
        if !checked {
            return Err("branch name is invalid".to_owned());
        }
    }
    if operation == ManagedGitOperation::Switch {
        let name_index = if git_arguments[1] == "--create" { 2 } else { 1 };
        let branch = git_arguments[name_index]
            .to_str()
            .ok_or_else(|| "branch name must be valid UTF-8".to_owned())?;
        let refname = format!("refs/heads/{branch}");
        if !git_client
            .valid_refname(&directory, &refname)
            .map_err(|_| "cannot validate switch branch name".to_owned())?
        {
            return Err("branch name is invalid".to_owned());
        }
        if git_arguments[1] != "--create" {
            git_client
                .resolve_commit_oid(&directory, &refname)
                .map_err(|_| "switch target is not an existing local branch".to_owned())?;
        } else if git_arguments.len() == 4 {
            let start = git_arguments[3]
                .to_str()
                .ok_or_else(|| "switch start point must be a commit OID".to_owned())?;
            git_client
                .resolve_commit_oid(&directory, start)
                .map_err(|_| "switch start point is not an existing commit".to_owned())?;
        }
    }
    if operation == ManagedGitOperation::Checkout {
        let create = git_arguments[1] == "-b";
        let branch_index = if create { 2 } else { 1 };
        let branch = git_arguments[branch_index]
            .to_str()
            .ok_or_else(|| "checkout branch name must be valid UTF-8".to_owned())?;
        let refname = format!("refs/heads/{branch}");
        if !git_client
            .valid_refname(&directory, &refname)
            .map_err(|_| "cannot validate checkout branch name".to_owned())?
        {
            return Err("branch name is invalid".to_owned());
        }
        if !create {
            git_client
                .resolve_commit_oid(&directory, &refname)
                .map_err(|_| "checkout target is not an existing local branch".to_owned())?;
        }
    }
    if operation == ManagedGitOperation::Rebase && git_arguments[1] == "--onto" {
        for argument in &git_arguments[2..4] {
            let branch = argument
                .to_str()
                .ok_or_else(|| "rebase branch must be valid UTF-8".to_owned())?;
            let valid = git_client
                .valid_refname(&directory, branch)
                .map_err(|_| "cannot validate rebase branch".to_owned())?;
            if !valid {
                return Err("rebase accepts only valid local branch refs".to_owned());
            }
            git_client
                .resolve_commit_oid(&directory, branch)
                .map_err(|_| "rebase target must be an existing local branch".to_owned())?;
        }
        if git_client
            .has_custom_merge_driver(&directory)
            .map_err(|_| "cannot inspect custom merge drivers before rebase".to_owned())?
        {
            return Err("rebase is blocked while custom merge drivers are configured".to_owned());
        }
    }
    if matches!(command, "cherry-pick" | "rebase")
        && git_client
            .has_custom_merge_driver(&directory)
            .map_err(|_| {
                "cannot inspect custom merge drivers before sequenced operation".to_owned()
            })?
    {
        return Err(
            "sequenced operation is blocked while custom merge drivers are configured".to_owned(),
        );
    }
    if operation == ManagedGitOperation::Merge && git_arguments[1] == "--ff-only" {
        let branch = git_arguments[2]
            .to_str()
            .ok_or_else(|| "merge target must be valid UTF-8".to_owned())?;
        let refname = format!("refs/heads/{branch}");
        if !git_client
            .valid_refname(&directory, &refname)
            .map_err(|_| "cannot validate merge target branch".to_owned())?
        {
            return Err("merge target is not a valid local branch".to_owned());
        }
        git_client
            .resolve_commit_oid(&directory, &refname)
            .map_err(|_| "merge target is not an existing local branch".to_owned())?;
    }
    if operation == ManagedGitOperation::CherryPick
        && git_arguments[1] != "--continue"
        && git_arguments[1] != "--abort"
    {
        let oid = git_arguments[1]
            .to_str()
            .ok_or_else(|| "cherry-pick target must be a commit OID".to_owned())?;
        git_client
            .resolve_commit_oid(&directory, oid)
            .map_err(|_| "cherry-pick target is not an existing commit".to_owned())?;
    }
    if command == "commit" {
        let inherited = GitClient::new(native_git.clone(), persona::git::safe_environment());
        let inherited_root = inherited
            .checkout_root(&directory)
            .map_err(|_| "cannot validate inherited Git worktree configuration".to_owned())?;
        if inherited_root != selection_directory {
            return Err("inherited Git configuration redirects the commit worktree".to_owned());
        }
    }
    if matches!(
        operation,
        ManagedGitOperation::Fetch | ManagedGitOperation::Pull
    ) {
        let remote = git_arguments
            .get(1)
            .and_then(|value| value.to_str())
            .ok_or_else(|| "fetch requires one explicit remote name".to_owned())?;
        let fetch_destinations = configured_fetch_destinations(profile, remote)
            .ok_or_else(|| "fetch requires a profile-bound remote fetch policy".to_owned())?;
        if fetch_destinations.is_empty() {
            return Err("remote is not authorized for fetching".to_owned());
        }
        if git_client
            .has_unsafe_https_transport_config(&directory)
            .map_err(|_| "cannot validate local Git HTTPS configuration".to_owned())?
        {
            return Err("unsafe local HTTPS transport configuration is present".to_owned());
        }
        let destinations = git_client
            .effective_fetch_destinations(&directory, remote)
            .map_err(|_| "cannot resolve the effective fetch destination".to_owned())?;
        if destinations.len() != 1 || !fetch_destinations.contains(&destinations[0]) {
            return Err(
                "effective fetch destination is not an exact allowed destination".to_owned(),
            );
        }
        managed_destination = Some(destinations[0].clone());
        if is_supported_https_destination(&destinations[0]) {
            use_managed_ssh = false;
        } else {
            validate_managed_ssh_destination(
                profile.ssh.as_ref(),
                &destinations[0],
                "git-upload-pack",
            )
            .map_err(|reason| {
                format!("SSH destination has no valid managed transport: {reason}")
            })?;
            use_managed_ssh = true;
        }
    } else if command == "push" {
        let push = persona::git_command::PushInvocation::parse(&git_arguments[1..])
            .map_err(str::to_owned)?;
        if push.set_upstream {
            return Err("managed push currently rejects implicit upstream tracking".to_owned());
        }
        if push.refspecs.len() > 1 && !push.atomic {
            return Err("multi-ref publication requires explicit --atomic".to_owned());
        }
        let remote = push.remote.as_str();
        let mut canonical = vec![OsString::from("push")];
        if push.atomic {
            canonical.push(OsString::from("--atomic"));
        }
        for lease in &push.leases {
            canonical.push(OsString::from(format!(
                "--force-with-lease={}:{}",
                lease.remote_ref, lease.expected_oid
            )));
        }
        canonical.push(OsString::from(remote));
        let push_policy = selected_policy
            .git
            .push
            .as_ref()
            .ok_or_else(|| "managed push requires an explicit destination policy".to_owned())?;
        if push_policy.remote != remote {
            return Err("push remote does not match the configured policy".to_owned());
        }
        let remote_push_destinations = configured_push_destinations(profile, remote)
            .ok_or_else(|| "push requires a profile-bound remote destination policy".to_owned())?;
        if remote_push_destinations != push_policy.destinations {
            return Err(
                "publication destinations do not match the named profile remote".to_owned(),
            );
        }
        let mut tuples = Vec::with_capacity(push.refspecs.len());
        let object_width = git_client
            .resolve_commit_oid(&directory, "HEAD")
            .map_or(40, |oid| oid.len());
        for refspec in &push.refspecs {
            let local_ref = refspec.source.as_str();
            let remote_ref = refspec.destination.as_str();
            let is_deletion = local_ref == "(delete)";
            let is_branch = remote_ref.starts_with("refs/heads/");
            let is_tag = remote_ref.starts_with("refs/tags/");
            if !is_branch && !is_tag {
                return Err("managed publication supports only branch and tag refs".to_owned());
            }
            if !is_deletion
                && !git_client
                    .valid_refname(&directory, local_ref)
                    .map_err(|_| "cannot validate push source ref".to_owned())?
            {
                return Err("push source ref is invalid".to_owned());
            }
            let canonical_refspec = if is_deletion {
                format!(":{remote_ref}")
            } else {
                format!("{local_ref}:{remote_ref}")
            };
            canonical.push(OsString::from(canonical_refspec));
            let remote_oid = if is_tag {
                let lease = push.leases.iter().find(|lease| lease.remote_ref == remote_ref)
                    .ok_or_else(|| "tag publication requires an exact --force-with-lease=<ref>:<oid> for the advertised remote state".to_owned())?;
                lease.expected_oid.clone()
            } else {
                let branch = remote_ref.strip_prefix("refs/heads/").unwrap_or_default();
                let tracking_ref = format!("refs/remotes/{remote}/{branch}");
                let cached = git_client
                    .optional_commit_oid(&directory, &tracking_ref)
                    .map_err(|_| "cannot resolve the cached remote OID for publication".to_owned())?
                    .unwrap_or_else(|| "0".repeat(object_width));
                if let Some(lease) = push
                    .leases
                    .iter()
                    .find(|lease| lease.remote_ref == remote_ref)
                {
                    if lease.expected_oid != cached {
                        return Err("force-with-lease OID does not match the cached remote ref; fetch and re-authorize explicitly".to_owned());
                    }
                }
                cached
            };
            for lease in push
                .leases
                .iter()
                .filter(|lease| lease.remote_ref == remote_ref)
            {
                if lease.expected_oid != remote_oid {
                    return Err(
                        "force-with-lease OID does not match the selected advertised remote state"
                            .to_owned(),
                    );
                }
            }
            let local_oid = if is_deletion {
                "0".repeat(remote_oid.len())
            } else {
                let oid = if is_branch {
                    git_client
                        .resolve_commit_oid(&directory, local_ref)
                        .map_err(|_| "push source branch does not resolve to a commit".to_owned())?
                } else {
                    git_client
                        .resolve_object_oid(&directory, local_ref)
                        .map_err(|_| "push source tag object is unavailable".to_owned())?
                };
                if oid.len() != remote_oid.len() {
                    return Err("local and remote object ID formats do not match".to_owned());
                }
                oid
            };
            if local_oid == remote_oid {
                return Err("managed push includes an unchanged or absent remote ref; omit it or refresh and re-authorize the exact update".to_owned());
            }
            tuples.push(PushTuple {
                local_ref: local_ref.to_owned(),
                local_oid,
                remote_ref: remote_ref.to_owned(),
                remote_oid,
            });
        }
        git_arguments = canonical;
        if git_client
            .has_push_options(&directory)
            .map_err(|_| "cannot inspect configured push options".to_owned())?
            || git_client
                .has_remote_mirror_push(&directory, remote)
                .map_err(|_| "cannot inspect remote mirror configuration".to_owned())?
        {
            return Err(
                "configured server-side push options or mirror mode are blocked".to_owned(),
            );
        }
        if git_client
            .has_unsafe_https_transport_config(&directory)
            .map_err(|_| "cannot validate local transport configuration".to_owned())?
        {
            return Err("unsafe local transport configuration is present".to_owned());
        }
        let destinations = git_client
            .effective_push_destinations(&directory, remote)
            .map_err(|_| "cannot resolve the effective push destination".to_owned())?;
        if destinations.len() != 1 || !remote_push_destinations.contains(&destinations[0]) {
            return Err("managed push requires exactly one exact allowed destination".to_owned());
        }
        let destination = destinations[0].clone();
        if is_supported_https_destination(&destination) {
            use_managed_ssh = false;
        } else {
            validate_managed_ssh_destination(
                profile.ssh.as_ref(),
                &destination,
                "git-receive-pack",
            )
            .map_err(|reason| {
                format!("SSH destination has no valid managed receive-pack transport: {reason}")
            })?;
            let (_, path) = parse_ssh_remote(&destination)
                .ok_or_else(|| "SSH push destination path is unsupported".to_owned())?;
            expected_ssh_push_path = Some(if destination.starts_with("ssh://") {
                format!("/{path}")
            } else {
                path.to_owned()
            });
            use_managed_ssh = true;
        }
        managed_push_request = Some(PushRequest {
            remote: remote.to_owned(),
            destination: destination.clone(),
            tuples,
            leases: push.leases,
        });
        managed_destination = Some(destination);
    } else if operation == ManagedGitOperation::Clone {
        let url = git_arguments[1]
            .to_str()
            .ok_or_else(|| "clone URL must be valid UTF-8".to_owned())?;
        let allowed_clone = profile.git.remotes.iter().any(|remote| {
            remote
                .fetch_destinations
                .iter()
                .any(|destination| destination == url)
        }) || (profile.git.remotes.is_empty()
            && profile.git.push.as_ref().is_some_and(|push| {
                push.destinations
                    .iter()
                    .any(|destination| destination == url)
            }));
        if !allowed_clone {
            return Err("clone URL is not an exact profile-bound fetch destination".to_owned());
        }
        managed_destination = Some(url.to_owned());
        if is_supported_https_destination(url) {
            use_managed_ssh = false;
        } else {
            validate_managed_ssh_destination(profile.ssh.as_ref(), url, "git-upload-pack")
                .map_err(|reason| {
                    format!("SSH clone URL has no valid managed transport: {reason}")
                })?;
            use_managed_ssh = true;
        }
        if git_client
            .has_unsafe_https_transport_config(&directory)
            .map_err(|_| "cannot validate local transport configuration".to_owned())?
        {
            return Err("unsafe local transport configuration is present".to_owned());
        }
        let target = PathBuf::from(&git_arguments[2]);
        let target = if target.is_absolute() {
            target
        } else {
            directory.join(target)
        };
        if target.exists() || std::fs::symlink_metadata(&target).is_ok() {
            return Err("clone target already exists".to_owned());
        }
        let parent = target
            .parent()
            .ok_or_else(|| "clone target has no parent".to_owned())?;
        let parent = std::fs::canonicalize(parent)
            .map_err(|_| "clone target parent must already exist".to_owned())?;
        let target_name = target
            .file_name()
            .ok_or_else(|| "clone target has no name".to_owned())?;
        if !parent.join(target_name).starts_with(&selected_scope.root) {
            return Err("clone target is outside the configured scope".to_owned());
        }
    }
    if gh_parent_authorized {
        if let Some(destination) = &managed_destination {
            validate_nested_gh_git_destination(profile, destination)?;
        }
    }
    if let Some(request) = &managed_push_request {
        let primary_evidence =
            authorize_managed_push(&config, &directory, profile, &git_client, request)?;
        if sha256_file(&config_path)? != config_digest_at_load {
            return Err("policy changed during primary push authorization".to_owned());
        }
        let paths = PersonaPaths::discover()
            .map_err(|_| "cannot resolve private state for push handoff".to_owned())?;
        let checkout_root = git_client
            .checkout_root(&directory)
            .map_err(|_| "cannot resolve checkout for push handoff".to_owned())?;
        let config_path = std::fs::canonicalize(&config_path)
            .map_err(|_| "cannot resolve policy path for push handoff".to_owned())?;
        let handoff = persona::push_handoff::PushHandoff {
            config_path,
            config_sha256: config_digest_at_load.clone(),
            hook_manifest_path: primary_evidence.hook_manifest_path,
            hook_manifest_sha256: primary_evidence.hook_manifest_sha256,
            checkout_root,
            profile: profile.name.clone(),
            remote: request.remote.clone(),
            destination: request.destination.clone(),
            tuples: request
                .tuples
                .iter()
                .map(|tuple| persona::push_handoff::HandoffTuple {
                    local_ref: tuple.local_ref.clone(),
                    local_oid: tuple.local_oid.clone(),
                    remote_ref: tuple.remote_ref.clone(),
                    remote_oid: tuple.remote_oid.clone(),
                    expected_lease_oid: request
                        .leases
                        .iter()
                        .find(|lease| lease.remote_ref == tuple.remote_ref)
                        .map(|lease| lease.expected_oid.clone()),
                })
                .collect(),
            github_binding: profile.github.as_ref().map(|binding| {
                persona::push_handoff::HandoffGithubBinding {
                    host: binding.host.clone(),
                    account_id: binding.account_id.clone(),
                }
            }),
        };
        push_handoff_file = Some(persona::push_handoff::write(&paths, &handoff)?);
    }
    let shim_dir = validate_managed_shim_directory()?;
    let helper_executable = shim_dir.join("git-credential-persona");
    let executable = persona_dispatcher_executable()
        .map_err(|_| "cannot resolve Persona executable for helper verification".to_owned())?;
    let helper_target = std::fs::canonicalize(&helper_executable)
        .map_err(|_| "managed Git credential helper is missing".to_owned())?;
    if helper_target != executable {
        return Err("managed Git credential helper target is unexpected".to_owned());
    }
    let ssh_adapter = shim_dir.join("ssh");
    if use_managed_ssh {
        let ssh_target = std::fs::canonicalize(&ssh_adapter)
            .map_err(|_| "managed SSH adapter is missing".to_owned())?;
        if ssh_target != executable {
            return Err("managed SSH adapter target is unexpected".to_owned());
        }
    }
    let managed_path =
        std::env::join_paths([shim_dir, PathBuf::from("/usr/bin"), PathBuf::from("/bin")])
            .map_err(|_| "cannot construct managed Git helper PATH".to_owned())?;
    let commit_operation = operation == ManagedGitOperation::Commit;
    let preserve_cherry_pick_author = selected_policy
        .git
        .push
        .as_ref()
        .is_some_and(|push| push.preserve_authors);
    let strict_cherry_pick_continue = operation == ManagedGitOperation::CherryPick
        && !preserve_cherry_pick_author
        && git_arguments
            .get(1)
            .is_some_and(|argument| argument == "--continue");
    let strict_cherry_pick_oid = if operation == ManagedGitOperation::CherryPick
        && !preserve_cherry_pick_author
    {
        if strict_cherry_pick_continue {
            Some(
                git_client
                    .resolve_commit_oid(&directory, "CHERRY_PICK_HEAD")
                    .map_err(|_| "cannot identify the in-progress cherry-pick commit".to_owned())?,
            )
        } else {
            git_arguments.get(1).and_then(|argument| {
                argument
                    .to_str()
                    .filter(|oid| {
                        matches!(oid.len(), 40 | 64)
                            && oid.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
                    .map(str::to_owned)
            })
        }
    } else {
        None
    };
    let sequenced_commit_operation = matches!(command, "cherry-pick" | "rebase");
    let signing_operation = commit_operation || sequenced_commit_operation || signed_tag_create;
    let identity_commit_operation = commit_operation || sequenced_commit_operation;
    let command_name = command;
    if strict_cherry_pick_continue {
        let oid = strict_cherry_pick_oid
            .as_deref()
            .ok_or_else(|| "cherry-pick continuation has no source commit".to_owned())?;
        let status = commit_cherry_pick_with_policy(
            &native_git,
            &directory,
            oid,
            selected_policy,
            &managed_path,
        )?;
        return Ok(status_exit_code(status));
    }
    let mut command = Command::new(&native_git);
    command
        .arg("--no-pager")
        .arg("-c")
        .arg("core.pager=cat")
        .arg("-c")
        .arg("core.fsmonitor=false");
    for (key, value) in persona::git_https::required_git_http_overrides() {
        command.arg("-c").arg(format!("{key}={value}"));
    }
    if use_managed_ssh {
        command.arg("-c").arg("ssh.variant=ssh");
    }
    command
        .arg("-c")
        .arg("fetch.prune=false")
        .arg("-c")
        .arg("fetch.pruneTags=false")
        .arg("-c")
        .arg("fetch.recurseSubmodules=false")
        .arg("-c")
        .arg("pull.ff=only")
        .arg("-c")
        .arg("pull.rebase=false")
        .arg("-c")
        .arg("push.followTags=false")
        .arg("-c")
        .arg("push.recurseSubmodules=no")
        .arg("-c")
        .arg("push.gpgSign=false");
    if command_name == "rebase"
        || (command_name == "cherry-pick" && git_arguments[1] == "--continue")
    {
        command.arg("-c").arg("core.editor=true");
    }
    command
        .arg("-c")
        .arg(format!("user.name={}", selected_policy.git.committer.name))
        .arg("-c")
        .arg(format!(
            "user.email={}",
            selected_policy.git.committer.email
        ))
        .arg("-c")
        .arg("credential.helper=persona")
        .arg("-c")
        .arg(format!(
            "commit.gpgSign={}",
            identity_commit_operation && selected_policy.git.signing.is_some()
        ))
        .arg("-c")
        .arg(format!(
            "tag.gpgSign={}",
            signed_tag_create && selected_policy.git.signing.is_some()
        ))
        .current_dir(&directory)
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", &managed_path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("PERSONA_CONFIG_PATH", &config_path)
        .env("PERSONA_GIT", &native_git);
    if let Some(path) = &expected_ssh_push_path {
        command.env("PERSONA_EXPECTED_SSH_PUSH_PATH", path);
    }
    if let Some(handoff) = &push_handoff_file {
        let state_home = handoff
            .path()
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| "cannot resolve private handoff state home".to_owned())?;
        command
            .env("PERSONA_PUSH_HANDOFF", handoff.path())
            .env("XDG_STATE_HOME", state_home);
    }
    if use_managed_ssh {
        command
            .env("GIT_SSH", &ssh_adapter)
            .env("GIT_SSH_VARIANT", "ssh");
        if let Some(ssh) = std::env::var_os("PERSONA_SSH") {
            command.env("PERSONA_SSH", ssh);
        }
        if let Some(ssh_keygen) = std::env::var_os("PERSONA_SSH_KEYGEN") {
            command.env("PERSONA_SSH_KEYGEN", ssh_keygen);
        }
    }
    if let Some(gh) = std::env::var_os("PERSONA_GH") {
        let gh = PathBuf::from(gh);
        if gh.is_absolute() && gh.is_file() {
            command.env("PERSONA_GH", gh);
        }
    }
    if signing_operation {
        if let Some(home) = std::env::var_os("HOME") {
            command.env("HOME", home);
        }
        if commit_operation {
            command
                .env("GIT_AUTHOR_NAME", &selected_policy.git.author.name)
                .env("GIT_AUTHOR_EMAIL", &selected_policy.git.author.email);
        }
        if identity_commit_operation || tag_create {
            command
                .env("GIT_COMMITTER_NAME", &selected_policy.git.committer.name)
                .env("GIT_COMMITTER_EMAIL", &selected_policy.git.committer.email);
        }
    }
    let original_home = std::env::var_os("HOME").map(PathBuf::from);
    let original_config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| original_home.as_ref().map(|home| home.join(".config")));
    let original_state_home = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| original_home.as_ref().map(|home| home.join(".local/state")));
    if let Some(path) = original_config_home {
        command.env("XDG_CONFIG_HOME", path.clone());
        command.env(
            "GH_CONFIG_DIR",
            std::env::var_os("GH_CONFIG_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| path.join("gh")),
        );
    }
    if let Some(path) = original_state_home {
        command.env("XDG_STATE_HOME", path);
    }
    if !gh_parent_authorized {
        for variable in [
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "GH_ENTERPRISE_TOKEN",
            "GITHUB_ENTERPRISE_TOKEN",
        ] {
            if std::env::var_os(variable).is_some() {
                command.env(variable, "");
            }
        }
    }
    if signing_operation {
        if let Some(signing) = &selected_policy.git.signing {
            let (format, signing_key) = match signing.format {
                persona::config::SigningFormat::OpenPgp => ("openpgp", signing.fingerprint.clone()),
                persona::config::SigningFormat::Ssh => {
                    ("ssh", signing.public_key.to_string_lossy().into_owned())
                }
            };
            command
                .arg("-c")
                .arg(format!("gpg.format={format}"))
                .arg("-c")
                .arg(format!("user.signingkey={signing_key}"));
            match signing.format {
                persona::config::SigningFormat::OpenPgp => {
                    let gpg = gpg_executable()
                        .ok_or_else(|| "configured OpenPGP signing requires GPG".to_owned())?;
                    command
                        .arg("-c")
                        .arg(format!("gpg.program={}", gpg.display()))
                        .arg("-c")
                        .arg(format!("gpg.openpgp.program={}", gpg.display()));
                    if let Some(home) = std::env::var_os("GNUPGHOME") {
                        command.env("GNUPGHOME", home);
                    } else if let Some(home) = original_home.as_ref() {
                        command.env("GNUPGHOME", home.join(".gnupg"));
                    }
                }
                persona::config::SigningFormat::Ssh => {
                    let ssh_keygen = ssh_keygen_executable()
                        .ok_or_else(|| "configured SSH signing requires ssh-keygen".to_owned())?;
                    command
                        .arg("-c")
                        .arg(format!("gpg.ssh.program={}", ssh_keygen.display()));
                    if let Some(socket) = std::env::var_os("SSH_AUTH_SOCK") {
                        command.env("SSH_AUTH_SOCK", socket);
                    }
                }
            }
        }
    }
    command.args(global_arguments);
    if let Some(oid) = &strict_cherry_pick_oid {
        command.args(["cherry-pick", "--no-commit", oid]);
    } else if matches!(command_name, "diff" | "show") {
        command
            .arg(command_name)
            .arg("--no-ext-diff")
            .arg("--no-textconv")
            .args(&git_arguments[1..]);
    } else {
        if operation == ManagedGitOperation::Commit
            && git_arguments.iter().any(|argument| argument == "--amend")
        {
            git_arguments.insert(1, OsString::from("--reset-author"));
        }
        command.args(git_arguments);
    }
    let status = command
        .status()
        .map_err(|error| format!("cannot launch managed Git: {error}"))?;
    if !status.success() {
        return Ok(status_exit_code(status));
    }
    if let Some(handoff) = &push_handoff_file {
        if handoff.path().exists() {
            return Err("managed push completed without consuming Persona's pre-push authorization barrier; refusing to report success".to_owned());
        }
    }
    if let Some(oid) = strict_cherry_pick_oid {
        let status = commit_cherry_pick_with_policy(
            &native_git,
            &directory,
            &oid,
            selected_policy,
            &managed_path,
        )?;
        return Ok(status_exit_code(status));
    }
    Ok(status_exit_code(status))
}

fn commit_cherry_pick_with_policy(
    native_git: &Path,
    directory: &Path,
    oid: &str,
    policy: &persona::config::ScopePolicy,
    managed_path: &std::ffi::OsStr,
) -> Result<std::process::ExitStatus, String> {
    let mut command = Command::new(native_git);
    command
        .arg("-c")
        .arg(format!("user.name={}", policy.git.committer.name))
        .arg("-c")
        .arg(format!("user.email={}", policy.git.committer.email))
        .arg("-c")
        .arg(format!("commit.gpgSign={}", policy.git.signing.is_some()))
        .arg("-c")
        .arg("credential.helper=persona")
        .current_dir(directory)
        .env_clear()
        .env("PATH", managed_path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", &policy.git.author.name)
        .env("GIT_AUTHOR_EMAIL", &policy.git.author.email)
        .env("GIT_COMMITTER_NAME", &policy.git.committer.name)
        .env("GIT_COMMITTER_EMAIL", &policy.git.committer.email);
    if let Some(home) = std::env::var_os("HOME") {
        command.env("HOME", home);
    }
    if let Some(signing) = &policy.git.signing {
        let (format, key) = match signing.format {
            persona::config::SigningFormat::OpenPgp => ("openpgp", signing.fingerprint.clone()),
            persona::config::SigningFormat::Ssh => {
                ("ssh", signing.public_key.to_string_lossy().into_owned())
            }
        };
        command
            .arg("-c")
            .arg(format!("gpg.format={format}"))
            .arg("-c")
            .arg(format!("user.signingkey={key}"));
        match signing.format {
            persona::config::SigningFormat::OpenPgp => {
                let gpg = gpg_executable()
                    .ok_or_else(|| "configured OpenPGP signing requires GPG".to_owned())?;
                command
                    .arg("-c")
                    .arg(format!("gpg.program={}", gpg.display()))
                    .arg("-c")
                    .arg(format!("gpg.openpgp.program={}", gpg.display()));
                if let Some(home) = std::env::var_os("GNUPGHOME") {
                    command.env("GNUPGHOME", home);
                } else if let Some(home) = std::env::var_os("HOME") {
                    command.env("GNUPGHOME", PathBuf::from(home).join(".gnupg"));
                }
            }
            persona::config::SigningFormat::Ssh => {
                let keygen = ssh_keygen_executable()
                    .ok_or_else(|| "configured SSH signing requires ssh-keygen".to_owned())?;
                command
                    .arg("-c")
                    .arg(format!("gpg.ssh.program={}", keygen.display()));
                if let Some(socket) = std::env::var_os("SSH_AUTH_SOCK") {
                    command.env("SSH_AUTH_SOCK", socket);
                }
            }
        }
    }
    command.args(["commit", "--reset-author", "--allow-empty", "-C", oid]);
    command
        .status()
        .map_err(|error| format!("cannot create policy-identity cherry-pick commit: {error}"))
}

fn validate_nested_gh_git_destination(profile: &Profile, destination: &str) -> Result<(), String> {
    let binding = profile
        .github
        .as_ref()
        .ok_or_else(|| "nested managed Git has no GitHub account binding".to_owned())?;
    let repository =
        persona::gh_adapter::repository_from_destination(destination).ok_or_else(|| {
            "nested managed Git destination is not a supported GitHub.com repository".to_owned()
        })?;
    let allowed = binding
        .repositories
        .iter()
        .map(|item| persona::gh_adapter::normalize_repository(item))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    if !allowed.contains(&repository) {
        return Err(
            "nested managed Git repository is outside the profile's GitHub allowlist".to_owned(),
        );
    }
    Ok(())
}

struct PushPrimaryEvidence {
    hook_manifest_path: PathBuf,
    hook_manifest_sha256: String,
}

fn authorize_managed_push(
    config: &Config,
    directory: &Path,
    profile: &Profile,
    git: &GitClient,
    request: &PushRequest,
) -> Result<PushPrimaryEvidence, String> {
    let executables = ExecutablePaths {
        git: git_executable(),
        gpg: gpg_executable(),
        ssh_keygen: ssh_keygen_executable(),
    };
    let (report, selected) = build_report(config, directory, Some(request), &executables)?;
    let selected = selected.ok_or_else(|| "push worktree is outside a managed scope".to_owned())?;
    let selected_policy = config
        .policies()
        .iter()
        .find(|policy| policy.name == selected.name)
        .ok_or_else(|| "push scope has no resolved policy".to_owned())?;
    let mut required = vec![
        "scope".to_owned(),
        "policy.profile".to_owned(),
        "git.worktree".to_owned(),
        "git.push.destination".to_owned(),
        "git.push.updates".to_owned(),
        "git.push.author".to_owned(),
        "git.push.committer".to_owned(),
    ];
    if request
        .tuples
        .iter()
        .any(|tuple| tuple.remote_ref.starts_with("refs/tags/") && tuple.local_ref != "(delete)")
    {
        required.push("git.push.tag_signature".to_owned());
    }
    if selected_policy.git.signing.is_some() {
        required.extend([
            "git.push.signature.present".to_owned(),
            "git.push.signature.valid".to_owned(),
            "git.push.signature.fingerprint".to_owned(),
        ]);
    }
    let core = authorize(
        AuthorizationOperation::GitPush,
        required.clone(),
        report.findings.clone(),
    );
    if !core.is_allowed() {
        return Err(format!(
            "primary push authorization blocked: {:?}",
            core.blockers
        ));
    }

    // The hook is a required second barrier, so missing, redirected, or changed hook
    // state fails before any credential selector or native transport is invoked.
    let root = git
        .checkout_root(directory)
        .map_err(|_| "cannot resolve push worktree for pre-push hook verification".to_owned())?;
    let hook_paths = persona::hooks::resolve_paths(git, &root)?;
    let manifest = persona::hooks::load_manifest(&hook_paths)?;
    let executable = persona_dispatcher_executable()
        .map_err(|_| "cannot resolve Persona dispatcher for push hook verification".to_owned())?;
    if manifest.persona_executable() != executable {
        return Err("installed pre-push hook belongs to a different Persona executable".to_owned());
    }
    persona::hooks::verify_installed_hook(&hook_paths, &manifest)?;
    let manifest_path = std::fs::canonicalize(&hook_paths.manifest)
        .map_err(|_| "cannot resolve installed hook manifest".to_owned())?;
    let manifest_digest = sha256_file(&manifest_path)?;

    let destination_host = persona::credential::destination_host(&request.destination);
    let github_required = destination_host.as_deref().is_some_and(|host| {
        persona::credential::is_known_github_host(host) || profile.github.is_some()
    }) || profile.github.is_some();
    if github_required {
        let binding = profile
            .github
            .as_ref()
            .ok_or_else(|| "GitHub push requires an enrolled account binding".to_owned())?;
        let host = destination_host
            .as_deref()
            .ok_or_else(|| "cannot determine GitHub push host".to_owned())?;
        if host != binding.host {
            return Err(
                "push destination host does not match the enrolled GitHub account".to_owned(),
            );
        }
        let gh = gh_executable()
            .ok_or_else(|| "native gh is unavailable for account-bound push".to_owned())?;
        let paths = PersonaPaths::discover()
            .map_err(|_| "cannot resolve private Persona state for GitHub push".to_owned())?;
        let selector =
            persona::credential::GithubSelector::discover(gh, binding.host.clone(), paths)
                .map_err(|_| "cannot safely inspect the selected GitHub account".to_owned())?;
        let token = selector
            .token_for_binding(binding)
            .map_err(|_| "cannot select the enrolled GitHub credential".to_owned())?
            .ok_or_else(|| {
                "selected GitHub credential does not match the enrolled account".to_owned()
            })?;
        drop(token);
        required.push("github.credential.binding".to_owned());
        let mut findings = report.findings;
        findings.push(persona::report::Finding::pass(
            "github.credential.binding",
            binding.account_id.clone(),
            binding.account_id.clone(),
            "the selected native credential fingerprint matched the enrolled account before transport",
        ));
        if !authorize(AuthorizationOperation::GitPush, required, findings).is_allowed() {
            return Err("GitHub account binding did not satisfy push authorization".to_owned());
        }
    }
    if sha256_file(&manifest_path)? != manifest_digest {
        return Err("installed hook manifest changed during primary authorization".to_owned());
    }
    Ok(PushPrimaryEvidence {
        hook_manifest_path: manifest_path,
        hook_manifest_sha256: manifest_digest,
    })
}

fn safe_status_arguments(arguments: &[OsString]) -> bool {
    arguments.iter().all(|argument| {
        matches!(
            argument.to_str(),
            Some(
                "--short"
                    | "-s"
                    | "--porcelain"
                    | "--branch"
                    | "--show-stash"
                    | "--untracked-files=no"
                    | "--ignore-submodules=none"
            )
        )
    })
}

fn safe_diff_arguments(arguments: &[OsString]) -> bool {
    let mut paths = false;
    let mut saw_option = false;
    for argument in arguments {
        let Some(value) = argument.to_str() else {
            return false;
        };
        if paths {
            if !safe_git_pathspec(value) {
                return false;
            }
        } else if value == "--" {
            paths = true;
        } else if matches!(
            value,
            "--cached"
                | "--staged"
                | "--stat"
                | "--name-only"
                | "--name-status"
                | "--check"
                | "--quiet"
                | "--no-color"
                | "--color=never"
        ) {
            saw_option = true;
        } else {
            return false;
        }
    }
    arguments.is_empty() || saw_option || paths
}

fn safe_show_arguments(arguments: &[OsString]) -> bool {
    arguments.iter().all(|argument| {
        argument.to_str().is_some_and(|value| {
            matches!(
                value,
                "--stat" | "--oneline" | "--no-patch" | "--no-color" | "HEAD"
            ) || (value.strip_prefix("HEAD~").is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
            }))
        })
    })
}

fn safe_add_arguments(arguments: &[OsString]) -> bool {
    let pathspecs = if arguments.first().is_some_and(|argument| argument == "--") {
        &arguments[1..]
    } else {
        arguments
    };
    !pathspecs.is_empty()
        && pathspecs.iter().all(|argument| {
            argument
                .to_str()
                .is_some_and(|value| !value.starts_with('-') && safe_git_pathspec(value))
        })
}

fn safe_restore_arguments(arguments: &[OsString]) -> bool {
    let pathspecs = match arguments {
        [separator, paths @ ..] if separator == "--" => paths,
        [staged, separator, paths @ ..] if staged == "--staged" && separator == "--" => paths,
        _ => return false,
    };
    !pathspecs.is_empty()
        && pathspecs.iter().all(|argument| {
            argument
                .to_str()
                .is_some_and(|value| !value.starts_with('-') && safe_git_pathspec(value))
        })
}

fn safe_rm_arguments(arguments: &[OsString]) -> bool {
    let paths = match arguments {
        [separator, paths @ ..] if separator == "--" => paths,
        [cached, separator, paths @ ..] if cached == "--cached" && separator == "--" => paths,
        _ => return false,
    };
    !paths.is_empty()
        && paths.iter().all(|argument| {
            argument
                .to_str()
                .is_some_and(|value| !value.starts_with('-') && safe_git_pathspec(value))
        })
}

fn safe_switch_arguments(arguments: &[OsString]) -> bool {
    (arguments.len() == 1
        && arguments[0]
            .to_str()
            .is_some_and(|name| !name.is_empty() && !name.starts_with('-')))
        || (arguments.len() == 2
            && arguments[0] == "--create"
            && arguments[1]
                .to_str()
                .is_some_and(|name| !name.is_empty() && !name.starts_with('-')))
        || (arguments.len() == 3
            && arguments[0] == "--create"
            && arguments[1]
                .to_str()
                .is_some_and(|name| !name.is_empty() && !name.starts_with('-'))
            && arguments[2].to_str().is_some_and(|oid| {
                matches!(oid.len(), 40 | 64) && oid.bytes().all(|byte| byte.is_ascii_hexdigit())
            }))
}

fn safe_merge_arguments(arguments: &[OsString]) -> bool {
    arguments == [OsString::from("--abort")]
        || (arguments.len() == 2
            && arguments[0] == "--ff-only"
            && arguments[1]
                .to_str()
                .is_some_and(|name| !name.is_empty() && !name.starts_with('-')))
}

fn safe_cherry_pick_arguments(arguments: &[OsString]) -> bool {
    if arguments == [OsString::from("--continue")] || arguments == [OsString::from("--abort")] {
        return true;
    }
    arguments.len() == 1
        && arguments[0].to_str().is_some_and(|oid| {
            matches!(oid.len(), 40 | 64) && oid.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

fn safe_checkout_arguments(arguments: &[OsString]) -> bool {
    (arguments.len() == 1
        && arguments[0]
            .to_str()
            .is_some_and(|name| !name.is_empty() && !name.starts_with('-')))
        || (arguments.len() == 2
            && arguments[0] == "-b"
            && arguments[1]
                .to_str()
                .is_some_and(|name| !name.is_empty() && !name.starts_with('-')))
}

fn safe_rebase_arguments(arguments: &[OsString]) -> bool {
    arguments == [OsString::from("--continue")]
        || arguments == [OsString::from("--abort")]
        || (arguments.len() == 3
            && arguments[0] == "--onto"
            && arguments[1]
                .to_str()
                .is_some_and(|name| name.starts_with("refs/heads/"))
            && arguments[2]
                .to_str()
                .is_some_and(|name| name.starts_with("refs/heads/")))
}

fn safe_lightweight_tag_arguments(arguments: &[OsString]) -> bool {
    (arguments.len() == 2 || arguments.len() == 3)
        && arguments[0] == "--no-sign"
        && arguments[1]
            .to_str()
            .is_some_and(|name| !name.is_empty() && !name.starts_with('-'))
        && arguments.get(2).is_none_or(|target| target == "HEAD")
}

fn safe_signed_tag_arguments(arguments: &[OsString]) -> bool {
    (arguments.len() == 4 || arguments.len() == 5)
        && arguments[0] == "-s"
        && arguments[1] == "-m"
        && arguments[2].to_str().is_some_and(|message| {
            !message.trim().is_empty()
                && message.len() <= 4096
                && !message.bytes().any(|byte| byte == 0)
        })
        && arguments[3]
            .to_str()
            .is_some_and(|name| !name.is_empty() && !name.starts_with('-'))
        && arguments.get(4).is_none_or(|target| target == "HEAD")
}

fn safe_worktree_add_arguments(arguments: &[OsString]) -> bool {
    arguments.len() == 4
        && arguments[0] == "add"
        && arguments[1] == "--detach"
        && arguments[2]
            .to_str()
            .is_some_and(|target| !target.is_empty() && !target.starts_with('-'))
        && arguments[3] == "HEAD"
}

fn safe_remote_add_arguments(arguments: &[OsString]) -> bool {
    arguments.len() == 3
        && arguments[0] == "add"
        && arguments[1].to_str().is_some_and(|name| {
            !name.is_empty()
                && name.len() <= 128
                && !name.starts_with('-')
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
        && arguments[2].to_str().is_some_and(|destination| {
            is_supported_https_destination(destination) || parse_ssh_remote(destination).is_some()
        })
}

fn safe_branch_create_arguments(arguments: &[OsString]) -> bool {
    arguments.len() == 1
        && arguments[0]
            .to_str()
            .is_some_and(|name| !name.is_empty() && !name.starts_with('-'))
}

fn safe_git_pathspec(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with(":(")
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && Path::new(value).components().all(|component| {
            !matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
}

fn safe_clone_arguments(arguments: &[OsString]) -> bool {
    if arguments.len() != 2 {
        return false;
    }
    arguments[0]
        .to_str()
        .is_some_and(|url| is_supported_https_destination(url) || parse_ssh_remote(url).is_some())
        && arguments[1]
            .to_str()
            .is_some_and(|path| !path.is_empty() && !path.starts_with('-'))
}

fn safe_push_arguments(arguments: &[OsString]) -> bool {
    let Ok(push) = persona::git_command::PushInvocation::parse(arguments) else {
        return false;
    };
    !push.set_upstream
        && (push.refspecs.len() == 1 || push.atomic)
        && push.refspecs.iter().all(|refspec| {
            let destination_namespace = if refspec.destination.starts_with("refs/heads/") {
                "refs/heads/"
            } else if refspec.destination.starts_with("refs/tags/") {
                "refs/tags/"
            } else {
                return false;
            };
            refspec.source == "(delete)"
                || (refspec.source.starts_with(destination_namespace)
                    && matches!(destination_namespace, "refs/heads/" | "refs/tags/"))
        })
}

fn safe_fetch_arguments(arguments: &[OsString]) -> bool {
    let Some(remote) = arguments.first().and_then(|value| value.to_str()) else {
        return false;
    };
    let valid_remote = !remote.is_empty()
        && !remote.starts_with('-')
        && remote.len() <= 128
        && remote
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    valid_remote
        && (arguments.len() == 1
            || (arguments.len() == 2
                && arguments[1].to_str().is_some_and(|refspec| {
                    refspec
                        .strip_prefix("refs/pull/")
                        .and_then(|value| value.strip_suffix("/head"))
                        .is_some_and(|number| {
                            !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
                        })
                })))
}

fn is_supported_https_destination(destination: &str) -> bool {
    let Some(rest) = destination.strip_prefix("https://") else {
        return false;
    };
    if rest
        .chars()
        .any(|character| matches!(character, '@' | '?' | '#' | '%' | '\\'))
    {
        return false;
    }
    let Some((authority, path)) = rest.split_once('/') else {
        return false;
    };
    if authority.is_empty()
        || path.is_empty()
        || authority.contains('\\')
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
        || path
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return false;
    }
    let mut host_port = authority.split(':');
    let Some(host) = host_port.next() else {
        return false;
    };
    let valid_host = !host.is_empty()
        && host.len() <= 253
        && host.is_ascii()
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'));
    let valid_port = host_port
        .next()
        .is_none_or(|port| port.parse::<u16>().is_ok_and(|port| port != 0));
    valid_host && valid_port && host_port.next().is_none()
}

fn validate_managed_ssh_destination(
    policy: Option<&persona::config::SshPolicy>,
    destination: &str,
    operation: &str,
) -> Result<(), &'static str> {
    let Some(policy) = policy else {
        return Err("SSH profile is not configured");
    };
    let Some((_authority, path)) = parse_ssh_remote(destination) else {
        return Err("SSH URL syntax is unsupported");
    };
    let Some(ssh) = ssh_executable() else {
        return Err("OpenSSH executable is unavailable");
    };
    let Some(ssh_keygen) = ssh_keygen_executable() else {
        return Err("ssh-keygen executable is unavailable");
    };
    let command = format!("{operation} '{path}'");
    persona::ssh_transport::ManagedSshTransport::new(ssh, ssh_keygen)
        .arguments(policy, destination, &command)
        .map(|_| ())
        .map_err(|error| match error {
            persona::ssh_transport::SshTransportError::RelativeExecutable(_) => {
                "transport executable is not absolute"
            }
            persona::ssh_transport::SshTransportError::UnsupportedDestination => {
                "SSH destination syntax is unsupported"
            }
            persona::ssh_transport::SshTransportError::DestinationMismatch => {
                "SSH destination differs from profile policy"
            }
            persona::ssh_transport::SshTransportError::UnsafePolicyPath(_) => {
                "SSH policy path is unsafe"
            }
            persona::ssh_transport::SshTransportError::PublicKeyMismatch => {
                "SSH key fingerprint differs from profile policy"
            }
            persona::ssh_transport::SshTransportError::UnsupportedRemoteCommand => {
                "Git remote command is unsupported"
            }
            _ => "managed SSH preflight failed",
        })
}

fn parse_ssh_remote(value: &str) -> Option<(String, String)> {
    let (authority, path) = if let Some(rest) = value.strip_prefix("ssh://") {
        let (authority, path) = rest.split_once('/')?;
        if authority.contains(['?', '#']) || path.is_empty() {
            return None;
        }
        (authority.to_owned(), path.to_owned())
    } else {
        let (authority, path) = value.split_once(':')?;
        if authority.matches('@').count() != 1 || path.is_empty() {
            return None;
        }
        (authority.to_owned(), path.to_owned())
    };
    if path.starts_with('-')
        || path.split('/').any(|part| matches!(part, "" | "." | ".."))
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        return None;
    }
    Some((authority, path))
}

fn safe_log_arguments(arguments: &[OsString]) -> bool {
    let mut index = 0;
    while index < arguments.len() {
        let Some(argument) = arguments[index].to_str() else {
            return false;
        };
        match argument {
            "--oneline" | "--decorate" | "--no-decorate" | "--no-color" => {}
            "-n" | "--max-count" => {
                index += 1;
                if !arguments
                    .get(index)
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
                {
                    return false;
                }
            }
            _ if argument.starts_with("--max-count=")
                && argument[12..].bytes().all(|byte| byte.is_ascii_digit()) => {}
            _ if argument.len() > 1
                && argument.starts_with('-')
                && argument[1..]
                    .bytes()
                    .all(|byte| byte == b'0' || byte.is_ascii_digit()) => {}
            _ => return false,
        }
        index += 1;
    }
    true
}

fn run_managed_ssh() -> Result<u8, String> {
    validate_managed_shim_directory()?;
    let mut arguments = std::env::args_os().skip(1).peekable();
    let mut requested_port = None;
    while arguments
        .peek()
        .is_some_and(|argument| argument.to_string_lossy().starts_with('-'))
    {
        match arguments
            .next()
            .and_then(|argument| argument.into_string().ok())
            .as_deref()
        {
            Some("-p") => {
                let port = arguments
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .and_then(|value| value.parse::<u16>().ok())
                    .filter(|port| *port != 0)
                    .ok_or_else(|| "SSH port argument is invalid".to_owned())?;
                requested_port = Some(port);
            }
            Some("-o")
                if arguments
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .as_deref()
                    == Some("SendEnv=GIT_PROTOCOL") => {}
            _ => return Err("unsupported SSH invocation option".to_owned()),
        }
    }
    let destination = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| "SSH destination is missing".to_owned())?;
    let remote_command = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| "SSH remote command is missing".to_owned())?;
    if arguments.next().is_some() {
        return Err("SSH invocation has unexpected trailing arguments".to_owned());
    }
    let (program, rest) = remote_command
        .split_once(" '")
        .ok_or_else(|| "SSH remote command is unsupported".to_owned())?;
    let planned_push_path = std::env::var("PERSONA_EXPECTED_SSH_PUSH_PATH").ok();
    let expected_program = if planned_push_path.is_some() {
        "git-receive-pack"
    } else {
        "git-upload-pack"
    };
    if program != expected_program || !rest.ends_with('\'') {
        return Err(
            "SSH remote command does not match the authorized managed operation".to_owned(),
        );
    }
    let path = &rest[..rest.len() - 1];
    if planned_push_path
        .as_deref()
        .is_some_and(|planned| planned != path)
    {
        return Err(
            "SSH receive-pack repository path differs from the authorized destination".to_owned(),
        );
    }
    let (user, host_with_port) = destination
        .split_once('@')
        .ok_or_else(|| "SSH destination must use an explicit user".to_owned())?;
    let (host, destination_port) = match host_with_port.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => (
            host,
            Some(
                port.parse::<u16>()
                    .ok()
                    .filter(|port| *port != 0)
                    .ok_or_else(|| "SSH destination port is invalid".to_owned())?,
            ),
        ),
        _ => (host_with_port, None),
    };
    let port = requested_port.or(destination_port).unwrap_or(22);
    if requested_port.is_some_and(|port| destination_port.is_some_and(|other| port != other)) {
        return Err("SSH port arguments do not agree".to_owned());
    }
    let ssh_url = format!(
        "ssh://{user}@{host}:{port}/{}",
        path.strip_prefix('/').unwrap_or(path)
    );

    let config_path = match std::env::var_os("PERSONA_CONFIG_PATH") {
        Some(path) => {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err("PERSONA_CONFIG_PATH must be absolute for managed SSH".to_owned());
            }
            path
        }
        None => resolve_config_path(None)?,
    };
    let config = Config::load(&config_path).map_err(|_| "cannot load Persona policy".to_owned())?;
    let cwd =
        std::env::current_dir().map_err(|_| "cannot resolve SSH working directory".to_owned())?;
    let git = git_executable();
    if !git.is_absolute() || !git.is_file() {
        return Err("native Git executable is unavailable".to_owned());
    }
    let home =
        tempfile::tempdir().map_err(|_| "cannot create isolated SSH preflight HOME".to_owned())?;
    let environment = vec![
        (OsString::from("HOME"), home.path().as_os_str().to_owned()),
        (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
        (
            OsString::from("GIT_CONFIG_SYSTEM"),
            OsString::from("/dev/null"),
        ),
        (
            OsString::from("GIT_CONFIG_GLOBAL"),
            OsString::from("/dev/null"),
        ),
        (OsString::from("GIT_TERMINAL_PROMPT"), OsString::from("0")),
    ];
    let client = GitClient::new(git, environment);
    let root = client.checkout_root(&cwd).unwrap_or(cwd);
    let scope = persona::context::resolve_context(&root, &config.scopes())
        .map_err(|_| "cannot resolve Persona scope for SSH".to_owned())?
        .ok_or_else(|| "SSH requires a managed Persona scope".to_owned())?;
    let policy = config
        .policies()
        .iter()
        .find(|policy| policy.name == scope.name)
        .ok_or_else(|| "SSH scope has no Git policy".to_owned())?;
    let push = policy
        .git
        .push
        .as_ref()
        .ok_or_else(|| "SSH requires an explicit allowed destination policy".to_owned())?;
    let profile = config
        .profiles()
        .iter()
        .find(|profile| profile.name == policy.profile)
        .ok_or_else(|| "SSH profile is unavailable".to_owned())?;
    let ssh_policy = profile
        .ssh
        .as_ref()
        .ok_or_else(|| "SSH profile has no transport policy".to_owned())?;
    let candidates = ssh_destination_candidates(user, host, port, path);
    if !candidates
        .iter()
        .any(|candidate| push.destinations.contains(candidate))
    {
        return Err("SSH destination is not explicitly allowed".to_owned());
    }
    validate_managed_ssh_destination(Some(ssh_policy), &ssh_url, expected_program)
        .map_err(|reason| format!("managed SSH policy rejected the request: {reason}"))?;
    let ssh = ssh_executable().ok_or_else(|| "OpenSSH executable is unavailable".to_owned())?;
    let ssh_keygen =
        ssh_keygen_executable().ok_or_else(|| "ssh-keygen executable is unavailable".to_owned())?;
    let mut command = persona::ssh_transport::ManagedSshTransport::new(ssh, ssh_keygen)
        .command(ssh_policy, &ssh_url, &remote_command)
        .map_err(|_| "managed SSH transport rejected the request".to_owned())?;
    let status = command
        .status()
        .map_err(|_| "cannot spawn managed SSH transport".to_owned())?;
    Ok(status_exit_code(status))
}

fn ssh_destination_candidates(user: &str, host: &str, port: u16, path: &str) -> Vec<String> {
    let url_path = path.strip_prefix('/').unwrap_or(path);
    let mut candidates = vec![format!("ssh://{user}@{host}:{port}/{url_path}")];
    if port == 22 {
        candidates.push(format!("ssh://{user}@{host}/{path}"));
        candidates.push(format!("{user}@{host}:{path}"));
    }
    candidates
}

fn safe_commit_arguments(arguments: &[OsString]) -> bool {
    let mut index = 0;
    let mut has_message = false;
    let mut amend = false;
    let mut no_edit = false;
    while index < arguments.len() {
        let Some(argument) = arguments[index].to_str() else {
            return false;
        };
        match argument {
            "-m" | "--message" => {
                index += 1;
                if index >= arguments.len() {
                    return false;
                }
                has_message = true;
            }
            _ if argument.starts_with("--message=") => has_message = true,
            "--quiet"
            | "-q"
            | "-a"
            | "--all"
            | "--allow-empty"
            | "--allow-empty-message"
            | "--signoff"
            | "-s" => {}
            "--amend" => amend = true,
            "--no-edit" => no_edit = true,
            _ => return false,
        }
        index += 1;
    }
    (has_message || no_edit) && (amend || !no_edit)
}

fn status_exit_code(status: std::process::ExitStatus) -> u8 {
    if let Some(code) = status.code() {
        code.clamp(0, u8::MAX as i32) as u8
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            status.signal().map_or(EXIT_ERROR, |signal| {
                (128 + signal).min(u8::MAX as i32) as u8
            })
        }
        #[cfg(not(unix))]
        {
            EXIT_ERROR
        }
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

fn parse_push_tuples(input: &str) -> Result<Vec<PushTuple>, String> {
    if input.len() > MAX_PUSH_INPUT_BYTES {
        return Err("push update input exceeds the 1 MiB limit".to_owned());
    }
    input
        .lines()
        .map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() != 4 {
                return Err("push update input must contain exactly four whitespace-separated fields per line".to_owned());
            }
            Ok(PushTuple {
                local_ref: fields[0].to_owned(),
                local_oid: fields[1].to_owned(),
                remote_ref: fields[2].to_owned(),
                remote_oid: fields[3].to_owned(),
            })
        })
        .collect()
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
                .map_err(|error| format!("cannot load Persona config: {error:?}"))?;
            let selected = persona::context::resolve_context(&cwd, &config.scopes())
                .map_err(|_| "cannot resolve Persona scope for shell marker".to_owned())?;
            if selected.is_some() {
                print!("[scope]");
            }
            Ok(0)
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
                installer::refresh()?
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
    if let Some(backup) = result {
        println!("Backup: {}", backup.display());
    }
    if !preview_only {
        println!("Installation operation complete.");
    }
    Ok(0)
}

fn hooks_command(command: HookCommands) -> Result<u8, String> {
    let cwd = match &command {
        HookCommands::Install { cwd, .. } | HookCommands::Remove { cwd, .. } => cwd,
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
                .map_err(|error| format!("cannot load Persona config: {error:?}"))?;
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
            persona::hooks::install(
                &paths,
                &config_path,
                &persona_dispatcher_executable()?,
                preview,
            )?
        }
        HookCommands::Remove { preview, .. } => persona::hooks::uninstall(&paths, preview)?,
    };
    println!("{message}");
    Ok(0)
}

fn hook_git_client() -> Result<(tempfile::TempDir, GitClient), String> {
    let executable = git_executable();
    if !executable.is_absolute() || !executable.is_file() {
        return Err("native Git executable is unavailable".to_owned());
    }
    let home = tempfile::tempdir().map_err(|_| "cannot create isolated Git HOME".to_owned())?;
    let environment = vec![
        (OsString::from("HOME"), home.path().as_os_str().to_owned()),
        (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
        (
            OsString::from("GIT_CONFIG_SYSTEM"),
            OsString::from("/dev/null"),
        ),
        (
            OsString::from("GIT_CONFIG_GLOBAL"),
            OsString::from("/dev/null"),
        ),
        (OsString::from("GIT_TERMINAL_PROMPT"), OsString::from("0")),
    ];
    Ok((home, GitClient::new(executable, environment)))
}

fn run_managed_pre_push() -> Result<u8, String> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 2 {
        return Err("Git supplied an unsupported pre-push argument vector".to_owned());
    }
    let remote = arguments[0]
        .to_str()
        .filter(|remote| !remote.is_empty() && remote.len() <= 128)
        .ok_or_else(|| "pre-push remote name is invalid".to_owned())?;
    let destination = arguments[1]
        .to_str()
        .ok_or_else(|| "pre-push destination is not valid UTF-8".to_owned())?;
    let cwd =
        std::env::current_dir().map_err(|_| "cannot resolve hook working directory".to_owned())?;
    let (_home, git) = hook_git_client()?;
    let root = git
        .checkout_root(&cwd)
        .map_err(|_| "pre-push hook is not running in a Git worktree".to_owned())?;
    let paths = persona::hooks::resolve_paths(&git, &root)?;
    let manifest = persona::hooks::load_manifest(&paths)?;
    let executable = persona_dispatcher_executable()?;
    if manifest.persona_executable() != executable {
        return Err("pre-push hook manifest belongs to a different Persona executable".to_owned());
    }

    let mut input = Vec::new();
    std::io::stdin()
        .take((MAX_PUSH_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| "cannot read bounded Git pre-push input".to_owned())?;
    if input.len() > MAX_PUSH_INPUT_BYTES {
        return Err("Git pre-push input exceeds the 1 MiB limit".to_owned());
    }
    let input_text = std::str::from_utf8(&input)
        .map_err(|_| "Git pre-push input is not valid UTF-8".to_owned())?;
    let tuples = parse_push_tuples(input_text)?;
    let checker = executable;
    let native_git = git_executable();
    let mut authorization = Command::new(checker);
    authorization
        .args(["check", "--config"])
        .arg(manifest.config_path())
        .args(["--cwd"])
        .arg(&root)
        .args([
            "--format",
            "json",
            "--operation",
            "push",
            "--remote",
            remote,
            "--destination-stdin",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", native_git)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(home) = std::env::var_os("HOME") {
        authorization.env("HOME", home);
    }
    if let Some(handoff) = std::env::var_os("PERSONA_PUSH_HANDOFF") {
        authorization.arg("--primary-handoff").arg(handoff);
    }
    for variable in [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "GH_HOST",
        "GH_CONFIG_DIR",
    ] {
        if std::env::var_os(variable).is_some() {
            authorization.env(variable, "");
        }
    }
    for variable in ["XDG_CONFIG_HOME", "XDG_STATE_HOME"] {
        if let Some(value) = std::env::var_os(variable) {
            authorization.env(variable, value);
        }
    }
    for (variable, executable) in [
        ("PERSONA_GH", gh_executable()),
        ("PERSONA_GPG", gpg_executable()),
        ("PERSONA_SSH_KEYGEN", ssh_keygen_executable()),
    ] {
        if let Some(executable) = executable {
            if executable.is_absolute() && executable.is_file() {
                authorization.env(variable, executable);
            }
        }
    }
    let mut child = authorization
        .spawn()
        .map_err(|_| "cannot launch isolated pre-push authorization".to_owned())?;
    let mut authorization_stdin = child
        .stdin
        .take()
        .ok_or_else(|| "pre-push authorization stdin is unavailable".to_owned())?;
    authorization_stdin
        .write_all(destination.as_bytes())
        .and_then(|()| authorization_stdin.write_all(&[0]))
        .and_then(|()| authorization_stdin.write_all(&input))
        .map_err(|_| "cannot pass framed native hook input to authorization".to_owned())?;
    drop(authorization_stdin);
    let output = child
        .wait_with_output()
        .map_err(|_| "cannot collect pre-push authorization result".to_owned())?;
    if !output.status.success() {
        if !output.stdout.is_empty() {
            std::io::stdout()
                .write_all(&output.stdout)
                .map_err(|_| "cannot report pre-push authorization result".to_owned())?;
        }
        if !output.stderr.is_empty() {
            std::io::stderr()
                .write_all(&output.stderr)
                .map_err(|_| "cannot report pre-push authorization error".to_owned())?;
        }
        return Ok(output.status.code().unwrap_or(1).clamp(1, u8::MAX as i32) as u8);
    }

    if let Some(original) = manifest.original_hook(&paths) {
        let mut hook = Command::new(original)
            .args([remote, destination])
            .current_dir(&root)
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| "cannot launch the preserved pre-push hook".to_owned())?;
        hook.stdin
            .take()
            .ok_or_else(|| "preserved hook stdin is unavailable".to_owned())?
            .write_all(&input)
            .map_err(|_| "cannot pass input to the preserved pre-push hook".to_owned())?;
        let status = hook
            .wait()
            .map_err(|_| "cannot wait for the preserved pre-push hook".to_owned())?;
        return Ok(status_exit_code(status));
    }
    let _ = tuples;
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
    let config = Config::load(&config_path).map_err(|error| format!("{error:?}"))?;
    let executables = ExecutablePaths {
        git: git_executable(),
        gpg: gpg_executable(),
        ssh_keygen: ssh_keygen_executable(),
    };
    let (report, _) = build_report(&config, &directory, None, &executables)?;
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
    let mut path_entries = vec![shims.path().to_path_buf()];
    if let Some(path) = std::env::var_os("PATH") {
        path_entries.extend(std::env::split_paths(&path));
    }
    let path = std::env::join_paths(path_entries)
        .map_err(|error| format!("cannot construct managed PATH: {error}"))?;
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
    let status = child
        .status()
        .map_err(|error| format!("cannot launch requested program: {error}"))?;
    if let Some(code) = status.code() {
        Ok(code.clamp(0, u8::MAX as i32) as u8)
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            Ok(status.signal().map_or(EXIT_ERROR, |signal| {
                (128 + signal).min(u8::MAX as i32) as u8
            }))
        }
        #[cfg(not(unix))]
        {
            Ok(EXIT_ERROR)
        }
    }
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

fn consume_primary_handoff(path: &Path) -> Result<(), String> {
    let paths = PersonaPaths::discover()
        .map_err(|_| "cannot resolve private state while consuming push handoff".to_owned())?;
    if path.parent() != Some(paths.state_dir.as_path()) {
        return Err("push handoff is outside private Persona state".to_owned());
    }
    std::fs::remove_file(path)
        .map_err(|_| "cannot consume one-time primary push authorization handoff".to_owned())
}

fn validate_primary_handoff(
    handoff_path: &Path,
    config_path: &Path,
    directory: &Path,
    request: &mut PushRequest,
) -> Result<Option<persona::push_handoff::HandoffGithubBinding>, String> {
    let paths = PersonaPaths::discover()
        .map_err(|_| "cannot resolve private state for push handoff verification".to_owned())?;
    let handoff = persona::push_handoff::read(&paths, handoff_path)?;
    let config_path = std::fs::canonicalize(config_path)
        .map_err(|_| "cannot resolve current policy for push handoff verification".to_owned())?;
    let handoff_config = std::fs::canonicalize(&handoff.config_path)
        .map_err(|_| "handoff policy path is unavailable".to_owned())?;
    if config_path != handoff_config || sha256_file(&config_path)? != handoff.config_sha256 {
        return Err("policy changed after primary push authorization".to_owned());
    }
    let git = GitClient::new(git_executable(), persona::git::safe_environment());
    let root = git
        .checkout_root(directory)
        .map_err(|_| "cannot resolve hook checkout for push handoff verification".to_owned())?;
    let hook_paths = persona::hooks::resolve_paths(&git, &root)?;
    let manifest_path = std::fs::canonicalize(&hook_paths.manifest)
        .map_err(|_| "installed hook manifest is unavailable".to_owned())?;
    if manifest_path != handoff.hook_manifest_path
        || sha256_file(&manifest_path)? != handoff.hook_manifest_sha256
    {
        return Err("installed hook manifest changed after primary authorization".to_owned());
    }
    if root != handoff.checkout_root
        || request.remote != handoff.remote
        || request.destination != handoff.destination
        || request.tuples.len() != handoff.tuples.len()
        || !request
            .tuples
            .iter()
            .zip(&handoff.tuples)
            .all(|(tuple, planned)| {
                tuple.local_ref == planned.local_ref
                    && tuple.local_oid == planned.local_oid
                    && tuple.remote_ref == planned.remote_ref
                    && tuple.remote_oid == planned.remote_oid
                    && planned
                        .expected_lease_oid
                        .as_deref()
                        .is_none_or(|oid| oid == tuple.remote_oid)
            })
    {
        return Err(
            "hook context or native ref/OID updates differ from primary authorization".to_owned(),
        );
    }
    request.leases = handoff
        .tuples
        .iter()
        .filter_map(|planned| {
            planned.expected_lease_oid.as_ref().map(|expected_oid| {
                persona::git_command::ExactPushLease {
                    remote_ref: planned.remote_ref.clone(),
                    expected_oid: expected_oid.clone(),
                }
            })
        })
        .collect();
    let config =
        Config::load(&config_path).map_err(|_| "cannot reload current policy".to_owned())?;
    let executables = ExecutablePaths {
        git: git_executable(),
        gpg: gpg_executable(),
        ssh_keygen: ssh_keygen_executable(),
    };
    let (_, selected) = build_report(&config, directory, Some(request), &executables)?;
    let selected =
        selected.ok_or_else(|| "push checkout is no longer in a managed scope".to_owned())?;
    let policy = config
        .policies()
        .iter()
        .find(|policy| policy.name == selected.name)
        .ok_or_else(|| "push scope no longer resolves a policy".to_owned())?;
    let profile = config
        .profiles()
        .iter()
        .find(|profile| profile.name == policy.profile)
        .ok_or_else(|| "push scope no longer resolves a profile".to_owned())?;
    if profile.name != handoff.profile {
        return Err("selected profile changed after primary push authorization".to_owned());
    }
    let binding =
        profile
            .github
            .as_ref()
            .map(|binding| persona::push_handoff::HandoffGithubBinding {
                host: binding.host.clone(),
                account_id: binding.account_id.clone(),
            });
    if handoff.github_binding != binding {
        return Err("enrolled GitHub binding changed after primary push authorization".to_owned());
    }
    Ok(binding)
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes =
        std::fs::read(path).map_err(|_| "cannot read policy for push handoff".to_owned())?;
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    Ok(output)
}

fn push_authorization_requirements(request: &PushRequest, signing_required: bool) -> Vec<String> {
    let mut required = vec![
        "scope".to_owned(),
        "policy.profile".to_owned(),
        "git.worktree".to_owned(),
        "git.push.destination".to_owned(),
        "git.push.updates".to_owned(),
        "git.push.author".to_owned(),
        "git.push.committer".to_owned(),
    ];
    if request
        .tuples
        .iter()
        .any(|tuple| tuple.remote_ref.starts_with("refs/tags/") && tuple.local_ref != "(delete)")
    {
        required.push("git.push.tag_signature".to_owned());
    }
    if signing_required {
        required.extend([
            "git.push.signature.present".to_owned(),
            "git.push.signature.valid".to_owned(),
            "git.push.signature.fingerprint".to_owned(),
        ]);
    }
    required
}

fn show_status(
    config_path: &Path,
    directory: &Path,
    format: OutputFormat,
    verbose: bool,
    push: Option<PushRequest>,
    handoff_binding: Option<persona::push_handoff::HandoffGithubBinding>,
    online_verified: bool,
) -> Result<u8, String> {
    let current_directory = std::env::current_dir()
        .map_err(|error| format!("cannot determine current directory: {error}"))?;
    let config_path = absolute_path(config_path, &current_directory);
    let directory = absolute_path(directory, &current_directory);
    let config = Config::load(&config_path).map_err(|error| format!("{error:?}"))?;
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
        if host != binding.host
            || !binding.repositories.iter().any(|candidate| {
                persona::gh_adapter::normalize_repository(candidate)
                    .is_ok_and(|normalized| normalized == repository)
            })
        {
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
    let report = Report::new(findings);
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
    let config = Config::load(&config_path).map_err(|error| format!("{error:?}"))?;
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
    if !verbose {
        let scope = selected
            .map(|scope| scope.name.as_str())
            .unwrap_or("unmanaged");
        println!("Persona: {scope} — {:?}", report.status);
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
                if decision.is_allowed() {
                    "ALLOW"
                } else {
                    "BLOCK"
                }
            );
        }
        println!("Use `persona doctor` or `--verbose` for offline findings.");
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
    println!("result: {}", format!("{:?}", report.status).to_uppercase());
    if let Some(decision) = decision {
        println!(
            "authorization: {} ({:?})",
            if decision.is_allowed() {
                "ALLOW"
            } else {
                "BLOCK"
            },
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
        let _ = write!(
            details,
            "finding {}: {:?} ({}), ",
            finding.property, finding.status, finding.coverage_reason
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
        .map_err(|error| format!("cannot resolve Persona paths: {error:?}"))?;
    paths
        .validate_private_config()
        .map_err(|error| format!("unsafe private configuration: {error:?}"))?;
    if paths.config_file.exists() {
        return Err("Persona is already configured; refusing to overwrite it".to_owned());
    }
    let current = std::env::current_dir()
        .map_err(|error| format!("cannot determine current directory: {error}"))?;
    let scope_root = physical_scope_root(&absolute_path(&args.scope, &current))?;
    let author_name = setup_value(args.author_name, "Author name")?;
    let author_email = setup_value(args.author_email, "Author email")?;
    let committer_name = setup_value(args.committer_name, "Committer name")?;
    let committer_email = setup_value(args.committer_email, "Committer email")?;
    let profile = Profile {
        name: args.profile,
        github: None,
        ssh: None,
        github_merge: None,
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
        },
    };
    let config = Config::single_scope(profile, args.scope_name, scope_root)
        .map_err(|error| format!("invalid initial profile/scope: {error:?}"))?;
    let contents = config
        .to_v3_toml()
        .map_err(|error| format!("cannot encode initial configuration: {error:?}"))?;
    paths
        .ensure_private_directories()
        .map_err(|error| format!("cannot prepare private Persona paths: {error:?}"))?;
    paths
        .create_config(contents.as_bytes())
        .map_err(|error| format!("cannot securely create Persona configuration: {error:?}"))?;
    println!(
        "Created private Persona configuration at {}",
        paths.config_file.display()
    );
    println!("No Git, SSH, GPG, GitHub, or credential settings were changed.");
    Ok(0)
}

fn setup_value(value: Option<String>, label: &str) -> Result<String, String> {
    if let Some(value) = value {
        if value.trim().is_empty() {
            return Err(format!("{label} cannot be empty"));
        }
        return Ok(value);
    }
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return Err(format!(
            "{label} is required; supply its --{} flag or run setup interactively",
            label.to_ascii_lowercase().replace(' ', "-")
        ));
    }
    print!("{label}: ");
    std::io::Write::flush(&mut std::io::stdout())
        .map_err(|error| format!("cannot write setup prompt: {error}"))?;
    let mut value = String::new();
    std::io::stdin()
        .read_line(&mut value)
        .map_err(|error| format!("cannot read setup input: {error}"))?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(value)
}

fn physical_scope_root(path: &Path) -> Result<PathBuf, String> {
    let canonical = persona::paths::canonical_directory(path)
        .map_err(|error| format!("invalid scope directory: {error:?}"))?;
    let git = GitClient::new(git_executable(), Vec::new());
    match git.checkout_root(&canonical) {
        Ok(root) => Ok(root),
        Err(persona::git::GitError::CommandFailed(_)) => Ok(canonical),
        Err(error) => Err(format!("cannot identify physical worktree root: {error:?}")),
    }
}

fn resolve_config_path(explicit: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    let paths = PersonaPaths::discover()
        .map_err(|error| format!("cannot resolve Persona paths: {error:?}"))?;
    paths
        .validate_private_config()
        .map_err(|error| format!("unsafe private configuration: {error:?}"))?;
    if !paths.config_file.is_file() {
        return Err(format!(
            "no Persona configuration at {}; run `persona setup` or pass --config",
            paths.config_file.display()
        ));
    }
    Ok(paths.config_file)
}

fn preview_config_migration(config_path: &Path) -> Result<u8, String> {
    let config = Config::load(config_path).map_err(|error| format!("{error:?}"))?;
    let preview = config
        .to_v3_toml()
        .map_err(|error| format!("cannot migrate configuration: {error:?}"))?;
    print!("{preview}");
    Ok(0)
}

fn apply_config_migration() -> Result<u8, String> {
    let paths = PersonaPaths::discover()
        .map_err(|error| format!("cannot resolve Persona paths: {error:?}"))?;
    paths
        .validate_private_config()
        .map_err(|error| format!("unsafe private configuration: {error:?}"))?;
    let config = Config::load(&paths.config_file)
        .map_err(|error| format!("cannot load private configuration: {error:?}"))?;
    if config.version() == 3 {
        return Err("configuration is already version 3".to_owned());
    }
    let contents = config
        .to_v3_toml()
        .map_err(|error| format!("cannot migrate configuration: {error:?}"))?;
    let backup = paths
        .write_config(contents.as_bytes())
        .map_err(|error| format!("cannot atomically migrate configuration: {error:?}"))?;
    println!("Migrated private configuration to v3.");
    if let Some(backup) = backup {
        println!("Backup: {}", backup.display());
    }
    Ok(0)
}

fn rollback_config(backup: &Path) -> Result<u8, String> {
    let paths = PersonaPaths::discover()
        .map_err(|error| format!("cannot resolve Persona paths: {error:?}"))?;
    let previous = paths
        .rollback(backup)
        .map_err(|error| format!("cannot roll back configuration: {error:?}"))?;
    println!("Restored configuration from {}.", backup.display());
    if let Some(previous) = previous {
        println!(
            "The replaced configuration was backed up to {}.",
            previous.display()
        );
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
    let config = load_config(configured_path.as_deref())?;
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
    let push_policy =
        policy.git.push.as_ref().ok_or_else(|| {
            "managed Persona profile has no allowed HTTPS destinations".to_owned()
        })?;
    let gh = gh_executable().ok_or_else(|| "GitHub CLI is unavailable".to_owned())?;
    let paths =
        PersonaPaths::discover().map_err(|_| "cannot resolve Persona private state".to_owned())?;
    let selector = persona::credential::GithubSelector::discover(gh, binding.host.clone(), paths)
        .map_err(|_| "cannot inspect native GitHub credential selector".to_owned())?;
    let mut output = std::io::stdout().lock();
    persona::git_https::handle_credential_helper(
        action,
        input.expose(),
        binding,
        push_policy,
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

fn profile_command(command: ProfileCommands) -> Result<u8, String> {
    match command {
        ProfileCommands::List { config } => {
            let config = load_config(config.as_deref())?;
            for profile in config.profiles() {
                println!("{}", profile.name);
            }
            Ok(0)
        }
        ProfileCommands::Show { name, config } => {
            let config = load_config(config.as_deref())?;
            let profile = config
                .profiles()
                .iter()
                .find(|profile| profile.name == name)
                .ok_or_else(|| format!("profile `{name}` does not exist"))?;
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
            }
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
            let mut config = load_private_config()?;
            let preview = args.preview;
            let profile = profile_from_args(*args, None)?;
            config
                .add_profile(profile)
                .map_err(|error| format!("cannot add profile: {error:?}"))?;
            persist_private_config(&config, preview)
        }
        ProfileCommands::Update(args) => {
            let mut config = load_private_config()?;
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
                .map_err(|error| format!("cannot update profile: {error:?}"))?;
            persist_private_config(&config, preview)
        }
        ProfileCommands::Remove { name, preview } => {
            let mut config = load_private_config()?;
            config
                .remove_profile(&name)
                .map_err(|error| format!("cannot remove profile: {error:?}"))?;
            persist_private_config(&config, preview)
        }
    }
}

fn configured_fetch_destinations<'a>(
    profile: &'a Profile,
    remote_name: &str,
) -> Option<&'a [String]> {
    profile
        .git
        .remotes
        .iter()
        .find(|remote| remote.name == remote_name)
        .map(|remote| remote.fetch_destinations.as_slice())
        .or_else(|| {
            profile
                .git
                .push
                .as_ref()
                .filter(|push| push.remote == remote_name)
                .map(|push| push.destinations.as_slice())
        })
}

fn configured_push_destinations<'a>(
    profile: &'a Profile,
    remote_name: &str,
) -> Option<&'a [String]> {
    profile
        .git
        .remotes
        .iter()
        .find(|remote| remote.name == remote_name)
        .map(|remote| remote.push_destinations.as_slice())
        .or_else(|| {
            profile
                .git
                .push
                .as_ref()
                .filter(|push| push.remote == remote_name)
                .map(|push| push.destinations.as_slice())
        })
}

fn profile_from_args(args: ProfileEditArgs, existing: Option<&Profile>) -> Result<Profile, String> {
    let signing = match (args.signing_fingerprint, args.public_key) {
        (Some(fingerprint), Some(public_key)) => Some(persona::config::SigningPolicy {
            fingerprint,
            format: match args.signing_format.as_deref().unwrap_or("openpgp") {
                "openpgp" => persona::config::SigningFormat::OpenPgp,
                "ssh" => persona::config::SigningFormat::Ssh,
                _ => return Err("--signing-format must be `openpgp` or `ssh`".to_owned()),
            },
            public_key,
        }),
        (None, None) if args.signing_format.is_none() => {
            existing.and_then(|profile| profile.git.signing.clone())
        }
        (None, None) => {
            return Err(
                "--signing-format requires --signing-fingerprint and --public-key".to_owned(),
            );
        }
        _ => {
            return Err(
                "--signing-fingerprint and --public-key must be supplied together".to_owned(),
            );
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
        Some(persona::config::SshPolicy {
            host: args
                .ssh_host
                .ok_or_else(|| "--ssh-host required for SSH policy".to_owned())?,
            user: args
                .ssh_user
                .ok_or_else(|| "--ssh-user required for SSH policy".to_owned())?,
            port: args
                .ssh_port
                .ok_or_else(|| "--ssh-port required for SSH policy".to_owned())?,
            fingerprint: args
                .ssh_fingerprint
                .ok_or_else(|| "--ssh-fingerprint required for SSH policy".to_owned())?,
            public_key: args
                .ssh_public_key
                .ok_or_else(|| "--ssh-public-key required for SSH policy".to_owned())?,
            identity_file: args.ssh_identity_file,
            agent_socket: args.ssh_agent_socket,
            known_hosts_file: args
                .ssh_known_hosts_file
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

    let github = if args.clear_github_repositories {
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
            .map(|repository| persona::gh_adapter::normalize_repository(repository))
            .collect::<Result<Vec<_>, _>>()?;
        Some(binding)
    } else {
        existing.and_then(|profile| profile.github.clone())
    };
    Ok(Profile {
        name: args.name,
        github,
        ssh,
        github_merge,
        git: GitPolicy {
            author: Identity {
                name: args.author_name,
                email: args.author_email,
            },
            committer: Identity {
                name: args.committer_name,
                email: args.committer_email,
            },
            signing,
            push,
            remotes,
        },
    })
}

fn scope_command(command: ScopeCommands) -> Result<u8, String> {
    match command {
        ScopeCommands::List { config } => {
            let config = load_config(config.as_deref())?;
            for scope in config.policies() {
                println!(
                    "{}\t{}\t{}",
                    scope.name,
                    scope.path.display(),
                    scope.profile
                );
            }
            Ok(0)
        }
        ScopeCommands::Show { name, config } | ScopeCommands::Verify { name, config } => {
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
            let mut config = load_private_config()?;
            let current = std::env::current_dir()
                .map_err(|error| format!("cannot determine current directory: {error}"))?;
            let root = physical_scope_root(&absolute_path(&path, &current))?;
            config
                .add_scope(name, root, &profile)
                .map_err(|error| format!("cannot add scope: {error:?}"))?;
            persist_private_config(&config, preview)
        }
        ScopeCommands::Update {
            name,
            path,
            profile,
            preview,
        } => {
            let mut config = load_private_config()?;
            let current = std::env::current_dir()
                .map_err(|error| format!("cannot determine current directory: {error}"))?;
            let root = physical_scope_root(&absolute_path(&path, &current))?;
            config
                .update_scope(&name, root, &profile)
                .map_err(|error| format!("cannot update scope: {error:?}"))?;
            persist_private_config(&config, preview)
        }
        ScopeCommands::Remove { name, preview } => {
            let mut config = load_private_config()?;
            config
                .remove_scope(&name)
                .map_err(|error| format!("cannot remove scope: {error:?}"))?;
            persist_private_config(&config, preview)
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
                .map_err(|error| format!("cannot resolve Persona paths: {error:?}"))?;
            paths
                .validate_private_config()
                .map_err(|error| format!("unsafe private configuration: {error:?}"))?;
            let mut config = Config::load(&paths.config_file)
                .map_err(|error| format!("cannot load private configuration: {error:?}"))?;
            let existing = config
                .profiles()
                .iter()
                .find(|item| item.name == profile)
                .cloned()
                .ok_or_else(|| format!("profile `{profile}` does not exist"))?;
            let gh = gh_executable().ok_or_else(|| {
                "cannot find gh; set PERSONA_GH to an absolute gh executable".to_owned()
            })?;
            let selector = persona::credential::GithubSelector::discover(gh, host.clone(), paths)
                .map_err(|error| {
                format!("cannot safely select native GitHub credentials: {error:?}")
            })?;
            let binding = selector
                .enroll(confirm_online, &user)
                .map_err(|error| format!("GitHub enrollment failed: {error:?}"))?;
            let mut updated = existing;
            updated.github = Some(binding.clone());
            config
                .update_profile(updated)
                .map_err(|error| format!("cannot bind GitHub account: {error:?}"))?;
            persist_private_config(&config, false)?;
            println!(
                "Bound stable GitHub account ID {} on {} to profile `{}`.",
                binding.account_id, binding.host, profile
            );
            println!(
                "The native token was not stored by Persona; only a keyed non-reversible fingerprint was saved."
            );
            Ok(0)
        }
        AuthCommands::Verify { profile } => {
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
                .map_err(|error| format!("cannot resolve Persona paths: {error:?}"))?;
            let selector =
                persona::credential::GithubSelector::discover(gh, binding.host.clone(), paths)
                    .map_err(|error| {
                        format!("cannot safely select native GitHub credentials: {error:?}")
                    })?;
            match selector.matches_selected_account(binding) {
                Ok(true) => {
                    println!(
                        "Selected native credential matches bound account ID {} on {}.",
                        binding.account_id, binding.host
                    );
                    Ok(0)
                }
                Ok(false) => {
                    println!(
                        "BLOCK: selected native credential does not match profile `{profile}`."
                    );
                    Ok(1)
                }
                Err(error) => {
                    println!("UNKNOWN: cannot verify selected native credential ({error:?}).");
                    Ok(1)
                }
            }
        }
        AuthCommands::Unbind { profile, preview } => {
            let mut config = load_private_config()?;
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
                .map_err(|error| format!("cannot remove GitHub binding: {error:?}"))?;
            persist_private_config(&config, preview)
        }
    }
}

fn load_config(explicit: Option<&Path>) -> Result<Config, String> {
    let path = resolve_config_path(explicit)?;
    Config::load(&path).map_err(|error| format!("{error:?}"))
}

fn load_private_config() -> Result<Config, String> {
    let paths = PersonaPaths::discover()
        .map_err(|error| format!("cannot resolve Persona paths: {error:?}"))?;
    paths
        .validate_private_config()
        .map_err(|error| format!("unsafe private configuration: {error:?}"))?;
    Config::load(&paths.config_file)
        .map_err(|error| format!("cannot load private configuration: {error:?}"))
}

fn persist_private_config(config: &Config, preview: bool) -> Result<u8, String> {
    let paths = PersonaPaths::discover()
        .map_err(|error| format!("cannot resolve Persona paths: {error:?}"))?;
    paths
        .validate_private_config()
        .map_err(|error| format!("unsafe private configuration: {error:?}"))?;
    let contents = config
        .to_v3_toml()
        .map_err(|error| format!("cannot serialize configuration: {error:?}"))?;
    Config::parse(&contents)
        .map_err(|error| format!("refusing invalid configuration: {error:?}"))?;
    if preview {
        println!("Preview only; no configuration was written.");
        print!("{contents}");
        return Ok(0);
    }
    let backup = paths
        .write_config(contents.as_bytes())
        .map_err(|error| format!("cannot atomically write configuration: {error:?}"))?;
    println!("Updated private Persona configuration.");
    if let Some(backup) = backup {
        println!("Backup: {}", backup.display());
    }
    Ok(0)
}

fn git_executable() -> PathBuf {
    if let Some(path) = std::env::var_os("PERSONA_GIT") {
        return PathBuf::from(path);
    }
    find_executable("git").unwrap_or_else(|| PathBuf::from("/usr/bin/git"))
}

fn gh_executable() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PERSONA_GH") {
        let path = PathBuf::from(path);
        return path
            .is_absolute()
            .then_some(path)
            .filter(|path| path.is_file());
    }
    find_executable("gh")
}

fn ssh_executable() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PERSONA_SSH") {
        let path = PathBuf::from(path);
        return path
            .is_absolute()
            .then_some(path)
            .filter(|path| path.is_file());
    }
    find_executable("ssh")
}

fn ssh_keygen_executable() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PERSONA_SSH_KEYGEN") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    find_executable("ssh-keygen")
}

fn gpg_executable() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PERSONA_GPG") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    find_executable("gpg")
}

fn find_executable(name: &str) -> Option<PathBuf> {
    let current = std::env::current_exe()
        .ok()
        .and_then(|path| std::fs::canonicalize(path).ok());
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join(name))
        .find(|path| {
            path.is_file()
                && std::fs::canonicalize(path)
                    .ok()
                    .is_some_and(|canonical| Some(canonical) != current)
        })
}

fn absolute_path(path: &Path, base: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}
