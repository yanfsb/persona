use crate::audit::{ExecutablePaths, PushRequest, build_report};
use crate::authorization::{Operation as AuthorizationOperation, authorize};
use crate::config::{Config, Profile, ScopePolicy};
use crate::git::{GitClient, PushTuple};
use crate::git_command::{GitInvocation, GitSubcommand, PushInvocation, normalize_ref};
use crate::runtime::{
    build_managed_path, gh_executable, git_executable, gpg_executable, isolated_git_environment,
    persona_dispatcher_executable, resolve_config_path, sha256_file, ssh_keygen_executable,
    status_exit_code, validate_managed_shim_directory,
};
use crate::ssh_adapter::validate_managed_ssh_destination;
use crate::storage::PersonaPaths;
use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command;

struct PushPrimaryEvidence {
    hook_manifest_path: PathBuf,
    hook_manifest_sha256: String,
}

struct ManagedFetchAllContext<'a> {
    native_git: &'a Path,
    directory: &'a Path,
    git_arguments: &'a [OsString],
    global_arguments: &'a [OsString],
    targets: &'a [(String, String, bool)],
    config_path: &'a Path,
    isolated_home: &'a Path,
    managed_path: &'a std::ffi::OsStr,
    ssh_adapter: &'a Path,
    shim_directory: &'a Path,
    native_gh: Option<&'a Path>,
}

struct ClassifiedGitCommand {
    selectors: Vec<String>,
    flags: Vec<String>,
    display: String,
}

fn classify_git_command(subcommand: &GitSubcommand, args: &[OsString]) -> ClassifiedGitCommand {
    let words: Vec<&str> = args
        .iter()
        .filter_map(|argument| argument.to_str())
        .collect();
    let mut flags = Vec::new();
    for word in &words {
        if *word == "--" {
            break;
        }
        if word.starts_with('-') && word.len() > 1 {
            flags.push((*word).to_owned());
        }
    }
    let positionals_before_dash: Vec<&str> = words
        .iter()
        .copied()
        .take_while(|word| *word != "--")
        .filter(|word| !word.starts_with('-'))
        .collect();

    let selectors: Vec<String> = match subcommand {
        GitSubcommand::Fetch => {
            if flags.iter().any(|flag| flag == "--all") {
                vec!["fetch.all".to_owned()]
            } else {
                vec!["fetch".to_owned()]
            }
        }
        GitSubcommand::Remote => {
            let sub = positionals_before_dash.first().copied().unwrap_or("list");
            let normalized = match sub {
                "rm" => "remove",
                other => other,
            };
            vec![format!("remote.{}", normalized.to_ascii_lowercase())]
        }
        GitSubcommand::Branch => {
            let is_delete = flags
                .iter()
                .any(|flag| matches!(flag.as_str(), "-d" | "-D" | "--delete"));
            let is_rename = flags.iter().any(|flag| {
                matches!(
                    flag.as_str(),
                    "-m" | "-M" | "--move" | "-c" | "-C" | "--copy"
                )
            });
            let is_list = positionals_before_dash.is_empty()
                || flags.iter().any(|flag| {
                    matches!(
                        flag.as_str(),
                        "--list"
                            | "-l"
                            | "--show-current"
                            | "-a"
                            | "--all"
                            | "-r"
                            | "--remotes"
                            | "-v"
                            | "-vv"
                            | "--contains"
                            | "--no-contains"
                            | "--merged"
                            | "--no-merged"
                    )
                });
            if is_delete {
                vec!["branch.delete".to_owned()]
            } else if is_rename {
                vec!["branch.rename".to_owned()]
            } else if is_list {
                vec!["branch.list".to_owned()]
            } else {
                vec!["branch.create".to_owned()]
            }
        }
        GitSubcommand::Worktree => {
            let sub = positionals_before_dash.first().copied().unwrap_or("list");
            vec![format!("worktree.{}", sub.to_ascii_lowercase())]
        }
        GitSubcommand::Tag => {
            if flags
                .iter()
                .any(|flag| matches!(flag.as_str(), "-d" | "--delete"))
            {
                vec!["tag.delete".to_owned()]
            } else if flags
                .iter()
                .any(|flag| matches!(flag.as_str(), "-v" | "--verify"))
            {
                vec!["tag.verify".to_owned()]
            } else if positionals_before_dash.is_empty()
                || flags
                    .iter()
                    .any(|flag| matches!(flag.as_str(), "-l" | "--list"))
            {
                vec!["tag.list".to_owned()]
            } else if flags
                .iter()
                .any(|flag| matches!(flag.as_str(), "-s" | "--sign"))
            {
                vec!["tag.signed".to_owned()]
            } else if flags
                .iter()
                .any(|flag| matches!(flag.as_str(), "-a" | "--annotate"))
            {
                vec!["tag.annotated".to_owned()]
            } else {
                vec!["tag.lightweight".to_owned()]
            }
        }
        GitSubcommand::Commit => {
            if flags.iter().any(|flag| flag == "--amend") {
                vec!["commit.amend".to_owned()]
            } else {
                vec!["commit".to_owned()]
            }
        }
        GitSubcommand::Push => {
            let mut modifiers = Vec::new();
            let has_plus_refspec = positionals_before_dash
                .iter()
                .any(|word| word.starts_with('+'));
            if has_plus_refspec
                || flags
                    .iter()
                    .any(|flag| matches!(flag.as_str(), "-f" | "--force"))
            {
                modifiers.push("push.force".to_owned());
            }
            if flags
                .iter()
                .any(|flag| flag == "--force-with-lease" || flag.starts_with("--force-with-lease="))
            {
                modifiers.push("push.force-with-lease".to_owned());
            }
            if flags
                .iter()
                .any(|flag| matches!(flag.as_str(), "-d" | "--delete"))
                || positionals_before_dash
                    .iter()
                    .skip(1)
                    .any(|spec| spec.starts_with(':'))
            {
                modifiers.push("push.delete".to_owned());
            }
            if flags
                .iter()
                .any(|flag| matches!(flag.as_str(), "--tags" | "--follow-tags"))
            {
                modifiers.push("push.tags".to_owned());
            }
            if flags.iter().any(|flag| flag == "--mirror") {
                modifiers.push("push.mirror".to_owned());
            }
            if flags.iter().any(|flag| flag == "--all") {
                modifiers.push("push.all".to_owned());
            }
            if modifiers.is_empty() {
                vec!["push".to_owned()]
            } else {
                modifiers
            }
        }
        GitSubcommand::Submodule => {
            if let Some(sub) = positionals_before_dash.first() {
                vec![format!("submodule.{}", sub.to_ascii_lowercase())]
            } else {
                vec!["submodule".to_owned()]
            }
        }
        GitSubcommand::Other(name) if name == "config" => {
            let is_read = flags.iter().any(|flag| {
                matches!(
                    flag.as_str(),
                    "--get" | "--get-all" | "--get-regexp" | "--get-urlmatch" | "--list" | "-l"
                )
            });
            if is_read {
                vec!["config.read".to_owned()]
            } else {
                vec!["config.write".to_owned()]
            }
        }
        GitSubcommand::Other(name) if name == "stash" => {
            if let Some(sub) = positionals_before_dash.first() {
                vec![format!("stash.{}", sub.to_ascii_lowercase())]
            } else {
                vec!["stash".to_owned()]
            }
        }
        other => vec![other.as_str().to_ascii_lowercase()],
    };

    let display = selectors.join(", ");
    ClassifiedGitCommand {
        selectors,
        flags,
        display,
    }
}

pub fn run_managed_git() -> Result<u8, String> {
    let current_directory = std::env::current_dir()
        .map_err(|error| format!("cannot determine Git working directory: {error}"))?;
    let invocation =
        GitInvocation::parse(std::env::args_os().skip(1)).map_err(|error| match error {
            crate::git_command::ParseError::MissingDirectory => {
                "Git -C requires a directory".to_owned()
            }
            crate::git_command::ParseError::UnsupportedGlobalOption => {
                "unsupported Git global option; configuration and repository redirects are blocked"
                    .to_owned()
            }
            crate::git_command::ParseError::MissingSubcommand => {
                "missing Git subcommand".to_owned()
            }
        })?;
    let directory = invocation
        .resolve_directory(&current_directory)
        .map_err(|_| "Git -C directory is missing or inaccessible".to_owned())?;
    let subcommand = invocation
        .subcommand()
        .map_err(|_| "missing Git subcommand".to_owned())?;
    let command_name = subcommand.as_str().to_owned();
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
    let native_gh = gh_executable().filter(|path| path.is_absolute() && path.is_file());
    let home =
        tempfile::tempdir().map_err(|error| format!("cannot create isolated Git HOME: {error}"))?;
    let git_client = GitClient::new(native_git.clone(), isolated_git_environment(home.path()));

    let classified = classify_git_command(&subcommand, &git_arguments[1..]);
    let primary_selector = classified.selectors[0].clone();

    let worktree_add = subcommand == GitSubcommand::Worktree
        && classified.selectors.iter().any(|s| s == "worktree.add");
    let target_operation = subcommand == GitSubcommand::Clone || worktree_add;
    let clone_plan = if subcommand == GitSubcommand::Clone {
        Some(parse_clone_target(&git_arguments[1..])?)
    } else {
        None
    };

    let selection_directory = if let Some((_, target)) = &clone_plan {
        if target.is_absolute() {
            target.clone()
        } else {
            directory.join(target)
        }
    } else if worktree_add {
        let target = parse_worktree_add_target(&git_arguments[1..])?;
        if target.is_absolute() {
            target
        } else {
            directory.join(target)
        }
    } else {
        match git_client.checkout_root(&directory) {
            Ok(root) => root,
            Err(_) if subcommand == GitSubcommand::Init => {
                if let Some(target) = parse_init_target(&git_arguments[1..]) {
                    if target.is_absolute() {
                        target
                    } else {
                        directory.join(target)
                    }
                } else {
                    directory.clone()
                }
            }
            Err(_) => {
                return Err("Git command requires a working tree in a managed scope".to_owned());
            }
        }
    };

    let selected_scope = if target_operation
        || (subcommand == GitSubcommand::Init && !selection_directory.exists())
    {
        crate::context::resolve_target_context(&selection_directory, &config.scopes())
    } else {
        crate::context::resolve_context(&selection_directory, &config.scopes())
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

    let selector_refs = classified
        .selectors
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let flag_refs = classified
        .flags
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    profile
        .git
        .commands
        .evaluate(&selector_refs, &flag_refs)
        .map_err(|denial| denial.describe("Git", &classified.display))?;

    let gh_parent_authorized = check_gh_parent_authorized(profile)?;
    let inherited_github_tokens_present = [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
    ]
    .iter()
    .any(|variable| std::env::var_os(variable).is_some());
    let is_network_command = matches!(
        subcommand,
        GitSubcommand::Fetch | GitSubcommand::Pull | GitSubcommand::Push | GitSubcommand::Clone
    ) || matches!(command_name.as_str(), "ls-remote" | "submodule");
    if is_network_command && inherited_github_tokens_present && !gh_parent_authorized {
        return Err(
            "inherited GitHub token override is not permitted for managed Git transport".to_owned(),
        );
    }

    // Optional strict repo-config hardening (off by default for day-to-day workflows).
    let checkout_mutation = worktree_add
        || matches!(
            command_name.as_str(),
            "restore" | "switch" | "checkout" | "merge" | "cherry-pick" | "rebase"
        );
    if selected_policy.git.strict_git_filters
        && (command_name == "add" || checkout_mutation)
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
    if selected_policy.git.strict_repo_hooks && checkout_mutation {
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
    if selected_policy.git.strict_merge_drivers
        && matches!(command_name.as_str(), "cherry-pick" | "rebase")
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

    // Always-on Layer A identity-separation guards on local mutations.
    if worktree_add {
        let source_root = git_client
            .checkout_root(&directory)
            .map_err(|_| "worktree creation requires an existing Git worktree".to_owned())?;
        crate::context::resolve_context(&source_root, &config.scopes())
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

    if subcommand == GitSubcommand::Remote
        && classified
            .selectors
            .iter()
            .any(|s| s == "remote.add" || s == "remote.set-url")
    {
        enforce_remote_mutation_policy(profile, &git_arguments[1..])?;
    }

    let signed_tag_create = classified.selectors.iter().any(|s| s == "tag.signed");
    let annotated_tag_create = classified.selectors.iter().any(|s| s == "tag.annotated");
    let lightweight_tag_create = classified.selectors.iter().any(|s| s == "tag.lightweight");
    let tag_create = signed_tag_create || annotated_tag_create || lightweight_tag_create;
    if signed_tag_create && selected_policy.git.signing.is_none() {
        return Err("annotated tag creation requires an explicit signing policy".to_owned());
    }
    if lightweight_tag_create
        && selected_policy
            .git
            .push
            .as_ref()
            .is_some_and(|push| !push.allow_lightweight_tags)
    {
        return Err("lightweight tag creation requires an explicit policy opt-in".to_owned());
    }

    if subcommand == GitSubcommand::Commit {
        let inherited = GitClient::new(native_git.clone(), crate::git::safe_environment());
        let inherited_root = inherited
            .checkout_root(&directory)
            .map_err(|_| "cannot validate inherited Git worktree configuration".to_owned())?;
        if inherited_root != selection_directory {
            return Err("inherited Git configuration redirects the commit worktree".to_owned());
        }
        enforce_commit_identity_args(&git_arguments[1..], &config, selected_policy)?;
    }

    if command_name == "config" && classified.selectors.iter().any(|s| s == "config.write") {
        enforce_config_write_guard(&git_arguments[1..])?;
    }

    // Network & destination guards.
    let fetch_all =
        subcommand == GitSubcommand::Fetch && classified.selectors.iter().any(|s| s == "fetch.all");
    let mut managed_fetch_targets: Vec<(String, String, bool)> = Vec::new();
    let mut managed_destination = None;
    let mut use_managed_ssh = false;
    let mut managed_push_request = None;
    let mut push_handoff_file = None;
    let mut expected_ssh_push_path = None;
    let mut push_dynamic_tuples = false;
    let mut push_force_requested = false;
    let mut push_dry_run = false;
    let mut push_follow_tags = false;

    if fetch_all {
        let configured_remotes = git_client
            .configured_remotes(&directory)
            .map_err(|_| "cannot resolve configured Git remotes".to_owned())?;
        if configured_remotes.is_empty() {
            return Err("fetch --all requires at least one configured remote".to_owned());
        }
        if git_client
            .has_unsafe_https_transport_config_with_options(
                &directory,
                profile.git.strict_git_filters,
                profile.git.strict_merge_drivers,
            )
            .map_err(|_| "cannot validate local Git HTTPS configuration".to_owned())?
        {
            return Err("unsafe local HTTPS transport configuration is present".to_owned());
        }
        for remote in git_client
            .fetch_all_remotes(&directory)
            .map_err(|_| "cannot resolve Git's eligible fetch-all remotes".to_owned())?
        {
            let (destination, uses_ssh) =
                managed_fetch_destination(&git_client, profile, &directory, &remote)?;
            managed_fetch_targets.push((remote, destination, uses_ssh));
        }
    } else if matches!(subcommand, GitSubcommand::Fetch | GitSubcommand::Pull) {
        if git_client
            .has_unsafe_https_transport_config_with_options(
                &directory,
                profile.git.strict_git_filters,
                profile.git.strict_merge_drivers,
            )
            .map_err(|_| "cannot validate local Git HTTPS configuration".to_owned())?
        {
            return Err("unsafe local HTTPS transport configuration is present".to_owned());
        }
        let remote_or_url =
            extract_fetch_or_pull_target(&git_arguments[1..], subcommand == GitSubcommand::Pull);
        let (remote_name, resolved_destination) = match remote_or_url {
            Some(target)
                if target.starts_with("https://")
                    || target.starts_with("ssh://")
                    || target.contains(':') =>
            {
                ("*".to_owned(), target)
            }
            Some(remote) => {
                let (dest, _) =
                    managed_fetch_destination(&git_client, profile, &directory, &remote)?;
                (remote, dest)
            }
            None => {
                let remote = if subcommand == GitSubcommand::Pull {
                    git_client
                        .configured_upstream(&directory)
                        .map(|(remote, _)| remote)
                        .or_else(|_| git_client.default_fetch_remote(&directory))
                        .map_err(|_| "pull requires one configured remote or upstream".to_owned())?
                } else {
                    git_client.default_fetch_remote(&directory).map_err(|_| {
                        "cannot resolve Git's configured default fetch remote".to_owned()
                    })?
                };
                let (dest, _) =
                    managed_fetch_destination(&git_client, profile, &directory, &remote)?;
                (remote, dest)
            }
        };
        if !profile
            .git
            .permits_fetch_destination(&remote_name, &resolved_destination)
        {
            return Err(
                "effective fetch destination is not an exact allowed destination".to_owned(),
            );
        }
        managed_destination = Some(resolved_destination.clone());
        use_managed_ssh =
            authorize_transport_scheme(profile, &resolved_destination, "git-upload-pack")?;
    } else if command_name == "ls-remote" {
        if git_client
            .has_unsafe_https_transport_config_with_options(
                &directory,
                profile.git.strict_git_filters,
                profile.git.strict_merge_drivers,
            )
            .map_err(|_| "cannot validate local Git HTTPS configuration".to_owned())?
        {
            return Err("unsafe local HTTPS transport configuration is present".to_owned());
        }
        let target = extract_ls_remote_target(&git_arguments[1..]);
        let (remote_name, resolved_destination) = match target {
            Some(value)
                if value.starts_with("https://")
                    || value.starts_with("ssh://")
                    || value.contains(':') =>
            {
                ("*".to_owned(), value)
            }
            Some(remote) => {
                let (dest, _) =
                    managed_fetch_destination(&git_client, profile, &directory, &remote)?;
                (remote, dest)
            }
            None => {
                let remote = git_client
                    .default_fetch_remote(&directory)
                    .unwrap_or_else(|_| "origin".to_owned());
                let (dest, _) =
                    managed_fetch_destination(&git_client, profile, &directory, &remote)?;
                (remote, dest)
            }
        };
        if !profile
            .git
            .permits_fetch_destination(&remote_name, &resolved_destination)
        {
            return Err("ls-remote destination is not allowed by this profile".to_owned());
        }
        managed_destination = Some(resolved_destination.clone());
        use_managed_ssh =
            authorize_transport_scheme(profile, &resolved_destination, "git-upload-pack")?;
    } else if subcommand == GitSubcommand::Clone {
        let (url, target) = clone_plan.as_ref().expect("clone plan parsed");
        let allowed_clone = crate::destination::destination_is_permitted(
            url,
            &clone_allowed_destinations(profile),
            &profile.git.deny_destinations,
        );
        if !allowed_clone {
            return Err("clone URL is not an allowed profile fetch destination".to_owned());
        }
        managed_destination = Some(url.clone());
        use_managed_ssh = authorize_transport_scheme(profile, url, "git-upload-pack")?;
        if git_client
            .has_unsafe_https_transport_config_with_options(
                &directory,
                profile.git.strict_git_filters,
                profile.git.strict_merge_drivers,
            )
            .map_err(|_| "cannot validate local transport configuration".to_owned())?
        {
            return Err("unsafe local transport configuration is present".to_owned());
        }
        let target = if target.is_absolute() {
            target.clone()
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
    } else if subcommand == GitSubcommand::Push {
        let push = PushInvocation::parse(&git_arguments[1..]).map_err(str::to_owned)?;
        if push.no_verify {
            return Err(
                "managed push refuses --no-verify because it bypasses Persona's pre-push barrier"
                    .to_owned(),
            );
        }
        push_dry_run = push.dry_run;
        push_follow_tags = push.follow_tags;
        push_force_requested =
            push.force || push.bare_force_with_lease || !push.lease_refs.is_empty();
        let remote = match push.remote.clone() {
            Some(remote) => remote,
            None => {
                let (remote, _) = git_client.default_push_target(&directory).map_err(|_| {
                    "cannot resolve Git's configured default push remote/ref".to_owned()
                })?;
                remote
            }
        };

        let push_policy = selected_policy
            .git
            .push
            .as_ref()
            .ok_or_else(|| "managed push requires an explicit destination policy".to_owned())?;
        if (push.force || push.refspecs.iter().any(|spec| spec.forced))
            && !push_policy.allow_force_push
        {
            return Err(
                "unleased force push is disabled by the active profile's push policy".to_owned(),
            );
        }
        if push_policy.remote != "*" && push_policy.remote != remote {
            return Err("push remote does not match the configured policy".to_owned());
        }
        let remote_push_destinations = profile
            .git
            .configured_push_destinations(&remote)
            .ok_or_else(|| "push requires a profile-bound remote destination policy".to_owned())?;
        if git_client
            .has_push_options(&directory)
            .map_err(|_| "cannot inspect configured push options".to_owned())?
            || git_client
                .has_remote_mirror_push(&directory, &remote)
                .map_err(|_| "cannot inspect remote mirror configuration".to_owned())?
        {
            return Err(
                "configured server-side push options or mirror mode are blocked".to_owned(),
            );
        }
        if git_client
            .has_unsafe_https_transport_config_with_options(
                &directory,
                profile.git.strict_git_filters,
                profile.git.strict_merge_drivers,
            )
            .map_err(|_| "cannot validate local transport configuration".to_owned())?
        {
            return Err("unsafe local transport configuration is present".to_owned());
        }
        let destinations = git_client
            .effective_push_destinations(&directory, &remote)
            .map_err(|_| "cannot resolve the effective push destination".to_owned())?;
        if destinations.len() != 1
            || !crate::destination::destination_is_permitted(
                &destinations[0],
                remote_push_destinations,
                &profile.git.deny_destinations,
            )
            || !crate::destination::destination_is_permitted(
                &destinations[0],
                &push_policy.destinations,
                &profile.git.deny_destinations,
            )
        {
            return Err("managed push requires one exact allowed destination".to_owned());
        }
        let destination = destinations[0].clone();
        if crate::destination::is_supported_https_destination(&destination) {
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
            let (_, path) = crate::destination::parse_ssh_remote(&destination)
                .ok_or_else(|| "SSH push destination path is unsupported".to_owned())?;
            expected_ssh_push_path = Some(if destination.starts_with("ssh://") {
                format!("/{path}")
            } else {
                path.to_owned()
            });
            use_managed_ssh = true;
        }

        push_dynamic_tuples = push.tags
            || push.follow_tags
            || push.bare_force_with_lease
            || !push.lease_refs.is_empty();
        if push_dynamic_tuples {
            managed_push_request = Some(PushRequest {
                remote: remote.clone(),
                destination: destination.clone(),
                tuples: Vec::new(),
                leases: push.leases,
                allow_unleased_force: push.force,
            });
        } else {
            let resolved_refspecs = if push.refspecs.is_empty() {
                let (default_remote, dest_branch) =
                    git_client.default_push_target(&directory).map_err(|_| {
                        "cannot resolve Git's configured default push remote/ref".to_owned()
                    })?;
                let branch = git_client
                    .current_branch(&directory)
                    .map_err(|_| "push requires a current branch".to_owned())?;
                if default_remote != remote {
                    vec![(
                        format!("refs/heads/{branch}"),
                        format!("refs/heads/{branch}"),
                    )]
                } else {
                    vec![(
                        format!("refs/heads/{branch}"),
                        format!("refs/heads/{dest_branch}"),
                    )]
                }
            } else {
                resolve_explicit_push_refspecs(&git_client, &directory, &push.refspecs)?
            };

            let mut canonical = vec![OsString::from("push")];
            if push.atomic {
                canonical.push(OsString::from("--atomic"));
            }
            if push.set_upstream {
                canonical.push(OsString::from("--set-upstream"));
            }
            if push.force {
                canonical.push(OsString::from("--force"));
            }
            if push.dry_run {
                canonical.push(OsString::from("--dry-run"));
            }
            if push.verbose {
                canonical.push(OsString::from("--verbose"));
            }
            if push.quiet {
                canonical.push(OsString::from("--quiet"));
            }
            for lease in &push.leases {
                canonical.push(OsString::from(format!(
                    "--force-with-lease={}:{}",
                    lease.remote_ref, lease.expected_oid
                )));
            }
            canonical.push(OsString::from(&remote));
            let object_width = git_client
                .resolve_commit_oid(&directory, "HEAD")
                .map_or(40, |oid| oid.len());
            let mut tuples = Vec::with_capacity(resolved_refspecs.len());
            for (local_ref, remote_ref) in resolved_refspecs {
                let is_deletion = local_ref == "(delete)";
                let is_branch = remote_ref.starts_with("refs/heads/");
                let is_tag = remote_ref.starts_with("refs/tags/");
                if !is_branch && !is_tag {
                    return Err("managed publication supports only branch and tag refs".to_owned());
                }
                if !is_deletion
                    && !git_client
                        .valid_refname(&directory, &local_ref)
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
                    if let Some(lease) = push
                        .leases
                        .iter()
                        .find(|lease| lease.remote_ref == remote_ref)
                    {
                        lease.expected_oid.clone()
                    } else if push_policy.require_tag_lease_on_create {
                        return Err(
                            "tag publication requires an exact --force-with-lease=<ref>:<oid> for the advertised remote state"
                                .to_owned(),
                        );
                    } else {
                        "0".repeat(object_width)
                    }
                } else {
                    let branch = remote_ref.strip_prefix("refs/heads/").unwrap_or_default();
                    let tracking_ref = format!("refs/remotes/{remote}/{branch}");
                    let cached = git_client
                        .optional_commit_oid(&directory, &tracking_ref)
                        .map_err(|_| {
                            "cannot resolve the cached remote OID for publication".to_owned()
                        })?
                        .unwrap_or_else(|| "0".repeat(object_width));
                    if let Some(lease) = push
                        .leases
                        .iter()
                        .find(|lease| lease.remote_ref == remote_ref)
                    {
                        if lease.expected_oid != cached {
                            return Err(
                                "force-with-lease OID does not match the cached remote ref; fetch and re-authorize explicitly"
                                    .to_owned(),
                            );
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
                            .resolve_commit_oid(&directory, &local_ref)
                            .map_err(|_| {
                                "push source branch does not resolve to a commit".to_owned()
                            })?
                    } else {
                        git_client
                            .resolve_object_oid(&directory, &local_ref)
                            .map_err(|_| "push source tag object is unavailable".to_owned())?
                    };
                    if oid.len() != remote_oid.len() {
                        return Err("local and remote object ID formats do not match".to_owned());
                    }
                    oid
                };
                if local_oid == remote_oid {
                    return Err(
                        "managed push includes an unchanged or absent remote ref; omit it or refresh and re-authorize the exact update"
                            .to_owned(),
                    );
                }
                tuples.push(PushTuple {
                    local_ref,
                    local_oid,
                    remote_ref,
                    remote_oid,
                });
            }
            git_arguments = canonical;
            managed_push_request = Some(PushRequest {
                remote: remote.clone(),
                destination: destination.clone(),
                tuples,
                leases: push.leases,
                allow_unleased_force: push.force,
            });
        }
        managed_destination = Some(destination);
    }

    if gh_parent_authorized {
        if fetch_all {
            for (_, destination, _) in &managed_fetch_targets {
                validate_nested_gh_git_destination(profile, destination)?;
            }
        } else if let Some(destination) = &managed_destination {
            validate_nested_gh_git_destination(profile, destination)?;
        }
    }

    if let Some(request) = &managed_push_request {
        let primary_evidence = authorize_managed_push(
            &config,
            &directory,
            profile,
            &git_client,
            request,
            push_dynamic_tuples,
        )?;
        if sha256_file(&config_path)? != config_digest_at_load {
            return Err("policy changed during primary push authorization".to_owned());
        }
        let paths = PersonaPaths::discover()
            .map_err(|_| "cannot resolve private state for push handoff".to_owned())?;
        let checkout_root = git_client
            .checkout_root(&directory)
            .map_err(|_| "cannot resolve checkout for push handoff".to_owned())?;
        let canonical_config_path = std::fs::canonicalize(&config_path)
            .map_err(|_| "cannot resolve policy path for push handoff".to_owned())?;
        let handoff = crate::push_handoff::PushHandoff {
            config_path: canonical_config_path,
            config_sha256: config_digest_at_load,
            hook_manifest_path: primary_evidence.hook_manifest_path,
            hook_manifest_sha256: primary_evidence.hook_manifest_sha256,
            checkout_root,
            profile: profile.name.clone(),
            remote: request.remote.clone(),
            destination: request.destination.clone(),
            tuples: request
                .tuples
                .iter()
                .map(|tuple| crate::push_handoff::HandoffTuple {
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
                crate::push_handoff::HandoffGithubBinding {
                    host: binding.host.clone(),
                    account_id: binding.account_id.clone(),
                }
            }),
            dynamic_tuples: push_dynamic_tuples,
            force_requested: push_force_requested,
        };
        push_handoff_file = Some(crate::push_handoff::write(&paths, &handoff)?);
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
    let managed_path = build_managed_path(&shim_dir)?;

    if fetch_all {
        return execute_managed_fetch_all(ManagedFetchAllContext {
            native_git: &native_git,
            directory: &directory,
            git_arguments: &git_arguments,
            global_arguments: &global_arguments,
            targets: &managed_fetch_targets,
            config_path: &config_path,
            isolated_home: home.path(),
            managed_path: &managed_path,
            ssh_adapter: &ssh_adapter,
            shim_directory: &shim_dir,
            native_gh: native_gh.as_deref(),
        });
    }

    let commit_operation = subcommand == GitSubcommand::Commit;
    let preserve_cherry_pick_author = selected_policy
        .git
        .push
        .as_ref()
        .is_some_and(|push| push.preserve_authors);
    let strict_cherry_pick_oid = if command_name == "cherry-pick" && !preserve_cherry_pick_author {
        if git_arguments.len() == 2 && git_arguments[1] == "--continue" {
            Some(
                git_client
                    .resolve_commit_oid(&directory, "CHERRY_PICK_HEAD")
                    .map_err(|_| "cannot identify the in-progress cherry-pick commit".to_owned())?,
            )
        } else if git_arguments.len() == 2 {
            git_arguments[1]
                .to_str()
                .filter(|oid| {
                    matches!(oid.len(), 40 | 64) && oid.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
                .map(str::to_owned)
        } else {
            None
        }
    } else {
        None
    };
    let strict_cherry_pick_continue = command_name == "cherry-pick"
        && !preserve_cherry_pick_author
        && git_arguments.len() == 2
        && git_arguments[1] == "--continue";
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

    let sequenced_commit_operation = matches!(command_name.as_str(), "cherry-pick" | "rebase");
    let signing_operation = commit_operation
        || sequenced_commit_operation
        || signed_tag_create
        || (annotated_tag_create && selected_policy.git.signing.is_some());
    let identity_commit_operation = commit_operation || sequenced_commit_operation;
    let is_tty = std::io::stdout().is_terminal();

    let mut command = Command::new(&native_git);
    if !is_tty {
        command.arg("--no-pager").arg("-c").arg("core.pager=cat");
    }
    for (key, value) in crate::git_https::required_git_http_overrides() {
        command.arg("-c").arg(format!("{key}={value}"));
    }
    if use_managed_ssh {
        command.arg("-c").arg("ssh.variant=ssh");
    } else if !is_network_command {
        // Ensure local commands never accidentally pick up an unsafe core.sshCommand.
        command.arg("-c").arg("core.sshCommand=");
    }
    if is_network_command {
        command
            .arg("-c")
            .arg("core.fsmonitor=false")
            .arg("-c")
            .arg("fetch.pruneTags=false")
            .arg("-c")
            .arg("fetch.recurseSubmodules=false")
            .arg("-c")
            .arg("push.recurseSubmodules=no")
            .arg("-c")
            .arg("push.gpgSign=false");
        if !push_follow_tags {
            command.arg("-c").arg("push.followTags=false");
        }
    }
    if (command_name == "rebase"
        && !git_arguments[1..]
            .iter()
            .any(|arg| arg == "-i" || arg == "--interactive")
        && !is_tty)
        || (command_name == "cherry-pick"
            && git_arguments.get(1).is_some_and(|arg| arg == "--continue")
            && !is_tty)
    {
        command.arg("-c").arg("core.editor=true");
    }

    let effective_author = &selected_policy.git.author;
    let effective_committer = &selected_policy.git.committer;
    command
        .arg("-c")
        .arg(format!("user.name={}", effective_committer.name))
        .arg("-c")
        .arg(format!("user.email={}", effective_committer.email))
        .arg("-c")
        .arg("credential.helper=")
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
            (signed_tag_create || (annotated_tag_create && selected_policy.git.signing.is_some()))
                && selected_policy.git.signing.is_some()
        ))
        .current_dir(&directory)
        .env_clear()
        .env("PATH", &managed_path)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("PERSONA_CONFIG_PATH", &config_path)
        .env("PERSONA_GIT", &native_git)
        .env(
            "PERSONA_GIT_CREDENTIAL_DIRECTION",
            if matches!(
                subcommand,
                GitSubcommand::Fetch | GitSubcommand::Pull | GitSubcommand::Clone
            ) {
                "fetch"
            } else {
                "push"
            },
        )
        .env("PERSONA_GIT_OPERATION_SELECTOR", &primary_selector);

    let original_home = std::env::var_os("HOME").map(PathBuf::from);
    if is_network_command || !selected_policy.git.inherit_git_config {
        command
            .env("HOME", home.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_CONFIG_GLOBAL", "/dev/null");
    } else if let Some(orig) = &original_home {
        command.env("HOME", orig);
    } else {
        command.env("HOME", home.path());
    }

    if matches!(subcommand, GitSubcommand::Fetch | GitSubcommand::Pull) {
        if let Some(remote) =
            extract_fetch_or_pull_target(&git_arguments[1..], subcommand == GitSubcommand::Pull)
        {
            if !remote.contains(':') && !remote.starts_with("https://") {
                command.env("PERSONA_GIT_CREDENTIAL_REMOTE", remote);
            }
        }
    }
    if let Some(path) = &expected_ssh_push_path {
        command.env("PERSONA_EXPECTED_SSH_PUSH_PATH", path);
    }
    if let Some(gh) = native_gh {
        command.env("PERSONA_GH", gh);
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
    if signing_operation || commit_operation || identity_commit_operation || tag_create {
        if let Some(orig) = &original_home {
            command.env("HOME", orig);
        }
        if commit_operation {
            command
                .env("GIT_AUTHOR_NAME", &effective_author.name)
                .env("GIT_AUTHOR_EMAIL", &effective_author.email);
        }
        if identity_commit_operation || tag_create {
            command
                .env("GIT_COMMITTER_NAME", &effective_committer.name)
                .env("GIT_COMMITTER_EMAIL", &effective_committer.email);
        }
    }
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
    if push_handoff_file.is_none() {
        if let Some(path) = original_state_home {
            command.env("XDG_STATE_HOME", path);
        }
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
    for variable in [
        "EDITOR",
        "VISUAL",
        "GIT_EDITOR",
        "TERM",
        "LANG",
        "LC_ALL",
        "SSH_AUTH_SOCK",
    ] {
        if let Some(value) = std::env::var_os(variable) {
            command.env(variable, value);
        }
    }
    if signing_operation {
        if let Some(signing) = &selected_policy.git.signing {
            let (format, signing_key) = match signing.format {
                crate::config::SigningFormat::OpenPgp => ("openpgp", signing.fingerprint.clone()),
                crate::config::SigningFormat::Ssh => {
                    ("ssh", signing.public_key.to_string_lossy().into_owned())
                }
            };
            command
                .arg("-c")
                .arg(format!("gpg.format={format}"))
                .arg("-c")
                .arg(format!("user.signingkey={signing_key}"));
            match signing.format {
                crate::config::SigningFormat::OpenPgp => {
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
                crate::config::SigningFormat::Ssh => {
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
    } else if matches!(command_name.as_str(), "diff" | "show") {
        command
            .arg(&command_name)
            .arg("--no-ext-diff")
            .arg("--no-textconv")
            .args(&git_arguments[1..]);
    } else if matches!(subcommand, GitSubcommand::Fetch | GitSubcommand::Pull) {
        command
            .arg(&command_name)
            .args(managed_fetch_safety_arguments(&git_arguments[1..]))
            .args(&git_arguments[1..]);
    } else {
        if subcommand == GitSubcommand::Commit
            && git_arguments.iter().any(|argument| argument == "--amend")
            && !selected_policy
                .git
                .push
                .as_ref()
                .is_some_and(|push| push.preserve_authors)
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
    if !push_dry_run {
        if let Some(handoff) = &push_handoff_file {
            if handoff.path().exists() {
                return Err(
                    "managed push completed without consuming Persona's pre-push authorization barrier; refusing to report success"
                        .to_owned(),
                );
            }
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

fn check_gh_parent_authorized(profile: &Profile) -> Result<bool, String> {
    match std::env::var_os("PERSONA_GH_AUTHORIZED") {
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
                crate::credential::GithubSelector::discover(gh, binding.host.clone(), paths)
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
            Ok(true)
        }
        Some(_) => Err("unrecognized managed gh child marker".to_owned()),
        None => Ok(false),
    }
}

fn enforce_commit_identity_args(
    args: &[OsString],
    config: &Config,
    selected_policy: &ScopePolicy,
) -> Result<(), String> {
    let preserve_authors = selected_policy
        .git
        .push
        .as_ref()
        .is_some_and(|push| push.preserve_authors);
    let mut index = 0;
    while index < args.len() {
        let Some(word) = args[index].to_str() else {
            index += 1;
            continue;
        };
        if word == "--" {
            break;
        }
        if word == "--no-gpg-sign" && selected_policy.git.signing.is_some() {
            return Err("active signing policy prohibits --no-gpg-sign".to_owned());
        }
        let author_val = if let Some(val) = word.strip_prefix("--author=") {
            Some(val)
        } else if word == "--author" {
            index += 1;
            args.get(index).and_then(|v| v.to_str())
        } else {
            None
        };
        if let Some(author) = author_val {
            let expected = format!(
                "{} <{}>",
                selected_policy.git.author.name, selected_policy.git.author.email
            );
            let matches_expected = author == expected
                || extract_email(author).is_some_and(|email| {
                    email.eq_ignore_ascii_case(&selected_policy.git.author.email)
                });
            if !preserve_authors && !matches_expected {
                return Err(
                    "commit --author does not match the active Persona profile's author identity"
                        .to_owned(),
                );
            }
            if selected_policy.git.cross_profile_identity_check {
                if let Some(email) = extract_email(author) {
                    let active_lower = selected_policy.git.author.email.to_ascii_lowercase();
                    let matches_other_profile = config.profiles().iter().any(|profile| {
                        let p_author = profile.git.author.email.to_ascii_lowercase();
                        let p_committer = profile.git.committer.email.to_ascii_lowercase();
                        (email.eq_ignore_ascii_case(&p_author)
                            || email.eq_ignore_ascii_case(&p_committer))
                            && !email.eq_ignore_ascii_case(&active_lower)
                    });
                    if matches_other_profile {
                        return Err(
                            "commit --author leaks another Persona profile's email identity"
                                .to_owned(),
                        );
                    }
                }
            }
        }
        index += 1;
    }
    Ok(())
}

fn extract_email(identity: &str) -> Option<&str> {
    let (_, rest) = identity.split_once('<')?;
    let (email, _) = rest.split_once('>')?;
    Some(email.trim())
}

fn enforce_config_write_guard(args: &[OsString]) -> Result<(), String> {
    let positionals: Vec<&str> = args
        .iter()
        .filter_map(|v| v.to_str())
        .filter(|w| !w.starts_with('-'))
        .collect();
    if let Some(key) = positionals.first() {
        let lower = key.to_ascii_lowercase();
        let blocked = lower.starts_with("user.")
            || lower.starts_with("author.")
            || lower.starts_with("committer.")
            || lower.starts_with("gpg.")
            || lower == "commit.gpgsign"
            || lower == "tag.gpgsign"
            || lower.starts_with("credential.")
            || lower == "core.sshcommand"
            || lower == "core.hookspath"
            || lower == "core.fsmonitor"
            || lower == "core.askpass"
            || lower.starts_with("http.")
            || lower.starts_with("url.")
            || lower.starts_with("filter.")
            || lower.starts_with("include.")
            || lower.starts_with("includeif.")
            || (lower.starts_with("merge.") && lower.ends_with(".driver"))
            || (lower.starts_with("remote.")
                && [".proxy", ".uploadpack", ".receivepack", ".vcs"]
                    .iter()
                    .any(|suffix| lower.ends_with(suffix)));
        if blocked {
            return Err(format!(
                "mutating Git config key `{key}` is blocked to preserve Persona identity/transport isolation"
            ));
        }
    }
    Ok(())
}

fn enforce_remote_mutation_policy(profile: &Profile, args: &[OsString]) -> Result<(), String> {
    let positionals: Vec<&str> = args
        .iter()
        .filter_map(|v| v.to_str())
        .filter(|w| !w.starts_with('-'))
        .collect();
    if positionals.len() < 3 {
        return Ok(());
    }
    let remote = positionals[1];
    let destination = positionals[2];
    if profile
        .git
        .deny_destinations
        .iter()
        .any(|pattern| crate::destination::destination_matches_pattern(destination, pattern))
    {
        return Err("remote destination is blocked by profile deny_destinations".to_owned());
    }
    if !profile.git.remotes.is_empty() || profile.git.push.is_some() {
        let fetch_ok = profile.git.permits_fetch_destination(remote, destination);
        let push_ok = profile.git.permits_push_destination(remote, destination);
        if !fetch_ok && !push_ok {
            return Err("remote name or destination is not authorized by this profile".to_owned());
        }
    }
    if !crate::destination::is_supported_https_destination(destination)
        && (destination.contains(':') || destination.starts_with("ssh://"))
    {
        validate_managed_ssh_destination(profile.ssh.as_ref(), destination, "git-upload-pack")
            .map_err(|reason| format!("remote destination has no managed SSH policy: {reason}"))?;
    }
    Ok(())
}

fn clone_allowed_destinations(profile: &Profile) -> Vec<String> {
    if !profile.git.remotes.is_empty() {
        profile
            .git
            .remotes
            .iter()
            .flat_map(|remote| remote.fetch_destinations.iter().cloned())
            .collect()
    } else if let Some(push) = &profile.git.push {
        push.destinations.clone()
    } else {
        Vec::new()
    }
}

fn parse_clone_target(args: &[OsString]) -> Result<(String, PathBuf), String> {
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let word = args[index]
            .to_str()
            .ok_or_else(|| "clone arguments must be valid UTF-8".to_owned())?;
        if word == "--" {
            for rest in &args[index + 1..] {
                positionals.push(
                    rest.to_str()
                        .ok_or_else(|| "clone target must be valid UTF-8".to_owned())?,
                );
            }
            break;
        }
        if matches!(
            word,
            "-o" | "--origin"
                | "-b"
                | "--branch"
                | "-u"
                | "--upload-pack"
                | "--reference"
                | "--reference-if-able"
                | "--template"
                | "--depth"
                | "--shallow-since"
                | "--shallow-exclude"
                | "--separate-git-dir"
                | "-j"
                | "--jobs"
                | "--filter"
                | "-c"
                | "--config"
                | "--bundle-uri"
        ) {
            index += 2;
            continue;
        }
        if word.starts_with('-') {
            index += 1;
            continue;
        }
        positionals.push(word);
        index += 1;
    }
    let url = positionals
        .first()
        .copied()
        .ok_or_else(|| "git clone requires a repository URL".to_owned())?;
    let target = if let Some(dir) = positionals.get(1) {
        PathBuf::from(dir)
    } else {
        let cleaned = url.trim_end_matches('/').trim_end_matches(".git");
        let name = cleaned
            .rsplit(['/', ':'])
            .next()
            .filter(|part| !part.is_empty())
            .ok_or_else(|| "cannot derive target directory from clone URL".to_owned())?;
        PathBuf::from(name)
    };
    Ok((url.to_owned(), target))
}

fn parse_worktree_add_target(args: &[OsString]) -> Result<PathBuf, String> {
    let mut index = 0;
    let mut seen_add = false;
    while index < args.len() {
        let word = args[index]
            .to_str()
            .ok_or_else(|| "worktree arguments must be valid UTF-8".to_owned())?;
        if !seen_add {
            if word == "add" {
                seen_add = true;
            }
            index += 1;
            continue;
        }
        if matches!(word, "-b" | "-B" | "--reason") {
            index += 2;
            continue;
        }
        if word.starts_with('-') {
            index += 1;
            continue;
        }
        return Ok(PathBuf::from(word));
    }
    Err("git worktree add requires a destination directory".to_owned())
}

fn parse_init_target(args: &[OsString]) -> Option<PathBuf> {
    let mut index = 0;
    while index < args.len() {
        let word = args[index].to_str()?;
        if matches!(
            word,
            "-b" | "--initial-branch" | "--template" | "--separate-git-dir" | "--shared"
        ) {
            index += 2;
            continue;
        }
        if word.starts_with('-') {
            index += 1;
            continue;
        }
        return Some(PathBuf::from(word));
    }
    None
}

fn extract_fetch_or_pull_target(args: &[OsString], pull: bool) -> Option<String> {
    let mut index = 0;
    while index < args.len() {
        let word = args[index].to_str()?;
        if word == "--" {
            return args
                .get(index + 1)
                .and_then(|v| v.to_str())
                .map(str::to_owned);
        }
        if matches!(
            word,
            "--depth"
                | "--deepen"
                | "--shallow-since"
                | "--shallow-exclude"
                | "-j"
                | "--jobs"
                | "--upload-pack"
                | "--refmap"
                | "--recurse-submodules-default"
                | "-o"
                | "--server-option"
        ) || (pull
            && matches!(
                word,
                "-s" | "--strategy" | "-X" | "--strategy-option" | "--rebase"
            ))
        {
            if word == "--rebase" {
                index += 1;
                continue;
            }
            index += 2;
            continue;
        }
        if word.starts_with('-') {
            index += 1;
            continue;
        }
        return Some(word.to_owned());
    }
    None
}

fn extract_ls_remote_target(args: &[OsString]) -> Option<String> {
    let mut index = 0;
    while index < args.len() {
        let word = args[index].to_str()?;
        if word == "--" {
            return args
                .get(index + 1)
                .and_then(|v| v.to_str())
                .map(str::to_owned);
        }
        if matches!(word, "--sort" | "--upload-pack" | "-o" | "--server-option") {
            index += 2;
            continue;
        }
        if word.starts_with('-') {
            index += 1;
            continue;
        }
        return Some(word.to_owned());
    }
    None
}

fn resolve_explicit_push_refspecs(
    git: &GitClient,
    directory: &Path,
    refspecs: &[crate::git_command::PushRefspec],
) -> Result<Vec<(String, String)>, String> {
    let mut resolved = Vec::with_capacity(refspecs.len());
    for spec in refspecs {
        if spec.raw_source == "(delete)" {
            let dest = if !spec.raw_destination.starts_with("refs/") {
                let tag_ref = format!("refs/tags/{}", spec.raw_destination);
                let head_ref = format!("refs/heads/{}", spec.raw_destination);
                if git
                    .optional_commit_oid(directory, &head_ref)
                    .ok()
                    .flatten()
                    .is_none()
                    && git.resolve_object_oid(directory, &tag_ref).is_ok()
                {
                    tag_ref
                } else {
                    spec.destination.clone()
                }
            } else {
                spec.destination.clone()
            };
            resolved.push(("(delete)".to_owned(), dest));
            continue;
        }
        let local_ref = if spec.raw_source == "HEAD" {
            let branch = git
                .current_branch(directory)
                .map_err(|_| "pushing HEAD requires an active branch".to_owned())?;
            format!("refs/heads/{branch}")
        } else if !spec.raw_source.starts_with("refs/") {
            let head_ref = format!("refs/heads/{}", spec.raw_source);
            let tag_ref = format!("refs/tags/{}", spec.raw_source);
            if git
                .optional_commit_oid(directory, &head_ref)
                .ok()
                .flatten()
                .is_some()
            {
                head_ref
            } else if git.resolve_object_oid(directory, &tag_ref).is_ok() {
                tag_ref
            } else {
                spec.source.clone()
            }
        } else {
            spec.source.clone()
        };

        let remote_ref = if spec.raw_destination == "HEAD" {
            let branch = git
                .current_branch(directory)
                .map_err(|_| "pushing to HEAD requires an active branch".to_owned())?;
            format!("refs/heads/{branch}")
        } else if !spec.raw_destination.starts_with("refs/")
            && spec.raw_source == spec.raw_destination
            && local_ref.starts_with("refs/tags/")
        {
            local_ref.clone()
        } else if !spec.raw_destination.starts_with("refs/") && local_ref.starts_with("refs/tags/")
        {
            normalize_ref(&format!("refs/tags/{}", spec.raw_destination), false)
                .map_err(str::to_owned)?
        } else {
            spec.destination.clone()
        };

        resolved.push((local_ref, remote_ref));
    }
    Ok(resolved)
}

fn authorize_transport_scheme(
    profile: &Profile,
    destination: &str,
    operation: &str,
) -> Result<bool, String> {
    if crate::destination::is_supported_https_destination(destination) {
        Ok(false)
    } else {
        validate_managed_ssh_destination(profile.ssh.as_ref(), destination, operation).map_err(
            |reason| format!("SSH destination has no valid managed transport: {reason}"),
        )?;
        Ok(true)
    }
}

fn validate_nested_gh_git_destination(profile: &Profile, destination: &str) -> Result<(), String> {
    let binding = profile
        .github
        .as_ref()
        .ok_or_else(|| "nested managed Git has no GitHub account binding".to_owned())?;
    let repository =
        crate::gh_adapter::repository_from_destination(destination).ok_or_else(|| {
            "nested managed Git destination is not a supported GitHub.com repository".to_owned()
        })?;
    if binding.repositories.is_empty() || !binding.permits_repository(&repository) {
        return Err(
            "nested managed Git repository is outside the profile's GitHub allowlist".to_owned(),
        );
    }
    Ok(())
}

fn authorize_managed_push(
    config: &Config,
    directory: &Path,
    profile: &Profile,
    git: &GitClient,
    request: &PushRequest,
    dynamic_tuples: bool,
) -> Result<PushPrimaryEvidence, String> {
    if !dynamic_tuples {
        let executables = ExecutablePaths {
            git: git_executable(),
            gpg: gpg_executable(),
            ssh_keygen: ssh_keygen_executable(),
        };
        let (report, selected) = build_report(config, directory, Some(request), &executables)?;
        let selected =
            selected.ok_or_else(|| "push worktree is outside a managed scope".to_owned())?;
        let selected_policy = config
            .policies()
            .iter()
            .find(|policy| policy.name == selected.name)
            .ok_or_else(|| "push scope has no resolved policy".to_owned())?;
        let required =
            push_authorization_requirements(request, selected_policy.git.signing.is_some());
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
    }

    let root = git
        .checkout_root(directory)
        .map_err(|_| "cannot resolve push worktree for pre-push hook verification".to_owned())?;
    let hook_paths = crate::hooks::resolve_paths(git, &root)?;
    let manifest = crate::hooks::load_manifest(&hook_paths)?;
    let executable = persona_dispatcher_executable()
        .map_err(|_| "cannot resolve Persona dispatcher for push hook verification".to_owned())?;
    let manifest_executable_matches = std::fs::canonicalize(manifest.persona_executable())
        .ok()
        .as_ref()
        == Some(&executable);
    if !manifest_executable_matches {
        return Err(format!(
            "installed pre-push hook belongs to a different Persona executable ({}); run `persona hooks refresh --cwd {}`",
            manifest.persona_executable().display(),
            root.display()
        ));
    }
    crate::hooks::verify_installed_hook(&hook_paths, &manifest)?;
    let manifest_path = std::fs::canonicalize(&hook_paths.manifest)
        .map_err(|_| "cannot resolve installed hook manifest".to_owned())?;
    let manifest_digest = sha256_file(&manifest_path)?;

    let destination_host = crate::credential::destination_host(&request.destination);
    let github_required = destination_host.as_deref().is_some_and(|host| {
        crate::credential::is_known_github_host(host) || profile.github.is_some()
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
        let selector = crate::credential::GithubSelector::discover(gh, binding.host.clone(), paths)
            .map_err(|_| "cannot safely inspect the selected GitHub account".to_owned())?;
        let token = selector
            .token_for_binding(binding)
            .map_err(|_| "cannot select the enrolled GitHub credential".to_owned())?
            .ok_or_else(|| {
                "selected GitHub credential does not match the enrolled account".to_owned()
            })?;
        drop(token);
        if !dynamic_tuples {
            let executables = ExecutablePaths {
                git: git_executable(),
                gpg: gpg_executable(),
                ssh_keygen: ssh_keygen_executable(),
            };
            let (report, _) = build_report(config, directory, Some(request), &executables)?;
            let mut required =
                push_authorization_requirements(request, profile.git.signing.is_some());
            required.push("github.credential.binding".to_owned());
            let mut findings = report.findings;
            findings.push(crate::report::Finding::pass(
                "github.credential.binding",
                binding.account_id.clone(),
                binding.account_id.clone(),
                "the selected native credential fingerprint matched the enrolled account before transport",
            ));
            if !authorize(AuthorizationOperation::GitPush, required, findings).is_allowed() {
                return Err("GitHub account binding did not satisfy push authorization".to_owned());
            }
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

pub fn push_authorization_requirements(
    request: &PushRequest,
    signing_required: bool,
) -> Vec<String> {
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

pub fn managed_fetch_safety_arguments(arguments: &[OsString]) -> Vec<&'static str> {
    let mut safety_arguments = Vec::with_capacity(3);
    if !arguments.iter().any(|argument| argument == "--prune") {
        safety_arguments.push("--no-prune");
    }
    safety_arguments.push("--no-prune-tags");
    safety_arguments.push("--no-recurse-submodules");
    safety_arguments
}

fn managed_fetch_destination(
    git: &GitClient,
    profile: &Profile,
    directory: &Path,
    remote: &str,
) -> Result<(String, bool), String> {
    let allowed = profile
        .git
        .configured_fetch_destinations(remote)
        .ok_or_else(|| {
            format!("fetch remote `{remote}` has no profile-bound destination policy")
        })?;
    if allowed.is_empty() {
        return Err(format!("fetch remote `{remote}` is not authorized"));
    }
    let destinations = git
        .effective_fetch_destinations(directory, remote)
        .map_err(|_| format!("cannot resolve effective destination for fetch remote `{remote}`"))?;
    if destinations.len() != 1
        || !crate::destination::destination_is_permitted(
            &destinations[0],
            allowed,
            &profile.git.deny_destinations,
        )
    {
        return Err(format!(
            "fetch remote `{remote}` does not resolve to one exact allowed destination"
        ));
    }
    let destination = destinations[0].clone();
    let uses_ssh = authorize_transport_scheme(profile, &destination, "git-upload-pack")
        .map_err(|reason| format!("fetch remote `{remote}`: {reason}"))?;
    Ok((destination, uses_ssh))
}

fn execute_managed_fetch_all(context: ManagedFetchAllContext<'_>) -> Result<u8, String> {
    let ManagedFetchAllContext {
        native_git,
        directory,
        git_arguments,
        global_arguments,
        targets,
        config_path,
        isolated_home,
        managed_path,
        ssh_adapter,
        shim_directory,
        native_gh,
    } = context;
    let original_home = std::env::var_os("HOME").map(PathBuf::from);
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| original_home.as_ref().map(|home| home.join(".config")));
    let state_home = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| original_home.as_ref().map(|home| home.join(".local/state")));
    let mut failed = false;

    for (index, (remote, _destination, use_ssh)) in targets.iter().enumerate() {
        let mut child = Command::new(native_git);
        child
            .arg("--no-pager")
            .arg("-c")
            .arg("core.pager=cat")
            .arg("-c")
            .arg("core.fsmonitor=false");
        for (key, value) in crate::git_https::required_git_http_overrides() {
            child.arg("-c").arg(format!("{key}={value}"));
        }
        if *use_ssh {
            child.arg("-c").arg("ssh.variant=ssh");
        }
        child
            .arg("-c")
            .arg("fetch.prune=false")
            .arg("-c")
            .arg("fetch.pruneTags=false")
            .arg("-c")
            .arg("fetch.recurseSubmodules=false")
            .arg("-c")
            .arg("credential.helper=")
            .arg("-c")
            .arg("credential.helper=persona")
            .arg("-c")
            .arg("fetch.bundleURI=")
            .args(global_arguments)
            .arg("fetch")
            .args(managed_fetch_safety_arguments(&git_arguments[1..]))
            .arg("--no-auto-gc")
            .arg("--no-write-commit-graph");
        child.args(
            git_arguments[1..]
                .iter()
                .filter(|argument| *argument != "--all"),
        );
        if index > 0 {
            child.arg("--append");
        }
        child
            .arg(remote)
            .current_dir(directory)
            .env_clear()
            .env("HOME", isolated_home)
            .env("PATH", managed_path)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("PERSONA_CONFIG_PATH", config_path)
            .env("PERSONA_GIT", native_git)
            .env("PERSONA_GIT_CREDENTIAL_DIRECTION", "fetch")
            .env("PERSONA_GIT_CREDENTIAL_REMOTE", remote)
            .env("PERSONA_GIT_OPERATION_SELECTOR", "fetch.all")
            .env("PERSONA_SHIM_DIR", shim_directory);
        if let Some(config_home) = &config_home {
            child.env("XDG_CONFIG_HOME", config_home).env(
                "GH_CONFIG_DIR",
                std::env::var_os("GH_CONFIG_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| config_home.join("gh")),
            );
        }
        if let Some(state_home) = &state_home {
            child.env("XDG_STATE_HOME", state_home);
        }
        if let Some(gh) = native_gh {
            child.env("PERSONA_GH", gh);
        }
        if *use_ssh {
            child
                .env("GIT_SSH", ssh_adapter)
                .env("GIT_SSH_VARIANT", "ssh");
            if let Some(ssh) = std::env::var_os("PERSONA_SSH") {
                child.env("PERSONA_SSH", ssh);
            }
            if let Some(ssh_keygen) = std::env::var_os("PERSONA_SSH_KEYGEN") {
                child.env("PERSONA_SSH_KEYGEN", ssh_keygen);
            }
        }
        match child.status() {
            Ok(status) if status.success() => {}
            Ok(_) => failed = true,
            Err(error) => {
                eprintln!("cannot launch managed fetch for remote `{remote}`: {error}");
                failed = true;
            }
        }
    }
    Ok(if failed { 1 } else { 0 })
}

fn commit_cherry_pick_with_policy(
    native_git: &Path,
    directory: &Path,
    oid: &str,
    policy: &ScopePolicy,
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
            crate::config::SigningFormat::OpenPgp => ("openpgp", signing.fingerprint.clone()),
            crate::config::SigningFormat::Ssh => {
                ("ssh", signing.public_key.to_string_lossy().into_owned())
            }
        };
        command
            .arg("-c")
            .arg(format!("gpg.format={format}"))
            .arg("-c")
            .arg(format!("user.signingkey={key}"));
        match signing.format {
            crate::config::SigningFormat::OpenPgp => {
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
            crate::config::SigningFormat::Ssh => {
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

#[cfg(test)]
mod tests {
    use super::{classify_git_command, managed_fetch_safety_arguments};
    use crate::git_command::GitSubcommand;
    use std::ffi::OsString;

    #[test]
    fn classifies_everyday_and_modifier_git_commands() {
        let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
        let log = classify_git_command(&GitSubcommand::Log, &args(&["-p", "-n", "5"]));
        assert_eq!(log.selectors, ["log"]);
        assert_eq!(log.flags, ["-p", "-n"]);

        let stash = classify_git_command(&GitSubcommand::Other("stash".into()), &args(&["pop"]));
        assert_eq!(stash.selectors, ["stash.pop"]);

        let push_force =
            classify_git_command(&GitSubcommand::Push, &args(&["--force", "origin", "main"]));
        assert_eq!(push_force.selectors, ["push.force"]);
        assert_eq!(push_force.flags, ["--force"]);

        let fetch_all = classify_git_command(&GitSubcommand::Fetch, &args(&["--all", "--prune"]));
        assert_eq!(fetch_all.selectors, ["fetch.all"]);
    }

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
