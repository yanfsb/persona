use crate::audit::{ExecutablePaths, PushRequest, build_report};
use crate::config::Config;
use crate::git::{GitClient, PushTuple};
use crate::push_handoff::LockedPushHandoff;
use crate::runtime::{
    gh_executable, git_executable, gpg_executable, hook_git_client, persona_dispatcher_executable,
    sha256_file, ssh_keygen_executable, status_exit_code,
};
use crate::storage::PersonaPaths;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

const MAX_PUSH_INPUT_BYTES: usize = 1024 * 1024;

pub struct ValidatedPrimaryHandoff {
    pub github_binding: Option<crate::push_handoff::HandoffGithubBinding>,
    pub allow_unleased_force: bool,
    pub _lock: LockedPushHandoff,
}

pub fn parse_push_tuples(input: &str) -> Result<Vec<PushTuple>, String> {
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

pub fn consume_primary_handoff(path: &Path) -> Result<(), String> {
    let paths = PersonaPaths::discover()
        .map_err(|_| "cannot resolve private state while consuming push handoff".to_owned())?;
    if path.parent() != Some(paths.state_dir.as_path()) {
        return Err("push handoff is outside private Persona state".to_owned());
    }
    std::fs::remove_file(path)
        .map_err(|_| "cannot consume one-time primary push authorization handoff".to_owned())
}

pub fn validate_primary_handoff(
    handoff_path: &Path,
    config_path: &Path,
    directory: &Path,
    request: &mut PushRequest,
) -> Result<ValidatedPrimaryHandoff, String> {
    let paths = PersonaPaths::discover()
        .map_err(|_| "cannot resolve private state for push handoff verification".to_owned())?;
    let locked_handoff = crate::push_handoff::read_locked(&paths, handoff_path)?;
    let handoff = locked_handoff.handoff();
    let config_path = std::fs::canonicalize(config_path)
        .map_err(|_| "cannot resolve current policy for push handoff verification".to_owned())?;
    let handoff_config = std::fs::canonicalize(&handoff.config_path)
        .map_err(|_| "handoff policy path is unavailable".to_owned())?;
    if config_path != handoff_config || sha256_file(&config_path)? != handoff.config_sha256 {
        return Err("policy changed after primary push authorization".to_owned());
    }
    let git = GitClient::new(git_executable(), crate::git::safe_environment());
    let root = git
        .checkout_root(directory)
        .map_err(|_| "cannot resolve hook checkout for push handoff verification".to_owned())?;
    let hook_paths = crate::hooks::resolve_paths(&git, &root)?;
    let manifest_path = std::fs::canonicalize(&hook_paths.manifest)
        .map_err(|_| "installed hook manifest is unavailable".to_owned())?;
    if manifest_path != handoff.hook_manifest_path
        || sha256_file(&manifest_path)? != handoff.hook_manifest_sha256
    {
        return Err("installed hook manifest changed after primary authorization".to_owned());
    }
    let base_matches = root == handoff.checkout_root
        && request.remote == handoff.remote
        && request.destination == handoff.destination;
    let tuples_match = if handoff.dynamic_tuples {
        !request.tuples.is_empty()
    } else {
        request.tuples.len() == handoff.tuples.len()
            && request
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
    };
    if !base_matches || !tuples_match {
        return Err(
            "hook context or native ref/OID updates differ from primary authorization".to_owned(),
        );
    }
    if handoff.dynamic_tuples {
        request.allow_unleased_force = handoff.force_requested;
    } else {
        request.allow_unleased_force = handoff.force_requested;
        request.leases = handoff
            .tuples
            .iter()
            .filter_map(|planned| {
                planned.expected_lease_oid.as_ref().map(|expected_oid| {
                    crate::git_command::ExactPushLease {
                        remote_ref: planned.remote_ref.clone(),
                        expected_oid: expected_oid.clone(),
                    }
                })
            })
            .collect();
    }
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
            .map(|binding| crate::push_handoff::HandoffGithubBinding {
                host: binding.host.clone(),
                account_id: binding.account_id.clone(),
            });
    if handoff.github_binding != binding {
        return Err("enrolled GitHub binding changed after primary push authorization".to_owned());
    }
    Ok(ValidatedPrimaryHandoff {
        github_binding: binding,
        allow_unleased_force: handoff.force_requested,
        _lock: locked_handoff,
    })
}

pub fn run_managed_pre_push() -> Result<u8, String> {
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
    let paths = crate::hooks::resolve_paths(&git, &root)?;
    let manifest = crate::hooks::load_manifest(&paths)?;
    let executable = persona_dispatcher_executable()?;
    if std::fs::canonicalize(manifest.persona_executable())
        .ok()
        .as_ref()
        != Some(&executable)
    {
        return Err(format!(
            "pre-push hook manifest belongs to a different Persona executable ({}); run `persona hooks refresh --cwd {}`",
            manifest.persona_executable().display(),
            root.display()
        ));
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
