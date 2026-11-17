use crate::config::{Config, SshPolicy};
use crate::git::GitClient;
use crate::runtime::{
    gh_executable, git_executable, isolated_git_environment, resolve_config_path, ssh_executable,
    ssh_keygen_executable, status_exit_code, validate_managed_shim_directory,
};
use std::path::PathBuf;

pub fn validate_managed_ssh_destination(
    policy: Option<&SshPolicy>,
    destination: &str,
    operation: &str,
) -> Result<(), &'static str> {
    let Some(policy) = policy else {
        return Err("SSH profile is not configured");
    };
    let Some((_authority, path)) = crate::destination::parse_ssh_remote(destination) else {
        return Err("SSH URL syntax is unsupported");
    };
    let Some(ssh) = ssh_executable() else {
        return Err("OpenSSH executable is unavailable");
    };
    let Some(ssh_keygen) = ssh_keygen_executable() else {
        return Err("ssh-keygen executable is unavailable");
    };
    let command = format!("{operation} '{path}'");
    crate::ssh_transport::ManagedSshTransport::new(ssh, ssh_keygen)
        .arguments(policy, destination, &command)
        .map(|_| ())
        .map_err(|error| match error {
            crate::ssh_transport::SshTransportError::RelativeExecutable(_) => {
                "transport executable is not absolute"
            }
            crate::ssh_transport::SshTransportError::UnsupportedDestination => {
                "SSH destination syntax is unsupported"
            }
            crate::ssh_transport::SshTransportError::DestinationMismatch => {
                "SSH destination differs from profile policy"
            }
            crate::ssh_transport::SshTransportError::UnsafePolicyPath(_) => {
                "SSH policy path is unsafe"
            }
            crate::ssh_transport::SshTransportError::PublicKeyMismatch => {
                "SSH key fingerprint differs from profile policy"
            }
            crate::ssh_transport::SshTransportError::UnsupportedRemoteCommand => {
                "Git remote command is unsupported"
            }
            _ => "managed SSH preflight failed",
        })
}

pub fn ssh_destination_candidates(user: &str, host: &str, port: u16, path: &str) -> Vec<String> {
    let url_path = path.strip_prefix('/').unwrap_or(path);
    let mut candidates = vec![format!("ssh://{user}@{host}:{port}/{url_path}")];
    if port == 22 {
        candidates.push(format!("ssh://{user}@{host}/{path}"));
        candidates.push(format!("{user}@{host}:{path}"));
    }
    candidates
}

pub fn run_managed_ssh() -> Result<u8, String> {
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
    let client = GitClient::new(git, isolated_git_environment(home.path()));
    let root = client.checkout_root(&cwd).unwrap_or(cwd);
    let scope = crate::context::resolve_context(&root, &config.scopes())
        .map_err(|_| "cannot resolve Persona scope for SSH".to_owned())?
        .ok_or_else(|| "SSH requires a managed Persona scope".to_owned())?;
    let policy = config
        .policies()
        .iter()
        .find(|policy| policy.name == scope.name)
        .ok_or_else(|| "SSH scope has no Git policy".to_owned())?;
    let profile = config
        .profiles()
        .iter()
        .find(|profile| profile.name == policy.profile)
        .ok_or_else(|| "SSH profile is unavailable".to_owned())?;
    let fallback_selector = if expected_program == "git-receive-pack" {
        "push"
    } else {
        "fetch"
    };
    let operation_selector = std::env::var("PERSONA_GIT_OPERATION_SELECTOR")
        .unwrap_or_else(|_| fallback_selector.to_owned());
    if !profile.git.commands.permits(&operation_selector) {
        return Err(format!(
            "SSH transport operation `{operation_selector}` is denied by the selected Persona profile"
        ));
    }
    let allowed_destinations = if expected_program == "git-receive-pack" {
        policy
            .git
            .push
            .as_ref()
            .ok_or_else(|| "SSH push requires an explicit allowed destination policy".to_owned())?
            .destinations
            .clone()
    } else if !profile.git.remotes.is_empty() {
        profile
            .git
            .remotes
            .iter()
            .flat_map(|remote| remote.fetch_destinations.iter().cloned())
            .collect::<Vec<_>>()
    } else {
        policy
            .git
            .push
            .as_ref()
            .map(|push| push.destinations.clone())
            .unwrap_or_default()
    };
    let ssh_policy = profile
        .ssh
        .as_ref()
        .ok_or_else(|| "SSH profile has no transport policy".to_owned())?;
    let candidates = ssh_destination_candidates(user, host, port, path);
    if !candidates.iter().any(|candidate| {
        crate::destination::destination_is_permitted(
            candidate,
            &allowed_destinations,
            &profile.git.deny_destinations,
        )
    }) {
        return Err("SSH destination is not explicitly allowed".to_owned());
    }
    validate_managed_ssh_destination(Some(ssh_policy), &ssh_url, expected_program)
        .map_err(|reason| format!("managed SSH policy rejected the request: {reason}"))?;
    let _ = gh_executable();
    let ssh = ssh_executable().ok_or_else(|| "OpenSSH executable is unavailable".to_owned())?;
    let ssh_keygen =
        ssh_keygen_executable().ok_or_else(|| "ssh-keygen executable is unavailable".to_owned())?;
    let mut command = crate::ssh_transport::ManagedSshTransport::new(ssh, ssh_keygen)
        .command(ssh_policy, &ssh_url, &remote_command)
        .map_err(|_| "managed SSH transport rejected the request".to_owned())?;
    let status = command
        .status()
        .map_err(|_| "cannot spawn managed SSH transport".to_owned())?;
    Ok(status_exit_code(status))
}
