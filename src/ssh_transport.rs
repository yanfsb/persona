use crate::config::SshPolicy;
use crate::runner::{RunError, RunOutput, RunRequest, SubprocessRunner};
use crate::ssh_signature::{SshSignatureError, SshVerifier};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug)]
pub enum SshTransportError {
    RelativeExecutable(PathBuf),
    UnsupportedDestination,
    DestinationMismatch,
    UnsafePolicyPath(PathBuf),
    PublicKeyMismatch,
    UnsupportedRemoteCommand,
    Spawn(String),
    Timeout,
    OutputLimit { stream: &'static str },
}

pub struct ManagedSshTransport {
    ssh: PathBuf,
    ssh_keygen: PathBuf,
    runner: SubprocessRunner,
}

impl ManagedSshTransport {
    pub fn new(ssh: PathBuf, ssh_keygen: PathBuf) -> Self {
        Self {
            ssh,
            ssh_keygen,
            runner: SubprocessRunner::default(),
        }
    }

    /// Build a shell-free OpenSSH command for adapters that need to connect its
    /// stdin/stdout directly to a Git transport protocol.
    pub fn command(
        &self,
        policy: &SshPolicy,
        destination: &str,
        remote_command: &str,
    ) -> Result<Command, SshTransportError> {
        let args = self.arguments(policy, destination, remote_command)?;
        let mut command = Command::new(&self.ssh);
        command
            .args(args)
            .current_dir("/")
            .env_clear()
            .env("HOME", "/")
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("SSH_ASKPASS_REQUIRE", "never");
        if let Some(agent) = &policy.agent_socket {
            command.env("SSH_AUTH_SOCK", agent);
        }
        Ok(command)
    }

    pub fn run(
        &self,
        policy: &SshPolicy,
        destination: &str,
        remote_command: &str,
    ) -> Result<RunOutput, SshTransportError> {
        let args = self.arguments(policy, destination, remote_command)?;
        let mut environment = vec![
            (OsString::from("HOME"), OsString::from("/")),
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
            (OsString::from("LC_ALL"), OsString::from("C")),
            (
                OsString::from("SSH_ASKPASS_REQUIRE"),
                OsString::from("never"),
            ),
        ];
        if let Some(agent) = &policy.agent_socket {
            environment.push((
                OsString::from("SSH_AUTH_SOCK"),
                agent.as_os_str().to_owned(),
            ));
        }
        self.runner
            .run(RunRequest {
                executable: &self.ssh,
                args: &args,
                cwd: Path::new("/"),
                environment: &environment,
                stdin: None,
            })
            .map_err(map_runner_error)
    }

    pub fn arguments(
        &self,
        policy: &SshPolicy,
        destination: &str,
        remote_command: &str,
    ) -> Result<Vec<OsString>, SshTransportError> {
        if self.ssh.is_relative() || self.ssh_keygen.is_relative() {
            return Err(SshTransportError::RelativeExecutable(
                if self.ssh.is_relative() {
                    self.ssh.clone()
                } else {
                    self.ssh_keygen.clone()
                },
            ));
        }
        validate_policy_paths(policy)?;
        let parsed = parse_destination(destination)?;
        if !parsed.host.eq_ignore_ascii_case(&policy.host)
            || parsed.user != policy.user
            || parsed.port != policy.port
        {
            return Err(SshTransportError::DestinationMismatch);
        }
        let verifier = SshVerifier::new(self.ssh_keygen.clone());
        if verifier
            .public_key_fingerprint(&policy.public_key)
            .map_err(map_signature_error)?
            != policy.fingerprint
        {
            return Err(SshTransportError::PublicKeyMismatch);
        }
        if let Some(identity) = &policy.identity_file {
            let public_identity = if identity
                .extension()
                .is_some_and(|extension| extension == "pub")
            {
                identity.clone()
            } else {
                PathBuf::from(format!("{}.pub", identity.display()))
            };
            validate_regular_file(&public_identity)?;
            if verifier
                .public_key_fingerprint(&public_identity)
                .ok()
                .as_deref()
                != Some(policy.fingerprint.as_str())
            {
                return Err(SshTransportError::PublicKeyMismatch);
            }
        }
        validate_remote_command(remote_command)?;

        let mut args = vec![
            OsString::from("-F"),
            OsString::from("none"),
            OsString::from("-o"),
            OsString::from("BatchMode=yes"),
            OsString::from("-o"),
            OsString::from("IdentitiesOnly=yes"),
            OsString::from("-o"),
            OsString::from("StrictHostKeyChecking=yes"),
            OsString::from("-o"),
            format!("UserKnownHostsFile={}", policy.known_hosts_file.display()).into(),
            OsString::from("-o"),
            OsString::from("GlobalKnownHostsFile=/dev/null"),
            OsString::from("-o"),
            OsString::from("UpdateHostKeys=no"),
            OsString::from("-o"),
            OsString::from("VerifyHostKeyDNS=no"),
            OsString::from("-o"),
            OsString::from("ProxyCommand=none"),
            OsString::from("-o"),
            OsString::from("ProxyJump=none"),
            OsString::from("-o"),
            OsString::from("ControlMaster=no"),
            OsString::from("-o"),
            OsString::from("ControlPath=none"),
            OsString::from("-o"),
            OsString::from("ControlPersist=no"),
            OsString::from("-o"),
            OsString::from("ForwardAgent=no"),
            OsString::from("-o"),
            OsString::from("ClearAllForwardings=yes"),
            OsString::from("-o"),
            OsString::from("PermitLocalCommand=no"),
            OsString::from("-o"),
            OsString::from("RequestTTY=no"),
            OsString::from("-p"),
            policy.port.to_string().into(),
            OsString::from("-l"),
            policy.user.clone().into(),
        ];
        if let Some(agent) = &policy.agent_socket {
            args.extend([
                OsString::from("-o"),
                format!("IdentityAgent={}", agent.display()).into(),
                OsString::from("-i"),
                policy.public_key.as_os_str().to_owned(),
            ]);
        } else if let Some(identity) = &policy.identity_file {
            args.extend([
                OsString::from("-o"),
                OsString::from("IdentityAgent=none"),
                OsString::from("-i"),
                identity.as_os_str().to_owned(),
            ]);
        }
        args.push(policy.host.clone().into());
        args.push(remote_command.into());
        Ok(args)
    }
}

struct ParsedDestination {
    user: String,
    host: String,
    port: u16,
}

fn parse_destination(value: &str) -> Result<ParsedDestination, SshTransportError> {
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(SshTransportError::UnsupportedDestination);
    }
    if let Some(rest) = value.strip_prefix("ssh://") {
        let (authority, path) = rest
            .split_once('/')
            .ok_or(SshTransportError::UnsupportedDestination)?;
        if path.is_empty()
            || authority.contains('?')
            || authority.contains('#')
            || authority.matches('@').count() != 1
        {
            return Err(SshTransportError::UnsupportedDestination);
        }
        let (user, host_port) = authority
            .split_once('@')
            .ok_or(SshTransportError::UnsupportedDestination)?;
        if user.is_empty() || user.contains(':') || host_port.contains('@') {
            return Err(SshTransportError::UnsupportedDestination);
        }
        let (host, port) = match host_port.rsplit_once(':') {
            Some((host, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => (
                host,
                port.parse::<u16>()
                    .ok()
                    .filter(|port| *port > 0)
                    .ok_or(SshTransportError::UnsupportedDestination)?,
            ),
            _ => (host_port, 22),
        };
        if !valid_host(host) {
            return Err(SshTransportError::UnsupportedDestination);
        }
        return Ok(ParsedDestination {
            user: user.to_owned(),
            host: host.to_ascii_lowercase(),
            port,
        });
    }
    let (authority, path) = value
        .split_once(':')
        .ok_or(SshTransportError::UnsupportedDestination)?;
    if path.is_empty() || authority.matches('@').count() != 1 {
        return Err(SshTransportError::UnsupportedDestination);
    }
    let (user, host) = authority
        .split_once('@')
        .ok_or(SshTransportError::UnsupportedDestination)?;
    if user.is_empty() || user.contains(':') || !valid_host(host) {
        return Err(SshTransportError::UnsupportedDestination);
    }
    Ok(ParsedDestination {
        user: user.to_owned(),
        host: host.to_ascii_lowercase(),
        port: 22,
    })
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.is_ascii()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn validate_remote_command(command: &str) -> Result<(), SshTransportError> {
    let (program, rest) = command
        .split_once(" '")
        .ok_or(SshTransportError::UnsupportedRemoteCommand)?;
    if !matches!(
        program,
        "git-upload-pack" | "git-receive-pack" | "git-upload-archive"
    ) || !rest.ends_with('\'')
    {
        return Err(SshTransportError::UnsupportedRemoteCommand);
    }
    let path = &rest[..rest.len() - 1];
    if path.is_empty()
        || path.starts_with('-')
        || path.split('/').any(|part| part == "..")
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        return Err(SshTransportError::UnsupportedRemoteCommand);
    }
    Ok(())
}

fn validate_policy_paths(policy: &SshPolicy) -> Result<(), SshTransportError> {
    for path in [
        Some(&policy.public_key),
        Some(&policy.known_hosts_file),
        policy.identity_file.as_ref(),
        policy.agent_socket.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if !path.is_absolute() {
            return Err(SshTransportError::UnsafePolicyPath(path.clone()));
        }
    }
    validate_option_path(&policy.public_key)?;
    validate_regular_file(&policy.public_key)?;
    validate_option_path(&policy.known_hosts_file)?;
    validate_regular_file(&policy.known_hosts_file)?;
    if let Some(identity) = &policy.identity_file {
        validate_option_path(identity)?;
        validate_regular_file(identity)?;
    }
    if let Some(agent) = &policy.agent_socket {
        validate_option_path(agent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            let metadata = std::fs::symlink_metadata(agent)
                .map_err(|_| SshTransportError::UnsafePolicyPath(agent.clone()))?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
                return Err(SshTransportError::UnsafePolicyPath(agent.clone()));
            }
        }
    }
    Ok(())
}

fn validate_option_path(path: &Path) -> Result<(), SshTransportError> {
    let text = path
        .to_str()
        .ok_or_else(|| SshTransportError::UnsafePolicyPath(path.to_path_buf()))?;
    if text.bytes().any(|byte| {
        byte.is_ascii_whitespace() || matches!(byte, b',' | b'\\' | b'\'' | b'"' | b'%')
    }) {
        return Err(SshTransportError::UnsafePolicyPath(path.to_path_buf()));
    }
    Ok(())
}

fn validate_regular_file(path: &Path) -> Result<(), SshTransportError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| SshTransportError::UnsafePolicyPath(path.to_path_buf()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SshTransportError::UnsafePolicyPath(path.to_path_buf()));
    }
    Ok(())
}

fn map_signature_error(error: SshSignatureError) -> SshTransportError {
    match error {
        SshSignatureError::RelativeExecutable(path) => SshTransportError::RelativeExecutable(path),
        SshSignatureError::Timeout => SshTransportError::Timeout,
        SshSignatureError::OutputLimit { stream } => SshTransportError::OutputLimit { stream },
        SshSignatureError::Runner(error) => SshTransportError::Spawn(error),
        _ => SshTransportError::PublicKeyMismatch,
    }
}

fn map_runner_error(error: RunError) -> SshTransportError {
    match error {
        RunError::RelativeExecutable(path) => SshTransportError::RelativeExecutable(path),
        RunError::Spawn(error)
        | RunError::Wait(error)
        | RunError::Termination(error)
        | RunError::StdinWrite(error) => SshTransportError::Spawn(error),
        RunError::Timeout => SshTransportError::Timeout,
        RunError::OutputLimit { stream } => SshTransportError::OutputLimit { stream },
    }
}
