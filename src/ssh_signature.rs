use crate::git::{GitClient, GitError};
use crate::runner::{RunError, RunOutput, RunRequest, SubprocessRunner, argument};
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

#[derive(Debug)]
pub enum SshSignatureError {
    RelativeExecutable(PathBuf),
    InvalidPublicKey,
    InvalidPrincipal,
    CommandFailed(Option<i32>),
    InvalidOutput,
    Runner(String),
    Timeout,
    OutputLimit { stream: &'static str },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshVerification {
    pub cryptographically_valid: bool,
    pub fingerprint: Option<String>,
}

pub struct SshVerifier {
    executable: PathBuf,
    runner: SubprocessRunner,
}

impl SshVerifier {
    pub fn new(executable: PathBuf) -> Self {
        Self {
            executable,
            runner: SubprocessRunner::default(),
        }
    }

    pub fn public_key_fingerprint(&self, public_key: &Path) -> Result<String, SshSignatureError> {
        if self.executable.is_relative() {
            return Err(SshSignatureError::RelativeExecutable(
                self.executable.clone(),
            ));
        }
        let bytes = std::fs::read(public_key).map_err(|_| SshSignatureError::InvalidPublicKey)?;
        if !bytes.is_ascii() {
            return Err(SshSignatureError::InvalidPublicKey);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| SshSignatureError::InvalidPublicKey)?;
        let mut lines = text.lines().filter(|line| !line.trim().is_empty());
        let key_line = lines
            .next()
            .ok_or(SshSignatureError::InvalidPublicKey)?
            .trim();
        if lines.next().is_some() {
            return Err(SshSignatureError::InvalidPublicKey);
        }
        let fields = key_line.split_whitespace().collect::<Vec<_>>();
        if !(2..=3).contains(&fields.len()) || !valid_key_type(fields[0]) {
            return Err(SshSignatureError::InvalidPublicKey);
        }
        let mut staged = NamedTempFile::new().map_err(|_| SshSignatureError::InvalidPublicKey)?;
        staged
            .write_all(key_line.as_bytes())
            .and_then(|_| staged.as_file_mut().sync_all())
            .map_err(|_| SshSignatureError::InvalidPublicKey)?;
        let path = staged.path().to_string_lossy().into_owned();
        let output = self.run(["-lf", &path, "-E", "sha256"], Path::new("/"))?;
        if !output.status.success() {
            return Err(SshSignatureError::InvalidPublicKey);
        }
        combine_output(output)?
            .split_whitespace()
            .find(|field| field.starts_with("SHA256:") && field.len() > "SHA256:".len())
            .map(str::to_owned)
            .ok_or(SshSignatureError::InvalidOutput)
    }

    pub fn verify_commit(
        &self,
        git: &GitClient,
        directory: &Path,
        oid: &str,
        public_key: &Path,
        principal: &str,
    ) -> Result<SshVerification, SshSignatureError> {
        self.verify_object(git, directory, oid, public_key, principal, false)
    }

    pub fn verify_tag(
        &self,
        git: &GitClient,
        directory: &Path,
        oid: &str,
        public_key: &Path,
        principal: &str,
    ) -> Result<SshVerification, SshSignatureError> {
        self.verify_object(git, directory, oid, public_key, principal, true)
    }

    fn verify_object(
        &self,
        git: &GitClient,
        directory: &Path,
        oid: &str,
        public_key: &Path,
        principal: &str,
        tag: bool,
    ) -> Result<SshVerification, SshSignatureError> {
        if self.executable.is_relative() {
            return Err(SshSignatureError::RelativeExecutable(
                self.executable.clone(),
            ));
        }
        if principal.is_empty()
            || principal
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte == 0)
        {
            return Err(SshSignatureError::InvalidPrincipal);
        }
        let bytes = std::fs::read(public_key).map_err(|_| SshSignatureError::InvalidPublicKey)?;
        if !bytes.is_ascii() {
            return Err(SshSignatureError::InvalidPublicKey);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| SshSignatureError::InvalidPublicKey)?;
        let mut lines = text.lines().filter(|line| !line.trim().is_empty());
        let key_line = lines
            .next()
            .ok_or(SshSignatureError::InvalidPublicKey)?
            .trim();
        if lines.next().is_some() {
            return Err(SshSignatureError::InvalidPublicKey);
        }
        let fields = key_line.split_whitespace().collect::<Vec<_>>();
        if !(2..=3).contains(&fields.len()) || !valid_key_type(fields[0]) {
            return Err(SshSignatureError::InvalidPublicKey);
        }

        let mut staged_key =
            NamedTempFile::new().map_err(|_| SshSignatureError::InvalidPublicKey)?;
        staged_key
            .write_all(key_line.as_bytes())
            .and_then(|_| staged_key.as_file_mut().sync_all())
            .map_err(|_| SshSignatureError::InvalidPublicKey)?;
        let staged_key_path = staged_key.path().to_string_lossy().into_owned();
        let fingerprint_output =
            self.run(["-lf", &staged_key_path, "-E", "sha256"], Path::new("/"))?;
        if !fingerprint_output.status.success() {
            return Err(SshSignatureError::InvalidPublicKey);
        }
        let fingerprint_text = combine_output(fingerprint_output)?;
        let fingerprint = fingerprint_text
            .split_whitespace()
            .find(|field| field.starts_with("SHA256:"))
            .filter(|field| field.len() > "SHA256:".len())
            .ok_or(SshSignatureError::InvalidOutput)?
            .to_owned();

        let mut allowed_signers =
            NamedTempFile::new().map_err(|_| SshSignatureError::InvalidPublicKey)?;
        writeln!(allowed_signers, "{principal} {key_line}")
            .and_then(|_| allowed_signers.as_file_mut().sync_all())
            .map_err(|_| SshSignatureError::InvalidPublicKey)?;
        let result = if tag {
            git.verify_ssh_tag(directory, oid, &self.executable, allowed_signers.path())
        } else {
            git.verify_ssh_commit(directory, oid, &self.executable, allowed_signers.path())
        }
        .map_err(map_git_error)?;
        let valid = result.status.success();
        let output = combine_output(result)?;
        let observed = output
            .split_whitespace()
            .find(|field| field.starts_with("SHA256:"))
            .map(str::to_owned);
        Ok(SshVerification {
            cryptographically_valid: valid,
            fingerprint: observed.or(Some(fingerprint)),
        })
    }

    fn run<const N: usize>(
        &self,
        args: [&str; N],
        cwd: &Path,
    ) -> Result<RunOutput, SshSignatureError> {
        let args = args.map(argument);
        let environment = vec![
            (OsString::from("HOME"), OsString::from("/")),
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
            (OsString::from("LC_ALL"), OsString::from("C")),
        ];
        self.runner
            .run(RunRequest {
                executable: &self.executable,
                args: &args,
                cwd,
                environment: &environment,
                stdin: None,
            })
            .map_err(map_runner_error)
    }
}

fn valid_key_type(value: &str) -> bool {
    value.starts_with("ssh-") || value.starts_with("ecdsa-") || value.starts_with("sk-")
}

fn combine_output(output: RunOutput) -> Result<String, SshSignatureError> {
    let mut text =
        String::from_utf8(output.stdout).map_err(|_| SshSignatureError::InvalidOutput)?;
    text.push_str(&String::from_utf8(output.stderr).map_err(|_| SshSignatureError::InvalidOutput)?);
    Ok(text)
}

fn map_runner_error(error: RunError) -> SshSignatureError {
    match error {
        RunError::RelativeExecutable(path) => SshSignatureError::RelativeExecutable(path),
        RunError::Spawn(error)
        | RunError::Wait(error)
        | RunError::Termination(error)
        | RunError::StdinWrite(error) => SshSignatureError::Runner(error),
        RunError::Timeout => SshSignatureError::Timeout,
        RunError::OutputLimit { stream } => SshSignatureError::OutputLimit { stream },
    }
}

fn map_git_error(error: GitError) -> SshSignatureError {
    match error {
        GitError::RelativeExecutable(path) => SshSignatureError::RelativeExecutable(path),
        GitError::Spawn(error) => SshSignatureError::Runner(error.to_string()),
        GitError::Runner(error) => SshSignatureError::Runner(error),
        GitError::Timeout => SshSignatureError::Timeout,
        GitError::OutputLimit { stream } => SshSignatureError::OutputLimit { stream },
        GitError::CommandFailed(code) => SshSignatureError::CommandFailed(code),
        _ => SshSignatureError::InvalidOutput,
    }
}
