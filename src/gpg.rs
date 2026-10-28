use crate::git::{GitClient, GitError};
use crate::runner::{RunError, RunOutput, RunRequest, SubprocessRunner, argument};
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::{NamedTempFile, TempDir};

#[derive(Debug)]
pub enum GpgError {
    RelativeExecutable(PathBuf),
    Spawn(String),
    CommandFailed(Option<i32>),
    Runner(String),
    InvalidOutput,
    MissingPublicKey,
    InvalidPublicKey,
    SecretKeyMaterial,
    Timeout,
    OutputLimit { stream: &'static str },
}

pub struct GpgClient {
    executable: PathBuf,
    runner: SubprocessRunner,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    pub cryptographically_valid: bool,
    pub unavailable_key: bool,
    pub primary_fingerprint: Option<String>,
}

impl GpgClient {
    pub fn new(executable: PathBuf) -> Self {
        Self {
            executable,
            runner: SubprocessRunner::default(),
        }
    }

    pub fn with_runner(executable: PathBuf, runner: SubprocessRunner) -> Self {
        Self { executable, runner }
    }

    /// Imports only the explicitly configured public-key file into an empty,
    /// temporary GnuPG home. No user keyring, config, agent, or keyserver is
    /// available to this operation.
    pub fn isolated_keyring(&self, public_key: &Path) -> Result<TempDir, GpgError> {
        if self.executable.is_relative() {
            return Err(GpgError::RelativeExecutable(self.executable.clone()));
        }
        if !public_key.is_file() {
            return Err(GpgError::MissingPublicKey);
        }

        let armor = std::fs::read(public_key).map_err(|_| GpgError::InvalidPublicKey)?;
        if !is_public_key_armor(&armor) {
            return Err(GpgError::InvalidPublicKey);
        }

        // Stage the bytes once before invoking GnuPG. Both the packet
        // preflight and the actual import use this immutable private file, so
        // replacing the configured path between operations cannot change what
        // is admitted to the temporary keyring.
        let mut staged_key =
            NamedTempFile::new().map_err(|error| GpgError::Spawn(error.to_string()))?;
        staged_key
            .write_all(&armor)
            .and_then(|_| staged_key.as_file_mut().sync_all())
            .map_err(|_| GpgError::InvalidPublicKey)?;
        let staged_key_path = staged_key.path().to_string_lossy().into_owned();

        // Inspect the packets without importing them. In particular, a
        // secret-key armor export must be rejected before any temporary
        // keyring is created or touched by an import operation.
        let validation_home =
            tempfile::tempdir().map_err(|error| GpgError::Spawn(error.to_string()))?;
        let validation_environment = isolated_environment(validation_home.path());
        let validation_home_path = validation_home.path().to_string_lossy().into_owned();
        let output = self.run(
            [
                "--no-options",
                "--batch",
                "--with-colons",
                "--import-options",
                "show-only",
                "--dry-run",
                "--homedir",
                &validation_home_path,
                "--import",
                &staged_key_path,
            ],
            Path::new("/"),
            &validation_environment,
        )?;
        if !output.status.success() {
            return Err(GpgError::InvalidPublicKey);
        }
        let packets = String::from_utf8(output.stdout).map_err(|_| GpgError::InvalidOutput)?;
        if packets
            .lines()
            .any(|line| matches!(line.split(':').next(), Some("sec" | "ssb")))
        {
            return Err(GpgError::SecretKeyMaterial);
        }
        if !packets
            .lines()
            .any(|line| line.split(':').next() == Some("pub"))
        {
            return Err(GpgError::InvalidPublicKey);
        }

        let home = tempfile::tempdir().map_err(|error| GpgError::Spawn(error.to_string()))?;
        let environment = isolated_environment(home.path());
        let home_path = home.path().to_string_lossy().into_owned();
        let output = self.run(
            [
                "--no-options",
                "--batch",
                "--homedir",
                &home_path,
                "--import",
                &staged_key_path,
            ],
            Path::new("/"),
            &environment,
        )?;
        if !output.status.success() {
            return Err(GpgError::InvalidPublicKey);
        }
        Ok(home)
    }

    pub fn configured_primary_fingerprint(
        &self,
        home: &Path,
        configured_key: &str,
    ) -> Result<Option<String>, GpgError> {
        let output = self.list_keys(home)?;
        let configured = configured_key.trim_end_matches('!').to_ascii_uppercase();
        if configured.len() != 40 || !configured.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(None);
        }

        let mut primary = None;
        let mut awaiting_fingerprint = false;
        let text = String::from_utf8(output.stdout).map_err(|_| GpgError::InvalidOutput)?;
        for line in text.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            match fields.first().copied() {
                Some("pub") => {
                    primary = None;
                    awaiting_fingerprint = true;
                }
                Some("sub") => awaiting_fingerprint = false,
                Some("fpr") if awaiting_fingerprint => {
                    let fingerprint = fields.get(9).unwrap_or(&"").to_ascii_uppercase();
                    if fingerprint.len() == 40 {
                        primary = Some(fingerprint.clone());
                        if fingerprint == configured {
                            return Ok(Some(fingerprint));
                        }
                    }
                    awaiting_fingerprint = false;
                }
                Some("fpr") => {
                    let fingerprint = fields.get(9).unwrap_or(&"").to_ascii_uppercase();
                    if fingerprint.len() == 40 && fingerprint == configured {
                        return Ok(primary);
                    }
                }
                _ => {}
            }
        }
        Ok(None)
    }

    pub fn verify_commit(
        &self,
        git: &GitClient,
        directory: &Path,
        home: &Path,
    ) -> Result<Verification, GpgError> {
        self.verify_commit_oid(git, directory, "HEAD", home)
    }

    pub fn verify_commit_oid(
        &self,
        git: &GitClient,
        directory: &Path,
        oid: &str,
        home: &Path,
    ) -> Result<Verification, GpgError> {
        let output = git
            .verify_commit(directory, oid, home, &self.executable)
            .map_err(map_git_error)?;
        let mut statuses = String::from_utf8(output.stdout).map_err(|_| GpgError::InvalidOutput)?;
        statuses.push_str(&String::from_utf8(output.stderr).map_err(|_| GpgError::InvalidOutput)?);

        let mut primary_fingerprint = None;
        let mut valid = false;
        let mut unavailable_key = false;
        for line in statuses.lines() {
            let Some(status) = line.strip_prefix("[GNUPG:] ") else {
                continue;
            };
            let fields: Vec<&str> = status.split_whitespace().collect();
            match fields.first().copied() {
                Some("VALIDSIG") => {
                    valid = true;
                    let candidate = fields.last().copied().unwrap_or_default();
                    let candidate = if candidate.len() == 40
                        && candidate.chars().all(|c| c.is_ascii_hexdigit())
                    {
                        candidate
                    } else {
                        fields.get(1).copied().unwrap_or_default()
                    };
                    if candidate.len() == 40 && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
                        primary_fingerprint = Some(candidate.to_ascii_uppercase());
                    }
                }
                Some("NO_PUBKEY") | Some("ERRSIG") => unavailable_key = true,
                _ => {}
            }
        }

        Ok(Verification {
            cryptographically_valid: valid && output.status.success(),
            unavailable_key,
            primary_fingerprint,
        })
    }

    fn list_keys(&self, home: &Path) -> Result<RunOutput, GpgError> {
        let environment = isolated_environment(home);
        let home_path = home.to_string_lossy().into_owned();
        self.run(
            [
                "--no-options",
                "--batch",
                "--with-colons",
                "--fixed-list-mode",
                "--homedir",
                &home_path,
                "--list-keys",
            ],
            Path::new("/"),
            &environment,
        )
    }

    fn run<const N: usize>(
        &self,
        args: [&str; N],
        cwd: &Path,
        environment: &[(OsString, OsString)],
    ) -> Result<RunOutput, GpgError> {
        let args = args.map(argument);
        self.runner
            .run(RunRequest {
                executable: &self.executable,
                args: &args,
                cwd,
                environment,
            })
            .map_err(map_runner_error)
    }
}

fn is_public_key_armor(contents: &[u8]) -> bool {
    if !contents.is_ascii() {
        return false;
    }
    let Ok(text) = std::str::from_utf8(contents) else {
        return false;
    };
    let text = text.trim();
    text.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        && text.ends_with("-----END PGP PUBLIC KEY BLOCK-----")
        && !text.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----")
        && !text.contains("-----BEGIN PGP SECRET KEY BLOCK-----")
}

fn isolated_environment(home: &Path) -> Vec<(OsString, OsString)> {
    vec![
        ("HOME".into(), home.as_os_str().to_owned()),
        ("GNUPGHOME".into(), home.as_os_str().to_owned()),
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("LC_ALL".into(), "C".into()),
    ]
}

fn map_runner_error(error: RunError) -> GpgError {
    match error {
        RunError::RelativeExecutable(path) => GpgError::RelativeExecutable(path),
        RunError::Spawn(error) | RunError::Wait(error) | RunError::Termination(error) => {
            GpgError::Runner(error)
        }
        RunError::Timeout => GpgError::Timeout,
        RunError::OutputLimit { stream } => GpgError::OutputLimit { stream },
    }
}

fn map_git_error(error: GitError) -> GpgError {
    match error {
        GitError::RelativeExecutable(path) => GpgError::RelativeExecutable(path),
        GitError::Spawn(error) => GpgError::Runner(error.to_string()),
        GitError::Runner(error) => GpgError::Runner(error),
        GitError::Timeout => GpgError::Timeout,
        GitError::OutputLimit { stream } => GpgError::OutputLimit { stream },
        GitError::CommandFailed(code) => GpgError::CommandFailed(code),
        _ => GpgError::InvalidOutput,
    }
}
