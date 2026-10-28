use crate::config::Identity;
use crate::paths::PathError;
use crate::runner::{RunError, RunOutput, RunRequest, SubprocessRunner, argument};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushTuple {
    pub local_ref: String,
    pub local_oid: String,
    pub remote_ref: String,
    pub remote_oid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitIdentity {
    pub oid: String,
    pub author: Identity,
    pub committer: Identity,
}

pub struct GitClient {
    executable: PathBuf,
    environment: Vec<(OsString, OsString)>,
    runner: SubprocessRunner,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveSigning {
    pub enabled: Option<bool>,
    pub format: Option<String>,
    pub key: Option<String>,
}

#[derive(Debug)]
pub enum GitError {
    RelativeExecutable(PathBuf),
    RedirectedEnvironment(String),
    Path(PathError),
    Spawn(std::io::Error),
    Runner(String),
    CommandFailed(Option<i32>),
    InvalidOutput,
    InvalidIdentity,
    InvalidSigningConfig,
    UnexpectedRoot(PathBuf),
    Timeout,
    OutputLimit { stream: &'static str },
    MissingObject,
    UnsupportedRepository,
    InvalidPushConfig,
}

impl GitClient {
    pub fn new(executable: PathBuf, environment: Vec<(OsString, OsString)>) -> Self {
        Self {
            executable,
            environment,
            runner: SubprocessRunner::default(),
        }
    }

    pub fn with_runner(
        executable: PathBuf,
        environment: Vec<(OsString, OsString)>,
        runner: SubprocessRunner,
    ) -> Self {
        Self {
            executable,
            environment,
            runner,
        }
    }

    pub fn checkout_root(&self, directory: &Path) -> Result<PathBuf, GitError> {
        self.validate_environment()?;
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let output = self.run(&directory, ["rev-parse", "--show-toplevel"])?;

        if !output.status.success() {
            return Err(GitError::CommandFailed(output.status.code()));
        }

        let text = String::from_utf8(output.stdout).map_err(|_| GitError::InvalidOutput)?;
        let value = text.strip_suffix('\n').ok_or(GitError::InvalidOutput)?;

        if value.is_empty() || value.contains('\n') || value.contains('\r') {
            return Err(GitError::InvalidOutput);
        }

        let root = crate::paths::canonical_directory(Path::new(value)).map_err(GitError::Path)?;

        if !directory.starts_with(&root) {
            return Err(GitError::UnexpectedRoot(root));
        }

        Ok(root)
    }

    pub fn effective_author(&self, directory: &Path) -> Result<Identity, GitError> {
        self.effective_identity(directory, "GIT_AUTHOR_IDENT")
    }

    pub fn effective_committer(&self, directory: &Path) -> Result<Identity, GitError> {
        self.effective_identity(directory, "GIT_COMMITTER_IDENT")
    }

    pub fn effective_push_destinations(
        &self,
        directory: &Path,
        remote: &str,
    ) -> Result<Vec<String>, GitError> {
        self.validate_environment()?;
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let push_key = format!("remote.{remote}.pushurl");
        let url_key = format!("remote.{remote}.url");
        let values = match self.config_values(&directory, &push_key)? {
            Some(values) if !values.is_empty() => values,
            _ => self
                .config_values(&directory, &url_key)?
                .ok_or(GitError::InvalidPushConfig)?,
        };
        let push_rewrites = self.config_rewrites(&directory, "pushInsteadOf")?;
        let ordinary_rewrites = self.config_rewrites(&directory, "insteadOf")?;
        Ok(values
            .into_iter()
            .map(|value| rewrite_destination(&value, &push_rewrites, &ordinary_rewrites))
            .collect())
    }

    /// Reports only transport schemes from local remote configuration. Remote
    /// names and URL values are intentionally not returned to callers.
    pub fn remote_transport_schemes(
        &self,
        directory: &Path,
        remote: Option<&str>,
    ) -> Result<Vec<String>, GitError> {
        self.validate_environment()?;
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let values = if let Some(remote) = remote {
            self.effective_push_destinations(&directory, remote)?
        } else {
            let output = self.run(
                &directory,
                ["config", "--get-regexp", r"^remote\..*\.(pushurl|url)$"],
            )?;
            if !output.status.success() {
                if output.status.code() == Some(1) {
                    return Ok(Vec::new());
                }
                return Err(GitError::CommandFailed(output.status.code()));
            }
            let text = String::from_utf8(output.stdout).map_err(|_| GitError::InvalidOutput)?;
            let mut configured =
                std::collections::BTreeMap::<String, (Vec<String>, Vec<String>)>::new();
            for line in text.lines() {
                let Some((key, value)) = line.split_once(char::is_whitespace) else {
                    return Err(GitError::InvalidPushConfig);
                };
                let key = key
                    .strip_prefix("remote.")
                    .ok_or(GitError::InvalidPushConfig)?;
                let Some((remote_name, kind)) = key.rsplit_once('.') else {
                    return Err(GitError::InvalidPushConfig);
                };
                let values = configured.entry(remote_name.to_owned()).or_default();
                match kind {
                    "pushurl" => values.0.push(value.trim().to_owned()),
                    "url" => values.1.push(value.trim().to_owned()),
                    _ => return Err(GitError::InvalidPushConfig),
                }
            }
            configured
                .into_values()
                .flat_map(
                    |(pushurls, urls)| {
                        if pushurls.is_empty() { urls } else { pushurls }
                    },
                )
                .collect()
        };

        let mut schemes = values
            .iter()
            .map(|value| transport_scheme(value))
            .collect::<Vec<_>>();
        schemes.sort();
        schemes.dedup();
        Ok(schemes)
    }

    pub fn repository_is_incomplete(&self, directory: &Path) -> Result<bool, GitError> {
        self.validate_environment()?;
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let shallow = self.run(&directory, ["rev-parse", "--is-shallow-repository"])?;
        if !shallow.status.success() {
            return Err(GitError::CommandFailed(shallow.status.code()));
        }
        let shallow = String::from_utf8(shallow.stdout).map_err(|_| GitError::InvalidOutput)?;
        if shallow.trim() == "true" {
            return Ok(true);
        }
        let partial = self.run(
            &directory,
            [
                "config",
                "--get-regexp",
                "^(extensions\\.partialClone|remote\\..*\\.promisor)$",
            ],
        )?;
        if !partial.status.success() && partial.status.code() != Some(1) {
            return Err(GitError::CommandFailed(partial.status.code()));
        }
        Ok(!partial.stdout.is_empty())
    }

    pub fn is_ancestor(
        &self,
        directory: &Path,
        ancestor: &str,
        descendant: &str,
    ) -> Result<bool, GitError> {
        self.validate_environment()?;
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let output = self.run(
            &directory,
            ["merge-base", "--is-ancestor", ancestor, descendant],
        )?;
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(GitError::MissingObject),
        }
    }

    pub fn outgoing_commit_identities(
        &self,
        directory: &Path,
        update: &PushTuple,
    ) -> Result<Vec<CommitIdentity>, GitError> {
        self.validate_environment()?;
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        if self.repository_is_incomplete(&directory)? {
            return Err(GitError::UnsupportedRepository);
        }
        if !is_oid(&update.local_oid) || is_zero_oid(&update.local_oid) {
            return Err(GitError::MissingObject);
        }
        let local_type = self.cat_file_type(&directory, &update.local_oid)?;
        if local_type != "commit" {
            return Err(GitError::UnsupportedRepository);
        }
        let mut args = vec![OsString::from("rev-list"), OsString::from("--topo-order")];
        args.push(OsString::from(&update.local_oid));
        if !is_zero_oid(&update.remote_oid) {
            if !is_oid(&update.remote_oid) {
                return Err(GitError::MissingObject);
            }
            args.push(OsString::from(format!("^{}", update.remote_oid)));
        }
        let output = self.run_owned(&directory, &args)?;
        if !output.status.success() {
            return Err(GitError::MissingObject);
        }
        let text = String::from_utf8(output.stdout).map_err(|_| GitError::InvalidOutput)?;
        let mut commits = Vec::new();
        for oid in text.lines() {
            if !is_oid(oid) {
                return Err(GitError::InvalidOutput);
            }
            commits.push(self.commit_identities(&directory, oid)?);
        }
        Ok(commits)
    }

    pub fn effective_signing(&self, directory: &Path) -> Result<EffectiveSigning, GitError> {
        self.validate_environment()?;
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let output = self.run(
            &directory,
            [
                "config",
                "--get-regexp",
                "^(commit\\.gpgsign|gpg\\.format|user\\.signingkey)$",
            ],
        )?;
        if !output.status.success() && output.status.code() != Some(1) {
            return Err(GitError::CommandFailed(output.status.code()));
        }

        let text = String::from_utf8(output.stdout).map_err(|_| GitError::InvalidOutput)?;
        let mut signing = EffectiveSigning::default();
        for line in text.lines() {
            let Some((name, value)) = line.split_once(char::is_whitespace) else {
                return Err(GitError::InvalidSigningConfig);
            };
            let value = value.trim();
            match name {
                "commit.gpgsign" | "commit.gpgSign" => {
                    signing.enabled =
                        Some(parse_bool(value).ok_or(GitError::InvalidSigningConfig)?);
                }
                "gpg.format" => signing.format = Some(value.to_owned()),
                "user.signingkey" => signing.key = Some(value.to_owned()),
                _ => return Err(GitError::InvalidSigningConfig),
            }
        }
        Ok(signing)
    }

    pub fn head_has_signature(&self, directory: &Path) -> Result<bool, GitError> {
        self.commit_has_signature(directory, "HEAD")
    }

    pub fn commit_has_signature(&self, directory: &Path, oid: &str) -> Result<bool, GitError> {
        self.validate_environment()?;
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let output = self.run(&directory, ["cat-file", "commit", oid])?;
        if !output.status.success() {
            return Err(GitError::CommandFailed(output.status.code()));
        }
        let text = String::from_utf8(output.stdout).map_err(|_| GitError::InvalidOutput)?;
        Ok(text.lines().any(|line| line.starts_with("gpgsig ")))
    }

    pub fn verify_head(
        &self,
        directory: &Path,
        gnupg_home: &Path,
        gpg_executable: &Path,
    ) -> Result<RunOutput, GitError> {
        self.verify_commit(directory, "HEAD", gnupg_home, gpg_executable)
    }

    pub fn verify_commit(
        &self,
        directory: &Path,
        oid: &str,
        gnupg_home: &Path,
        gpg_executable: &Path,
    ) -> Result<RunOutput, GitError> {
        self.validate_environment()?;
        if gpg_executable.is_relative() {
            return Err(GitError::RelativeExecutable(gpg_executable.to_path_buf()));
        }
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let mut environment = self.bounded_environment();
        environment.retain(|(name, _)| {
            name != "GNUPGHOME" && name != "GPG_AGENT_INFO" && name != "GPG_TTY"
        });
        environment.push(("GNUPGHOME".into(), gnupg_home.as_os_str().to_owned()));
        // Command-line config has higher precedence than repository, global,
        // and system config, so an untrusted repo cannot replace the selected
        // verifier with its own gpg.program helper.
        let gpg_config = format!("gpg.program={}", gpg_executable.display());
        self.run_with_environment(
            &directory,
            ["-c", &gpg_config, "verify-commit", "--raw", oid],
            &environment,
        )
    }

    fn effective_identity(&self, directory: &Path, variable: &str) -> Result<Identity, GitError> {
        self.validate_environment()?;
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let output = self.run(&directory, ["var", variable])?;

        if !output.status.success() {
            return Err(GitError::CommandFailed(output.status.code()));
        }

        let text = String::from_utf8(output.stdout).map_err(|_| GitError::InvalidOutput)?;
        parse_identity(text.trim_end_matches('\n'))
    }

    fn run<const N: usize>(
        &self,
        directory: &Path,
        args: [&str; N],
    ) -> Result<crate::runner::RunOutput, GitError> {
        let environment = self.bounded_environment();
        self.run_with_environment(directory, args, &environment)
    }

    fn run_owned(
        &self,
        directory: &Path,
        args: &[OsString],
    ) -> Result<crate::runner::RunOutput, GitError> {
        let environment = self.bounded_environment();
        self.runner
            .run(crate::runner::RunRequest {
                executable: &self.executable,
                args,
                cwd: directory,
                environment: &environment,
            })
            .map_err(map_runner_error)
    }

    fn config_values(&self, directory: &Path, key: &str) -> Result<Option<Vec<String>>, GitError> {
        let args = vec![
            OsString::from("config"),
            OsString::from("--get-all"),
            OsString::from(key),
        ];
        let output = self.run_owned(directory, &args)?;
        if !output.status.success() {
            if output.status.code() == Some(1) {
                return Ok(None);
            }
            return Err(GitError::CommandFailed(output.status.code()));
        }
        let text = String::from_utf8(output.stdout).map_err(|_| GitError::InvalidOutput)?;
        Ok(Some(text.lines().map(str::to_owned).collect()))
    }

    fn config_rewrites(
        &self,
        directory: &Path,
        suffix: &str,
    ) -> Result<Vec<(String, String)>, GitError> {
        let suffix_lower = suffix.to_ascii_lowercase();
        let pattern = format!(r"^url\..*\.{suffix_lower}$");
        let args = vec![
            OsString::from("config"),
            OsString::from("--get-regexp"),
            OsString::from(pattern),
        ];
        let output = self.run_owned(directory, &args)?;
        if !output.status.success() {
            if output.status.code() == Some(1) {
                return Ok(Vec::new());
            }
            return Err(GitError::CommandFailed(output.status.code()));
        }
        let text = String::from_utf8(output.stdout).map_err(|_| GitError::InvalidOutput)?;
        let mut rewrites = Vec::new();
        for line in text.lines() {
            let Some((key, value)) = line.split_once(char::is_whitespace) else {
                return Err(GitError::InvalidOutput);
            };
            let key_without_url = key.strip_prefix("url.").ok_or(GitError::InvalidOutput)?;
            let key_lower = key_without_url.to_ascii_lowercase();
            let suffix_marker = format!(".{suffix_lower}");
            let prefix_length = key_lower
                .strip_suffix(&suffix_marker)
                .map(|prefix| prefix.len())
                .ok_or(GitError::InvalidOutput)?;
            let prefix = &key_without_url[..prefix_length];
            rewrites.push((prefix.to_owned(), value.trim().to_owned()));
        }
        Ok(rewrites)
    }

    fn cat_file_type(&self, directory: &Path, oid: &str) -> Result<String, GitError> {
        let output = self.run(directory, ["cat-file", "-t", oid])?;
        if !output.status.success() {
            return Err(GitError::MissingObject);
        }
        String::from_utf8(output.stdout)
            .map_err(|_| GitError::InvalidOutput)
            .map(|value| value.trim().to_owned())
    }

    fn commit_identities(&self, directory: &Path, oid: &str) -> Result<CommitIdentity, GitError> {
        let output = self.run(directory, ["cat-file", "commit", oid])?;
        if !output.status.success() {
            return Err(GitError::MissingObject);
        }
        let text = String::from_utf8(output.stdout).map_err(|_| GitError::InvalidOutput)?;
        let author = parse_commit_identity(&text, "author ")?;
        let committer = parse_commit_identity(&text, "committer ")?;
        Ok(CommitIdentity {
            oid: oid.to_owned(),
            author,
            committer,
        })
    }

    fn run_with_environment<const N: usize>(
        &self,
        directory: &Path,
        args: [&str; N],
        environment: &[(OsString, OsString)],
    ) -> Result<crate::runner::RunOutput, GitError> {
        let args = args.map(argument);
        self.runner
            .run(RunRequest {
                executable: &self.executable,
                args: &args,
                cwd: directory,
                environment,
            })
            .map_err(map_runner_error)
    }

    fn bounded_environment(&self) -> Vec<(OsString, OsString)> {
        let mut environment = self.environment.clone();
        for variable in [
            "GIT_TERMINAL_PROMPT",
            "GIT_OPTIONAL_LOCKS",
            "GIT_NO_LAZY_FETCH",
        ] {
            environment.retain(|(name, _)| name != variable);
        }
        environment.extend([
            ("GIT_TERMINAL_PROMPT".into(), "0".into()),
            ("GIT_OPTIONAL_LOCKS".into(), "0".into()),
            ("GIT_NO_LAZY_FETCH".into(), "1".into()),
        ]);
        environment
    }

    fn validate_environment(&self) -> Result<(), GitError> {
        if self.executable.is_relative() {
            return Err(GitError::RelativeExecutable(self.executable.clone()));
        }

        for (key, _) in &self.environment {
            for variable in [
                "GIT_DIR",
                "GIT_WORK_TREE",
                "GIT_COMMON_DIR",
                "GIT_CONFIG_COUNT",
                "GIT_CONFIG_PARAMETERS",
                "GIT_CONFIG_KEY_0",
                "GIT_CONFIG_VALUE_0",
            ] {
                if key.as_os_str() == std::ffi::OsStr::new(variable) {
                    return Err(GitError::RedirectedEnvironment(variable.to_owned()));
                }
            }
        }
        Ok(())
    }
}

fn parse_commit_identity(value: &str, prefix: &str) -> Result<Identity, GitError> {
    let line = value
        .lines()
        .find(|line| line.starts_with(prefix))
        .ok_or(GitError::InvalidIdentity)?;
    parse_identity(line[prefix.len()..].trim_end())
}

fn parse_identity(value: &str) -> Result<Identity, GitError> {
    // `git var` appends the timestamp and timezone after the identity.
    let Some(email_end) = value.rfind('>') else {
        return Err(GitError::InvalidIdentity);
    };
    if !value[email_end + 1..]
        .chars()
        .next()
        .is_some_and(char::is_whitespace)
    {
        return Err(GitError::InvalidIdentity);
    }
    let Some(email_start) = value[..email_end].rfind('<') else {
        return Err(GitError::InvalidIdentity);
    };
    let name = value[..email_start].trim();
    let email = value[email_start + 1..email_end].trim();
    if name.is_empty() || email.is_empty() {
        return Err(GitError::InvalidIdentity);
    }
    Ok(Identity {
        name: name.to_owned(),
        email: email.to_owned(),
    })
}

fn map_runner_error(error: RunError) -> GitError {
    match error {
        RunError::RelativeExecutable(path) => GitError::RelativeExecutable(path),
        RunError::Spawn(error) | RunError::Wait(error) | RunError::Termination(error) => {
            GitError::Runner(error)
        }
        RunError::Timeout => GitError::Timeout,
        RunError::OutputLimit { stream } => GitError::OutputLimit { stream },
    }
}

fn is_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn is_zero_oid(value: &str) -> bool {
    is_oid(value) && value.chars().all(|character| character == '0')
}

fn transport_scheme(value: &str) -> String {
    let value = value.trim();
    let lower = value.to_ascii_lowercase();
    if value.contains('@')
        && value
            .find(':')
            .is_some_and(|colon| value.find('@').is_some_and(|at| at < colon))
    {
        return "ssh".to_owned();
    }

    let Some((scheme, _)) = lower.split_once("://") else {
        return "unknown".to_owned();
    };
    if !valid_uri_scheme(scheme) {
        return "unknown".to_owned();
    }

    match scheme {
        "ssh" | "git+ssh" => "ssh".to_owned(),
        "http" | "https" => scheme.to_owned(),
        "git" | "file" => scheme.to_owned(),
        _ => "unknown".to_owned(),
    }
}

fn valid_uri_scheme(scheme: &str) -> bool {
    let mut characters = scheme.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic())
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
}

fn rewrite_destination(
    value: &str,
    push_rewrites: &[(String, String)],
    ordinary_rewrites: &[(String, String)],
) -> String {
    let rewrite = push_rewrites
        .iter()
        .filter(|(_, suffix)| value.starts_with(suffix))
        .max_by_key(|(_, suffix)| suffix.len())
        .or_else(|| {
            ordinary_rewrites
                .iter()
                .filter(|(_, suffix)| value.starts_with(suffix))
                .max_by_key(|(_, suffix)| suffix.len())
        });
    rewrite
        .map(|(prefix, suffix)| format!("{prefix}{}", &value[suffix.len()..]))
        .unwrap_or_else(|| value.to_owned())
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Some(true),
        "false" | "no" | "off" | "0" => Some(false),
        _ => None,
    }
}

pub fn safe_environment() -> Vec<(OsString, OsString)> {
    std::env::vars_os()
        .filter(|(name, _)| !is_sensitive_environment_name(name.to_string_lossy().as_ref()))
        .collect()
}

fn is_sensitive_environment_name(name: &str) -> bool {
    matches!(
        name,
        "GH_TOKEN"
            | "GITHUB_TOKEN"
            | "GH_HOST"
            | "GH_CONFIG_DIR"
            | "GIT_SSH"
            | "GIT_SSH_COMMAND"
            | "SSH_AUTH_SOCK"
            | "GIT_ASKPASS"
            | "SSH_ASKPASS"
            | "AWS_SECRET_ACCESS_KEY"
            | "AWS_SESSION_TOKEN"
    ) || name.ends_with("_TOKEN")
        || name.ends_with("_PASSWORD")
        || name.ends_with("_SECRET")
}
