use crate::config::Identity;
use crate::paths::PathError;
use crate::runner::{RunError, RunLimits, RunOutput, RunRequest, SubprocessRunner, argument};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

const MAX_REACHABLE_PUBLICATION_OBJECTS: usize = 65_536;
const MAX_REACHABLE_PUBLICATION_BYTES: usize = 256 * 1024 * 1024;
const MAX_GIT_STDOUT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachableObjects {
    pub object_ids: Vec<String>,
    pub complete: bool,
}

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
    pub tag_enabled: Option<bool>,
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
    UnsupportedSignatureFormat(String),
    UnexpectedRoot(PathBuf),
    Timeout,
    OutputLimit { stream: &'static str },
    MissingObject,
    UnsupportedRepository,
    InvalidPushConfig,
    UnsafeTransportConfiguration,
}

impl GitClient {
    pub fn new(executable: PathBuf, environment: Vec<(OsString, OsString)>) -> Self {
        Self {
            executable,
            environment,
            runner: SubprocessRunner::new(RunLimits {
                timeout: std::time::Duration::from_secs(5),
                max_stdout_bytes: MAX_GIT_STDOUT_BYTES,
                max_stderr_bytes: 64 * 1024,
                poll_interval: std::time::Duration::from_millis(5),
            }),
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

    pub fn effective_fetch_destinations(
        &self,
        directory: &Path,
        remote: &str,
    ) -> Result<Vec<String>, GitError> {
        self.effective_remote_destinations(directory, remote, false)
    }

    pub fn effective_push_destinations(
        &self,
        directory: &Path,
        remote: &str,
    ) -> Result<Vec<String>, GitError> {
        self.effective_remote_destinations(directory, remote, true)
    }

    fn effective_remote_destinations(
        &self,
        directory: &Path,
        remote: &str,
        push: bool,
    ) -> Result<Vec<String>, GitError> {
        self.validate_environment()?;
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        if remote.is_empty()
            || remote.len() > 128
            || remote.starts_with('-')
            || !remote
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(GitError::InvalidPushConfig);
        }
        let output = if push {
            self.run(
                &directory,
                ["remote", "get-url", "--push", "--all", "--", remote],
            )?
        } else {
            self.run(&directory, ["remote", "get-url", "--all", "--", remote])?
        };
        if !output.status.success() {
            return if output.status.code() == Some(2) {
                Err(GitError::InvalidPushConfig)
            } else {
                Err(GitError::CommandFailed(output.status.code()))
            };
        }
        let text = String::from_utf8(output.stdout).map_err(|_| GitError::InvalidOutput)?;
        let destinations = text.lines().map(str::to_owned).collect::<Vec<_>>();
        if destinations.is_empty() || destinations.iter().any(|value| value.is_empty()) {
            return Err(GitError::InvalidPushConfig);
        }
        Ok(destinations)
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
            let output = self.run(&directory, ["remote"])?;
            if !output.status.success() {
                return Err(GitError::CommandFailed(output.status.code()));
            }
            let text = String::from_utf8(output.stdout).map_err(|_| GitError::InvalidOutput)?;
            let mut destinations = Vec::new();
            for name in text.lines() {
                destinations.extend(self.effective_push_destinations(&directory, name)?);
            }
            destinations
        };

        let mut schemes = values
            .iter()
            .map(|value| transport_scheme(value))
            .collect::<Vec<_>>();
        schemes.sort();
        schemes.dedup();
        Ok(schemes)
    }

    /// Inspect local and worktree Git config key names for HTTPS settings that
    /// could inject helpers, credentials, proxy routes, custom TLS trust, or
    /// redirects. Values (which can contain secrets) are never decoded, returned,
    /// or logged.
    pub fn has_custom_hooks_path(&self, directory: &Path) -> Result<bool, GitError> {
        self.validate_environment()?;
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let mut output = self.run(
            &directory,
            ["config", "--show-scope", "--name-only", "--list"],
        )?;
        if !output.status.success() {
            output.stdout.fill(0);
            return Err(GitError::CommandFailed(output.status.code()));
        }
        let configured = output.stdout.split(|byte| *byte == b'\n').any(|line| {
            line.split(|byte| *byte == b'\t')
                .next_back()
                .is_some_and(|key| key.eq_ignore_ascii_case(b"core.hookspath"))
        });
        output.stdout.fill(0);
        Ok(configured)
    }

    /// Return true if repository-local configuration declares any external
    /// Git clean/smudge filter. Staging is refused in that case because `git
    /// add` can execute the configured filter process.
    pub fn has_push_options(&self, directory: &Path) -> Result<bool, GitError> {
        self.validate_environment()?;
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let mut output = self.run(
            &directory,
            ["config", "--show-scope", "--name-only", "--list"],
        )?;
        if !output.status.success() {
            output.stdout.fill(0);
            return Err(GitError::CommandFailed(output.status.code()));
        }
        let found = output.stdout.split(|byte| *byte == b'\n').any(|line| {
            let key = line
                .split(|byte| *byte == b'\t')
                .next_back()
                .unwrap_or(line);
            key.eq_ignore_ascii_case(b"push.pushoption")
        });
        output.stdout.fill(0);
        Ok(found)
    }

    pub fn has_remote_mirror_push(&self, directory: &Path, remote: &str) -> Result<bool, GitError> {
        self.validate_environment()?;
        if remote.is_empty()
            || remote
                .bytes()
                .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
        {
            return Err(GitError::InvalidOutput);
        }
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let mut output = self.run(
            &directory,
            ["config", "--show-scope", "--name-only", "--list"],
        )?;
        if !output.status.success() {
            output.stdout.fill(0);
            return Err(GitError::CommandFailed(output.status.code()));
        }
        let key = format!("remote.{remote}.mirror");
        let found = output.stdout.split(|byte| *byte == b'\n').any(|line| {
            line.split(|byte| *byte == b'\t')
                .next_back()
                .is_some_and(|configured| configured.eq_ignore_ascii_case(key.as_bytes()))
        });
        output.stdout.fill(0);
        Ok(found)
    }

    pub fn has_custom_merge_driver(&self, directory: &Path) -> Result<bool, GitError> {
        self.validate_environment()?;
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let mut output = self.run(
            &directory,
            ["config", "--show-scope", "--name-only", "--list"],
        )?;
        if !output.status.success() {
            output.stdout.fill(0);
            return Err(GitError::CommandFailed(output.status.code()));
        }
        let found = output.stdout.split(|byte| *byte == b'\n').any(|line| {
            let key = line
                .split(|byte| *byte == b'\t')
                .next_back()
                .unwrap_or(line);
            let key = key.to_ascii_lowercase();
            key.starts_with(b"merge.") && key.ends_with(b".driver")
        });
        output.stdout.fill(0);
        Ok(found)
    }

    pub fn has_external_filter_config(&self, directory: &Path) -> Result<bool, GitError> {
        self.validate_environment()?;
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let mut output = self.run(
            &directory,
            ["config", "--show-scope", "--name-only", "--list"],
        )?;
        if !output.status.success() {
            output.stdout.fill(0);
            return Err(GitError::CommandFailed(output.status.code()));
        }
        let has_filter = output.stdout.split(|byte| *byte == b'\n').any(|line| {
            let key = line
                .split(|byte| *byte == b'\t')
                .next_back()
                .unwrap_or(line);
            key.get(..7)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"filter."))
        });
        output.stdout.fill(0);
        Ok(has_filter)
    }

    pub fn has_unsafe_https_transport_config(&self, directory: &Path) -> Result<bool, GitError> {
        self.validate_environment()?;
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let mut output = self.run(
            &directory,
            ["config", "--show-scope", "--name-only", "--list"],
        )?;
        if !output.status.success() {
            output.stdout.fill(0);
            return Err(GitError::CommandFailed(output.status.code()));
        }
        let unsafe_config =
            crate::git_https::contains_unsafe_transport_config_key_names(&output.stdout);
        output.stdout.fill(0);
        Ok(unsafe_config)
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
        if !partial.stdout.is_empty() {
            return Ok(true);
        }
        let grafts_path = self.git_path(&directory, "info/grafts")?;
        let alternates_path = self.git_path(&directory, "objects/info/alternates")?;
        Ok(grafts_path.is_file() || alternates_path.is_file())
    }

    pub fn worktree_is_clean(&self, directory: &Path) -> Result<bool, GitError> {
        self.validate_environment()?;
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let output = self.run(
            &directory,
            [
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ],
        )?;
        if !output.status.success() {
            return Err(GitError::CommandFailed(output.status.code()));
        }
        Ok(output.stdout.is_empty())
    }

    pub fn optional_commit_oid(
        &self,
        directory: &Path,
        refname: &str,
    ) -> Result<Option<String>, GitError> {
        self.validate_environment()?;
        if !self.valid_refname(directory, refname)? {
            return Err(GitError::InvalidOutput);
        }
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let expression = format!("{refname}^{{commit}}");
        let output = self.run(
            &directory,
            [
                "rev-parse",
                "--verify",
                "--quiet",
                "--end-of-options",
                &expression,
            ],
        )?;
        match output.status.code() {
            Some(0) => {
                let oid = String::from_utf8(output.stdout)
                    .map_err(|_| GitError::InvalidOutput)?
                    .trim()
                    .to_owned();
                if is_oid(&oid) {
                    Ok(Some(oid))
                } else {
                    Err(GitError::InvalidOutput)
                }
            }
            Some(1) => Ok(None),
            _ => Err(GitError::CommandFailed(output.status.code())),
        }
    }

    pub fn resolve_object_oid(
        &self,
        directory: &Path,
        reference: &str,
    ) -> Result<String, GitError> {
        self.validate_environment()?;
        if reference.is_empty()
            || reference.starts_with('-')
            || reference
                .bytes()
                .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
        {
            return Err(GitError::InvalidOutput);
        }
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let output = self.run(
            &directory,
            ["rev-parse", "--verify", "--end-of-options", reference],
        )?;
        if !output.status.success() {
            return Err(GitError::MissingObject);
        }
        let oid = String::from_utf8(output.stdout)
            .map_err(|_| GitError::InvalidOutput)?
            .trim()
            .to_owned();
        if !is_oid(&oid) || is_zero_oid(&oid) {
            return Err(GitError::InvalidOutput);
        }
        self.object_type(&directory, &oid)?;
        Ok(oid)
    }

    pub fn resolve_commit_oid(&self, directory: &Path, revision: &str) -> Result<String, GitError> {
        self.validate_environment()?;
        if revision.is_empty()
            || revision.starts_with('-')
            || revision
                .bytes()
                .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
        {
            return Err(GitError::InvalidOutput);
        }
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let expression = format!("{revision}^{{commit}}");
        let output = self.run(
            &directory,
            ["rev-parse", "--verify", "--end-of-options", &expression],
        )?;
        if !output.status.success() {
            return Err(GitError::MissingObject);
        }
        let oid = String::from_utf8(output.stdout)
            .map_err(|_| GitError::InvalidOutput)?
            .trim()
            .to_owned();
        if !is_oid(&oid) {
            return Err(GitError::InvalidOutput);
        }
        Ok(oid)
    }

    pub fn valid_refname(&self, directory: &Path, refname: &str) -> Result<bool, GitError> {
        self.validate_environment()?;
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let output = self.run(&directory, ["check-ref-format", refname])?;
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(GitError::CommandFailed(output.status.code())),
        }
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

    pub fn reachable_publication_objects(
        &self,
        directory: &Path,
        oid: &str,
        deadline: std::time::Instant,
    ) -> Result<ReachableObjects, GitError> {
        self.reachable_publication_objects_many(directory, &[oid.to_owned()], deadline)
    }

    pub fn reachable_publication_objects_many(
        &self,
        directory: &Path,
        oids: &[String],
        deadline: std::time::Instant,
    ) -> Result<ReachableObjects, GitError> {
        ensure_git_deadline(deadline)?;
        self.validate_environment()?;
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        if oids.is_empty()
            || oids.len() > 16
            || oids.iter().any(|oid| !is_oid(oid) || is_zero_oid(oid))
        {
            return Err(GitError::MissingObject);
        }
        let mut arguments = vec![
            OsString::from("rev-list"),
            OsString::from("--objects"),
            OsString::from("--missing=print"),
        ];
        arguments.extend(oids.iter().map(OsString::from));
        let output = self.run_owned(&directory, &arguments)?;
        ensure_git_deadline(deadline)?;
        if !output.status.success() {
            return Err(GitError::MissingObject);
        }
        let text = String::from_utf8(output.stdout).map_err(|_| GitError::InvalidOutput)?;
        let mut object_ids = std::collections::BTreeSet::new();
        let mut complete = true;
        for line in text.lines() {
            let token = line
                .split_ascii_whitespace()
                .next()
                .ok_or(GitError::InvalidOutput)?;
            let missing = token.starts_with('?');
            let oid = token.strip_prefix('?').unwrap_or(token);
            if !is_oid(oid) {
                return Err(GitError::InvalidOutput);
            }
            complete &= !missing;
            object_ids.insert(oid.to_owned());
            if object_ids.len() > MAX_REACHABLE_PUBLICATION_OBJECTS {
                return Err(GitError::UnsupportedRepository);
            }
        }
        let object_ids = object_ids.into_iter().collect::<Vec<_>>();
        if complete {
            self.reachable_publication_object_bytes(&directory, &object_ids, deadline)?;
        }
        let mut fsck_arguments = vec![
            OsString::from("fsck"),
            OsString::from("--no-reflogs"),
            OsString::from("--no-progress"),
        ];
        fsck_arguments.extend(oids.iter().map(OsString::from));
        let fsck = self.run_owned(&directory, &fsck_arguments)?;
        ensure_git_deadline(deadline)?;
        if !fsck.status.success() {
            return Err(GitError::MissingObject);
        }
        Ok(ReachableObjects {
            object_ids,
            complete,
        })
    }

    pub fn reachable_publication_object_bytes(
        &self,
        directory: &Path,
        object_ids: &[String],
        deadline: std::time::Instant,
    ) -> Result<usize, GitError> {
        ensure_git_deadline(deadline)?;
        self.validate_environment()?;
        if object_ids.len() > MAX_REACHABLE_PUBLICATION_OBJECTS
            || object_ids.iter().any(|oid| !is_oid(oid))
        {
            return Err(GitError::UnsupportedRepository);
        }
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let mut input = Vec::with_capacity(object_ids.len().saturating_mul(65));
        for oid in object_ids {
            input.extend_from_slice(oid.as_bytes());
            input.push(b'\n');
        }
        let environment = self.bounded_environment();
        let args = [
            OsString::from("cat-file"),
            OsString::from("--batch-check=%(objectname) %(objecttype) %(objectsize)"),
        ];
        let output = self
            .runner
            .run(RunRequest {
                executable: &self.executable,
                args: &args,
                cwd: &directory,
                environment: &environment,
                stdin: Some(&input),
            })
            .map_err(map_runner_error)?;
        ensure_git_deadline(deadline)?;
        if !output.status.success() {
            return Err(GitError::MissingObject);
        }
        let text = String::from_utf8(output.stdout).map_err(|_| GitError::InvalidOutput)?;
        let mut total_bytes = 0usize;
        let mut checked = 0usize;
        for line in text.lines() {
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            if fields.len() != 3
                || object_ids
                    .get(checked)
                    .is_none_or(|expected| expected != fields[0])
                || !is_oid(fields[0])
                || !matches!(fields[1], "commit" | "tree" | "blob" | "tag")
            {
                return Err(GitError::InvalidOutput);
            }
            let object_bytes = fields[2]
                .parse::<usize>()
                .map_err(|_| GitError::InvalidOutput)?;
            total_bytes = total_bytes.saturating_add(object_bytes);
            checked = checked.saturating_add(1);
            if total_bytes > MAX_REACHABLE_PUBLICATION_BYTES || checked > object_ids.len() {
                return Err(GitError::UnsupportedRepository);
            }
        }
        if checked != object_ids.len() {
            return Err(GitError::MissingObject);
        }
        Ok(total_bytes)
    }

    pub fn outgoing_commit_identities(
        &self,
        directory: &Path,
        update: &PushTuple,
        deadline: std::time::Instant,
    ) -> Result<Vec<CommitIdentity>, GitError> {
        self.outgoing_commit_identities_many(directory, std::slice::from_ref(update), deadline)
    }

    pub fn outgoing_commit_oids_many(
        &self,
        directory: &Path,
        updates: &[PushTuple],
        deadline: std::time::Instant,
    ) -> Result<Vec<String>, GitError> {
        ensure_git_deadline(deadline)?;
        self.validate_environment()?;
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        if self.repository_is_incomplete(&directory)? || updates.is_empty() || updates.len() > 16 {
            return Err(GitError::UnsupportedRepository);
        }
        let mut args = vec![OsString::from("rev-list"), OsString::from("--topo-order")];
        for update in updates {
            ensure_git_deadline(deadline)?;
            if is_zero_oid(&update.local_oid) {
                continue;
            }
            let tip = if update.local_ref.starts_with("refs/tags/") {
                self.tag_commit_target_oid(&directory, &update.local_oid)?
            } else {
                update.local_oid.clone()
            };
            if self.cat_file_type(&directory, &tip)? != "commit" {
                return Err(GitError::UnsupportedRepository);
            }
            args.push(OsString::from(tip));
        }
        if args.len() == 2 {
            return Ok(Vec::new());
        }
        let excluded = updates
            .iter()
            .filter(|update| !is_zero_oid(&update.remote_oid))
            .collect::<Vec<_>>();
        if !excluded.is_empty() {
            args.push(OsString::from("--not"));
            for update in excluded {
                let oid = if update.remote_ref.starts_with("refs/tags/") {
                    self.tag_commit_target_oid(&directory, &update.remote_oid)
                        .unwrap_or_else(|_| update.remote_oid.clone())
                } else {
                    update.remote_oid.clone()
                };
                if !is_oid(&oid) {
                    return Err(GitError::MissingObject);
                }
                args.push(OsString::from(oid));
            }
        }
        let output = self.run_owned(&directory, &args)?;
        ensure_git_deadline(deadline)?;
        if !output.status.success() {
            return Err(GitError::MissingObject);
        }
        let text = String::from_utf8(output.stdout).map_err(|_| GitError::InvalidOutput)?;
        let oids = text.lines().map(str::to_owned).collect::<Vec<_>>();
        if oids.len() > 2048 || oids.iter().any(|oid| !is_oid(oid)) {
            return Err(GitError::UnsupportedRepository);
        }
        Ok(oids)
    }

    pub fn outgoing_commit_identities_many(
        &self,
        directory: &Path,
        updates: &[PushTuple],
        deadline: std::time::Instant,
    ) -> Result<Vec<CommitIdentity>, GitError> {
        ensure_git_deadline(deadline)?;
        self.validate_environment()?;
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        if self.repository_is_incomplete(&directory)? || updates.is_empty() || updates.len() > 16 {
            return Err(GitError::UnsupportedRepository);
        }
        let mut args = vec![OsString::from("rev-list"), OsString::from("--topo-order")];
        for update in updates {
            ensure_git_deadline(deadline)?;
            if !is_oid(&update.local_oid) || is_zero_oid(&update.local_oid) {
                return Err(GitError::MissingObject);
            }
            if self.cat_file_type(&directory, &update.local_oid)? != "commit" {
                return Err(GitError::UnsupportedRepository);
            }
            args.push(OsString::from(&update.local_oid));
        }
        let excluded = updates
            .iter()
            .filter(|update| !is_zero_oid(&update.remote_oid))
            .collect::<Vec<_>>();
        if !excluded.is_empty() {
            args.push(OsString::from("--not"));
            for update in excluded {
                if !is_oid(&update.remote_oid) {
                    return Err(GitError::MissingObject);
                }
                args.push(OsString::from(&update.remote_oid));
            }
        }
        let output = self.run_owned(&directory, &args)?;
        ensure_git_deadline(deadline)?;
        if !output.status.success() {
            return Err(GitError::MissingObject);
        }
        let text = String::from_utf8(output.stdout).map_err(|_| GitError::InvalidOutput)?;
        let commit_oids = text.lines().map(str::to_owned).collect::<Vec<_>>();
        if commit_oids.len() > 2048 || commit_oids.iter().any(|oid| !is_oid(oid)) {
            return Err(GitError::UnsupportedRepository);
        }
        ensure_git_deadline(deadline)?;
        let commits = self.commit_identities_batch(&directory, &commit_oids)?;
        ensure_git_deadline(deadline)?;
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
                "^(commit\\.gpgsign|tag\\.gpgsign|gpg\\.format|user\\.signingkey)$",
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
                "tag.gpgsign" | "tag.gpgSign" => {
                    signing.tag_enabled =
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

    pub fn object_type(&self, directory: &Path, oid: &str) -> Result<String, GitError> {
        self.validate_environment()?;
        if !is_oid(oid) {
            return Err(GitError::InvalidOutput);
        }
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let output = self.run(&directory, ["cat-file", "-t", oid])?;
        if !output.status.success() {
            return Err(GitError::MissingObject);
        }
        let kind = String::from_utf8(output.stdout)
            .map_err(|_| GitError::InvalidOutput)?
            .trim()
            .to_owned();
        if !matches!(kind.as_str(), "commit" | "tree" | "blob" | "tag") {
            return Err(GitError::InvalidOutput);
        }
        Ok(kind)
    }

    pub fn tag_target(&self, directory: &Path, oid: &str) -> Result<(String, String), GitError> {
        let contents = self.tag_object_contents_oid(directory, oid)?;
        let header = contents
            .split_once("\n\n")
            .map(|(headers, _)| headers)
            .ok_or(GitError::InvalidOutput)?;
        let mut target_oid = None;
        let mut target_type = None;
        for line in header.lines() {
            if let Some(value) = line.strip_prefix("object ") {
                if target_oid.replace(value.to_owned()).is_some() || !is_oid(value) {
                    return Err(GitError::InvalidOutput);
                }
            } else if let Some(value) = line.strip_prefix("type ") {
                if target_type.replace(value.to_owned()).is_some()
                    || !matches!(value, "commit" | "tree" | "blob" | "tag")
                {
                    return Err(GitError::InvalidOutput);
                }
            }
        }
        Ok((
            target_oid.ok_or(GitError::InvalidOutput)?,
            target_type.ok_or(GitError::InvalidOutput)?,
        ))
    }

    pub fn tag_commit_target_oid(
        &self,
        directory: &Path,
        tag_oid: &str,
    ) -> Result<String, GitError> {
        let mut current = tag_oid.to_owned();
        let mut visited = std::collections::HashSet::new();
        for _ in 0..32 {
            if !visited.insert(current.clone()) {
                return Err(GitError::InvalidOutput);
            }
            if self.object_type(directory, &current)? != "tag" {
                if self.object_type(directory, &current)? == "commit" {
                    return Ok(current);
                }
                return Err(GitError::InvalidOutput);
            }
            let (target, declared_type) = self.tag_target(directory, &current)?;
            let actual_type = self.object_type(directory, &target)?;
            if declared_type != actual_type {
                return Err(GitError::InvalidOutput);
            }
            if actual_type == "commit" {
                return Ok(target);
            }
            if actual_type != "tag" {
                return Err(GitError::InvalidOutput);
            }
            current = target;
        }
        Err(GitError::UnsupportedRepository)
    }

    pub fn tag_object_contents_oid(&self, directory: &Path, oid: &str) -> Result<String, GitError> {
        if self.object_type(directory, oid)? != "tag" {
            return Err(GitError::InvalidOutput);
        }
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let output = self.run(&directory, ["cat-file", "tag", oid])?;
        if !output.status.success() {
            return Err(GitError::MissingObject);
        }
        String::from_utf8(output.stdout).map_err(|_| GitError::InvalidOutput)
    }

    pub fn tag_object(&self, directory: &Path, tag: &str) -> Result<(String, String), GitError> {
        self.validate_environment()?;
        if tag.is_empty()
            || tag.starts_with('-')
            || tag.bytes().any(|byte| byte == 0 || byte == b'\n')
        {
            return Err(GitError::InvalidOutput);
        }
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let reference = format!("refs/tags/{tag}");
        let valid = self.run(&directory, ["check-ref-format", &reference])?;
        if !valid.status.success() {
            return Err(GitError::InvalidOutput);
        }
        let resolved = self.run(
            &directory,
            [
                "rev-parse",
                "--verify",
                "--end-of-options",
                &format!("{reference}^{{tag}}"),
            ],
        )?;
        if !resolved.status.success() {
            return Err(GitError::CommandFailed(resolved.status.code()));
        }
        let oid = String::from_utf8(resolved.stdout)
            .map_err(|_| GitError::InvalidOutput)?
            .trim()
            .to_owned();
        if !is_oid(&oid) {
            return Err(GitError::InvalidOutput);
        }
        let contents = self.run(&directory, ["cat-file", "tag", &oid])?;
        if !contents.status.success() {
            return Err(GitError::CommandFailed(contents.status.code()));
        }
        let contents = String::from_utf8(contents.stdout).map_err(|_| GitError::InvalidOutput)?;
        Ok((oid, contents))
    }

    pub fn verify_ssh_tag(
        &self,
        directory: &Path,
        oid: &str,
        ssh_keygen: &Path,
        allowed_signers: &Path,
    ) -> Result<RunOutput, GitError> {
        self.verify_ssh_object(directory, oid, ssh_keygen, allowed_signers, "verify-tag")
    }

    fn verify_ssh_object(
        &self,
        directory: &Path,
        oid: &str,
        ssh_keygen: &Path,
        allowed_signers: &Path,
        command: &str,
    ) -> Result<RunOutput, GitError> {
        self.validate_environment()?;
        if ssh_keygen.is_relative() || allowed_signers.is_relative() {
            return Err(GitError::RelativeExecutable(ssh_keygen.to_path_buf()));
        }
        let directory = crate::paths::canonical_directory(directory).map_err(GitError::Path)?;
        let mut environment = self.bounded_environment();
        environment.retain(|(name, _)| name != "GIT_SSH" && name != "GIT_SSH_COMMAND");
        let args = [
            OsString::from("-c"),
            OsString::from("gpg.format=ssh"),
            OsString::from("-c"),
            format!("gpg.ssh.program={}", ssh_keygen.display()).into(),
            OsString::from("-c"),
            format!("gpg.ssh.allowedSignersFile={}", allowed_signers.display()).into(),
            OsString::from("-c"),
            OsString::from("gpg.ssh.revocationFile="),
            OsString::from(command),
            OsString::from("--raw"),
            OsString::from(oid),
        ];
        self.runner
            .run(RunRequest {
                executable: &self.executable,
                args: &args,
                cwd: &directory,
                environment: &environment,
                stdin: None,
            })
            .map_err(map_runner_error)
    }

    pub fn verify_tag(
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
        let config = format!("gpg.program={}", gpg_executable.display());
        let openpgp_config = format!("gpg.openpgp.program={}", gpg_executable.display());
        let mut environment = self.bounded_environment();
        environment.retain(|(name, _)| {
            name != "GNUPGHOME" && name != "GPG_AGENT_INFO" && name != "GPG_TTY"
        });
        environment.push(("GNUPGHOME".into(), gnupg_home.as_os_str().to_owned()));
        self.run_with_environment(
            &directory,
            [
                "-c",
                "gpg.format=openpgp",
                "-c",
                &config,
                "-c",
                &openpgp_config,
                "verify-tag",
                "--raw",
                oid,
            ],
            &environment,
        )
    }

    pub fn verify_head(
        &self,
        directory: &Path,
        gnupg_home: &Path,
        gpg_executable: &Path,
    ) -> Result<RunOutput, GitError> {
        self.verify_commit(directory, "HEAD", gnupg_home, gpg_executable)
    }

    pub fn verify_ssh_commit(
        &self,
        directory: &Path,
        oid: &str,
        ssh_keygen: &Path,
        allowed_signers: &Path,
    ) -> Result<RunOutput, GitError> {
        self.verify_ssh_object(directory, oid, ssh_keygen, allowed_signers, "verify-commit")
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
        let signing = self.effective_signing(&directory)?;
        if let Some(format) = signing.format.as_deref() {
            if !format.eq_ignore_ascii_case("openpgp") {
                return Err(GitError::UnsupportedSignatureFormat(format.to_owned()));
            }
        }
        let mut environment = self.bounded_environment();
        environment.retain(|(name, _)| {
            name != "GNUPGHOME" && name != "GPG_AGENT_INFO" && name != "GPG_TTY"
        });
        environment.push(("GNUPGHOME".into(), gnupg_home.as_os_str().to_owned()));
        // Command-line config has higher precedence than repository, global,
        // and system config. Force both generic and format-specific verifier
        // settings so repository helpers cannot replace the selected binary.
        let gpg_config = format!("gpg.program={}", gpg_executable.display());
        let openpgp_config = format!("gpg.openpgp.program={}", gpg_executable.display());
        self.run_with_environment(
            &directory,
            [
                "-c",
                &gpg_config,
                "-c",
                &openpgp_config,
                "verify-commit",
                "--raw",
                oid,
            ],
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
                stdin: None,
            })
            .map_err(map_runner_error)
    }

    pub fn git_path(&self, directory: &Path, path: &str) -> Result<PathBuf, GitError> {
        let output = self.run(directory, ["rev-parse", "--git-path", path])?;
        if !output.status.success() {
            return Err(GitError::CommandFailed(output.status.code()));
        }
        let text = String::from_utf8(output.stdout).map_err(|_| GitError::InvalidOutput)?;
        let value = text.strip_suffix('\n').ok_or(GitError::InvalidOutput)?;
        if value.is_empty() || value.contains(['\n', '\r']) {
            return Err(GitError::InvalidOutput);
        }
        let path = PathBuf::from(value);
        Ok(if path.is_absolute() {
            path
        } else {
            directory.join(path)
        })
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

    fn commit_identities_batch(
        &self,
        directory: &Path,
        oids: &[String],
    ) -> Result<Vec<CommitIdentity>, GitError> {
        if oids.is_empty() {
            return Ok(Vec::new());
        }
        let mut input = Vec::with_capacity(oids.len().saturating_mul(65));
        for oid in oids {
            input.extend_from_slice(oid.as_bytes());
            input.push(b'\n');
        }
        let environment = self.bounded_environment();
        let args = [OsString::from("cat-file"), OsString::from("--batch")];
        let output = self
            .runner
            .run(RunRequest {
                executable: &self.executable,
                args: &args,
                cwd: directory,
                environment: &environment,
                stdin: Some(&input),
            })
            .map_err(map_runner_error)?;
        if !output.status.success() {
            return Err(GitError::MissingObject);
        }
        let bytes = output.stdout;
        let mut offset = 0usize;
        let mut commits = Vec::with_capacity(oids.len());
        for expected_oid in oids {
            let header_end = bytes[offset..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|relative| offset + relative)
                .ok_or(GitError::InvalidOutput)?;
            let header = std::str::from_utf8(&bytes[offset..header_end])
                .map_err(|_| GitError::InvalidOutput)?;
            let fields = header.split_ascii_whitespace().collect::<Vec<_>>();
            if fields.len() != 3
                || !fields[0].eq_ignore_ascii_case(expected_oid)
                || fields[1] != "commit"
            {
                return Err(GitError::InvalidOutput);
            }
            let size = fields[2]
                .parse::<usize>()
                .map_err(|_| GitError::InvalidOutput)?;
            offset = header_end.saturating_add(1);
            let body_end = offset.checked_add(size).ok_or(GitError::InvalidOutput)?;
            let body = bytes.get(offset..body_end).ok_or(GitError::InvalidOutput)?;
            if bytes.get(body_end) != Some(&b'\n') {
                return Err(GitError::InvalidOutput);
            }
            let text = std::str::from_utf8(body).map_err(|_| GitError::InvalidOutput)?;
            commits.push(CommitIdentity {
                oid: expected_oid.clone(),
                author: parse_commit_identity(text, "author ")?,
                committer: parse_commit_identity(text, "committer ")?,
            });
            offset = body_end.saturating_add(1);
        }
        if offset != bytes.len() {
            return Err(GitError::InvalidOutput);
        }
        Ok(commits)
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
                stdin: None,
            })
            .map_err(map_runner_error)
    }

    fn bounded_environment(&self) -> Vec<(OsString, OsString)> {
        let mut environment = self.environment.clone();
        for variable in [
            "GIT_TERMINAL_PROMPT",
            "GIT_OPTIONAL_LOCKS",
            "GIT_NO_LAZY_FETCH",
            "GIT_NO_REPLACE_OBJECTS",
        ] {
            environment.retain(|(name, _)| name != variable);
        }
        environment.extend([
            ("GIT_TERMINAL_PROMPT".into(), "0".into()),
            ("GIT_OPTIONAL_LOCKS".into(), "0".into()),
            ("GIT_NO_LAZY_FETCH".into(), "1".into()),
            ("GIT_NO_REPLACE_OBJECTS".into(), "1".into()),
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
                "GIT_REPLACE_REF_BASE",
                "GIT_GRAFT_FILE",
                "GIT_OBJECT_DIRECTORY",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
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

pub fn parse_tag_identity_email(value: &str) -> Result<String, GitError> {
    parse_identity(value).map(|identity| identity.email)
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
        RunError::Spawn(error)
        | RunError::Wait(error)
        | RunError::Termination(error)
        | RunError::StdinWrite(error) => GitError::Runner(error),
        RunError::Timeout => GitError::Timeout,
        RunError::OutputLimit { stream } => GitError::OutputLimit { stream },
    }
}

fn ensure_git_deadline(deadline: std::time::Instant) -> Result<(), GitError> {
    if std::time::Instant::now() >= deadline {
        Err(GitError::Timeout)
    } else {
        Ok(())
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
