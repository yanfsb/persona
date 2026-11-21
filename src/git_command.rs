use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Parsed Git global options before the subcommand. This keeps option
/// interpretation independent from policy and subprocess execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitInvocation {
    pub directory_changes: Vec<PathBuf>,
    pub git_dir: Option<PathBuf>,
    pub work_tree: Option<PathBuf>,
    pub global_arguments: Vec<OsString>,
    pub arguments: Vec<OsString>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitSubcommand {
    Status,
    Init,
    Commit,
    Log,
    Branch,
    Worktree,
    Tag,
    Fetch,
    Pull,
    Clone,
    RevParse,
    Push,
    Remote,
    Submodule,
    Other(String),
}

impl GitSubcommand {
    pub fn parse(value: &str) -> Self {
        match value {
            "status" => Self::Status,
            "init" => Self::Init,
            "commit" => Self::Commit,
            "log" => Self::Log,
            "branch" => Self::Branch,
            "worktree" => Self::Worktree,
            "tag" => Self::Tag,
            "fetch" => Self::Fetch,
            "pull" => Self::Pull,
            "clone" => Self::Clone,
            "rev-parse" => Self::RevParse,
            "push" => Self::Push,
            "remote" => Self::Remote,
            "submodule" => Self::Submodule,
            other => Self::Other(other.to_owned()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Status => "status",
            Self::Init => "init",
            Self::Commit => "commit",
            Self::Log => "log",
            Self::Branch => "branch",
            Self::Worktree => "worktree",
            Self::Tag => "tag",
            Self::Fetch => "fetch",
            Self::Pull => "pull",
            Self::Clone => "clone",
            Self::RevParse => "rev-parse",
            Self::Push => "push",
            Self::Remote => "remote",
            Self::Submodule => "submodule",
            Self::Other(value) => value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    MissingDirectory,
    UnsupportedGlobalOption,
    MissingSubcommand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushRefspec {
    pub source: String,
    pub destination: String,
    pub raw_source: String,
    pub raw_destination: String,
    pub forced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushInvocation {
    pub remote: Option<String>,
    pub refspecs: Vec<PushRefspec>,
    pub leases: Vec<ExactPushLease>,
    pub bare_force_with_lease: bool,
    pub lease_refs: Vec<String>,
    pub empty_lease_refs: Vec<String>,
    pub force_if_includes: bool,
    pub atomic: bool,
    pub set_upstream: bool,
    pub force: bool,
    pub dry_run: bool,
    pub tags: bool,
    pub follow_tags: bool,
    pub delete: bool,
    pub verbose: bool,
    pub quiet: bool,
    pub no_verify: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactPushLease {
    pub remote_ref: String,
    pub expected_oid: String,
}

impl PushInvocation {
    /// Parse a bounded explicit or shorthand push request without authorizing or executing it.
    pub fn parse(arguments: &[OsString]) -> Result<Self, &'static str> {
        const MAX_REFSPECS: usize = 16;
        let mut remote: Option<String> = None;
        let mut refspecs = Vec::new();
        let mut leases = Vec::new();
        let mut bare_force_with_lease = false;
        let mut lease_refs = Vec::new();
        let mut empty_lease_refs = Vec::new();
        let mut force_if_includes = false;
        let mut atomic = false;
        let mut set_upstream = false;
        let mut force = false;
        let mut dry_run = false;
        let mut tags = false;
        let mut follow_tags = false;
        let mut delete = false;
        let mut verbose = false;
        let mut quiet = false;
        let mut no_verify = false;
        let mut index = 0;
        while index < arguments.len() {
            let word = arguments[index]
                .to_str()
                .ok_or("push arguments must be valid UTF-8")?;
            match word {
                "--atomic" => atomic = true,
                "-u" | "--set-upstream" => set_upstream = true,
                "-f" | "--force" => force = true,
                "-n" | "--dry-run" => dry_run = true,
                "--tags" => tags = true,
                "--follow-tags" => follow_tags = true,
                "-d" | "--delete" => delete = true,
                "-v" | "--verbose" => verbose = true,
                "-q" | "--quiet" => quiet = true,
                "--no-verify" => no_verify = true,
                "--force-if-includes" => force_if_includes = true,
                "--force-with-lease" => bare_force_with_lease = true,
                _ if word.starts_with("--force-with-lease=") => {
                    let value = word.trim_start_matches("--force-with-lease=");
                    if let Some((remote_ref, expected_oid)) = value.split_once(':') {
                        let remote_ref = normalize_ref(remote_ref, false)?;
                        if expected_oid.is_empty() {
                            empty_lease_refs.push(remote_ref);
                        } else {
                            if !(matches!(expected_oid.len(), 40 | 64)
                                && expected_oid.bytes().all(|byte| byte.is_ascii_hexdigit()))
                            {
                                return Err("force-with-lease object ID is invalid");
                            }
                            leases.push(ExactPushLease {
                                remote_ref,
                                expected_oid: expected_oid.to_ascii_lowercase(),
                            });
                        }
                    } else if !value.is_empty() {
                        lease_refs.push(normalize_ref(value, false)?);
                    } else {
                        return Err("force-with-lease value is empty");
                    }
                }
                _ if word.starts_with('-') => return Err("unsupported push option"),
                _ if remote.is_none() => {
                    if !valid_remote_name(word) {
                        return Err("invalid push remote");
                    }
                    remote = Some(word.to_owned());
                }
                _ => {
                    if refspecs.len() == MAX_REFSPECS {
                        return Err("push refspec count exceeds the limit");
                    }
                    if delete {
                        if word.contains(':') || word.starts_with('+') {
                            return Err("unsupported push deletion refspec");
                        }
                        let destination = normalize_ref(word, false)?;
                        refspecs.push(PushRefspec {
                            source: "(delete)".to_owned(),
                            destination,
                            raw_source: "(delete)".to_owned(),
                            raw_destination: word.to_owned(),
                            forced: false,
                        });
                    } else {
                        let (forced, raw_spec) = if let Some(rest) = word.strip_prefix('+') {
                            force = true;
                            (true, rest)
                        } else {
                            (false, word)
                        };
                        let (raw_source, raw_destination) =
                            if let Some((source, destination)) = raw_spec.split_once(':') {
                                (source, destination)
                            } else {
                                (raw_spec, raw_spec)
                            };
                        if raw_destination.is_empty() {
                            return Err("unsupported push refspec");
                        }
                        let source = if raw_source.is_empty() {
                            "(delete)".to_owned()
                        } else if raw_source == "HEAD" {
                            "HEAD".to_owned()
                        } else {
                            normalize_ref(raw_source, true)?
                        };
                        let destination = if raw_destination == "HEAD" {
                            "HEAD".to_owned()
                        } else {
                            normalize_ref(raw_destination, false)?
                        };
                        refspecs.push(PushRefspec {
                            source,
                            destination,
                            raw_source: raw_source.to_owned(),
                            raw_destination: raw_destination.to_owned(),
                            forced,
                        });
                    }
                }
            }
            index += 1;
        }
        if remote.is_none() && !refspecs.is_empty() {
            return Err("push requires an explicit remote");
        }
        let mut leased_refs = std::collections::HashSet::new();
        for remote_ref in leases
            .iter()
            .map(|lease| lease.remote_ref.as_str())
            .chain(lease_refs.iter().map(String::as_str))
            .chain(empty_lease_refs.iter().map(String::as_str))
        {
            if !leased_refs.insert(remote_ref) {
                return Err("force-with-lease may name each ref only once");
            }
        }
        if !refspecs.is_empty() {
            let mut destinations = std::collections::HashSet::new();
            for refspec in &refspecs {
                if refspec.destination != "HEAD"
                    && !destinations.insert(refspec.destination.as_str())
                {
                    return Err("push refspec destinations must be unique");
                }
            }
            for remote_ref in &leased_refs {
                if !destinations.contains(remote_ref)
                    && !remote_ref.strip_prefix("refs/heads/").is_some_and(|name| {
                        refspecs.iter().any(|spec| spec.raw_destination == name)
                    })
                {
                    return Err("force-with-lease must match a requested destination ref");
                }
            }
        }
        Ok(Self {
            remote,
            refspecs,
            leases,
            bare_force_with_lease,
            lease_refs,
            empty_lease_refs,
            force_if_includes,
            atomic,
            set_upstream,
            force,
            dry_run,
            tags,
            follow_tags,
            delete,
            verbose,
            quiet,
            no_verify,
        })
    }
}

fn valid_remote_name(word: &str) -> bool {
    !word.is_empty()
        && word.len() <= 128
        && word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub fn normalize_ref(reference: &str, source: bool) -> Result<String, &'static str> {
    let reference = if reference.starts_with("refs/heads/") || reference.starts_with("refs/tags/") {
        reference.to_owned()
    } else if reference.starts_with("refs/") {
        return Err("unsupported fully qualified ref namespace");
    } else if reference.is_empty()
        || reference.starts_with('-')
        || reference.contains(['*', '?', '[', '\\'])
        || reference.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err("ambiguous refspec name");
    } else {
        format!("refs/heads/{reference}")
    };
    let prefix = if reference.starts_with("refs/heads/") {
        "refs/heads/"
    } else {
        "refs/tags/"
    };
    let name = reference
        .strip_prefix(prefix)
        .ok_or("unsupported ref namespace")?;
    if name.is_empty()
        || name == "@"
        || name.contains("..")
        || name.contains("@{")
        || name.bytes().any(|byte| {
            byte <= b' '
                || byte == 0x7f
                || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
        || name.split('/').any(|component| {
            component.is_empty()
                || component.starts_with('.')
                || component.ends_with('.')
                || component.ends_with(".lock")
        })
        || (!source && reference == "HEAD")
    {
        return Err("invalid refspec");
    }
    Ok(reference)
}

fn is_safe_global_config_override(entry: &str) -> bool {
    let Some((key, _value)) = entry.split_once('=') else {
        return false;
    };
    let key = key.trim().to_ascii_lowercase();
    const SAFE_PREFIXES: &[&str] = &["color.", "advice.", "diff.", "log.", "status."];
    const BLOCKED_EXACT_OR_SUB: &[&str] = &["diff.external", "diff.guitool", "diff.tool"];
    if BLOCKED_EXACT_OR_SUB.contains(&key.as_str())
        || key.ends_with(".textconv")
        || key.ends_with(".command")
    {
        return false;
    }
    SAFE_PREFIXES.iter().any(|prefix| key.starts_with(prefix))
}

impl GitInvocation {
    pub fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Self, ParseError> {
        let mut arguments = arguments.into_iter();
        let mut directory_changes = Vec::new();
        let mut git_dir = None;
        let mut work_tree = None;
        let mut global_arguments = Vec::new();
        let mut native_arguments = Vec::new();
        let mut command_seen = false;

        while let Some(argument) = arguments.next() {
            if command_seen {
                native_arguments.push(argument);
                continue;
            }
            if argument == "-C" {
                directory_changes
                    .push(arguments.next().ok_or(ParseError::MissingDirectory)?.into());
                continue;
            }
            if let Some(path) = argument.to_str().and_then(|value| value.strip_prefix("-C")) {
                if path.is_empty() {
                    return Err(ParseError::MissingDirectory);
                }
                directory_changes.push(PathBuf::from(path));
                continue;
            }
            if argument == "--git-dir" {
                let path = arguments.next().ok_or(ParseError::MissingDirectory)?;
                if path.is_empty() {
                    return Err(ParseError::MissingDirectory);
                }
                git_dir = Some(PathBuf::from(&path));
                global_arguments.push(argument);
                global_arguments.push(path);
                continue;
            }
            if let Some(path) = argument
                .to_str()
                .and_then(|value| value.strip_prefix("--git-dir="))
            {
                if path.is_empty() {
                    return Err(ParseError::MissingDirectory);
                }
                git_dir = Some(PathBuf::from(path));
                global_arguments.push(argument);
                continue;
            }
            if argument == "--work-tree" {
                let path = arguments.next().ok_or(ParseError::MissingDirectory)?;
                if path.is_empty() {
                    return Err(ParseError::MissingDirectory);
                }
                work_tree = Some(PathBuf::from(&path));
                global_arguments.push(argument);
                global_arguments.push(path);
                continue;
            }
            if let Some(path) = argument
                .to_str()
                .and_then(|value| value.strip_prefix("--work-tree="))
            {
                if path.is_empty() {
                    return Err(ParseError::MissingDirectory);
                }
                work_tree = Some(PathBuf::from(path));
                global_arguments.push(argument);
                continue;
            }
            if argument == "-c" {
                let entry = arguments
                    .next()
                    .ok_or(ParseError::UnsupportedGlobalOption)?;
                let Some(entry_str) = entry.to_str() else {
                    return Err(ParseError::UnsupportedGlobalOption);
                };
                if !is_safe_global_config_override(entry_str) {
                    return Err(ParseError::UnsupportedGlobalOption);
                }
                global_arguments.push(OsString::from("-c"));
                global_arguments.push(entry);
                continue;
            }
            if argument == "--no-pager"
                || argument == "-P"
                || argument == "--literal-pathspecs"
                || argument == "--paginate"
                || argument == "-p"
            {
                global_arguments.push(argument);
                continue;
            }
            if argument == "--version" || argument == "-v" {
                command_seen = true;
                native_arguments.push(OsString::from("version"));
                continue;
            }
            if argument == "--help" || argument == "-h" {
                command_seen = true;
                native_arguments.push(OsString::from("help"));
                continue;
            }
            if argument.to_string_lossy().starts_with('-') {
                return Err(ParseError::UnsupportedGlobalOption);
            }
            command_seen = true;
            native_arguments.push(argument);
        }

        if !command_seen {
            return Err(ParseError::MissingSubcommand);
        }
        Ok(Self {
            directory_changes,
            git_dir,
            work_tree,
            global_arguments,
            arguments: native_arguments,
        })
    }

    pub fn subcommand(&self) -> Result<GitSubcommand, ParseError> {
        self.arguments
            .first()
            .and_then(|value| value.to_str())
            .map(GitSubcommand::parse)
            .ok_or(ParseError::MissingSubcommand)
    }

    /// Apply repeated `-C` options with Git's sequential relative-path rules.
    /// Each directory is canonicalized before resolving the next one.
    pub fn resolve_directory(&self, current: &Path) -> Result<PathBuf, std::io::Error> {
        let mut directory = current.to_path_buf();
        for path in &self.directory_changes {
            let path = if path.is_absolute() {
                path.clone()
            } else {
                directory.join(path)
            };
            directory = std::fs::canonicalize(path)?;
            if !directory.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotADirectory,
                    "Git -C target is not a directory",
                ));
            }
        }
        Ok(directory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn separates_repeated_global_directory_options_from_native_arguments() {
        let parsed = GitInvocation::parse(args(&[
            "-C",
            "repo",
            "--no-pager",
            "-Csubdir",
            "-c",
            "color.ui=always",
            "status",
            "-C",
            "not-a-global-option",
        ]))
        .unwrap();
        assert_eq!(
            parsed.directory_changes,
            [PathBuf::from("repo"), PathBuf::from("subdir")]
        );
        assert_eq!(
            parsed.global_arguments,
            args(&["--no-pager", "-c", "color.ui=always"])
        );
        assert_eq!(
            parsed.arguments,
            args(&["status", "-C", "not-a-global-option"])
        );
        assert_eq!(parsed.subcommand().unwrap(), GitSubcommand::Status);
    }

    #[test]
    fn rejects_missing_and_unsafe_global_options() {
        assert_eq!(
            GitInvocation::parse(args(&["-C"])),
            Err(ParseError::MissingDirectory)
        );
        for unsafe_args in [
            vec!["-c", "alias.x=...", "status"],
            vec!["-c", "user.email=wrong@example.invalid", "commit"],
            vec!["-c", "credential.helper=store", "fetch"],
            vec!["-c", "core.sshCommand=evil", "fetch"],
            vec!["-c", "diff.external=evil", "diff"],
            vec!["--exec-path=/tmp/evil", "status"],
        ] {
            assert_eq!(
                GitInvocation::parse(args(&unsafe_args)),
                Err(ParseError::UnsupportedGlobalOption),
                "{unsafe_args:?}"
            );
        }
        let with_git_dir = GitInvocation::parse(args(&[
            "--git-dir=/tmp/other/.git",
            "--work-tree",
            "/tmp/other",
            "rev-parse",
            "HEAD",
        ]))
        .unwrap();
        assert_eq!(with_git_dir.git_dir, Some(PathBuf::from("/tmp/other/.git")));
        assert_eq!(with_git_dir.work_tree, Some(PathBuf::from("/tmp/other")));
        assert_eq!(
            GitInvocation::parse(args(&["--git-dir="])),
            Err(ParseError::MissingDirectory)
        );
        assert_eq!(
            GitInvocation::parse(Vec::<OsString>::new()),
            Err(ParseError::MissingSubcommand)
        );
    }

    #[test]
    fn parses_bounded_and_everyday_push_requests() {
        let parsed = PushInvocation::parse(&args(&[
            "--atomic",
            "-u",
            "--force-with-lease=refs/heads/main:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "origin",
            "HEAD:main",
            "feature:feature",
            ":obsolete",
        ]))
        .unwrap();
        assert_eq!(parsed.remote.as_deref(), Some("origin"));
        assert_eq!(parsed.refspecs.len(), 3);
        assert!(parsed.atomic);
        assert!(parsed.set_upstream);
        assert_eq!(parsed.leases[0].remote_ref, "refs/heads/main");
        assert_eq!(parsed.refspecs[0].source, "HEAD");
        assert_eq!(parsed.refspecs[0].destination, "refs/heads/main");
        assert_eq!(parsed.refspecs[1].source, "refs/heads/feature");
        assert_eq!(parsed.refspecs[2].source, "(delete)");

        let tags = PushInvocation::parse(&args(&["origin", "--tags", "--dry-run"])).unwrap();
        assert!(tags.tags && tags.dry_run);

        let forced = PushInvocation::parse(&args(&[
            "origin",
            "--force",
            "refs/heads/main:refs/heads/main",
        ]))
        .unwrap();
        assert!(forced.force);

        let bare_lease =
            PushInvocation::parse(&args(&["--force-with-lease", "--force-if-includes"])).unwrap();
        assert!(bare_lease.bare_force_with_lease);
        assert!(bare_lease.force_if_includes);
        assert!(!bare_lease.force);

        let ref_lease =
            PushInvocation::parse(&args(&["--force-with-lease=main", "origin", "main"])).unwrap();
        assert_eq!(ref_lease.lease_refs, ["refs/heads/main"]);
        assert!(ref_lease.empty_lease_refs.is_empty());

        let empty_lease =
            PushInvocation::parse(&args(&["--force-with-lease=main:", "origin", "main"])).unwrap();
        assert_eq!(empty_lease.empty_lease_refs, ["refs/heads/main"]);
        assert!(empty_lease.lease_refs.is_empty());

        for invalid in [
            vec!["origin", "refs/notes/a:refs/notes/b"],
            vec!["origin", "main..backup:main"],
            vec!["origin", "feature/.hidden:feature/.hidden"],
            vec!["origin", "main.lock:main.lock"],
            vec!["origin", "main:main", "feature:main"],
            vec![
                "origin",
                "--force-with-lease=refs/heads/elsewhere:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "main:main",
            ],
            vec!["origin", "--force-with-lease=elsewhere", "main:main"],
            vec!["origin", "--force-with-lease=elsewhere:", "main:main"],
            vec![
                "origin",
                "--force-with-lease=main:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--force-with-lease=refs/heads/main:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "main:main",
            ],
            vec![
                "origin",
                "--force-with-lease=main",
                "--force-with-lease=refs/heads/main:",
                "main:main",
            ],
        ] {
            assert!(
                PushInvocation::parse(&args(&invalid)).is_err(),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn accepts_git_push_same_name_refspec_spelling() {
        let parsed = PushInvocation::parse(&args(&["origin", "main"])).unwrap();
        assert_eq!(parsed.remote.as_deref(), Some("origin"));
        assert_eq!(parsed.refspecs[0].source, "refs/heads/main");
        assert_eq!(parsed.refspecs[0].destination, "refs/heads/main");
    }

    #[test]
    fn resolves_repeated_relative_c_options_sequentially() {
        let temporary = tempfile::tempdir().unwrap();
        let first = temporary.path().join("first");
        let second = first.join("second");
        std::fs::create_dir_all(&second).unwrap();
        let parsed = GitInvocation::parse(args(&["-C", "first", "-Csecond", "status"])).unwrap();
        assert_eq!(
            parsed.resolve_directory(temporary.path()).unwrap(),
            std::fs::canonicalize(second).unwrap()
        );
    }
}
