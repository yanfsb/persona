use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Parsed Git global options before the subcommand. This keeps option
/// interpretation independent from policy and subprocess execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitInvocation {
    pub directory_changes: Vec<PathBuf>,
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
    Unsupported(String),
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
            other => Self::Unsupported(other.to_owned()),
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
            Self::Unsupported(value) => value,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushInvocation {
    pub remote: String,
    pub refspecs: Vec<PushRefspec>,
    pub leases: Vec<ExactPushLease>,
    pub atomic: bool,
    pub set_upstream: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactPushLease {
    pub remote_ref: String,
    pub expected_oid: String,
}

impl PushInvocation {
    /// Parse a bounded explicit push grammar without authorizing or executing it.
    /// Unsupported options/refspec forms fail here so callers cannot reinterpret them.
    pub fn parse(arguments: &[OsString]) -> Result<Self, &'static str> {
        const MAX_REFSPECS: usize = 16;
        let mut remote: Option<String> = None;
        let mut refspecs = Vec::new();
        let mut leases = Vec::new();
        let mut atomic = false;
        let mut set_upstream = false;
        let mut index = 0;
        while index < arguments.len() {
            let word = arguments[index]
                .to_str()
                .ok_or("push arguments must be valid UTF-8")?;
            match word {
                "--atomic" => atomic = true,
                "-u" | "--set-upstream" => set_upstream = true,
                _ if word.starts_with("--force-with-lease=") => {
                    let value = word.trim_start_matches("--force-with-lease=");
                    let (remote_ref, expected_oid) = value
                        .split_once(':')
                        .ok_or("force-with-lease must bind ref and expected object ID")?;
                    let remote_ref = normalize_ref(remote_ref, false)?;
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
                _ if word.starts_with('-') => return Err("unsupported push option"),
                _ if remote.is_none() => {
                    if word.is_empty()
                        || word.len() > 128
                        || !word.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                        })
                    {
                        return Err("invalid push remote");
                    }
                    remote = Some(word.to_owned());
                }
                _ => {
                    if refspecs.len() == MAX_REFSPECS {
                        return Err("push refspec count exceeds the limit");
                    }
                    let (source, destination) = word
                        .split_once(':')
                        .ok_or("push refspec must specify source and destination")?;
                    if source.starts_with('+') || destination.is_empty() {
                        return Err("unsupported push refspec");
                    }
                    let source = if source.is_empty() {
                        "(delete)".to_owned()
                    } else if source == "HEAD" {
                        "HEAD".to_owned()
                    } else {
                        normalize_ref(source, true)?
                    };
                    let destination = normalize_ref(destination, false)?;
                    refspecs.push(PushRefspec {
                        source,
                        destination,
                    });
                }
            }
            index += 1;
        }
        if refspecs.is_empty() {
            return Err("push requires at least one explicit refspec");
        }
        let mut destinations = std::collections::HashSet::new();
        for refspec in &refspecs {
            if !destinations.insert(refspec.destination.as_str()) {
                return Err("push refspec destinations must be unique");
            }
        }
        let mut leased_refs = std::collections::HashSet::new();
        for lease in &leases {
            if !leased_refs.insert(lease.remote_ref.as_str()) {
                return Err("force-with-lease may name each ref only once");
            }
            if !destinations.contains(lease.remote_ref.as_str()) {
                return Err("force-with-lease must match a requested destination ref");
            }
        }
        Ok(Self {
            remote: remote.ok_or("push requires an explicit remote")?,
            refspecs,
            leases,
            atomic,
            set_upstream,
        })
    }
}

fn normalize_ref(reference: &str, source: bool) -> Result<String, &'static str> {
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

impl GitInvocation {
    pub fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Self, ParseError> {
        let mut arguments = arguments.into_iter();
        let mut directory_changes = Vec::new();
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
            if argument == "--no-pager" || argument == "--literal-pathspecs" {
                global_arguments.push(argument);
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
            "status",
            "-C",
            "not-a-global-option",
        ]))
        .unwrap();
        assert_eq!(
            parsed.directory_changes,
            [PathBuf::from("repo"), PathBuf::from("subdir")]
        );
        assert_eq!(parsed.global_arguments, args(&["--no-pager"]));
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
        assert_eq!(
            GitInvocation::parse(args(&["-c", "alias.x=...", "status"])),
            Err(ParseError::UnsupportedGlobalOption)
        );
        assert_eq!(
            GitInvocation::parse(Vec::<OsString>::new()),
            Err(ParseError::MissingSubcommand)
        );
    }

    #[test]
    fn parses_bounded_explicit_push_requests_without_authorizing_them() {
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
        assert_eq!(parsed.remote, "origin");
        assert_eq!(parsed.refspecs.len(), 3);
        assert!(parsed.atomic);
        assert!(parsed.set_upstream);
        assert_eq!(parsed.leases[0].remote_ref, "refs/heads/main");
        assert_eq!(parsed.refspecs[0].source, "HEAD");
        assert_eq!(parsed.refspecs[0].destination, "refs/heads/main");
        assert_eq!(parsed.refspecs[1].source, "refs/heads/feature");
        assert_eq!(parsed.refspecs[2].source, "(delete)");

        for invalid in [
            vec!["origin"],
            vec!["origin", "refs/notes/a:refs/notes/b"],
            vec!["origin", "main..backup:main"],
            vec!["origin", "feature/.hidden:feature/.hidden"],
            vec!["origin", "main.lock:main.lock"],
            vec!["origin", "+refs/heads/main:refs/heads/main"],
            vec!["origin", "--force", "refs/heads/main:refs/heads/main"],
            vec!["origin", "main:main", "feature:main"],
            vec![
                "origin",
                "--force-with-lease=refs/heads/elsewhere:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "main:main",
            ],
            vec![
                "origin",
                "--force-with-lease=main:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--force-with-lease=refs/heads/main:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
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
