use std::collections::BTreeSet;
use std::ffi::OsString;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GhOperation {
    Read,
    Clone,
    Create,
    ServerMerge,
    AuditedRelease,
    AuditedReleaseAssetUpload,
    Review,
    Checkout,
    General,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhRequest {
    pub arguments: Vec<OsString>,
    pub selector: String,
    pub flags: Vec<String>,
    pub repositories: Vec<String>,
    pub operation: GhOperation,
    pub clone_directory: Option<std::path::PathBuf>,
    pub merge: Option<GhMergeRequest>,
    pub release: Option<GhReleaseRequest>,
    pub asset_upload: Option<GhAssetUploadRequest>,
    pub review: Option<GhReviewRequest>,
    pub checkout: Option<GhCheckoutRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhMergeRequest {
    pub repository: String,
    pub pull_number: u64,
    pub strategy: crate::config::MergeStrategy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhReleaseRequest {
    pub repository: String,
    pub tag: String,
    pub title: Option<String>,
    pub notes: Option<String>,
    pub draft: bool,
    pub prerelease: bool,
    pub generate_notes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhAssetUploadRequest {
    pub repository: String,
    pub tag: String,
    pub files: Vec<std::path::PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhReviewRequest {
    pub repository: String,
    pub pull_number: u64,
    pub event: GhReviewEvent,
    pub body: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GhReviewEvent {
    Approve,
    RequestChanges,
    Comment,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhCheckoutRequest {
    pub repository: String,
    pub pull_number: u64,
    pub branch: Option<String>,
}

pub fn parse(arguments: &[OsString]) -> Result<GhRequest, String> {
    parse_with_inferred_repository(arguments, None)
}

pub fn parse_with_inferred_repository(
    arguments: &[OsString],
    inferred_repository: Option<&str>,
) -> Result<GhRequest, String> {
    let words = arguments
        .iter()
        .map(|argument| {
            argument
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| "gh arguments must be valid UTF-8".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if words.is_empty() {
        return Err("gh command is incomplete".to_owned());
    }

    let mut command = words;
    command[0] = normalize_group(&command[0]).to_owned();
    if command.get(1).is_some_and(|word| word == "ls") {
        command[1] = "list".to_owned();
    }
    check_hostname(&command)?;

    if command[0] == "auth" {
        let sub = command.get(1).map(String::as_str).unwrap_or("");
        if sub == "status" {
            return Err(
                "gh auth status is not a protected repository operation; use `persona auth verify` for API-free local verification"
                    .to_owned(),
            );
        }
        return Err(
            "gh auth commands are blocked in managed mode to prevent global credential switches or token disclosure"
                .to_owned(),
        );
    }
    if matches!(command[0].as_str(), "alias" | "extension" | "ext") {
        return Err("gh aliases and extensions are unsupported in managed mode".to_owned());
    }

    if command.iter().any(|word| word == "--public")
        && command.iter().any(|word| word == "--private")
    {
        return Err("gh repo create cannot combine --public and --private".to_owned());
    }

    let raw_flags = extract_flags(&command[1..]);

    if command[0] == "api" {
        return parse_api(command, raw_flags, inferred_repository);
    }

    // Single-word top-level commands like `gh status` or `gh search` (actually search takes subcommand).
    if command.len() == 1 || command[1].starts_with('-') {
        let selector = command[0].clone();
        let mut repositories = Vec::new();
        if let Some(repo) = extract_repo_flag(&command[1..])? {
            repositories.push(repo);
        } else if let Some(inferred) = inferred_repository {
            if group_accepts_inferred_repo(&command[0]) {
                repositories.push(normalize_repository(inferred)?);
            }
        }
        return Ok(GhRequest {
            arguments: command.into_iter().map(OsString::from).collect(),
            selector,
            flags: raw_flags,
            repositories,
            operation: GhOperation::General,
            clone_directory: None,
            merge: None,
            release: None,
            asset_upload: None,
            review: None,
            checkout: None,
        });
    }

    let group = command[0].as_str();
    let sub = command[1].as_str();
    let selector = format!("{group}.{sub}");

    match (group, sub) {
        ("pr", "merge")
        | ("pr", "review")
        | ("pr", "checkout")
        | ("release", "create")
        | ("release", "upload") => {
            parse_audited_operation(command, selector, raw_flags, inferred_repository)
        }
        ("repo", "clone") => parse_clone_operation(command, selector, raw_flags),
        ("repo", "fork") => parse_fork_operation(command, selector, raw_flags, inferred_repository),
        _ => parse_general_operation(command, selector, raw_flags, inferred_repository),
    }
}

fn normalize_group(group: &str) -> &str {
    match group {
        "repository" => "repo",
        "pull-request" => "pr",
        "issues" => "issue",
        "releases" => "release",
        other => other,
    }
}

fn check_hostname(command: &[String]) -> Result<(), String> {
    let mut index = 0;
    while index < command.len() {
        if command[index] == "--hostname" {
            let host = command
                .get(index + 1)
                .ok_or_else(|| "--hostname requires a value".to_owned())?;
            if host != "github.com" {
                return Err(
                    "managed gh supports only the explicitly bound github.com host".to_owned(),
                );
            }
            index += 2;
            continue;
        }
        if let Some(host) = command[index].strip_prefix("--hostname=") {
            if host != "github.com" {
                return Err(
                    "managed gh supports only the explicitly bound github.com host".to_owned(),
                );
            }
        }
        index += 1;
    }
    Ok(())
}

fn group_accepts_inferred_repo(group: &str) -> bool {
    matches!(
        group,
        "pr" | "issue"
            | "release"
            | "run"
            | "workflow"
            | "cache"
            | "label"
            | "ruleset"
            | "secret"
            | "variable"
    )
}

fn parse_clone_operation(
    command: Vec<String>,
    selector: String,
    flags: Vec<String>,
) -> Result<GhRequest, String> {
    let positionals = general_positionals(&command[2..]);
    let target = positionals
        .first()
        .copied()
        .ok_or_else(|| "gh repo clone requires a repository target".to_owned())?;
    let repository = normalize_repo_or_url(target)?;
    let clone_directory = if let Some(dir) = positionals.get(1) {
        std::path::PathBuf::from(dir)
    } else {
        let (_, name) = repository
            .split_once('/')
            .ok_or_else(|| "GitHub target must be an explicit OWNER/REPO".to_owned())?;
        std::path::PathBuf::from(name)
    };
    Ok(GhRequest {
        arguments: command.into_iter().map(OsString::from).collect(),
        selector,
        flags,
        repositories: vec![repository],
        operation: GhOperation::Clone,
        clone_directory: Some(clone_directory),
        merge: None,
        release: None,
        asset_upload: None,
        review: None,
        checkout: None,
    })
}

fn parse_fork_operation(
    command: Vec<String>,
    selector: String,
    flags: Vec<String>,
    inferred_repository: Option<&str>,
) -> Result<GhRequest, String> {
    let positionals = general_positionals(&command[2..]);
    let source = if let Some(target) = positionals.first() {
        normalize_repo_or_url(target)?
    } else if let Some(repo) = extract_repo_flag(&command[2..])? {
        repo
    } else if let Some(inferred) = inferred_repository {
        normalize_repository(inferred)?
    } else {
        return Err("gh repo fork requires an explicit or inferred OWNER/REPO target".to_owned());
    };
    let mut repositories = vec![source.clone()];
    if let Some(org) = find_flag_value(&command[2..], "--org") {
        let name = source.split_once('/').unwrap().1;
        repositories.push(normalize_repository(&format!("{org}/{name}"))?);
    }
    Ok(GhRequest {
        arguments: command.into_iter().map(OsString::from).collect(),
        selector,
        flags,
        repositories,
        operation: GhOperation::Create,
        clone_directory: None,
        merge: None,
        release: None,
        asset_upload: None,
        review: None,
        checkout: None,
    })
}

fn parse_general_operation(
    command: Vec<String>,
    selector: String,
    flags: Vec<String>,
    inferred_repository: Option<&str>,
) -> Result<GhRequest, String> {
    let group = command[0].as_str();
    let sub = command[1].as_str();
    let explicit_repo = extract_repo_flag(&command[2..])?;
    let mut repositories = Vec::new();
    if let Some(repo) = explicit_repo {
        repositories.push(repo);
    } else if group == "repo" && sub != "list" {
        let positionals = general_positionals(&command[2..]);
        if let Some(target) = positionals.first() {
            repositories.push(normalize_repo_or_url(target)?);
        } else if let Some(inferred) = inferred_repository {
            repositories.push(normalize_repository(inferred)?);
        } else {
            return Err(
                "gh repo command requires an explicit or inferred OWNER/REPO target".to_owned(),
            );
        }
    } else if group_accepts_inferred_repo(group) {
        if let Some(inferred) = inferred_repository {
            repositories.push(normalize_repository(inferred)?);
        } else {
            return Err(
                "gh repository operations require explicit --repo OWNER/REPO outside a managed Git checkout"
                    .to_owned(),
            );
        }
    }

    let operation = match (group, sub) {
        (_, "view" | "list" | "diff" | "checks" | "status") => GhOperation::Read,
        (_, "create") => GhOperation::Create,
        _ => GhOperation::General,
    };

    Ok(GhRequest {
        arguments: command.into_iter().map(OsString::from).collect(),
        selector,
        flags,
        repositories,
        operation,
        clone_directory: None,
        merge: None,
        release: None,
        asset_upload: None,
        review: None,
        checkout: None,
    })
}

fn parse_audited_operation(
    command: Vec<String>,
    selector: String,
    flags: Vec<String>,
    inferred_repository: Option<&str>,
) -> Result<GhRequest, String> {
    let repositories = match extract_repo_flag(&command[2..])? {
        Some(repo) => vec![repo],
        None => match inferred_repository {
            Some(inferred) => vec![normalize_repository(inferred)?],
            None => {
                return Err(
                    "gh repository operations require explicit --repo OWNER/REPO".to_owned(),
                );
            }
        },
    };
    let (operation, permitted_positionals, allowed_value_flags, allowed_boolean_flags) =
        match (command[0].as_str(), command[1].as_str()) {
            ("pr", "merge") => (
                GhOperation::ServerMerge,
                1,
                flag_set(&[]),
                flag_set(&["--merge", "--squash", "--rebase"]),
            ),
            ("pr", "review") => (
                GhOperation::Review,
                1,
                flag_set(&["--body"]),
                flag_set(&["--approve", "--request-changes", "--comment"]),
            ),
            ("pr", "checkout") => (
                GhOperation::Checkout,
                1,
                flag_set(&["--branch"]),
                flag_set(&[]),
            ),
            ("release", "create") => (
                GhOperation::AuditedRelease,
                1,
                flag_set(&["--title", "--notes"]),
                flag_set(&["--draft", "--prerelease", "--generate-notes"]),
            ),
            ("release", "upload") => (
                GhOperation::AuditedReleaseAssetUpload,
                usize::MAX,
                flag_set(&[]),
                flag_set(&[]),
            ),
            _ => unreachable!(),
        };

    validate_audited_options(
        &command[2..],
        permitted_positionals,
        &allowed_value_flags,
        &allowed_boolean_flags,
    )?;
    let positionals = audited_positional_words(&command[2..]);
    match (command[0].as_str(), command[1].as_str()) {
        ("release", "create")
            if positionals.len() != 1 || !valid_component(positionals[0], false) =>
        {
            return Err(
                "managed release creation requires one explicit safe existing tag name".to_owned(),
            );
        }
        ("release", "upload") => {
            if command
                .iter()
                .any(|word| word == "-R" || word == "--hostname")
            {
                return Err("release asset uploads require exactly --repo OWNER/REPO".to_owned());
            }
            if positionals.len() < 2
                || !valid_component(positionals[0], false)
                || positionals[1..].iter().any(|path| {
                    *path == "-"
                        || path.contains(['#', '*', '?', '[', ']'])
                        || std::path::Path::new(path)
                            .file_name()
                            .and_then(|name| name.to_str())
                            .is_none_or(|name| !crate::asset_upload::valid_asset_name(name))
                })
            {
                return Err(
                    "release upload requires one safe existing tag and explicit safe file paths"
                        .to_owned(),
                );
            }
            if positionals.len() - 1 > crate::asset_upload::MAX_ASSET_FILES {
                return Err(format!(
                    "release uploads accept at most {} files",
                    crate::asset_upload::MAX_ASSET_FILES
                ));
            }
            let mut names = BTreeSet::new();
            for path in &positionals[1..] {
                let name = std::path::Path::new(path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("validated asset basename");
                if !names.insert(name.to_ascii_lowercase()) {
                    return Err("release asset basenames must be unique".to_owned());
                }
            }
        }
        ("pr", "merge") => {
            let _pull_number = positionals
                .first()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|number| *number > 0)
                .ok_or_else(|| {
                    "gh pr merge requires an explicit positive numeric pull request ID".to_owned()
                })?;
            let count = ["--merge", "--squash", "--rebase"]
                .iter()
                .filter(|flag| command.iter().any(|word| word == *flag))
                .count();
            if count != 1 {
                return Err(
                    "gh pr merge requires exactly one of --merge, --squash, or --rebase".to_owned(),
                );
            }
        }
        ("pr", "checkout") => {
            let _number = positionals
                .first()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|number| *number > 0)
                .ok_or_else(|| {
                    "gh pr checkout requires an explicit positive numeric pull request ID"
                        .to_owned()
                })?;
        }
        ("pr", "review") => {
            let _number = positionals
                .first()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|number| *number > 0)
                .ok_or_else(|| {
                    "gh pr review requires an explicit positive numeric pull request ID".to_owned()
                })?;
            let events = ["--approve", "--request-changes", "--comment"]
                .iter()
                .filter(|flag| command.iter().any(|word| word == **flag))
                .count();
            if events != 1 {
                return Err(
                    "gh pr review requires exactly one of --approve, --request-changes, or --comment"
                        .to_owned(),
                );
            }
            if command
                .windows(2)
                .find(|pair| pair[0] == "--body")
                .is_some_and(|pair| pair[1].len() > 65_536)
            {
                return Err("review body exceeds the size limit".to_owned());
            }
            if command
                .iter()
                .any(|word| word == "--request-changes" || word == "--comment")
                && !command
                    .windows(2)
                    .any(|pair| pair[0] == "--body" && !pair[1].is_empty())
            {
                return Err(
                    "request-changes and comment reviews require a non-empty --body".to_owned(),
                );
            }
        }
        _ => {}
    }

    let checkout = if command[0] == "pr" && command[1] == "checkout" {
        let words = audited_positional_words(&command[2..]);
        let pull_number = words
            .first()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| "pull request ID is invalid".to_owned())?;
        Some(GhCheckoutRequest {
            repository: repositories
                .first()
                .cloned()
                .ok_or_else(|| "checkout request has no repository".to_owned())?,
            pull_number,
            branch: command
                .windows(2)
                .find(|pair| pair[0] == "--branch")
                .map(|pair| pair[1].clone()),
        })
    } else {
        None
    };
    let merge = if command[0] == "pr" && command[1] == "merge" {
        let pull_number = audited_positional_words(&command[2..])[0]
            .parse::<u64>()
            .map_err(|_| "gh pr merge pull request ID is invalid".to_owned())?;
        let strategy = if command.iter().any(|word| word == "--merge") {
            crate::config::MergeStrategy::Merge
        } else if command.iter().any(|word| word == "--squash") {
            crate::config::MergeStrategy::Squash
        } else {
            crate::config::MergeStrategy::Rebase
        };
        Some(GhMergeRequest {
            repository: repositories
                .first()
                .cloned()
                .ok_or_else(|| "merge request has no repository".to_owned())?,
            pull_number,
            strategy,
        })
    } else {
        None
    };
    let review = if command[0] == "pr" && command[1] == "review" {
        let words = audited_positional_words(&command[2..]);
        let pull_number = words
            .first()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| "pull request ID is invalid".to_owned())?;
        let event = if command.iter().any(|word| word == "--approve") {
            GhReviewEvent::Approve
        } else if command.iter().any(|word| word == "--request-changes") {
            GhReviewEvent::RequestChanges
        } else {
            GhReviewEvent::Comment
        };
        Some(GhReviewRequest {
            repository: repositories
                .first()
                .cloned()
                .ok_or_else(|| "review request has no repository".to_owned())?,
            pull_number,
            event,
            body: command
                .windows(2)
                .find(|pair| pair[0] == "--body")
                .map(|pair| pair[1].clone()),
        })
    } else {
        None
    };
    let asset_upload = if command[0] == "release" && command[1] == "upload" {
        let positionals = audited_positional_words(&command[2..]);
        Some(GhAssetUploadRequest {
            repository: repositories
                .first()
                .cloned()
                .ok_or_else(|| "release upload request has no repository".to_owned())?,
            tag: positionals[0].to_owned(),
            files: positionals[1..]
                .iter()
                .map(std::path::PathBuf::from)
                .collect(),
        })
    } else {
        None
    };
    let release = if command[0] == "release" && command[1] == "create" {
        let tag = audited_positional_words(&command[2..])
            .first()
            .ok_or_else(|| "release tag is required".to_owned())?
            .to_string();
        Some(GhReleaseRequest {
            repository: repositories
                .first()
                .cloned()
                .ok_or_else(|| "release request has no repository".to_owned())?,
            tag,
            title: command
                .windows(2)
                .find(|pair| pair[0] == "--title")
                .map(|pair| pair[1].clone()),
            notes: command
                .windows(2)
                .find(|pair| pair[0] == "--notes")
                .map(|pair| pair[1].clone()),
            draft: command.iter().any(|word| word == "--draft"),
            prerelease: command.iter().any(|word| word == "--prerelease"),
            generate_notes: command.iter().any(|word| word == "--generate-notes"),
        })
    } else {
        None
    };
    if release.as_ref().is_some_and(|request| {
        request
            .title
            .as_ref()
            .is_some_and(|value| value.len() > 255)
            || request
                .notes
                .as_ref()
                .is_some_and(|value| value.len() > 65_536)
            || (request.notes.is_none() && !request.generate_notes)
    }) {
        return Err("managed release requires bounded title/notes or --generate-notes".to_owned());
    }
    Ok(GhRequest {
        arguments: command.into_iter().map(OsString::from).collect(),
        selector,
        flags,
        repositories,
        operation,
        clone_directory: None,
        merge,
        release,
        asset_upload,
        review,
        checkout,
    })
}

fn parse_api(
    words: Vec<String>,
    flags: Vec<String>,
    inferred_repository: Option<&str>,
) -> Result<GhRequest, String> {
    let endpoint = words
        .get(1)
        .ok_or_else(|| "gh api requires an explicit endpoint".to_owned())?;
    let route = endpoint.strip_prefix('/').unwrap_or(endpoint);
    if route.starts_with('/') || route.contains("..") {
        return Err("gh api endpoint path is ambiguous".to_owned());
    }
    let mut repositories = Vec::new();
    let mut parts = route.split('/');
    if parts.next() == Some("repos") {
        if let (Some(owner), Some(name)) = (parts.next(), parts.next()) {
            if owner != "{owner}" && name != "{repo}" {
                let path_part = name.split(['?', '#']).next().unwrap_or(name);
                if let Ok(repo) = normalize_repository(&format!("{owner}/{path_part}")) {
                    repositories.push(repo);
                }
            } else if let Some(inferred) = inferred_repository {
                repositories.push(normalize_repository(inferred)?);
            }
        }
    }

    let mut method = "GET";
    let mut index = 2;
    while index < words.len() {
        match words[index].as_str() {
            "--method" | "-X" => {
                index += 1;
                method = words
                    .get(index)
                    .map(String::as_str)
                    .ok_or_else(|| "gh api --method requires a value".to_owned())?;
            }
            _ if words[index].starts_with("--method=") => {
                method = &words[index]["--method=".len()..];
            }
            _ if words[index].starts_with("-X") && words[index].len() > 2 => {
                method = &words[index][2..];
            }
            _ => {}
        }
        index += 1;
    }
    let selector = if route == "graphql" {
        "api.graphql".to_owned()
    } else {
        format!("api.{}", method.to_ascii_lowercase())
    };
    let operation = if method.eq_ignore_ascii_case("GET") {
        GhOperation::Read
    } else {
        GhOperation::General
    };
    Ok(GhRequest {
        arguments: words.into_iter().map(OsString::from).collect(),
        selector,
        flags,
        repositories,
        operation,
        clone_directory: None,
        merge: None,
        release: None,
        asset_upload: None,
        review: None,
        checkout: None,
    })
}

fn extract_flags(words: &[String]) -> Vec<String> {
    let mut flags = Vec::new();
    for word in words {
        if word == "--" {
            break;
        }
        if word.starts_with('-') && word.len() > 1 {
            flags.push(word.clone());
        }
    }
    flags
}

fn find_flag_value<'a>(words: &'a [String], name: &str) -> Option<&'a str> {
    let mut index = 0;
    while index < words.len() {
        if words[index] == "--" {
            break;
        }
        if words[index] == name {
            return words.get(index + 1).map(String::as_str);
        }
        if let Some(value) = words[index].strip_prefix(&format!("{name}=")) {
            return Some(value);
        }
        index += 1;
    }
    None
}

fn extract_repo_flag(words: &[String]) -> Result<Option<String>, String> {
    let mut repository = None;
    let mut index = 0;
    while index < words.len() {
        let word = words[index].as_str();
        if word == "--" {
            break;
        }
        let candidate = if matches!(word, "--repo" | "-R") {
            index += 1;
            words
                .get(index)
                .map(String::as_str)
                .ok_or_else(|| "--repo requires OWNER/REPO".to_owned())?
        } else if let Some(value) = word.strip_prefix("--repo=") {
            value
        } else if let Some(value) = word.strip_prefix("-R") {
            if value.is_empty() {
                return Err("-R requires OWNER/REPO".to_owned());
            }
            value
        } else {
            index += 1;
            continue;
        };
        if repository.is_some() {
            return Err("gh repository target is specified more than once".to_owned());
        }
        repository = Some(normalize_repo_or_url(candidate)?);
        index += 1;
    }
    Ok(repository)
}

fn normalize_repo_or_url(value: &str) -> Result<String, String> {
    if value.starts_with("https://") || value.starts_with("ssh://") || value.contains('@') {
        repository_from_destination(value)
            .ok_or_else(|| "GitHub target URL is outside github.com or malformed".to_owned())
    } else {
        normalize_repository(value)
    }
}

fn general_positionals(words: &[String]) -> Vec<&str> {
    let mut positionals = Vec::new();
    let mut index = 0;
    let mut after_double_dash = false;
    while index < words.len() {
        let word = words[index].as_str();
        if after_double_dash {
            positionals.push(word);
            index += 1;
            continue;
        }
        if word == "--" {
            after_double_dash = true;
            index += 1;
            continue;
        }
        if matches!(
            word,
            "--repo"
                | "-R"
                | "--hostname"
                | "--org"
                | "--description"
                | "--json"
                | "--jq"
                | "-q"
                | "--limit"
                | "-L"
                | "--title"
                | "-t"
                | "--body"
                | "-b"
                | "--body-file"
                | "-F"
                | "--base"
                | "-B"
                | "--head"
                | "-H"
                | "--assignee"
                | "-a"
                | "--reviewer"
                | "-r"
                | "--label"
                | "-l"
                | "--state"
                | "-s"
                | "--author"
                | "-A"
                | "--milestone"
                | "-m"
                | "--notes"
                | "--notes-file"
                | "--target"
                | "--branch"
                | "--template"
                | "--workflow"
                | "-w"
                | "--dir"
                | "-D"
                | "--pattern"
                | "-p"
                | "--reason"
                | "--comment"
                | "-c"
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
    positionals
}

fn audited_positional_words(words: &[String]) -> Vec<&str> {
    let value_options = [
        "--hostname",
        "--repo",
        "-R",
        "--org",
        "--description",
        "--json",
        "--jq",
        "--limit",
        "--title",
        "--body",
        "--base",
        "--head",
        "--assignee",
        "--reviewer",
        "--label",
        "--state",
        "--author",
        "--milestone",
        "--notes",
        "--target",
        "--branch",
    ];
    let boolean_options = [
        "--public",
        "--private",
        "--disable-issues",
        "--disable-wiki",
        "--add-readme",
        "--draft",
        "--fill",
        "--latest",
        "--verify-tag",
        "--generate-notes",
        "--prerelease",
        "--merge",
        "--squash",
        "--rebase",
        "--approve",
        "--request-changes",
        "--comment",
    ];
    let mut output = Vec::new();
    let mut index = 0;
    while index < words.len() {
        if value_options.contains(&words[index].as_str()) {
            index += 2;
        } else if boolean_options.contains(&words[index].as_str()) {
            index += 1;
        } else {
            output.push(words[index].as_str());
            index += 1;
        }
    }
    output
}

fn validate_audited_options(
    words: &[String],
    max_positionals: usize,
    allowed_values: &BTreeSet<&str>,
    allowed_booleans: &BTreeSet<&str>,
) -> Result<(), String> {
    let mut positional_count = 0;
    let mut seen_flags = BTreeSet::new();
    let mut index = 0;
    while index < words.len() {
        let word = &words[index];
        if word == "--hostname" {
            if words.get(index + 1).is_none_or(|host| host != "github.com") {
                return Err("managed gh supports only github.com".to_owned());
            }
            index += 2;
            continue;
        }
        if matches!(word.as_str(), "--repo" | "-R") {
            if words.get(index + 1).is_none_or(String::is_empty) {
                return Err("--repo requires OWNER/REPO".to_owned());
            }
            index += 2;
            continue;
        }
        if word.starts_with("--") {
            if !seen_flags.insert(word.as_str()) {
                return Err(format!("duplicate gh option `{word}` is ambiguous"));
            }
            if allowed_booleans.contains(word.as_str()) {
                index += 1;
                continue;
            }
            if allowed_values.contains(word.as_str()) {
                let value = words
                    .get(index + 1)
                    .ok_or_else(|| format!("gh option `{word}` requires a value"))?;
                if value.is_empty() || value == "--" {
                    return Err(format!("gh option `{word}` requires a non-empty value"));
                }
                index += 2;
                continue;
            }
            return Err(format!("unsupported gh option `{word}`"));
        }
        if word.starts_with('-') {
            return Err("unsupported short gh option".to_owned());
        }
        positional_count += 1;
        index += 1;
    }
    if positional_count > max_positionals {
        return Err("gh command has extra positional arguments".to_owned());
    }
    Ok(())
}

pub fn normalize_repository(value: &str) -> Result<String, String> {
    let value = value.strip_prefix("github.com/").unwrap_or(value);
    let Some((owner, name)) = value.split_once('/') else {
        return Err("GitHub target must be an explicit OWNER/REPO".to_owned());
    };
    if name.contains('/') || !valid_component(owner, true) || !valid_component(name, false) {
        return Err("GitHub repository target is malformed".to_owned());
    }
    Ok(format!(
        "{}/{}",
        owner.to_ascii_lowercase(),
        name.to_ascii_lowercase()
    ))
}

pub fn repository_from_destination(destination: &str) -> Option<String> {
    let destination = destination.trim();
    let (host, path) = if let Some(rest) = destination.strip_prefix("https://") {
        let (authority, path) = rest.split_once('/')?;
        if authority.contains('@') || authority.contains(':') {
            return None;
        }
        (authority, path)
    } else if let Some(rest) = destination.strip_prefix("ssh://") {
        let (authority, path) = rest.split_once('/')?;
        let (user, host) = authority.rsplit_once('@').unwrap_or(("", authority));
        if user.contains(':') || host.contains(':') {
            return None;
        }
        (host, path)
    } else if let Some((authority, path)) = destination.split_once(':') {
        let host = authority.rsplit('@').next()?;
        (host, path)
    } else {
        return None;
    };
    if !host.eq_ignore_ascii_case("github.com") || path.contains(['?', '#', '@']) {
        return None;
    }
    let path = path.strip_suffix(".git").unwrap_or(path);
    normalize_repository(path).ok()
}

fn valid_component(value: &str, owner: bool) -> bool {
    !value.is_empty()
        && value.len() <= if owner { 39 } else { 100 }
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && value != "."
        && value != ".."
        && (!owner || !value.contains('_'))
}

fn flag_set(values: &[&'static str]) -> BTreeSet<&'static str> {
    values.iter().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_words(words: &[&str]) -> Result<GhRequest, String> {
        parse(&words.iter().map(OsString::from).collect::<Vec<_>>())
    }

    #[test]
    fn normalizes_aliases_and_infers_repository_when_provided() {
        let request = parse_words(&[
            "pull-request",
            "ls",
            "--repo",
            "Acme/Persona",
            "--limit",
            "20",
        ])
        .unwrap();
        assert_eq!(request.arguments[0], "pr");
        assert_eq!(request.arguments[1], "list");
        assert_eq!(request.selector, "pr.list");
        assert_eq!(request.repositories, ["acme/persona"]);
        assert_eq!(request.operation, GhOperation::Read);

        let inferred = parse_with_inferred_repository(
            &["pr", "diff", "12"]
                .iter()
                .map(OsString::from)
                .collect::<Vec<_>>(),
            Some("yanfsb/persona"),
        )
        .unwrap();
        assert_eq!(inferred.selector, "pr.diff");
        assert_eq!(inferred.repositories, ["yanfsb/persona"]);
    }

    #[test]
    fn allows_everyday_gh_subcommands_and_flags_for_policy_evaluation() {
        let checks = parse_words(&["pr", "checks", "42", "-R", "acme/persona", "-w"]).unwrap();
        assert_eq!(checks.selector, "pr.checks");
        assert_eq!(checks.repositories, ["acme/persona"]);
        assert!(checks.flags.contains(&"-w".to_owned()));

        let run_list = parse_words(&["run", "list", "-R", "acme/persona", "-L", "5"]).unwrap();
        assert_eq!(run_list.selector, "run.list");
        assert_eq!(run_list.repositories, ["acme/persona"]);

        let issue_close = parse_words(&["issue", "close", "12", "--repo", "acme/persona"]).unwrap();
        assert_eq!(issue_close.selector, "issue.close");
        assert_eq!(issue_close.repositories, ["acme/persona"]);
    }

    #[test]
    fn server_merge_requests_are_typed_and_require_exact_strategy_and_pull_id() {
        let request =
            parse_words(&["pr", "merge", "42", "--repo", "Acme/Persona", "--squash"]).unwrap();
        assert_eq!(request.operation, GhOperation::ServerMerge);
        assert_eq!(request.repositories, ["acme/persona"]);
        assert_eq!(
            request.merge,
            Some(GhMergeRequest {
                repository: "acme/persona".to_owned(),
                pull_number: 42,
                strategy: crate::config::MergeStrategy::Squash,
            })
        );
        assert!(
            parse_words(&[
                "pr",
                "merge",
                "42",
                "--repo",
                "acme/persona",
                "--auto",
                "--squash"
            ])
            .is_err()
        );
        assert!(
            parse_words(&[
                "pr",
                "merge",
                "42",
                "--repo",
                "acme/persona",
                "--merge",
                "--squash"
            ])
            .is_err()
        );
        assert!(parse_words(&["pr", "merge", "--repo", "acme/persona", "--squash"]).is_err());
    }

    #[test]
    fn pull_request_checkout_requires_numeric_id_and_repository() {
        let request = parse_words(&[
            "pr",
            "checkout",
            "15",
            "--repo",
            "Acme/Persona",
            "--branch",
            "feature/review",
        ])
        .unwrap();
        assert_eq!(request.operation, GhOperation::Checkout);
        assert_eq!(
            request.checkout,
            Some(GhCheckoutRequest {
                repository: "acme/persona".to_owned(),
                pull_number: 15,
                branch: Some("feature/review".to_owned())
            })
        );
        assert!(parse_words(&["pr", "checkout", "15"]).is_err());
    }

    #[test]
    fn review_actions_are_typed_and_require_one_explicit_event() {
        let request =
            parse_words(&["pr", "review", "12", "--repo", "Acme/Persona", "--approve"]).unwrap();
        assert_eq!(request.operation, GhOperation::Review);
        assert_eq!(
            request.review,
            Some(GhReviewRequest {
                repository: "acme/persona".to_owned(),
                pull_number: 12,
                event: GhReviewEvent::Approve,
                body: None
            })
        );
        assert!(
            parse_words(&[
                "pr",
                "review",
                "12",
                "--repo",
                "acme/persona",
                "--approve",
                "--comment"
            ])
            .is_err()
        );
        assert!(
            parse_words(&["pr", "review", "12", "--repo", "acme/persona", "--comment"]).is_err()
        );
        assert!(
            parse_words(&[
                "pr",
                "review",
                "12",
                "--repo",
                "acme/persona",
                "--request-changes",
                "--body",
                "needs work"
            ])
            .is_ok()
        );
    }

    #[test]
    fn release_creation_and_upload_preserve_audited_contracts() {
        let request = parse_words(&[
            "release",
            "create",
            "v1.2.3",
            "--repo",
            "Acme/Persona",
            "--title",
            "Release",
            "--notes",
            "notes",
            "--draft",
        ])
        .unwrap();
        assert_eq!(request.operation, GhOperation::AuditedRelease);
        assert_eq!(
            request.release,
            Some(GhReleaseRequest {
                repository: "acme/persona".to_owned(),
                tag: "v1.2.3".to_owned(),
                title: Some("Release".to_owned()),
                notes: Some("notes".to_owned()),
                draft: true,
                prerelease: false,
                generate_notes: false,
            })
        );
        assert!(parse_words(&["release", "create", "v1.2.3", "--repo", "acme/persona"]).is_err());

        let upload = parse_words(&[
            "release",
            "upload",
            "v1.2.3",
            "dist.tar.gz",
            "--repo",
            "acme/persona",
        ])
        .unwrap();
        assert_eq!(upload.operation, GhOperation::AuditedReleaseAssetUpload);
        assert!(
            parse_words(&[
                "release",
                "upload",
                "v1",
                "dist.tar.gz",
                "--repo",
                "acme/persona",
                "--clobber"
            ])
            .is_err()
        );
    }

    #[test]
    fn clone_derives_target_directory_when_omitted() {
        let implicit = parse_words(&["repo", "clone", "acme/persona"]).unwrap();
        assert_eq!(
            implicit.clone_directory.as_deref(),
            Some(std::path::Path::new("persona"))
        );
        let explicit = parse_words(&["repo", "clone", "acme/persona", "./checkout"]).unwrap();
        assert_eq!(
            explicit.clone_directory.as_deref(),
            Some(std::path::Path::new("./checkout"))
        );
    }

    #[test]
    fn api_classifies_method_and_extracts_repository_when_present() {
        let request = parse_words(&[
            "api",
            "/repos/acme/persona/issues",
            "--method",
            "POST",
            "--field",
            "title=hello",
        ])
        .unwrap();
        assert_eq!(request.repositories, ["acme/persona"]);
        assert_eq!(request.selector, "api.post");

        let graphql = parse_words(&["api", "graphql"]).unwrap();
        assert_eq!(graphql.selector, "api.graphql");
    }

    #[test]
    fn derives_only_github_dot_com_repository_destinations() {
        assert_eq!(
            repository_from_destination("https://github.com/Acme/Persona.git"),
            Some("acme/persona".to_owned())
        );
        assert_eq!(
            repository_from_destination("git@github.com:Acme/Persona.git"),
            Some("acme/persona".to_owned())
        );
        assert_eq!(
            repository_from_destination("ssh://git@github.com/Acme/Persona.git"),
            Some("acme/persona".to_owned())
        );
        assert_eq!(
            repository_from_destination("https://user:secret@github.com/acme/persona"),
            None
        );
        assert_eq!(
            repository_from_destination("https://evil.invalid/acme/persona"),
            None
        );
    }

    #[test]
    fn rejects_enterprise_hosts_auth_mutations_and_extensions() {
        assert!(
            parse_words(&[
                "repo",
                "view",
                "--hostname",
                "enterprise.invalid",
                "acme/persona"
            ])
            .is_err()
        );
        assert!(parse_words(&["extension", "install", "foo/bar"]).is_err());
        assert!(parse_words(&["auth", "switch"]).is_err());
        assert!(parse_words(&["auth", "status"]).is_err());
        assert!(parse_words(&["pr", "view", "2"]).is_err());
        assert!(parse_words(&["repo", "create", "acme/persona", "--public", "--private"]).is_err());
    }
}
