use std::collections::BTreeSet;
use std::ffi::OsString;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GhOperation {
    Read,
    Clone,
    Create,
    ServerMerge,
    AuditedRelease,
    Review,
    Checkout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhRequest {
    pub arguments: Vec<OsString>,
    pub repositories: Vec<String>,
    pub operation: GhOperation,
    pub clone_directory: Option<std::path::PathBuf>,
    pub merge: Option<GhMergeRequest>,
    pub release: Option<GhReleaseRequest>,
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

type ParsedOperation = (
    Vec<String>,
    GhOperation,
    usize,
    BTreeSet<&'static str>,
    BTreeSet<&'static str>,
);

pub fn parse(arguments: &[OsString]) -> Result<GhRequest, String> {
    let words = arguments
        .iter()
        .map(|argument| {
            argument
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| "gh arguments must be valid UTF-8".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if words.len() < 2 {
        return Err(
            "gh command is incomplete; supported groups are repo, pr, issue, release, and api"
                .to_owned(),
        );
    }

    let mut command = words;
    command[0] = match command[0].as_str() {
        "repository" => "repo".to_owned(),
        "pull-request" => "pr".to_owned(),
        "issues" => "issue".to_owned(),
        "releases" => "release".to_owned(),
        other => other.to_owned(),
    };
    if command.get(1).is_some_and(|word| word == "ls") {
        command[1] = "list".to_owned();
    }
    for pair in command.windows(2) {
        if pair[0] == "--hostname" && pair[1] != "github.com" {
            return Err("managed gh supports only the explicitly bound github.com host".to_owned());
        }
    }

    if command.iter().any(|word| word == "--public")
        && command.iter().any(|word| word == "--private")
    {
        return Err("gh repo create cannot combine --public and --private".to_owned());
    }
    let (repositories, operation, permitted_positionals, allowed_value_flags, allowed_boolean_flags) =
        match (command[0].as_str(), command[1].as_str()) {
            ("repo", "view") => (repo_operand(&command[2..], 1)?, GhOperation::Read, 1, flags(&["--json", "--jq"]), flags(&[])),
            ("repo", "clone") => (repo_operand(&command[2..], 2)?, GhOperation::Clone, 2, flags(&[]), flags(&[])),
            ("repo", "fork") => (repo_fork_repositories(&command[2..])?, GhOperation::Create, 1, flags(&["--org"]), flags(&[])),
            ("repo", "create") => (repo_operand(&command[2..], 1)?, GhOperation::Create, 1, flags(&["--description"]), flags(&["--public", "--private", "--disable-issues", "--disable-wiki", "--add-readme"])),
            ("pr", "view") => (repo_option(&command[2..])?, GhOperation::Read, 1, flags(&["--json", "--jq"]), flags(&[])),
            ("pr", "list") => (repo_option(&command[2..])?, GhOperation::Read, 0, flags(&["--json", "--jq", "--limit", "--state", "--base", "--head", "--author", "--assignee", "--label"]), flags(&[])),
            ("pr", "create") => (repo_option(&command[2..])?, GhOperation::Create, 0, flags(&["--title", "--body", "--base", "--head", "--assignee", "--reviewer", "--label"]), flags(&["--draft", "--fill"])),
            ("pr", "merge") => (repo_option(&command[2..])?, GhOperation::ServerMerge, 1, flags(&[]), flags(&["--merge", "--squash", "--rebase"])),
            ("pr", "review") => (repo_option(&command[2..])?, GhOperation::Review, 1, flags(&["--body"]), flags(&["--approve", "--request-changes", "--comment"])),
            ("pr", "checkout") => (repo_option(&command[2..])?, GhOperation::Checkout, 1, flags(&["--branch"]), flags(&[])),
            ("issue", "view") => (repo_option(&command[2..])?, GhOperation::Read, 1, flags(&["--json", "--jq"]), flags(&[])),
            ("issue", "list") => (repo_option(&command[2..])?, GhOperation::Read, 0, flags(&["--json", "--jq", "--limit", "--state", "--assignee", "--author", "--label", "--milestone"]), flags(&[])),
            ("issue", "create") => (repo_option(&command[2..])?, GhOperation::Create, 0, flags(&["--title", "--body", "--assignee", "--label", "--milestone"]), flags(&[])),
            ("release", "view") => (repo_option(&command[2..])?, GhOperation::Read, 1, flags(&["--json", "--jq"]), flags(&[])),
            ("release", "list") => (repo_option(&command[2..])?, GhOperation::Read, 0, flags(&["--json", "--jq", "--limit"]), flags(&[])),
            ("release", "create") => (repo_option(&command[2..])?, GhOperation::AuditedRelease, 1, flags(&["--title", "--notes"]), flags(&["--draft", "--prerelease", "--generate-notes"])),
            ("api", _) => parse_api(&command)?,
            ("auth", "status") => return Err("gh auth status is not a protected repository operation; use `persona auth verify` for API-free local verification".to_owned()),
            ("alias", _) | ("extension", _) | ("ext", _) => return Err("gh aliases and extensions are unsupported in managed mode".to_owned()),
            _ => return Err("unsupported gh command or destructive operation".to_owned()),
        };

    if command[0] != "api" {
        validate_options(
            &command[2..],
            permitted_positionals,
            &allowed_value_flags,
            &allowed_boolean_flags,
        )?;
    }
    let positionals = positional_words(&command[2..]);
    match (command[0].as_str(), command[1].as_str()) {
        ("pr" | "issue", "view")
            if positionals.len() == 1
                && !positionals[0].bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            return Err(
                "managed PR/issue view requires a numeric identifier, not a URL or owner alias"
                    .to_owned(),
            );
        }
        ("release", "view" | "create")
            if !positionals.is_empty() && !valid_component(positionals[0], false) =>
        {
            return Err("release tag must be a single safe tag name".to_owned());
        }
        ("release", "create")
            if positionals.len() != 1 || !valid_component(positionals[0], false) =>
        {
            return Err(
                "managed release creation requires one explicit safe existing tag name".to_owned(),
            );
        }
        ("pr", "create")
            if !command
                .iter()
                .any(|word| word == "--title" || word == "--fill") =>
        {
            return Err("gh pr create requires an explicit title or --fill".to_owned());
        }
        ("pr", "merge") => {
            let pull_number = positionals
                .first()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|number| *number > 0)
                .ok_or_else(|| {
                    "gh pr merge requires an explicit positive numeric pull request ID".to_owned()
                })?;
            let strategies = [
                ("--merge", crate::config::MergeStrategy::Merge),
                ("--squash", crate::config::MergeStrategy::Squash),
                ("--rebase", crate::config::MergeStrategy::Rebase),
            ];
            let selected = strategies
                .iter()
                .filter(|(flag, _)| command.iter().any(|word| word == flag))
                .map(|(_, strategy)| *strategy)
                .collect::<Vec<_>>();
            if selected.len() != 1 {
                return Err(
                    "gh pr merge requires exactly one of --merge, --squash, or --rebase".to_owned(),
                );
            }
            let _ = pull_number;
            let _ = selected;
        }
        ("pr", "checkout") => {
            let number = positionals
                .first()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|number| *number > 0)
                .ok_or_else(|| {
                    "gh pr checkout requires an explicit positive numeric pull request ID"
                        .to_owned()
                })?;
            let _ = number;
        }
        ("pr", "review") => {
            let number = positionals
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
                return Err("gh pr review requires exactly one of --approve, --request-changes, or --comment".to_owned());
            }
            if command
                .windows(2)
                .find(|pair| pair[0] == "--body")
                .is_some_and(|pair| pair[1].len() > 65_536)
            {
                return Err("review body exceeds the size limit".to_owned());
            }
            if (command
                .iter()
                .any(|word| word == "--request-changes" || word == "--comment"))
                && !command
                    .windows(2)
                    .any(|pair| pair[0] == "--body" && !pair[1].is_empty())
            {
                return Err(
                    "request-changes and comment reviews require a non-empty --body".to_owned(),
                );
            }
            let _ = number;
        }
        ("issue", "create") if !command.iter().any(|word| word == "--title") => {
            return Err("gh issue create requires --title".to_owned());
        }
        _ => {}
    }
    let checkout = if command[0] == "pr" && command[1] == "checkout" {
        let words = positional_words(&command[2..]);
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
        let pull_number = positional_words(&command[2..])[0]
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
        let words = positional_words(&command[2..]);
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
    let release = if command[0] == "release" && command[1] == "create" {
        let tag = positional_words(&command[2..])
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
    let clone_directory = if command[0] == "repo" && command[1] == "clone" {
        let positional = positional_words(&command[2..]);
        if positional.len() != 2 {
            return Err("gh repo clone requires an explicit destination directory".to_owned());
        }
        Some(std::path::PathBuf::from(positional[1]))
    } else {
        None
    };
    Ok(GhRequest {
        arguments: command.into_iter().map(OsString::from).collect(),
        repositories,
        operation,
        clone_directory,
        merge,
        release,
        review,
        checkout,
    })
}

fn parse_api(words: &[String]) -> Result<ParsedOperation, String> {
    let endpoint = words
        .get(1)
        .ok_or_else(|| "gh api requires an explicit repository endpoint".to_owned())?;
    let route = endpoint.strip_prefix('/').unwrap_or(endpoint);
    if route.starts_with('/') {
        return Err("gh api endpoint has repeated leading slashes".to_owned());
    }
    let mut parts = route.split('/');
    if parts.next() != Some("repos") {
        return Err("gh api only supports repository-scoped REST endpoints".to_owned());
    }
    let owner = parts
        .next()
        .ok_or_else(|| "gh api endpoint has no repository owner".to_owned())?;
    let name = parts
        .next()
        .ok_or_else(|| "gh api endpoint has no repository name".to_owned())?;
    let repository = normalize_repository(&format!("{owner}/{name}"))?;
    let suffix = parts.collect::<Vec<_>>();
    if suffix.is_empty()
        || suffix.iter().any(|part| {
            part.is_empty()
                || part == &"."
                || part == &".."
                || part.bytes().any(|byte| {
                    !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
                })
        })
        || endpoint.contains(['?', '#', '%'])
    {
        return Err("gh api endpoint is ambiguous or outside the repository path".to_owned());
    }
    let mut method = "GET";
    let mut method_seen = false;
    let mut field_names = BTreeSet::new();
    let mut index = 2;
    while index < words.len() {
        match words[index].as_str() {
            "--hostname" => {
                let host = words.get(index + 1).ok_or_else(|| "--hostname requires a value".to_owned())?;
                if host != "github.com" {
                    return Err("managed gh supports only github.com".to_owned());
                }
                index += 1;
            }
            "--method" | "-X" => {
                if method_seen {
                    return Err("gh api method is specified more than once".to_owned());
                }
                method_seen = true;
                index += 1;
                method = words.get(index).map(String::as_str).ok_or_else(|| "gh api --method requires a value".to_owned())?;
                if !matches!(method, "GET" | "POST") {
                    return Err("gh api permits only GET and constrained create-only POST requests".to_owned());
                }
            }
            "--field" | "-F" | "--raw-field" | "-f" => {
                index += 1;
                let field = words.get(index).ok_or_else(|| "gh api field option requires key=value".to_owned())?;
                let (key, value) = field.split_once('=').ok_or_else(|| "gh api fields must use key=value".to_owned())?;
                if value.is_empty() || value.starts_with('@') || value.contains(['\n', '\r']) {
                    return Err("gh api file-backed or multiline fields are unsupported".to_owned());
                }
                if !field_names.insert(key.to_owned()) {
                    return Err("duplicate gh api fields are ambiguous and unsupported".to_owned());
                }
            }
            _ => return Err("unsupported gh api option; headers, input files, pagination, GraphQL, and arbitrary methods are denied".to_owned()),
        }
        index += 1;
    }
    let operation = if method == "GET" {
        if !field_names.is_empty() {
            return Err("gh api GET does not accept body fields".to_owned());
        }
        GhOperation::Read
    } else {
        let endpoint_ok = matches!(suffix.as_slice(), ["issues"] | ["pulls"]);
        let keys_ok = match suffix.as_slice() {
            ["issues"] => field_names.iter().all(|key| {
                matches!(
                    key.as_str(),
                    "title" | "body" | "assignees" | "labels" | "milestone"
                )
            }),
            ["pulls"] => field_names
                .iter()
                .all(|key| matches!(key.as_str(), "title" | "body" | "head" | "base" | "draft")),
            _ => false,
        };
        if !endpoint_ok || !keys_ok {
            return Err(
                "gh api POST is restricted to issue, pull-request, and release creation endpoints"
                    .to_owned(),
            );
        }
        let required = match suffix.as_slice() {
            ["issues"] | ["pulls"] => "title",
            _ => unreachable!(),
        };
        if !field_names.contains(required) {
            return Err(format!(
                "gh api create request requires the `{required}` field"
            ));
        }
        GhOperation::Create
    };
    Ok((vec![repository], operation, 0, flags(&[]), flags(&[])))
}

fn repo_operand(words: &[String], _max_positionals: usize) -> Result<Vec<String>, String> {
    let operand = positional_words(words)
        .into_iter()
        .next()
        .ok_or_else(|| "gh command requires an explicit OWNER/REPO target".to_owned())?;
    Ok(vec![normalize_repository(operand)?])
}

fn positional_words(words: &[String]) -> Vec<&str> {
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

fn repo_fork_repositories(words: &[String]) -> Result<Vec<String>, String> {
    let source = repo_operand(words, 1)?.remove(0);
    let org = words
        .windows(2)
        .find(|pair| pair[0] == "--org")
        .map(|pair| pair[1].as_str());
    let Some(org) = org else {
        return Err(
            "gh repo fork requires an explicit --org so the fork destination can be checked"
                .to_owned(),
        );
    };
    let name = source.split_once('/').unwrap().1;
    let destination = normalize_repository(&format!("{org}/{name}"))?;
    Ok(vec![source, destination])
}

fn repo_option(words: &[String]) -> Result<Vec<String>, String> {
    let mut repository = None;
    let mut index = 0;
    while index < words.len() {
        if matches!(words[index].as_str(), "--repo" | "-R") {
            index += 1;
            if repository.is_some() {
                return Err("gh repository target is specified more than once".to_owned());
            }
            repository = Some(normalize_repository(
                words
                    .get(index)
                    .ok_or_else(|| "--repo requires OWNER/REPO".to_owned())?,
            )?);
        }
        index += 1;
    }
    repository
        .map(|repository| vec![repository])
        .ok_or_else(|| "gh repository operations require explicit --repo OWNER/REPO".to_owned())
}

fn validate_options(
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
        if matches!(word.as_str(), "--hostname") {
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
                if word == "--limit"
                    && value
                        .parse::<u16>()
                        .map_or(true, |limit| !(1..=100).contains(&limit))
                {
                    return Err("managed gh list limits must be between 1 and 100".to_owned());
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

fn flags(values: &[&'static str]) -> BTreeSet<&'static str> {
    values.iter().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_words(words: &[&str]) -> Result<GhRequest, String> {
        parse(&words.iter().map(OsString::from).collect::<Vec<_>>())
    }

    #[test]
    fn normalizes_safe_aliases_and_binds_repository_targets() {
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
        assert_eq!(request.repositories, ["acme/persona"]);
        assert_eq!(request.operation, GhOperation::Read);
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
    fn pull_request_checkout_requires_numeric_id_and_explicit_repository() {
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
        assert!(
            parse_words(&[
                "pr",
                "checkout",
                "https://github.com/acme/persona/pull/15",
                "--repo",
                "acme/persona"
            ])
            .is_err()
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
    fn release_creation_is_typed_and_requires_an_existing_tag_name_and_notes() {
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
        assert!(
            parse_words(&[
                "release",
                "create",
                "v1.2.3",
                "--repo",
                "acme/persona",
                "--notes",
                "notes",
                "--target",
                "main"
            ])
            .is_err()
        );
        assert!(parse_words(&["release", "create", "v1.2.3", "--repo", "acme/persona"]).is_err());
    }

    #[test]
    fn requires_an_explicit_safe_clone_directory_before_api_delegation() {
        assert!(parse_words(&["repo", "clone", "acme/persona"]).is_err());
        let request = parse_words(&["repo", "clone", "acme/persona", "./checkout"]).unwrap();
        assert_eq!(
            request.clone_directory.as_deref(),
            Some(std::path::Path::new("./checkout"))
        );
    }

    #[test]
    fn allows_only_creation_api_endpoints_with_typed_required_fields() {
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
        assert_eq!(request.operation, GhOperation::Create);
        assert!(parse_words(&["api", "graphql"]).is_err());
        assert!(parse_words(&["api", "repos/acme/persona/issues", "--method", "DELETE"]).is_err());
        assert!(
            parse_words(&[
                "api",
                "repos/acme/persona/issues",
                "--method",
                "POST",
                "--field",
                "title=@secret-file"
            ])
            .is_err()
        );
        assert!(
            parse_words(&[
                "api",
                "repos/acme/persona/releases",
                "--method",
                "POST",
                "--field",
                "tag_name=v1"
            ])
            .is_err()
        );
        assert!(parse_words(&["release", "create", "v1", "--repo", "acme/persona"]).is_err());
        assert!(
            parse_words(&[
                "release",
                "create",
                "v1",
                "--repo",
                "acme/persona",
                "--verify-tag",
            ])
            .is_err()
        );
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
    fn rejects_enterprise_alias_extension_destructive_and_ambiguous_targets() {
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
        assert!(parse_words(&["pr", "merge", "2", "--repo", "acme/persona"]).is_err());
        assert!(parse_words(&["pr", "view", "2"]).is_err());
        assert!(parse_words(&["repo", "fork", "acme/persona"]).is_err());
        assert!(parse_words(&["repo", "view", "https://github.com/acme/persona"]).is_err());
        assert!(
            parse_words(&[
                "issue",
                "view",
                "https://github.com/acme/persona/issues/1",
                "--repo",
                "acme/persona"
            ])
            .is_err()
        );
        assert!(parse_words(&["pr", "list", "--repo", "acme/persona", "--limit", "1000"]).is_err());
        assert!(parse_words(&["repo", "create", "acme/persona", "--public", "--private"]).is_err());
        assert_eq!(
            parse_words(&["repo", "fork", "acme/source", "--org", "acme-fork"])
                .unwrap()
                .repositories,
            ["acme/source", "acme-fork/source"]
        );
    }
}
