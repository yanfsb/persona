/// Unified destination and GitHub repository pattern validation and matching.
///
/// Patterns support either exact targets or trailing wildcards (`owner/*` for
/// repositories; `scheme://host[:port]/prefix/*`, `user@host:prefix/*`, or
/// `user@host:*` for Git remote destinations; `*` for catch-all rules).
pub fn valid_repository_pattern(pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let Some((owner, name)) = pattern.split_once('/') else {
        return false;
    };
    if name.contains('/') || !valid_repo_component(owner, true) {
        return false;
    }
    name == "*" || valid_repo_component(name, false)
}

pub fn normalize_repository_pattern(pattern: &str) -> Result<String, String> {
    let stripped = pattern.strip_prefix("github.com/").unwrap_or(pattern);
    if !valid_repository_pattern(stripped) {
        return Err("GitHub repository target or pattern is malformed".to_owned());
    }
    Ok(stripped.to_ascii_lowercase())
}

pub fn repository_matches_pattern(repository: &str, pattern: &str) -> bool {
    let Ok(repo) = crate::gh_adapter::normalize_repository(repository) else {
        return false;
    };
    let Ok(pattern) = normalize_repository_pattern(pattern) else {
        return false;
    };
    if pattern == "*" || repo == pattern {
        return true;
    }
    if let Some(owner_prefix) = pattern.strip_suffix("/*") {
        return repo
            .split_once('/')
            .is_some_and(|(owner, _)| owner == owner_prefix);
    }
    false
}

pub fn repository_is_permitted(repository: &str, allowed: &[String], denied: &[String]) -> bool {
    if denied
        .iter()
        .any(|pattern| repository_matches_pattern(repository, pattern))
    {
        return false;
    }
    allowed
        .iter()
        .any(|pattern| repository_matches_pattern(repository, pattern))
}

pub fn valid_destination_pattern(pattern: &str) -> bool {
    if pattern.is_empty()
        || pattern.trim() != pattern
        || pattern
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return false;
    }
    if pattern == "*" {
        return true;
    }
    if pattern.contains(['?', '#', '%', '\\']) || pattern.contains("..") {
        return false;
    }
    let star_count = pattern.bytes().filter(|byte| *byte == b'*').count();
    if star_count == 0 {
        return true;
    }
    if star_count > 1 {
        return false;
    }
    pattern.ends_with("/*") || pattern.ends_with(":*")
}

pub fn destination_matches_pattern(actual: &str, pattern: &str) -> bool {
    if actual.is_empty() || !valid_destination_pattern(pattern) {
        return false;
    }
    if actual == pattern {
        return true;
    }
    if actual.contains(['?', '#', '%'])
        || actual
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return false;
    }
    if pattern == "*" {
        return true;
    }

    if let (Some(actual_ssh), Some(pattern_ssh)) = (parse_ssh_like(actual), parse_ssh_like(pattern))
    {
        if actual_ssh.user == pattern_ssh.user
            && actual_ssh.host.eq_ignore_ascii_case(&pattern_ssh.host)
            && actual_ssh.port == pattern_ssh.port
        {
            return path_matches_pattern(&actual_ssh.path, &pattern_ssh.path);
        }
        return false;
    }

    if let (Some(actual_http), Some(pattern_http)) = (
        parse_http_like(actual, false),
        parse_http_like(pattern, true),
    ) {
        return actual_http
            .authority
            .eq_ignore_ascii_case(pattern_http.authority)
            && path_matches_pattern(actual_http.path, pattern_http.path);
    }

    if let (Some(actual_file), Some(pattern_file)) = (
        actual.strip_prefix("file://"),
        pattern.strip_prefix("file://"),
    ) {
        return abs_path_matches_pattern(actual_file, pattern_file);
    }

    if actual.starts_with('/') && pattern.starts_with('/') {
        return abs_path_matches_pattern(actual, pattern);
    }

    false
}

fn abs_path_matches_pattern(actual: &str, pattern: &str) -> bool {
    match (actual.strip_prefix('/'), pattern.strip_prefix('/')) {
        (Some(a), Some(p)) => path_matches_pattern(a, p),
        _ => false,
    }
}

pub fn destination_is_permitted(actual: &str, allowed: &[String], denied: &[String]) -> bool {
    if denied
        .iter()
        .any(|pattern| destination_matches_pattern(actual, pattern))
    {
        return false;
    }
    allowed
        .iter()
        .any(|pattern| destination_matches_pattern(actual, pattern))
}

pub fn is_supported_https_destination(destination: &str) -> bool {
    let Some(rest) = destination.strip_prefix("https://") else {
        return false;
    };
    if rest
        .chars()
        .any(|character| matches!(character, '@' | '?' | '#' | '%' | '\\'))
    {
        return false;
    }
    let Some((authority, path)) = rest.split_once('/') else {
        return false;
    };
    if authority.is_empty()
        || path.is_empty()
        || authority.contains('\\')
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
        || path
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return false;
    }
    let mut host_port = authority.split(':');
    let Some(host) = host_port.next() else {
        return false;
    };
    let valid_host = !host.is_empty()
        && host.len() <= 253
        && host.is_ascii()
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'));
    let valid_port = host_port
        .next()
        .is_none_or(|port| port.parse::<u16>().is_ok_and(|port| port != 0));
    valid_host && valid_port && host_port.next().is_none()
}

pub fn parse_ssh_remote(value: &str) -> Option<(String, String)> {
    let (authority, path) = if let Some(rest) = value.strip_prefix("ssh://") {
        let (authority, path) = rest.split_once('/')?;
        if authority.contains(['?', '#']) || path.is_empty() {
            return None;
        }
        (authority.to_owned(), path.to_owned())
    } else {
        let (authority, path) = value.split_once(':')?;
        if authority.matches('@').count() != 1 || path.is_empty() {
            return None;
        }
        (authority.to_owned(), path.to_owned())
    };
    if path.starts_with('-')
        || path.split('/').any(|part| matches!(part, "" | "." | ".."))
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        return None;
    }
    Some((authority, path))
}

struct ParsedSsh {
    user: String,
    host: String,
    port: u16,
    path: String,
}

fn parse_ssh_like(value: &str) -> Option<ParsedSsh> {
    let (authority, path, is_url) = if let Some(rest) = value.strip_prefix("ssh://") {
        let (authority, path) = rest.split_once('/')?;
        (authority, path, true)
    } else {
        let (authority, path) = value.split_once(':')?;
        if authority.contains('/') || authority.matches('@').count() != 1 {
            return None;
        }
        (authority, path, false)
    };
    if path.is_empty() || path.starts_with('-') {
        return None;
    }
    let (user, host_port) = authority.split_once('@')?;
    if user.is_empty() {
        return None;
    }
    let (host, port) = if is_url {
        match host_port.rsplit_once(':') {
            Some((host, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => {
                let port = port.parse::<u16>().ok().filter(|port| *port != 0)?;
                (host, port)
            }
            _ => (host_port, 22),
        }
    } else {
        (host_port, 22)
    };
    if host.is_empty() {
        return None;
    }
    let normalized_path = path.strip_prefix('/').unwrap_or(path);
    if !valid_path_or_pattern(normalized_path) {
        return None;
    }
    Some(ParsedSsh {
        user: user.to_owned(),
        host: host.to_owned(),
        port,
        path: normalized_path.to_owned(),
    })
}

struct ParsedHttp<'a> {
    authority: &'a str,
    path: &'a str,
}

fn parse_http_like(value: &str, allow_wildcard: bool) -> Option<ParsedHttp<'_>> {
    let rest = value.strip_prefix("https://")?;
    if rest
        .chars()
        .any(|character| matches!(character, '@' | '?' | '#' | '%' | '\\'))
    {
        return None;
    }
    let (authority, path) = rest.split_once('/')?;
    if authority.is_empty() || path.is_empty() {
        return None;
    }
    if allow_wildcard {
        if !valid_path_or_pattern(path) {
            return None;
        }
    } else if !is_supported_https_destination(value) {
        return None;
    }
    Some(ParsedHttp { authority, path })
}

fn valid_path_or_pattern(path: &str) -> bool {
    if path == "*" {
        return true;
    }
    let body = path.strip_suffix("/*").unwrap_or(path);
    !body.is_empty()
        && !body.contains('*')
        && body
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
        && body
            .split('/')
            .all(|segment| !segment.is_empty() && !matches!(segment, "." | ".."))
}

fn path_matches_pattern(actual: &str, pattern: &str) -> bool {
    if actual.contains("..")
        || actual.contains('\\')
        || actual
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return false;
    }
    if actual == pattern || pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return actual
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1);
    }
    false
}

fn valid_repo_component(value: &str, owner: bool) -> bool {
    !value.is_empty()
        && value.len() <= if owner { 39 } else { 100 }
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && value != "."
        && value != ".."
        && (!owner || !value.contains('_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_repository_wildcards_and_enforces_deny_precedence() {
        let allowed = vec!["yanfsb/*".to_owned(), "sollus-labs/*".to_owned()];
        let denied = vec!["yanfsb/private-archive".to_owned()];
        assert!(repository_is_permitted("yanfsb/persona", &allowed, &denied));
        assert!(repository_is_permitted(
            "Sollus-Labs/Neo-Everest",
            &allowed,
            &denied
        ));
        assert!(!repository_is_permitted(
            "yanfsb/private-archive",
            &allowed,
            &denied
        ));
        assert!(!repository_is_permitted("opsec/secret", &allowed, &denied));
    }

    #[test]
    fn matches_ssh_and_https_destination_wildcards_safely() {
        let allowed = vec![
            "git@github.com:yanfsb/*".to_owned(),
            "https://github.com/yanfsb/*".to_owned(),
        ];
        let denied = vec!["https://github.com/yanfsb/secret.git".to_owned()];

        assert!(destination_is_permitted(
            "git@github.com:yanfsb/persona.git",
            &allowed,
            &denied
        ));
        assert!(destination_is_permitted(
            "ssh://git@github.com/yanfsb/persona.git",
            &allowed,
            &denied
        ));
        assert!(destination_is_permitted(
            "https://github.com/yanfsb/persona.git",
            &allowed,
            &denied
        ));
        assert!(!destination_is_permitted(
            "https://github.com/yanfsb/secret.git",
            &allowed,
            &denied
        ));
        assert!(!destination_is_permitted(
            "https://github.com/yanfsb/../other/repo.git",
            &allowed,
            &denied
        ));
        assert!(!destination_is_permitted(
            "git@github.com:yanfsb-other/repo.git",
            &allowed,
            &denied
        ));
        assert!(!destination_is_permitted(
            "https://github.com/opsec/repo.git",
            &allowed,
            &denied
        ));
        assert!(destination_is_permitted(
            "file:///tmp/work/repo.git",
            &["file:///tmp/work/*".to_owned()],
            &[]
        ));
        assert!(!destination_is_permitted(
            "file:///tmp/other/repo.git",
            &["file:///tmp/work/*".to_owned()],
            &[]
        ));
    }
}
