use crate::config::GitHubBinding;
use crate::credential::{CredentialError, GithubSelector, Secret};
use std::io::{self, Write};

const MAX_CREDENTIAL_INPUT_BYTES: usize = 8 * 1024;

/// Command-line Git configuration required for a managed HTTPS operation. The
/// adapter must additionally clear Git/askpass/proxy environment variables,
/// isolate HOME (to suppress netrc), and reject extraHeader/custom TLS keys.
pub const fn required_git_http_overrides() -> [(&'static str, &'static str); 9] {
    [
        ("credential.helper", ""),
        ("credential.useHttpPath", "true"),
        ("credential.interactive", "false"),
        ("core.askPass", ""),
        ("http.followRedirects", "false"),
        ("http.sslVerify", "true"),
        ("http.cookieFile", "/dev/null"),
        ("http.saveCookies", "false"),
        ("http.proxy", ""),
    ]
}

/// Git configuration values are never returned; only local/worktree key names
/// are inspected. These settings can inject credentials, helpers, proxy routes,
/// custom trust roots, cookies, or redirects into an HTTPS transport.
pub fn contains_unsafe_transport_config_key_names(names: &[u8]) -> bool {
    contains_unsafe_transport_config_key_names_with_options(names, true, true)
}

/// Inspect local/worktree config key names for transport-hijacking settings,
/// optionally gating filter/textconv and merge-driver keys behind policy toggles.
pub fn contains_unsafe_transport_config_key_names_with_options(
    names: &[u8],
    strict_filters: bool,
    strict_merge: bool,
) -> bool {
    let Ok(names) = std::str::from_utf8(names) else {
        return true;
    };
    names.lines().any(|line| {
        let Some((scope, name)) = line.split_once('\t') else {
            return true;
        };
        if !matches!(scope, "local" | "worktree") {
            return false;
        }
        let name = name.to_ascii_lowercase();
        name == "core.askpass"
            || name == "credential.helper"
            || (name.starts_with("credential.") && name.ends_with(".helper"))
            || (name.starts_with("remote.")
                && [".proxy", ".uploadpack", ".receivepack", ".vcs"]
                    .iter()
                    .any(|suffix| name.ends_with(suffix)))
            || name == "core.sshcommand"
            || name == "core.fsmonitor"
            || (strict_filters
                && ((name.starts_with("filter.")
                    && [".clean", ".smudge", ".process"]
                        .iter()
                        .any(|suffix| name.ends_with(suffix)))
                    || (name.starts_with("diff.") && name.ends_with(".textconv"))))
            || (strict_merge && name.starts_with("merge.") && name.ends_with(".driver"))
            || (name.starts_with("http.")
                && [
                    ".extraheader",
                    ".cookiefile",
                    ".savecookies",
                    ".proxy",
                    ".proxyauthmethod",
                    ".curloptresolve",
                    ".followredirects",
                    ".sslverify",
                    ".sslbackend",
                    ".sslversion",
                    ".sslcainfo",
                    ".sslcapath",
                    ".sslkey",
                    ".sslcert",
                    ".sslcertpasswordprotected",
                    ".proxysslverify",
                    ".proxysslcainfo",
                    ".proxysslcapath",
                    ".proxysslkey",
                    ".proxysslcert",
                    ".sslbackend",
                ]
                .iter()
                .any(|suffix| name.ends_with(suffix)))
    })
}

#[derive(Debug)]
pub enum HttpsCredentialError {
    InputTooLarge,
    MalformedRequest,
    UnsupportedOperation,
    UnsupportedDestination,
    DestinationNotAllowed,
    CredentialUnavailable,
    Credential(CredentialError),
    Output(io::ErrorKind),
}

#[derive(Debug, PartialEq, Eq)]
pub struct CredentialRequest {
    host: String,
    path: String,
}

/// Parse Git's credential-helper protocol while discarding unused metadata.
/// Only the unique HTTPS destination fields participate in authorization;
/// caller-supplied credentials and URL-based destination overrides are refused.
pub fn parse_credential_request(input: &[u8]) -> Result<CredentialRequest, HttpsCredentialError> {
    if input.len() > MAX_CREDENTIAL_INPUT_BYTES {
        return Err(HttpsCredentialError::InputTooLarge);
    }
    let mut fields = std::collections::HashMap::new();
    let mut terminated = false;
    let mut lines = input.split_inclusive(|byte| *byte == b'\n');
    for raw_line in lines.by_ref() {
        let has_newline = raw_line.ends_with(b"\n");
        let mut line = raw_line.strip_suffix(b"\n").unwrap_or(raw_line);
        if has_newline {
            line = line.strip_suffix(b"\r").unwrap_or(line);
        }
        if line.is_empty() {
            terminated = true;
            break;
        }
        if line.contains(&b'\r') || line.contains(&0) {
            return Err(HttpsCredentialError::MalformedRequest);
        }
        let separator = line
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or(HttpsCredentialError::MalformedRequest)?;
        let (name, value_with_separator) = line.split_at(separator);
        let value = &value_with_separator[1..];
        if name.is_empty()
            || !name.iter().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'[' | b']')
            })
        {
            return Err(HttpsCredentialError::MalformedRequest);
        }
        let name = match name {
            b"password" | b"credential" | b"oauth_refresh_token" | b"url" => {
                return Err(HttpsCredentialError::MalformedRequest);
            }
            b"protocol" => "protocol",
            b"host" => "host",
            b"path" => "path",
            b"username" => "username",
            _ => continue,
        };
        let value = std::str::from_utf8(value)
            .map_err(|_| HttpsCredentialError::MalformedRequest)?
            .to_owned();
        if fields.insert(name, value).is_some() {
            return Err(HttpsCredentialError::MalformedRequest);
        }
    }
    if terminated && lines.any(|line| !line.is_empty()) {
        return Err(HttpsCredentialError::MalformedRequest);
    }
    if fields.get("protocol").map(String::as_str) != Some("https") {
        return Err(HttpsCredentialError::MalformedRequest);
    }
    let host = parse_credential_host(
        fields
            .get("host")
            .map(String::as_str)
            .ok_or(HttpsCredentialError::MalformedRequest)?,
    )?;
    let path = validate_repository_path(
        fields
            .get("path")
            .map(String::as_str)
            .ok_or(HttpsCredentialError::MalformedRequest)?,
    )?;
    Ok(CredentialRequest { host, path })
}

/// Resolve a credential only after the request host/path matches an explicitly
/// configured fetch or push HTTPS destination, then verify the selected native gh token
/// against the profile's local HMAC binding. No provider is contacted.
pub fn select_https_credential(
    action: &str,
    input: &[u8],
    binding: &GitHubBinding,
    allowed_destinations: &[String],
    selector: &GithubSelector,
) -> Result<Option<Secret>, HttpsCredentialError> {
    select_https_credential_with_denies(action, input, binding, allowed_destinations, &[], selector)
}

pub fn select_https_credential_with_denies(
    action: &str,
    input: &[u8],
    binding: &GitHubBinding,
    allowed_destinations: &[String],
    denied_destinations: &[String],
    selector: &GithubSelector,
) -> Result<Option<Secret>, HttpsCredentialError> {
    match action {
        "store" | "erase" => return Ok(None),
        "get" => {}
        _ => return Err(HttpsCredentialError::UnsupportedOperation),
    }
    if binding.host != "github.com" {
        return Err(HttpsCredentialError::UnsupportedDestination);
    }
    let request = parse_credential_request(input)?;
    if request.host != binding.host {
        return Err(HttpsCredentialError::DestinationNotAllowed);
    }
    let actual_url = format!("https://{}/{}", request.host, request.path);
    if denied_destinations
        .iter()
        .any(|pattern| crate::destination::destination_matches_pattern(&actual_url, pattern))
    {
        return Err(HttpsCredentialError::DestinationNotAllowed);
    }
    if let Some(repo) = crate::gh_adapter::repository_from_destination(&actual_url) {
        if binding
            .deny_repositories
            .iter()
            .any(|pattern| crate::destination::repository_matches_pattern(&repo, pattern))
        {
            return Err(HttpsCredentialError::DestinationNotAllowed);
        }
    }
    let allowed = allowed_destinations.iter().any(|destination| {
        parse_https_destination(destination)
            .is_ok_and(|(host, path)| host == request.host && path == request.path)
            || crate::destination::destination_matches_pattern(&actual_url, destination)
    });
    if !allowed {
        return Err(HttpsCredentialError::DestinationNotAllowed);
    }
    selector
        .token_for_binding(binding)
        .map_err(HttpsCredentialError::Credential)?
        .map(Some)
        .ok_or(HttpsCredentialError::CredentialUnavailable)
}

/// Write the credential only to Git's protocol stream. `store` and `erase` are
/// intentionally no-ops: Persona never becomes a credential store.
pub fn handle_credential_helper<W: Write>(
    action: &str,
    input: &[u8],
    binding: &GitHubBinding,
    allowed_destinations: &[String],
    selector: &GithubSelector,
    output: &mut W,
) -> Result<(), HttpsCredentialError> {
    handle_credential_helper_with_denies(
        action,
        input,
        binding,
        allowed_destinations,
        &[],
        selector,
        output,
    )
}

pub fn handle_credential_helper_with_denies<W: Write>(
    action: &str,
    input: &[u8],
    binding: &GitHubBinding,
    allowed_destinations: &[String],
    denied_destinations: &[String],
    selector: &GithubSelector,
    output: &mut W,
) -> Result<(), HttpsCredentialError> {
    let Some(token) = select_https_credential_with_denies(
        action,
        input,
        binding,
        allowed_destinations,
        denied_destinations,
        selector,
    )?
    else {
        return Ok(());
    };
    output
        .write_all(b"username=x-access-token\npassword=")
        .and_then(|_| output.write_all(token.expose()))
        .and_then(|_| output.write_all(b"\n\n"))
        .map_err(|error| HttpsCredentialError::Output(error.kind()))
}

fn parse_credential_host(value: &str) -> Result<String, HttpsCredentialError> {
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => (host, port),
        _ => (value, "443"),
    };
    if port != "443" || !valid_dns_host(host) {
        return Err(HttpsCredentialError::UnsupportedDestination);
    }
    Ok(host.to_ascii_lowercase())
}

fn parse_https_destination(value: &str) -> Result<(String, String), HttpsCredentialError> {
    let remainder = value
        .strip_prefix("https://")
        .ok_or(HttpsCredentialError::UnsupportedDestination)?;
    let (authority, path) = remainder
        .split_once('/')
        .ok_or(HttpsCredentialError::UnsupportedDestination)?;
    if authority.contains('@') || authority.contains('?') || authority.contains('#') {
        return Err(HttpsCredentialError::UnsupportedDestination);
    }
    let host = parse_credential_host(authority)?;
    let path = validate_repository_path(path)?;
    Ok((host, path))
}

fn validate_repository_path(value: &str) -> Result<String, HttpsCredentialError> {
    let path = value.strip_prefix('/').unwrap_or(value);
    let mut components = path.split('/');
    let owner = components.next().unwrap_or_default();
    let repository = components.next().unwrap_or_default();
    if components.next().is_some()
        || !valid_repo_component(owner)
        || !valid_repo_component(repository)
        || owner == "."
        || owner == ".."
        || repository == "."
        || repository == ".."
    {
        return Err(HttpsCredentialError::UnsupportedDestination);
    }
    Ok(format!("{owner}/{repository}"))
}

fn valid_repo_component(value: &str) -> bool {
    !value.is_empty()
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_dns_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.is_ascii()
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

#[cfg(test)]
mod tests {
    use super::{
        HttpsCredentialError, contains_unsafe_transport_config_key_names, parse_credential_request,
        required_git_http_overrides, validate_repository_path,
    };

    #[test]
    fn required_overrides_disable_redirects_prompts_and_other_credential_helpers() {
        let overrides = required_git_http_overrides();
        assert!(overrides.contains(&("credential.helper", "")));
        assert!(overrides.contains(&("credential.useHttpPath", "true")));
        assert!(overrides.contains(&("core.askPass", "")));
        assert!(overrides.contains(&("http.followRedirects", "false")));
        assert!(overrides.contains(&("http.sslVerify", "true")));
        assert!(overrides.contains(&("http.cookieFile", "/dev/null")));
        assert!(overrides.contains(&("http.proxy", "")));
    }

    #[test]
    fn detects_secret_bearing_or_redirecting_git_http_settings_by_name_only() {
        for key in [
            "http.extraheader",
            "http.https://github.com/.extraheader",
            "http.cookiefile",
            "http.proxy",
            "http.followredirects",
            "http.curloptresolve",
            "http.sslbackend",
            "http.sslverify",
            "credential.helper",
            "credential.https://github.com.helper",
            "core.askpass",
            "core.sshcommand",
            "remote.origin.proxy",
            "remote.origin.uploadpack",
            "remote.origin.receivepack",
            "remote.origin.vcs",
            "core.fsmonitor",
            "filter.lfs.smudge",
            "filter.custom.process",
            "diff.custom.textconv",
            "merge.custom.driver",
        ] {
            let scoped_key = format!("local\t{key}");
            assert!(
                contains_unsafe_transport_config_key_names(scoped_key.as_bytes()),
                "missed {key}"
            );
        }
        assert!(!contains_unsafe_transport_config_key_names(
            b"local\tuser.name\nworktree\tcredential.usehttppath\nlocal\thttp.version\nglobal\thttp.extraheader"
        ));
    }

    #[test]
    fn parses_only_bounded_https_repository_credentials() {
        let request = parse_credential_request(
            b"protocol=https\nhost=github.com:443\npath=org/repo.git\nusername=x-access-token\n\n",
        )
        .unwrap();
        assert_eq!(request.host, "github.com");
        assert_eq!(request.path, "org/repo.git");
    }

    #[test]
    fn accepts_standard_git_metadata_and_repeated_attributes() {
        let request = parse_credential_request(
            b"capability[]=authtype\ncapability[]=state\nprotocol=https\nhost=github.com\npath=org/repo.git\nusername=another-hint\nwwwauth[]=Basic realm=fixture\nwwwauth[]=Bearer realm=fixture\nstate[]=helper=value\nunknown[]=\nunknown[]=opaque=value\nunknown=opaque=value\n\n",
        )
        .unwrap();
        assert_eq!(request.host, "github.com");
        assert_eq!(request.path, "org/repo.git");
    }

    #[test]
    fn accepts_eof_terminated_and_crlf_credential_requests() {
        for input in [
            &b"protocol=https\nhost=github.com\npath=org/repo.git"[..],
            &b"protocol=https\nhost=github.com\npath=org/repo.git\n"[..],
            &b"protocol=https\r\nhost=github.com\r\npath=org/repo.git\r\n\r\n"[..],
        ] {
            let request = parse_credential_request(input).unwrap();
            assert_eq!(request.host, "github.com");
            assert_eq!(request.path, "org/repo.git");
        }
    }

    #[test]
    fn refuses_credential_protocol_secrets_duplicates_and_userinfo() {
        for input in [
            &b"protocol=https\nhost=github.com\npath=org/repo\npassword=stolen\n\n"[..],
            &b"protocol=https\nhost=github.com\npath=org/repo\ncredential=Bearer stolen\n\n"[..],
            &b"protocol=https\nhost=github.com\npath=org/repo\noauth_refresh_token=stolen\n\n"[..],
            &b"protocol=https\nhost=github.com\nhost=evil.example\npath=org/repo\n\n"[..],
            &b"protocol=https\nhost=github.com\npath=org/repo\nurl=https://u:p@github.com/org/repo\n\n"[..],
            &b"protocol=https\nhost=github.com\npath=org/repo\n\nprotocol=https\nhost=evil.example\npath=org/other\n\n"[..],
            &b"protocol=https\nhost=github.com\nhost=evil.example\npath=org/repo\n\n"[..],
            &b"protocol=http\nhost=github.com\npath=org/repo\n\n"[..],
            &b"protocol=https\nhost=github.com:444\npath=org/repo\n\n"[..],
        ] {
            assert!(matches!(
                parse_credential_request(input),
                Err(HttpsCredentialError::MalformedRequest)
                    | Err(HttpsCredentialError::UnsupportedDestination)
            ));
        }
        assert!(matches!(
            parse_credential_request(&vec![b'a'; 8 * 1024 + 1]),
            Err(HttpsCredentialError::InputTooLarge)
        ));
    }

    #[test]
    fn rejects_ambiguous_or_escaped_repository_paths() {
        for path in [
            "",
            "/",
            "org",
            "org/repo/other",
            "org/../repo",
            "org/r%65po",
            "org/repo?x",
        ] {
            assert!(validate_repository_path(path).is_err(), "accepted {path:?}");
        }
        assert_eq!(
            validate_repository_path("/org/repo.git").unwrap(),
            "org/repo.git"
        );
    }
}
