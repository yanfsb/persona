use crate::config::GitHubBinding;
use crate::runner::{RunError, RunRequest, SubprocessRunner};
use crate::storage::{PersonaPaths, StorageError};
use hmac::{Hmac, Mac};
use serde_yaml::Value;
use sha2::Sha256;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub enum CredentialError {
    OnlineConfirmationRequired,
    InvalidHost,
    MissingHome,
    RelativeGhConfig(PathBuf),
    EnvironmentTokenPresent,
    UnknownNativeStore,
    PlaintextTokenStore,
    MissingGh,
    Command(RunError),
    AuthenticationUnavailable,
    InvalidAccountId,
    InvalidMergeResponse,
    KeyUnavailable,
    UnsafeKeyFile,
    Storage(StorageError),
    Io { path: PathBuf, source: io::Error },
}

pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub fn destination_host(destination: &str) -> Option<String> {
    let value = destination.trim();
    let authority = if let Some((_, remainder)) = value.split_once("://") {
        remainder.split(['/', '?', '#']).next()?
    } else if let Some((_, path)) = value.split_once('@') {
        path.split(':').next()?
    } else {
        return None;
    };
    let authority = authority.rsplit('@').next()?;
    let host = authority
        .split(':')
        .next()?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty()
        || !host.is_ascii()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        return None;
    }
    Some(host)
}

pub fn is_known_github_host(host: &str) -> bool {
    matches!(host, "github.com" | "ssh.github.com" | "ghe.com") || host.ends_with(".ghe.com")
}

pub struct GithubSelector {
    executable: PathBuf,
    host: String,
    gh_config_dir: PathBuf,
    home: PathBuf,
    xdg_config_home: Option<PathBuf>,
    persona_paths: PersonaPaths,
    environment_tokens_present: bool,
    runner: SubprocessRunner,
}

impl GithubSelector {
    pub fn discover(
        executable: PathBuf,
        host: String,
        persona_paths: PersonaPaths,
    ) -> Result<Self, CredentialError> {
        validate_host(&host)?;
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or(CredentialError::MissingHome)?;
        let xdg_config_home = env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
        let gh_config_dir = match env::var_os("GH_CONFIG_DIR") {
            Some(path) => PathBuf::from(path),
            None => xdg_config_home
                .as_ref()
                .map(|path| path.join("gh"))
                .unwrap_or_else(|| home.join(".config/gh")),
        };
        if !gh_config_dir.is_absolute() {
            return Err(CredentialError::RelativeGhConfig(gh_config_dir));
        }
        Ok(Self::with_context(
            executable,
            host,
            gh_config_dir,
            home,
            xdg_config_home,
            persona_paths,
            [
                "GH_TOKEN",
                "GITHUB_TOKEN",
                "GH_ENTERPRISE_TOKEN",
                "GITHUB_ENTERPRISE_TOKEN",
            ]
            .iter()
            .any(|variable| env::var_os(variable).is_some()),
        ))
    }

    fn with_context(
        executable: PathBuf,
        host: String,
        gh_config_dir: PathBuf,
        home: PathBuf,
        xdg_config_home: Option<PathBuf>,
        persona_paths: PersonaPaths,
        environment_tokens_present: bool,
    ) -> Self {
        Self {
            executable,
            host,
            gh_config_dir,
            home,
            xdg_config_home,
            persona_paths,
            environment_tokens_present,
            runner: SubprocessRunner::new(crate::runner::RunLimits {
                timeout: Duration::from_secs(15),
                max_stdout_bytes: 64 * 1024,
                max_stderr_bytes: 16 * 1024,
                poll_interval: Duration::from_millis(5),
            }),
        }
    }

    /// Enrollment calls the GitHub API only when the caller explicitly opts in.
    /// The selected native account is explicit and is never globally switched.
    pub fn enroll(
        &self,
        online_opt_in: bool,
        account_selector: &str,
    ) -> Result<GitHubBinding, CredentialError> {
        if !online_opt_in {
            return Err(CredentialError::OnlineConfirmationRequired);
        }
        validate_account_selector(account_selector)?;
        self.validate_native_store()?;
        let token = self.current_token(Some(account_selector))?;
        let api_environment = self.environment_with_token(&token.0);
        let api = self.run(&["api", "user", "--jq", ".id"], &api_environment)?;
        if !api.status.success() {
            return Err(CredentialError::AuthenticationUnavailable);
        }
        let account_id = String::from_utf8(api.stdout)
            .map_err(|_| CredentialError::InvalidAccountId)?
            .trim()
            .to_owned();
        if account_id.is_empty()
            || !account_id.bytes().all(|byte| byte.is_ascii_digit())
            || account_id.parse::<u64>().is_err()
        {
            return Err(CredentialError::InvalidAccountId);
        }
        let key = load_or_create_fingerprint_key(&self.persona_paths)?;
        let fingerprint = token_fingerprint(&key.0, &token.0);
        Ok(GitHubBinding {
            host: self.host.clone(),
            account_id,
            account_selector: Some(account_selector.to_owned()),
            token_fingerprint: fingerprint,
            repositories: Vec::new(),
        })
    }

    /// Compare only the local native selector. This performs no API/network call.
    pub fn matches_selected_account(
        &self,
        binding: &GitHubBinding,
    ) -> Result<bool, CredentialError> {
        self.token_for_binding(binding).map(|token| token.is_some())
    }

    /// Return the selected native token only when its local fingerprint matches
    /// the explicitly enrolled binding. The caller must keep it transient and
    /// never persist or print it except through the native Git credential pipe.
    pub fn token_for_binding(
        &self,
        binding: &GitHubBinding,
    ) -> Result<Option<Secret>, CredentialError> {
        if binding.host != self.host {
            return Ok(None);
        }
        let account_selector = binding
            .account_selector
            .as_deref()
            .ok_or(CredentialError::UnknownNativeStore)?;
        validate_account_selector(account_selector)?;
        self.validate_native_store()?;
        let token = self.current_token(Some(account_selector))?;
        let key = load_fingerprint_key(&self.persona_paths)?;
        if verify_fingerprint(&key.0, &token.0, &binding.token_fingerprint)? {
            Ok(Some(token))
        } else {
            Ok(None)
        }
    }

    /// Compare a transient token passed from a managed parent gh process without
    /// consulting or modifying the native selector.
    pub fn token_matches_binding(
        &self,
        binding: &GitHubBinding,
        token: &[u8],
    ) -> Result<bool, CredentialError> {
        if binding.host != self.host {
            return Ok(false);
        }
        let key = load_fingerprint_key(&self.persona_paths)?;
        verify_fingerprint(&key.0, token, &binding.token_fingerprint)
    }

    pub fn tag_ref_oid(
        &self,
        token: &Secret,
        repository: &str,
        tag: &str,
    ) -> Result<String, CredentialError> {
        let endpoint = format!("repos/{repository}/git/ref/tags/{tag}");
        let output = self.run(
            &[
                "api",
                &endpoint,
                "--jq",
                "[.object.sha, .object.type] | @json",
            ],
            &self.environment_with_token(&token.0),
        )?;
        if !output.status.success() {
            return Err(CredentialError::AuthenticationUnavailable);
        }
        let response: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| CredentialError::InvalidMergeResponse)?;
        let values = response
            .as_array()
            .ok_or(CredentialError::InvalidMergeResponse)?;
        let oid = values
            .first()
            .and_then(serde_json::Value::as_str)
            .filter(|value| {
                matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            .ok_or(CredentialError::InvalidMergeResponse)?;
        if values.get(1).and_then(serde_json::Value::as_str) != Some("tag") {
            return Err(CredentialError::InvalidMergeResponse);
        }
        Ok(oid.to_ascii_lowercase())
    }

    pub fn submit_pull_request_review(
        &self,
        token: &Secret,
        repository: &str,
        pull_number: u64,
        event: crate::gh_adapter::GhReviewEvent,
        body: Option<&str>,
    ) -> Result<u64, CredentialError> {
        if pull_number == 0 || body.is_some_and(|value| value.len() > 65_536) {
            return Err(CredentialError::InvalidMergeResponse);
        }
        let endpoint = format!("repos/{repository}/pulls/{pull_number}/reviews");
        let event = match event {
            crate::gh_adapter::GhReviewEvent::Approve => "APPROVE",
            crate::gh_adapter::GhReviewEvent::RequestChanges => "REQUEST_CHANGES",
            crate::gh_adapter::GhReviewEvent::Comment => "COMMENT",
        };
        let mut arguments = vec![
            "api".to_owned(),
            endpoint,
            "--method".to_owned(),
            "POST".to_owned(),
            "--raw-field".to_owned(),
            format!("event={event}"),
        ];
        if let Some(body) = body {
            arguments.extend(["--raw-field".to_owned(), format!("body={body}")]);
        }
        let args = arguments.iter().map(String::as_str).collect::<Vec<_>>();
        let output = self.run(&args, &self.environment_with_token(&token.0))?;
        if !output.status.success() {
            return Err(CredentialError::AuthenticationUnavailable);
        }
        let response: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| CredentialError::InvalidMergeResponse)?;
        response
            .get("id")
            .and_then(serde_json::Value::as_u64)
            .filter(|id| *id > 0)
            .ok_or(CredentialError::InvalidMergeResponse)
    }

    pub fn create_release(
        &self,
        token: &Secret,
        request: &crate::gh_adapter::GhReleaseRequest,
        audited_commit_oid: &str,
    ) -> Result<u64, CredentialError> {
        if !matches!(audited_commit_oid.len(), 40 | 64)
            || !audited_commit_oid
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || request.tag.is_empty()
            || request.tag.len() > 255
            || request
                .title
                .as_ref()
                .is_some_and(|value| value.len() > 255)
            || request
                .notes
                .as_ref()
                .is_some_and(|value| value.len() > 65_536)
        {
            return Err(CredentialError::InvalidMergeResponse);
        }
        let endpoint = format!("repos/{}/releases", request.repository);
        let mut arguments = vec![
            "api".to_owned(),
            endpoint,
            "--method".to_owned(),
            "POST".to_owned(),
            "--raw-field".to_owned(),
            format!("tag_name={}", request.tag),
        ];
        arguments.extend([
            "--field".to_owned(),
            format!("target_commitish={audited_commit_oid}"),
        ]);
        if let Some(title) = request.title.as_deref() {
            arguments.extend(["--raw-field".to_owned(), format!("name={title}")]);
        }
        if let Some(notes) = request.notes.as_deref() {
            arguments.extend(["--raw-field".to_owned(), format!("body={notes}")]);
        }
        if request.draft {
            arguments.extend(["--field".to_owned(), "draft=true".to_owned()]);
        }
        if request.prerelease {
            arguments.extend(["--field".to_owned(), "prerelease=true".to_owned()]);
        }
        if request.generate_notes {
            arguments.extend([
                "--field".to_owned(),
                "generate_release_notes=true".to_owned(),
            ]);
        }
        let args = arguments.iter().map(String::as_str).collect::<Vec<_>>();
        let output = self.run(&args, &self.environment_with_token(&token.0))?;
        if !output.status.success() {
            return Err(CredentialError::AuthenticationUnavailable);
        }
        let response: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| CredentialError::InvalidMergeResponse)?;
        if response.get("tag_name").and_then(serde_json::Value::as_str)
            != Some(request.tag.as_str())
        {
            return Err(CredentialError::InvalidMergeResponse);
        }
        response
            .get("id")
            .and_then(serde_json::Value::as_u64)
            .filter(|id| *id > 0)
            .ok_or(CredentialError::InvalidMergeResponse)
    }

    pub fn commit_is_verified(
        &self,
        token: &Secret,
        repository: &str,
        commit_oid: &str,
    ) -> Result<bool, CredentialError> {
        if !matches!(commit_oid.len(), 40 | 64)
            || !commit_oid.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(CredentialError::InvalidMergeResponse);
        }
        let endpoint = format!("repos/{repository}/commits/{commit_oid}");
        let output = self.run(
            &["api", &endpoint, "--jq", ".commit.verification.verified"],
            &self.environment_with_token(&token.0),
        )?;
        if !output.status.success() {
            return Err(CredentialError::AuthenticationUnavailable);
        }
        match String::from_utf8(output.stdout)
            .map_err(|_| CredentialError::InvalidMergeResponse)?
            .trim()
        {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(CredentialError::InvalidMergeResponse),
        }
    }

    pub fn pull_request_checkout_context(
        &self,
        token: &Secret,
        repository: &str,
        pull_number: u64,
    ) -> Result<(String, String), CredentialError> {
        let endpoint = format!("repos/{repository}/pulls/{pull_number}");
        let output = self.run(
            &["api", &endpoint, "--jq", "[.head.sha, .head.ref] | @json"],
            &self.environment_with_token(&token.0),
        )?;
        if !output.status.success() {
            return Err(CredentialError::AuthenticationUnavailable);
        }
        let response: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| CredentialError::InvalidMergeResponse)?;
        let values = response
            .as_array()
            .ok_or(CredentialError::InvalidMergeResponse)?;
        let sha = values
            .first()
            .and_then(serde_json::Value::as_str)
            .filter(|value| {
                matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            .ok_or(CredentialError::InvalidMergeResponse)?;
        let head_ref = values
            .get(1)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 255)
            .ok_or(CredentialError::InvalidMergeResponse)?;
        Ok((sha.to_ascii_lowercase(), head_ref.to_owned()))
    }

    pub fn pull_request_merge_context(
        &self,
        token: &Secret,
        repository: &str,
        pull_number: u64,
    ) -> Result<(String, String), CredentialError> {
        let endpoint = format!("repos/{repository}/pulls/{pull_number}");
        let output = self.run(
            &["api", &endpoint, "--jq", "[.base.ref, .head.sha] | @json"],
            &self.environment_with_token(&token.0),
        )?;
        if !output.status.success() {
            return Err(CredentialError::AuthenticationUnavailable);
        }
        let response: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| CredentialError::InvalidMergeResponse)?;
        let values = response
            .as_array()
            .ok_or(CredentialError::InvalidMergeResponse)?;
        let base = values
            .first()
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(CredentialError::InvalidMergeResponse)?;
        let head = values
            .get(1)
            .and_then(serde_json::Value::as_str)
            .filter(|value| {
                matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            .ok_or(CredentialError::InvalidMergeResponse)?;
        Ok((base.to_owned(), head.to_ascii_lowercase()))
    }

    pub fn merge_pull_request(
        &self,
        token: &Secret,
        repository: &str,
        pull_number: u64,
        strategy: crate::config::MergeStrategy,
        expected_head: &str,
    ) -> Result<String, CredentialError> {
        if !matches!(expected_head.len(), 40 | 64)
            || !expected_head.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(CredentialError::InvalidMergeResponse);
        }
        let endpoint = format!("repos/{repository}/pulls/{pull_number}/merge");
        let method = match strategy {
            crate::config::MergeStrategy::Merge => "merge",
            crate::config::MergeStrategy::Squash => "squash",
            crate::config::MergeStrategy::Rebase => "rebase",
        };
        let merge_method = format!("merge_method={method}");
        let head_field = format!("sha={expected_head}");
        let output = self.run(
            &[
                "api",
                &endpoint,
                "--method",
                "PUT",
                "--field",
                &merge_method,
                "--field",
                &head_field,
            ],
            &self.environment_with_token(&token.0),
        )?;
        if !output.status.success() {
            return Err(CredentialError::AuthenticationUnavailable);
        }
        let response: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| CredentialError::InvalidMergeResponse)?;
        if response.get("merged").and_then(serde_json::Value::as_bool) != Some(true) {
            return Err(CredentialError::InvalidMergeResponse);
        }
        response
            .get("sha")
            .and_then(serde_json::Value::as_str)
            .filter(|sha| {
                matches!(sha.len(), 40 | 64) && sha.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            .map(str::to_ascii_lowercase)
            .ok_or(CredentialError::InvalidMergeResponse)
    }

    fn validate_native_store(&self) -> Result<(), CredentialError> {
        if self.environment_tokens_present {
            return Err(CredentialError::EnvironmentTokenPresent);
        }
        let hosts_file = self.gh_config_dir.join("hosts.yml");
        let metadata =
            fs::symlink_metadata(&hosts_file).map_err(|_| CredentialError::UnknownNativeStore)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CredentialError::UnknownNativeStore);
        }
        let bytes = fs::read(&hosts_file).map_err(|_| CredentialError::UnknownNativeStore)?;
        let yaml: Value =
            serde_yaml::from_slice(&bytes).map_err(|_| CredentialError::UnknownNativeStore)?;
        let host = yaml
            .as_mapping()
            .and_then(|hosts| hosts.get(Value::String(self.host.clone())))
            .ok_or(CredentialError::UnknownNativeStore)?;
        let host_map = host
            .as_mapping()
            .ok_or(CredentialError::UnknownNativeStore)?;
        if !host_map.contains_key(Value::String("user".to_owned()))
            || host_map.contains_key(Value::String("api_host".to_owned()))
            || contains_plaintext_token(host)
        {
            return Err(if contains_plaintext_token(host) {
                CredentialError::PlaintextTokenStore
            } else {
                CredentialError::UnknownNativeStore
            });
        }
        Ok(())
    }

    fn current_token(&self, account_selector: Option<&str>) -> Result<Secret, CredentialError> {
        let environment = self.base_environment();
        let mut arguments = vec!["auth", "token", "--hostname", self.host.as_str()];
        if let Some(account_selector) = account_selector {
            arguments.extend(["--user", account_selector]);
        }
        let mut output = self.run(&arguments, &environment)?;
        if !output.status.success() {
            output.stdout.fill(0);
            output.stderr.fill(0);
            return Err(CredentialError::AuthenticationUnavailable);
        }
        output.stderr.fill(0);
        let secret = Secret(output.stdout);
        let token = trim_token(&secret.0).ok_or(CredentialError::AuthenticationUnavailable)?;
        Ok(Secret(token.to_vec()))
    }

    fn run(
        &self,
        args: &[&str],
        environment: &[(OsString, OsString)],
    ) -> Result<crate::runner::RunOutput, CredentialError> {
        if !self.executable.is_absolute() {
            return Err(CredentialError::MissingGh);
        }
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let cwd = Path::new("/");
        self.runner
            .run(RunRequest {
                executable: &self.executable,
                args: &args,
                cwd,
                environment,
                stdin: None,
            })
            .map_err(CredentialError::Command)
    }

    fn base_environment(&self) -> Vec<(OsString, OsString)> {
        let mut environment = vec![
            (OsString::from("HOME"), self.home.as_os_str().to_owned()),
            (
                OsString::from("GH_CONFIG_DIR"),
                self.gh_config_dir.as_os_str().to_owned(),
            ),
        ];
        if let Some(path) = &self.xdg_config_home {
            environment.push((
                OsString::from("XDG_CONFIG_HOME"),
                path.as_os_str().to_owned(),
            ));
        }
        environment
    }

    fn environment_with_token(&self, token: &[u8]) -> Vec<(OsString, OsString)> {
        let mut environment = self.base_environment();
        environment.push((OsString::from("GH_HOST"), OsString::from(&self.host)));
        environment.push((
            OsString::from("GH_TOKEN"),
            OsString::from(String::from_utf8_lossy(token).as_ref()),
        ));
        environment
    }
}

fn validate_account_selector(selector: &str) -> Result<(), CredentialError> {
    let bytes = selector.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 39
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    {
        return Err(CredentialError::UnknownNativeStore);
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<(), CredentialError> {
    if host.is_empty()
        || host.len() > 253
        || !host.is_ascii()
        || !host
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '-'))
    {
        return Err(CredentialError::InvalidHost);
    }
    Ok(())
}

fn contains_plaintext_token(value: &Value) -> bool {
    match value {
        Value::Mapping(mapping) => mapping.iter().any(|(key, value)| {
            key.as_str() == Some("oauth_token") || contains_plaintext_token(value)
        }),
        Value::Sequence(values) => values.iter().any(contains_plaintext_token),
        _ => false,
    }
}

fn trim_token(bytes: &[u8]) -> Option<&[u8]> {
    let token = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let token = token.strip_suffix(b"\r").unwrap_or(token);
    if token.is_empty()
        || token
            .iter()
            .any(|byte| byte.is_ascii_whitespace() || !byte.is_ascii_graphic())
    {
        None
    } else {
        Some(token)
    }
}

fn token_fingerprint(key: &[u8], token: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    mac.update(token);
    let digest = mac.finalize().into_bytes();
    let mut output = String::from("hmac-sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn verify_fingerprint(
    key: &[u8],
    token: &[u8],
    fingerprint: &str,
) -> Result<bool, CredentialError> {
    let Some(hex) = fingerprint.strip_prefix("hmac-sha256:") else {
        return Ok(false);
    };
    if hex.len() != 64 {
        return Ok(false);
    }
    let bytes = hex.as_bytes();
    let mut expected = [0_u8; 32];
    for (index, byte) in expected.iter_mut().enumerate() {
        let Some(high) = hex_nibble(bytes[index * 2]) else {
            return Ok(false);
        };
        let Some(low) = hex_nibble(bytes[index * 2 + 1]) else {
            return Ok(false);
        };
        *byte = (high << 4) | low;
    }
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    mac.update(token);
    Ok(mac.verify_slice(&expected).is_ok())
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn sign_private_state_payload(
    paths: &PersonaPaths,
    payload: &[u8],
) -> Result<String, CredentialError> {
    let key = load_or_create_fingerprint_key(paths)?;
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts arbitrary key lengths");
    mac.update(payload);
    Ok(hex_encode(&mac.finalize().into_bytes()))
}

pub(crate) fn verify_private_state_payload(
    paths: &PersonaPaths,
    payload: &[u8],
    signature: &str,
) -> Result<bool, CredentialError> {
    let key = load_fingerprint_key(paths)?;
    let Some(signature) = hex_decode(signature) else {
        return Ok(false);
    };
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts arbitrary key lengths");
    mac.update(payload);
    Ok(mac.verify_slice(&signature).is_ok())
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if value.len() != 64 || !value.is_ascii() {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            Some((digit(pair[0])? << 4) | digit(pair[1])?)
        })
        .collect()
}

fn load_or_create_fingerprint_key(paths: &PersonaPaths) -> Result<Secret, CredentialError> {
    paths
        .ensure_private_directories()
        .map_err(CredentialError::Storage)?;
    let path = paths.state_dir.join("credential-fingerprint.key");
    match read_private_key(&path) {
        Ok(key) => return Ok(Secret(key)),
        Err(CredentialError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut key = Secret(vec![0; 32]);
    File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut key.0))
        .map_err(|source| CredentialError::Io {
            path: PathBuf::from("/dev/urandom"),
            source,
        })?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(&path) {
        Ok(mut file) => {
            use std::io::Write;
            file.write_all(&key.0)
                .and_then(|_| file.sync_all())
                .map_err(|source| CredentialError::Io { path, source })?;
            Ok(key)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            read_private_key(&path).map(Secret)
        }
        Err(source) => Err(CredentialError::Io { path, source }),
    }
}

fn load_fingerprint_key(paths: &PersonaPaths) -> Result<Secret, CredentialError> {
    paths
        .validate_private_state()
        .map_err(CredentialError::Storage)?;
    read_private_key(&paths.state_dir.join("credential-fingerprint.key")).map(Secret)
}

fn read_private_key(path: &Path) -> Result<Vec<u8>, CredentialError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| CredentialError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CredentialError::UnsafeKeyFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(CredentialError::UnsafeKeyFile);
        }
    }
    let bytes = fs::read(path).map_err(|source| CredentialError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if bytes.len() != 32 {
        return Err(CredentialError::UnsafeKeyFile);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{CredentialError, GithubSelector, Secret, token_fingerprint, verify_fingerprint};
    use crate::storage::PersonaPaths;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn hmac_fingerprints_are_stable_and_keyed() {
        let first = token_fingerprint(b"key-one", b"synthetic-token");
        let repeat = token_fingerprint(b"key-one", b"synthetic-token");
        let other_key = token_fingerprint(b"key-two", b"synthetic-token");
        assert_eq!(first, repeat);
        assert_ne!(first, other_key);
        assert!(verify_fingerprint(b"key-one", b"synthetic-token", &first).unwrap());
        assert!(!verify_fingerprint(b"key-one", b"different-token", &first).unwrap());
    }

    #[test]
    fn enrollment_and_selector_comparison_use_only_synthetic_gh_commands() {
        let temporary = tempdir().unwrap();
        let config_home = temporary.path().join("config");
        let gh_config = config_home.join("gh");
        let state_home = temporary.path().join("state");
        let home = temporary.path().join("home");
        fs::create_dir_all(&gh_config).unwrap();
        fs::set_permissions(&gh_config, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            gh_config.join("hosts.yml"),
            "github.com:\n  user: synthetic-user\n",
        )
        .unwrap();
        let gh = temporary.path().join("gh-fixture");
        fs::write(&gh, "#!/bin/sh\nif [ \"$1 $2\" = \"auth token\" ]; then [ \"$5\" = \"--user\" ] && [ \"$6\" = \"synthetic-user\" ] || exit 63; printf 'synthetic-token\\n'; exit 0; fi\nif [ \"$1 $2\" = \"api user\" ]; then printf '4242\\n'; exit 0; fi\nexit 64\n").unwrap();
        fs::set_permissions(&gh, fs::Permissions::from_mode(0o700)).unwrap();
        let paths =
            PersonaPaths::from_environment(Some(&home), Some(&config_home), Some(&state_home))
                .unwrap();
        let selector = GithubSelector::with_context(
            gh,
            "github.com".to_owned(),
            gh_config,
            home,
            None,
            paths,
            false,
        );
        let binding = selector.enroll(true, "synthetic-user").unwrap();
        assert_eq!(binding.account_id, "4242");
        assert!(binding.token_fingerprint.starts_with("hmac-sha256:"));
        assert!(!binding.token_fingerprint.contains("synthetic-token"));
        assert!(selector.matches_selected_account(&binding).unwrap());
    }

    #[test]
    fn account_binding_selects_named_users_independently_of_the_active_gh_user() {
        let temporary = tempdir().unwrap();
        let config_home = temporary.path().join("config");
        let gh_config = config_home.join("gh");
        let home = temporary.path().join("home");
        fs::create_dir_all(&gh_config).unwrap();
        fs::set_permissions(&gh_config, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            gh_config.join("hosts.yml"),
            "github.com:\n  user: beta-user\n",
        )
        .unwrap();
        let gh = temporary.path().join("gh-fixture");
        fs::write(
            &gh,
            "#!/bin/sh\nif [ \"$1 $2\" = \"auth token\" ]; then case \"$6\" in alpha-user) printf 'alpha-token\\n';; beta-user) printf 'beta-token\\n';; *) exit 63;; esac; exit 0; fi\nif [ \"$1 $2\" = \"api user\" ]; then case \"$GH_TOKEN\" in alpha-token) printf '111\\n';; beta-token) printf '222\\n';; *) exit 64;; esac; exit 0; fi\nexit 64\n",
        )
        .unwrap();
        fs::set_permissions(&gh, fs::Permissions::from_mode(0o700)).unwrap();
        let paths = PersonaPaths::from_environment(
            Some(&home),
            Some(&config_home),
            Some(&temporary.path().join("state")),
        )
        .unwrap();
        let selector = GithubSelector::with_context(
            gh,
            "github.com".to_owned(),
            gh_config,
            home,
            None,
            paths,
            false,
        );

        let alpha = selector.enroll(true, "alpha-user").unwrap();
        let beta = selector.enroll(true, "beta-user").unwrap();
        assert_eq!(alpha.account_id, "111");
        assert_eq!(beta.account_id, "222");
        assert_eq!(alpha.account_selector.as_deref(), Some("alpha-user"));
        assert_eq!(beta.account_selector.as_deref(), Some("beta-user"));
        assert!(selector.matches_selected_account(&alpha).unwrap());
        assert!(selector.matches_selected_account(&beta).unwrap());
        assert_ne!(alpha.token_fingerprint, beta.token_fingerprint);
    }

    #[test]
    fn https_git_helper_checks_allowlisted_destination_before_selecting_synthetic_gh_token() {
        let temporary = tempdir().unwrap();
        let config_home = temporary.path().join("config");
        let gh_config = config_home.join("gh");
        let state_home = temporary.path().join("state");
        let home = temporary.path().join("home");
        fs::create_dir_all(&gh_config).unwrap();
        fs::set_permissions(&gh_config, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            gh_config.join("hosts.yml"),
            "github.com:\n  user: synthetic-user\n",
        )
        .unwrap();
        let marker = temporary.path().join("gh-called");
        let gh = temporary.path().join("gh-fixture");
        fs::write(
            &gh,
            format!(
                "#!/bin/sh\n: > '{}'\nif [ \"$1 $2\" = \"auth token\" ]; then [ \"$5\" = \"--user\" ] && [ \"$6\" = \"synthetic-user\" ] || exit 63; printf 'synthetic-token\\n'; exit 0; fi\nif [ \"$1 $2\" = \"api user\" ]; then printf '4242\\n'; exit 0; fi\nexit 64\n",
                marker.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&gh, fs::Permissions::from_mode(0o700)).unwrap();
        let paths =
            PersonaPaths::from_environment(Some(&home), Some(&config_home), Some(&state_home))
                .unwrap();
        let selector = GithubSelector::with_context(
            gh,
            "github.com".to_owned(),
            gh_config,
            home,
            None,
            paths,
            false,
        );
        let binding = selector.enroll(true, "synthetic-user").unwrap();
        fs::remove_file(&marker).unwrap();
        let policy = crate::config::PushPolicy {
            remote: "origin".to_owned(),
            destinations: vec!["https://github.com/org/repo.git".to_owned()],
            ..crate::config::PushPolicy::default()
        };
        let invalid = b"protocol=https\nhost=github.com\npath=org/other.git\n\n";
        assert!(matches!(
            crate::git_https::select_https_credential("get", invalid, &binding, &policy, &selector),
            Err(crate::git_https::HttpsCredentialError::DestinationNotAllowed)
        ));
        assert!(
            !marker.exists(),
            "rejected destination must not request a token"
        );
        let redirected = b"protocol=https\nhost=attacker.example\npath=org/repo.git\n\n";
        assert!(matches!(
            crate::git_https::select_https_credential(
                "get", redirected, &binding, &policy, &selector
            ),
            Err(crate::git_https::HttpsCredentialError::DestinationNotAllowed)
        ));
        assert!(
            !marker.exists(),
            "redirected host must not retrieve a token"
        );
        let mut ignored = Vec::new();
        crate::git_https::handle_credential_helper(
            "store",
            invalid,
            &binding,
            &policy,
            &selector,
            &mut ignored,
        )
        .unwrap();
        assert!(ignored.is_empty());
        assert!(
            !marker.exists(),
            "store must not persist or retrieve a token"
        );

        let request =
            b"protocol=https\nhost=github.com:443\npath=org/repo.git\nusername=x-access-token\n\n";
        let mut output = Vec::new();
        crate::git_https::handle_credential_helper(
            "get",
            request,
            &binding,
            &policy,
            &selector,
            &mut output,
        )
        .unwrap();
        assert_eq!(
            output,
            b"username=x-access-token\npassword=synthetic-token\n\n"
        );
        assert!(marker.exists());
    }

    #[test]
    fn audited_release_api_checks_ref_type_and_posts_only_explicit_release_fields() {
        let temporary = tempfile::tempdir().unwrap();
        let home = temporary.path().join("home");
        let config = temporary.path().join("gh-config");
        let state = temporary.path().join("state");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&config).unwrap();
        fs::create_dir_all(&state).unwrap();
        let marker = temporary.path().join("release-args");
        let gh = temporary.path().join("gh-fixture");
        fs::write(&gh, format!("#!/bin/sh\n[ \"$GH_TOKEN\" = synthetic-token ] || exit 61\nprintf '%s\\n' \"$*\" >> '{}'\nif [ \"$1 $2\" = \"api repos/acme/project/git/ref/tags/v1.0\" ]; then printf '[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"tag\"]\\n'; exit 0; fi\nif [ \"$1 $2\" = \"api repos/acme/project/releases\" ]; then printf '%s\\n' '{{\"id\":55,\"tag_name\":\"v1.0\",\"target_commitish\":\"main\"}}'; exit 0; fi\nexit 62\n", marker.display())).unwrap();
        fs::set_permissions(&gh, fs::Permissions::from_mode(0o700)).unwrap();
        let paths = PersonaPaths {
            config_file: temporary.path().join("config.toml"),
            config_dir: temporary.path().join("persona"),
            state_dir: state,
        };
        let selector = GithubSelector::with_context(
            gh.clone(),
            "github.com".to_owned(),
            config,
            home,
            None,
            paths,
            false,
        );
        let token = Secret::new(b"synthetic-token".to_vec());
        assert_eq!(
            selector
                .tag_ref_oid(&token, "acme/project", "v1.0")
                .unwrap(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        let request = crate::gh_adapter::GhReleaseRequest {
            repository: "acme/project".to_owned(),
            tag: "v1.0".to_owned(),
            title: Some("Synthetic".to_owned()),
            notes: Some("notes @not-a-file".to_owned()),
            draft: true,
            prerelease: false,
            generate_notes: false,
        };
        assert_eq!(
            selector
                .create_release(&token, &request, "cccccccccccccccccccccccccccccccccccccccc")
                .unwrap(),
            55
        );
        let args = fs::read_to_string(marker).unwrap();
        assert!(args.contains("repos/acme/project/git/ref/tags/v1.0"));
        assert!(args.contains("repos/acme/project/releases"));
        assert!(args.contains("--raw-field tag_name=v1.0"));
        assert!(args.contains("--raw-field body=notes @not-a-file"));
        assert!(args.contains("--field draft=true"));
        assert!(args.contains("--field target_commitish=cccccccccccccccccccccccccccccccccccccccc"));
        assert!(!args.contains("synthetic-token"));

        let mismatched_gh = temporary.path().join("gh-mismatched-release");
        let mismatched_script = fs::read_to_string(&gh)
            .unwrap()
            .replace(r#""tag_name":"v1.0""#, r#""tag_name":"other-tag""#);
        fs::write(&mismatched_gh, mismatched_script).unwrap();
        fs::set_permissions(&mismatched_gh, fs::Permissions::from_mode(0o700)).unwrap();
        let mut mismatched_selector = selector;
        mismatched_selector.executable = mismatched_gh;
        assert!(matches!(
            mismatched_selector.create_release(
                &token,
                &request,
                "cccccccccccccccccccccccccccccccccccccccc"
            ),
            Err(CredentialError::InvalidMergeResponse)
        ));
    }

    #[test]
    fn online_commit_verification_queries_only_the_explicit_commit_with_selected_token() {
        let temporary = tempfile::tempdir().unwrap();
        let home = temporary.path().join("home");
        let config = temporary.path().join("gh-config");
        let state = temporary.path().join("state");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&config).unwrap();
        fs::create_dir_all(&state).unwrap();
        let marker = temporary.path().join("verification-call");
        let oid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let gh = temporary.path().join("gh-fixture");
        fs::write(&gh, format!("#!/bin/sh\n[ \"$GH_TOKEN\" = synthetic-token ] || exit 61\nprintf '%s\\n' \"$*\" > '{}'\nprintf 'true\\n'\n", marker.display())).unwrap();
        fs::set_permissions(&gh, fs::Permissions::from_mode(0o700)).unwrap();
        let paths = PersonaPaths {
            config_file: temporary.path().join("config.toml"),
            config_dir: temporary.path().join("persona"),
            state_dir: state,
        };
        let selector = GithubSelector::with_context(
            gh,
            "github.com".to_owned(),
            config,
            home,
            None,
            paths,
            false,
        );
        let token = Secret::new(b"synthetic-token".to_vec());
        assert!(
            selector
                .commit_is_verified(&token, "acme/project", oid)
                .unwrap()
        );
        let args = fs::read_to_string(marker).unwrap();
        assert!(args.contains(&format!("repos/acme/project/commits/{oid}")));
        assert!(args.contains(".commit.verification.verified"));
        assert!(!args.contains("synthetic-token"));
        assert!(
            selector
                .commit_is_verified(&token, "acme/project", "not-an-oid")
                .is_err()
        );
    }

    #[test]
    fn server_merge_api_is_bound_to_expected_head_and_selected_token() {
        let temporary = tempfile::tempdir().unwrap();
        let home = temporary.path().join("home");
        let config = temporary.path().join("gh");
        let state = temporary.path().join("state");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&config).unwrap();
        fs::create_dir_all(&state).unwrap();
        let marker = temporary.path().join("merge-args");
        let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let gh = temporary.path().join("gh-fixture");
        fs::write(&gh, format!("#!/bin/sh\n[ \"$GH_TOKEN\" = synthetic-token ] || exit 61\nif [ \"$1 $2\" = \"api repos/acme/project/pulls/42\" ]; then printf '[\"main\",\"{sha}\"]\\n'; exit 0; fi\nif [ \"$1 $2\" = \"api repos/acme/project/pulls/42/merge\" ]; then printf '%s\\n' \"$*\" > '{}'; printf '{{\"sha\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"merged\":true}}\\n'; exit 0; fi\nexit 62\n", marker.display())).unwrap();
        fs::set_permissions(&gh, fs::Permissions::from_mode(0o700)).unwrap();
        let paths = PersonaPaths {
            config_file: temporary.path().join("config.toml"),
            config_dir: temporary.path().join("persona"),
            state_dir: state,
        };
        let selector = GithubSelector::with_context(
            gh,
            "github.com".to_owned(),
            config,
            home,
            None,
            paths,
            false,
        );
        let token = Secret::new(b"synthetic-token".to_vec());
        let (base, head) = selector
            .pull_request_merge_context(&token, "acme/project", 42)
            .unwrap();
        assert_eq!(base, "main");
        assert_eq!(head, sha);
        let merged = selector
            .merge_pull_request(
                &token,
                "acme/project",
                42,
                crate::config::MergeStrategy::Squash,
                &head,
            )
            .unwrap();
        assert_eq!(merged, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let args = fs::read_to_string(marker).unwrap();
        assert!(args.contains("--field merge_method=squash"));
        assert!(args.contains(&format!("--field sha={sha}")));
    }

    #[test]
    fn refuses_plaintext_native_token_and_missing_online_opt_in() {
        let temporary = tempdir().unwrap();
        let config_home = temporary.path().join("config");
        let gh_config = config_home.join("gh");
        let home = temporary.path().join("home");
        fs::create_dir_all(&gh_config).unwrap();
        fs::write(
            gh_config.join("hosts.yml"),
            "github.com:\n  user: synthetic-user\n  oauth_token: synthetic-secret\n",
        )
        .unwrap();
        let gh = temporary.path().join("gh-fixture");
        fs::write(&gh, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&gh, fs::Permissions::from_mode(0o700)).unwrap();
        let paths = PersonaPaths::from_environment(Some(&home), Some(&config_home), None).unwrap();
        let selector = GithubSelector::with_context(
            gh,
            "github.com".to_owned(),
            gh_config,
            home,
            None,
            paths,
            false,
        );
        assert!(matches!(
            selector.enroll(false, "synthetic-user"),
            Err(CredentialError::OnlineConfirmationRequired)
        ));
        assert!(matches!(
            selector.enroll(true, "synthetic-user"),
            Err(CredentialError::PlaintextTokenStore)
        ));
    }

    #[test]
    fn destination_host_parsing_never_returns_url_credentials() {
        assert_eq!(
            super::destination_host("https://user:secret@github.com/org/repo"),
            Some("github.com".to_owned())
        );
        assert_eq!(
            super::destination_host("git@github.com:org/repo.git"),
            Some("github.com".to_owned())
        );
        assert_eq!(super::destination_host("file:///tmp/repo.git"), None);
    }

    #[test]
    fn rejects_bad_hosts_before_any_gh_invocation() {
        let temporary = tempdir().unwrap();
        let paths = PersonaPaths::from_environment(Some(temporary.path()), None, None).unwrap();
        let result = GithubSelector::discover(
            Path::new("relative-gh").to_path_buf(),
            "https://github.com".to_owned(),
            paths,
        );
        assert!(matches!(result, Err(CredentialError::InvalidHost)));
    }
}
