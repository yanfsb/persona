use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Config {
    version: u32,
    profiles: Vec<Profile>,
    scope_profiles: Vec<String>,
    scopes: Vec<ScopePolicy>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    pub git: GitPolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github: Option<GitHubBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh: Option<SshPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github_merge: Option<GitHubMergePolicy>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GitHubBinding {
    pub host: String,
    pub account_id: String,
    /// Native `gh auth token --user` selector; absent on legacy bindings, which
    /// must not silently fall back to the active account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_selector: Option<String>,
    pub token_fingerprint: String,
    /// Explicit GitHub.com repositories this profile may address, in OWNER/REPO form.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repositories: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SshPolicy {
    pub host: String,
    pub user: String,
    pub port: u16,
    pub fingerprint: String,
    pub public_key: PathBuf,
    pub identity_file: Option<PathBuf>,
    pub agent_socket: Option<PathBuf>,
    pub known_hosts_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ScopePolicy {
    pub name: String,
    pub path: PathBuf,
    pub profile: String,
    pub git: GitPolicy,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitPolicy {
    pub author: Identity,
    pub committer: Identity,
    pub signing: Option<SigningPolicy>,
    pub push: Option<PushPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remotes: Vec<RemotePolicy>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemotePolicy {
    pub name: String,
    #[serde(default)]
    pub fetch_destinations: Vec<String>,
    #[serde(default)]
    pub push_destinations: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GitHubMergePolicy {
    pub repositories: Vec<GitHubMergeRepository>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GitHubMergeRepository {
    pub repository: String,
    pub base_branches: Vec<String>,
    pub strategies: Vec<MergeStrategy>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum MergeStrategy {
    Merge,
    Squash,
    Rebase,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct PushPolicy {
    /// Exact remote name accepted by the push audit.
    pub remote: String,
    /// Exact effective destinations accepted by the push audit.
    pub destinations: Vec<String>,
    /// Explicitly permits upstream/cherry-picked author identities to be preserved.
    pub preserve_authors: bool,
    /// Permit a branch to be published when the remote ref does not exist yet.
    pub allow_initial_push: bool,
    /// Permit a branch update only when local object evidence proves fast-forward.
    pub allow_fast_forward: bool,
    /// Permit annotated tags only after signature-policy verification.
    pub allow_annotated_tags: bool,
    /// Permit lightweight tags only by explicit opt-in.
    pub allow_lightweight_tags: bool,
    /// Permit branch ref deletion only by explicit opt-in.
    pub allow_branch_deletion: bool,
    /// Permit tag ref deletion only by explicit opt-in.
    pub allow_tag_deletion: bool,
    /// Permit rewrites only with a separately captured expected remote OID lease.
    pub allow_force_with_lease: bool,
    /// Explicitly pinned remote-tracking baselines; these are never inferred from Git config.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstream_baselines: Vec<UpstreamBaseline>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpstreamBaseline {
    pub destination: String,
    pub tracking_ref: String,
    pub oid: String,
}

impl Default for PushPolicy {
    fn default() -> Self {
        Self {
            remote: String::new(),
            destinations: Vec::new(),
            preserve_authors: false,
            allow_initial_push: true,
            allow_fast_forward: true,
            allow_annotated_tags: false,
            allow_lightweight_tags: false,
            allow_branch_deletion: false,
            allow_tag_deletion: false,
            allow_force_with_lease: false,
            upstream_baselines: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SigningFormat {
    #[default]
    OpenPgp,
    Ssh,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SigningPolicy {
    /// Authorized OpenPGP primary or SSH key fingerprint.
    pub fingerprint: String,
    #[serde(default)]
    pub format: SigningFormat,
    /// Absolute path to an exported public-key file. It is imported into a
    /// temporary keyring; the user's GnuPG home is never consulted.
    pub public_key: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub name: String,
    pub email: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigV1 {
    version: u32,
    scopes: Vec<ScopePolicyV1>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopePolicyV1 {
    name: String,
    path: PathBuf,
    git: GitPolicy,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigV2 {
    version: u32,
    profiles: Vec<Profile>,
    scopes: Vec<ScopeProfile>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigV3 {
    version: u32,
    profiles: Vec<Profile>,
    scopes: Vec<ScopeProfile>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScopeProfile {
    name: String,
    path: PathBuf,
    profile: String,
}

#[derive(Debug, Deserialize)]
struct VersionProbe {
    version: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    InvalidToml,
    Serialization,
    UnsupportedVersion(u32),
    EmptyProfiles,
    EmptyScopes,
    InvalidProfileName,
    DuplicateProfileName(String),
    MissingProfile(String),
    ProfileInUse(String),
    UnknownProfile { scope: String, profile: String },
    UnknownScope(String),
    InvalidScopeName,
    DuplicateScopeName(String),
    DuplicateScopeRoot(PathBuf),
    RelativeScopePath(PathBuf),
    EmptyIdentity { scope: String, role: String },
    InvalidSigningFingerprint { scope: String },
    RelativeSigningKey { scope: String, path: PathBuf },
    EmptyPushRemote { scope: String },
    EmptyPushDestinations { scope: String },
    EmptyPushDestination { scope: String },
    AnnotatedTagsRequireSigning { scope: String },
    InvalidUpstreamBaseline { scope: String },
    InvalidGithubBinding { profile: String },
    InvalidGithubMergePolicy { profile: String },
    InvalidRemotePolicy { scope: String },
    InvalidSshPolicy { profile: String },
}

#[derive(Debug)]
pub enum ConfigLoadError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Invalid(ConfigError),
}

impl Config {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let version: VersionProbe = toml::from_str(input).map_err(|_| ConfigError::InvalidToml)?;
        match version.version {
            1 => Self::parse_v1(input),
            2 => Self::parse_v2(input),
            3 => Self::parse_v3(input),
            other => Err(ConfigError::UnsupportedVersion(other)),
        }
    }

    pub fn load(path: &Path) -> Result<Self, ConfigLoadError> {
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigLoadError::Read {
            path: path.to_path_buf(),
            source,
        })?;

        Self::parse(&contents).map_err(ConfigLoadError::Invalid)
    }

    pub fn single_scope(
        profile: Profile,
        scope_name: String,
        scope_path: PathBuf,
    ) -> Result<Self, ConfigError> {
        if profile.name.trim().is_empty() || profile.name.trim() != profile.name {
            return Err(ConfigError::InvalidProfileName);
        }
        let mut names = HashSet::new();
        validate_scope_name(&scope_name, &mut names)?;
        if scope_path.is_relative() {
            return Err(ConfigError::RelativeScopePath(scope_path));
        }
        validate_git_policy(&scope_name, &profile.git)?;
        validate_github_binding(&profile)?;
        validate_ssh_policy(&profile)?;
        validate_github_merge_policy(&profile)?;
        Ok(Self {
            version: 3,
            profiles: vec![profile.clone()],
            scope_profiles: vec![profile.name.clone()],
            scopes: vec![ScopePolicy {
                name: scope_name,
                path: scope_path,
                profile: profile.name.clone(),
                git: profile.git,
            }],
        })
    }

    pub fn add_profile(&mut self, profile: Profile) -> Result<(), ConfigError> {
        if profile.name.trim().is_empty() || profile.name.trim() != profile.name {
            return Err(ConfigError::InvalidProfileName);
        }
        if self.profiles.iter().any(|item| item.name == profile.name) {
            return Err(ConfigError::DuplicateProfileName(profile.name));
        }
        validate_git_policy(&profile.name, &profile.git)?;
        validate_github_binding(&profile)?;
        validate_ssh_policy(&profile)?;
        validate_github_merge_policy(&profile)?;
        self.profiles.push(profile);
        self.version = 3;
        Ok(())
    }

    pub fn update_profile(&mut self, profile: Profile) -> Result<(), ConfigError> {
        let Some(index) = self
            .profiles
            .iter()
            .position(|item| item.name == profile.name)
        else {
            return Err(ConfigError::MissingProfile(profile.name));
        };
        validate_github_binding(&profile)?;
        validate_ssh_policy(&profile)?;
        validate_github_merge_policy(&profile)?;
        for scope in self
            .scopes
            .iter()
            .filter(|scope| scope.profile == profile.name)
        {
            validate_git_policy(&scope.name, &profile.git)?;
        }
        self.profiles[index] = profile.clone();
        for scope in self
            .scopes
            .iter_mut()
            .filter(|scope| scope.profile == profile.name)
        {
            scope.git = profile.git.clone();
        }
        self.version = 3;
        Ok(())
    }

    pub fn remove_profile(&mut self, name: &str) -> Result<(), ConfigError> {
        if self.scope_profiles.iter().any(|profile| profile == name) {
            return Err(ConfigError::ProfileInUse(name.to_owned()));
        }
        let Some(index) = self
            .profiles
            .iter()
            .position(|profile| profile.name == name)
        else {
            return Err(ConfigError::MissingProfile(name.to_owned()));
        };
        if self.profiles.len() == 1 {
            return Err(ConfigError::EmptyProfiles);
        }
        self.profiles.remove(index);
        self.version = 3;
        Ok(())
    }

    pub fn add_scope(
        &mut self,
        name: String,
        path: PathBuf,
        profile_name: &str,
    ) -> Result<(), ConfigError> {
        let mut names: HashSet<String> =
            self.scopes.iter().map(|scope| scope.name.clone()).collect();
        validate_scope_name(&name, &mut names)?;
        if path.is_relative() {
            return Err(ConfigError::RelativeScopePath(path));
        }
        if self.scopes.iter().any(|scope| scope.path == path) {
            return Err(ConfigError::DuplicateScopeRoot(path));
        }
        let profile = self
            .profiles
            .iter()
            .find(|profile| profile.name == profile_name)
            .ok_or_else(|| ConfigError::UnknownProfile {
                scope: name.clone(),
                profile: profile_name.to_owned(),
            })?;
        validate_git_policy(&name, &profile.git)?;
        self.scopes.push(ScopePolicy {
            name,
            path,
            profile: profile.name.clone(),
            git: profile.git.clone(),
        });
        self.scope_profiles.push(profile.name.clone());
        self.version = 3;
        Ok(())
    }

    pub fn update_scope(
        &mut self,
        name: &str,
        path: PathBuf,
        profile_name: &str,
    ) -> Result<(), ConfigError> {
        let Some(index) = self.scopes.iter().position(|scope| scope.name == name) else {
            return Err(ConfigError::UnknownScope(name.to_owned()));
        };
        if path.is_relative() {
            return Err(ConfigError::RelativeScopePath(path));
        }
        if self
            .scopes
            .iter()
            .enumerate()
            .any(|(other, scope)| other != index && scope.path == path)
        {
            return Err(ConfigError::DuplicateScopeRoot(path));
        }
        let profile = self
            .profiles
            .iter()
            .find(|profile| profile.name == profile_name)
            .ok_or_else(|| ConfigError::UnknownProfile {
                scope: name.to_owned(),
                profile: profile_name.to_owned(),
            })?;
        validate_git_policy(name, &profile.git)?;
        let scope = &mut self.scopes[index];
        scope.path = path;
        scope.profile = profile.name.clone();
        scope.git = profile.git.clone();
        self.scope_profiles[index] = profile.name.clone();
        self.version = 3;
        Ok(())
    }

    pub fn remove_scope(&mut self, name: &str) -> Result<(), ConfigError> {
        let Some(index) = self.scopes.iter().position(|scope| scope.name == name) else {
            return Err(ConfigError::UnknownScope(name.to_owned()));
        };
        if self.scopes.len() == 1 {
            return Err(ConfigError::EmptyScopes);
        }
        self.scopes.remove(index);
        self.scope_profiles.remove(index);
        self.version = 3;
        Ok(())
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn profiles(&self) -> &[Profile] {
        &self.profiles
    }

    pub fn policies(&self) -> &[ScopePolicy] {
        &self.scopes
    }

    pub fn scopes(&self) -> Vec<crate::Scope> {
        self.scopes
            .iter()
            .map(|policy| crate::Scope {
                name: policy.name.clone(),
                root: policy.path.clone(),
            })
            .collect()
    }

    /// Serialize an explicit migration preview. This method never writes the
    /// result or changes the source configuration.
    pub fn to_v2_toml(&self) -> Result<String, ConfigError> {
        let config = ConfigV2 {
            version: 2,
            profiles: self.profiles.clone(),
            scopes: self
                .scopes
                .iter()
                .zip(&self.scope_profiles)
                .map(|(scope, profile)| ScopeProfile {
                    name: scope.name.clone(),
                    path: scope.path.clone(),
                    profile: profile.clone(),
                })
                .collect(),
        };
        toml::to_string_pretty(&config).map_err(|_| ConfigError::Serialization)
    }

    /// Serialize the canonical mutable configuration as v3.
    pub fn to_v3_toml(&self) -> Result<String, ConfigError> {
        let mut profiles = self.profiles.clone();
        for profile in &mut profiles {
            if profile.git.remotes.is_empty() {
                if let Some(push) = &profile.git.push {
                    profile.git.remotes.push(RemotePolicy {
                        name: push.remote.clone(),
                        fetch_destinations: push.destinations.clone(),
                        push_destinations: push.destinations.clone(),
                    });
                }
            }
        }
        let config = ConfigV3 {
            version: 3,
            profiles,
            scopes: self
                .scopes
                .iter()
                .zip(&self.scope_profiles)
                .map(|(scope, profile)| ScopeProfile {
                    name: scope.name.clone(),
                    path: scope.path.clone(),
                    profile: profile.clone(),
                })
                .collect(),
        };
        toml::to_string_pretty(&config).map_err(|_| ConfigError::Serialization)
    }

    fn parse_v1(input: &str) -> Result<Self, ConfigError> {
        let config: ConfigV1 = toml::from_str(input).map_err(|_| ConfigError::InvalidToml)?;
        if config.version != 1 {
            return Err(ConfigError::UnsupportedVersion(config.version));
        }
        if config.scopes.is_empty() {
            return Err(ConfigError::EmptyScopes);
        }

        let mut names = HashSet::new();
        let mut profiles = Vec::with_capacity(config.scopes.len());
        let mut scope_profiles = Vec::with_capacity(config.scopes.len());
        let mut scopes = Vec::with_capacity(config.scopes.len());
        for scope in config.scopes {
            validate_scope_name(&scope.name, &mut names)?;
            if scope.path.is_relative() {
                return Err(ConfigError::RelativeScopePath(scope.path));
            }
            validate_git_policy(&scope.name, &scope.git)?;
            profiles.push(Profile {
                name: scope.name.clone(),
                git: scope.git.clone(),
                github: None,
                ssh: None,
                github_merge: None,
            });
            scope_profiles.push(scope.name.clone());
            scopes.push(ScopePolicy {
                name: scope.name,
                path: scope.path,
                profile: scope_profiles
                    .last()
                    .expect("profile mapping was added")
                    .clone(),
                git: scope.git,
            });
        }

        Ok(Self {
            version: 1,
            profiles,
            scope_profiles,
            scopes,
        })
    }

    fn parse_v2(input: &str) -> Result<Self, ConfigError> {
        let config: ConfigV2 = toml::from_str(input).map_err(|_| ConfigError::InvalidToml)?;
        if config.version != 2 {
            return Err(ConfigError::UnsupportedVersion(config.version));
        }
        if config.profiles.is_empty() {
            return Err(ConfigError::EmptyProfiles);
        }
        if config.scopes.is_empty() {
            return Err(ConfigError::EmptyScopes);
        }

        let mut profile_indexes = std::collections::HashMap::new();
        for (index, profile) in config.profiles.iter().enumerate() {
            validate_github_binding(profile)?;
            validate_ssh_policy(profile)?;
            validate_github_merge_policy(profile)?;
            if profile.name.trim().is_empty() || profile.name.trim() != profile.name {
                return Err(ConfigError::InvalidProfileName);
            }
            if profile_indexes
                .insert(profile.name.as_str(), index)
                .is_some()
            {
                return Err(ConfigError::DuplicateProfileName(profile.name.clone()));
            }
        }

        let mut names = HashSet::new();
        let mut scope_profiles = Vec::with_capacity(config.scopes.len());
        let mut scopes = Vec::with_capacity(config.scopes.len());
        for scope in config.scopes {
            validate_scope_name(&scope.name, &mut names)?;
            if scope.path.is_relative() {
                return Err(ConfigError::RelativeScopePath(scope.path));
            }
            let profile_index = profile_indexes.get(scope.profile.as_str()).ok_or_else(|| {
                ConfigError::UnknownProfile {
                    scope: scope.name.clone(),
                    profile: scope.profile.clone(),
                }
            })?;
            let profile = &config.profiles[*profile_index];
            validate_git_policy(&scope.name, &profile.git)?;
            scope_profiles.push(scope.profile.clone());
            scopes.push(ScopePolicy {
                name: scope.name,
                path: scope.path,
                profile: scope.profile,
                git: profile.git.clone(),
            });
        }

        Ok(Self {
            version: 2,
            profiles: config.profiles,
            scope_profiles,
            scopes,
        })
    }

    fn parse_v3(input: &str) -> Result<Self, ConfigError> {
        let config: ConfigV3 = toml::from_str(input).map_err(|_| ConfigError::InvalidToml)?;
        if config.version != 3 {
            return Err(ConfigError::UnsupportedVersion(config.version));
        }
        if config.profiles.is_empty() {
            return Err(ConfigError::EmptyProfiles);
        }
        if config.scopes.is_empty() {
            return Err(ConfigError::EmptyScopes);
        }
        let mut indexes = std::collections::HashMap::new();
        for (index, profile) in config.profiles.iter().enumerate() {
            validate_github_binding(profile)?;
            validate_ssh_policy(profile)?;
            validate_github_merge_policy(profile)?;
            if profile.git.push.as_ref().is_some_and(|push| {
                !profile.git.remotes.iter().any(|remote| {
                    remote.name == push.remote && remote.push_destinations == push.destinations
                })
            }) {
                return Err(ConfigError::InvalidRemotePolicy {
                    scope: profile.name.clone(),
                });
            }
            if profile.name.trim().is_empty()
                || profile.name.trim() != profile.name
                || indexes.insert(profile.name.as_str(), index).is_some()
            {
                return Err(ConfigError::InvalidProfileName);
            }
        }
        let mut names = HashSet::new();
        let mut scope_profiles = Vec::with_capacity(config.scopes.len());
        let mut scopes = Vec::with_capacity(config.scopes.len());
        for scope in config.scopes {
            validate_scope_name(&scope.name, &mut names)?;
            if scope.path.is_relative() {
                return Err(ConfigError::RelativeScopePath(scope.path));
            }
            let profile_index =
                indexes
                    .get(scope.profile.as_str())
                    .ok_or_else(|| ConfigError::UnknownProfile {
                        scope: scope.name.clone(),
                        profile: scope.profile.clone(),
                    })?;
            let profile = &config.profiles[*profile_index];
            validate_git_policy(&scope.name, &profile.git)?;
            scope_profiles.push(scope.profile.clone());
            scopes.push(ScopePolicy {
                name: scope.name,
                path: scope.path,
                profile: scope.profile,
                git: profile.git.clone(),
            });
        }
        Ok(Self {
            version: 3,
            profiles: config.profiles,
            scope_profiles,
            scopes,
        })
    }
}

fn validate_scope_name(name: &str, seen: &mut HashSet<String>) -> Result<(), ConfigError> {
    if name.trim().is_empty() || name.trim() != name {
        return Err(ConfigError::InvalidScopeName);
    }
    if !seen.insert(name.to_owned()) {
        return Err(ConfigError::DuplicateScopeName(name.to_owned()));
    }
    Ok(())
}

fn validate_github_binding(profile: &Profile) -> Result<(), ConfigError> {
    let Some(binding) = &profile.github else {
        return Ok(());
    };
    let host_valid = !binding.host.is_empty()
        && binding.host.len() <= 253
        && binding.host.is_ascii()
        && binding
            .host
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '-'));
    let id_valid = !binding.account_id.is_empty()
        && binding.account_id.bytes().all(|byte| byte.is_ascii_digit())
        && binding.account_id.parse::<u64>().is_ok_and(|id| id > 0);
    let selector_valid = binding.account_selector.as_deref().is_none_or(|selector| {
        let bytes = selector.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 39
            && bytes[0].is_ascii_alphanumeric()
            && bytes[bytes.len() - 1].is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    });
    let fingerprint_valid = binding
        .token_fingerprint
        .strip_prefix("hmac-sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let mut repositories = HashSet::new();
    let repositories_valid = binding.repositories.iter().all(|repository| {
        let Some((owner, name)) = repository.split_once('/') else {
            return false;
        };
        !owner.is_empty()
            && !name.is_empty()
            && !name.contains('/')
            && owner.len() <= 39
            && name.len() <= 100
            && owner
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            && repositories.insert(repository.to_ascii_lowercase())
    });
    if !host_valid || !id_valid || !selector_valid || !fingerprint_valid || !repositories_valid {
        return Err(ConfigError::InvalidGithubBinding {
            profile: profile.name.clone(),
        });
    }
    Ok(())
}

fn validate_github_merge_policy(profile: &Profile) -> Result<(), ConfigError> {
    let Some(policy) = &profile.github_merge else {
        return Ok(());
    };
    let valid = profile.github.as_ref().is_some_and(|binding| {
        binding.host == "github.com"
            && !policy.repositories.is_empty()
            && policy.repositories.iter().all(|rule| {
                binding
                    .repositories
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(&rule.repository))
                    && !rule.base_branches.is_empty()
                    && !rule.strategies.is_empty()
                    && rule.strategies.iter().collect::<HashSet<_>>().len() == rule.strategies.len()
                    && rule
                        .base_branches
                        .iter()
                        .all(|branch| valid_policy_branch(branch))
                    && rule.base_branches.iter().collect::<HashSet<_>>().len()
                        == rule.base_branches.len()
            })
            && policy
                .repositories
                .iter()
                .map(|rule| rule.repository.to_ascii_lowercase())
                .collect::<HashSet<_>>()
                .len()
                == policy.repositories.len()
    });
    if !valid {
        return Err(ConfigError::InvalidGithubMergePolicy {
            profile: profile.name.clone(),
        });
    }
    Ok(())
}

fn valid_policy_branch(branch: &str) -> bool {
    !branch.is_empty()
        && branch.len() <= 255
        && !branch.starts_with('-')
        && !branch.starts_with('/')
        && !branch.ends_with('/')
        && !branch.contains("..")
        && !branch.contains("@{")
        && branch.bytes().all(|byte| {
            byte > b' '
                && byte != 0x7f
                && !matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
}

fn valid_ssh_host(host: &str) -> bool {
    if host.is_empty() || !host.is_ascii() || host.len() > 253 {
        return false;
    }
    host.split('.').all(|label| {
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

fn validate_ssh_policy(profile: &Profile) -> Result<(), ConfigError> {
    let Some(ssh) = &profile.ssh else {
        return Ok(());
    };
    let host_valid = valid_ssh_host(&ssh.host);
    let user_valid = !ssh.user.is_empty()
        && ssh
            .user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    let fingerprint_valid = ssh
        .fingerprint
        .strip_prefix("SHA256:")
        .is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        });
    let paths_valid = ssh.public_key.is_absolute()
        && ssh.known_hosts_file.is_absolute()
        && ssh
            .identity_file
            .as_ref()
            .is_none_or(|path| path.is_absolute())
        && ssh
            .agent_socket
            .as_ref()
            .is_none_or(|path| path.is_absolute());
    if !host_valid
        || !user_valid
        || ssh.port == 0
        || !fingerprint_valid
        || !paths_valid
        || (ssh.identity_file.is_some() == ssh.agent_socket.is_some())
    {
        return Err(ConfigError::InvalidSshPolicy {
            profile: profile.name.clone(),
        });
    }
    Ok(())
}

fn validate_git_policy(scope: &str, git: &GitPolicy) -> Result<(), ConfigError> {
    for (role, identity) in [("author", &git.author), ("committer", &git.committer)] {
        if identity.name.trim().is_empty() || identity.email.trim().is_empty() {
            return Err(ConfigError::EmptyIdentity {
                scope: scope.to_owned(),
                role: role.to_owned(),
            });
        }
    }

    if let Some(signing) = &git.signing {
        let fingerprint_valid = match signing.format {
            SigningFormat::OpenPgp => {
                signing.fingerprint.len() == 40
                    && signing
                        .fingerprint
                        .chars()
                        .all(|character| character.is_ascii_hexdigit())
            }
            SigningFormat::Ssh => {
                signing.fingerprint.starts_with("SHA256:")
                    && signing.fingerprint.len() > "SHA256:".len()
                    && signing.fingerprint["SHA256:".len()..].bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
                    })
            }
        };
        if !fingerprint_valid {
            return Err(ConfigError::InvalidSigningFingerprint {
                scope: scope.to_owned(),
            });
        }
        if signing.public_key.is_relative() {
            return Err(ConfigError::RelativeSigningKey {
                scope: scope.to_owned(),
                path: signing.public_key.clone(),
            });
        }
    }

    let mut remote_names = HashSet::new();
    for remote in &git.remotes {
        let name_valid = !remote.name.is_empty()
            && remote.name.len() <= 128
            && !remote.name.starts_with('-')
            && remote
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
        let fetch_unique = remote
            .fetch_destinations
            .iter()
            .collect::<HashSet<_>>()
            .len()
            == remote.fetch_destinations.len();
        let push_unique = remote
            .push_destinations
            .iter()
            .collect::<HashSet<_>>()
            .len()
            == remote.push_destinations.len();
        if !name_valid
            || (remote.fetch_destinations.is_empty() && remote.push_destinations.is_empty())
            || !remote_names.insert(remote.name.as_str())
            || !fetch_unique
            || !push_unique
            || remote
                .fetch_destinations
                .iter()
                .chain(&remote.push_destinations)
                .any(|destination| destination.is_empty())
        {
            return Err(ConfigError::InvalidRemotePolicy {
                scope: scope.to_owned(),
            });
        }
    }

    if let Some(push) = &git.push {
        if !git.remotes.is_empty()
            && !git.remotes.iter().any(|remote| {
                remote.name == push.remote && remote.push_destinations == push.destinations
            })
        {
            return Err(ConfigError::InvalidRemotePolicy {
                scope: scope.to_owned(),
            });
        }
        if push.allow_annotated_tags && git.signing.is_none() {
            return Err(ConfigError::AnnotatedTagsRequireSigning {
                scope: scope.to_owned(),
            });
        }
        if push.remote.trim().is_empty() {
            return Err(ConfigError::EmptyPushRemote {
                scope: scope.to_owned(),
            });
        }
        if push.destinations.is_empty() {
            return Err(ConfigError::EmptyPushDestinations {
                scope: scope.to_owned(),
            });
        }
        if push
            .destinations
            .iter()
            .any(|destination| destination.is_empty())
        {
            return Err(ConfigError::EmptyPushDestination {
                scope: scope.to_owned(),
            });
        }
        let mut baseline_refs = HashSet::new();
        let baseline_prefix = format!("refs/remotes/{}/", push.remote);
        for baseline in &push.upstream_baselines {
            let destination_valid = push
                .destinations
                .iter()
                .any(|destination| destination == &baseline.destination);
            let oid_valid = matches!(baseline.oid.len(), 40 | 64)
                && baseline.oid.bytes().all(|byte| byte.is_ascii_hexdigit());
            let ref_name = baseline.tracking_ref.strip_prefix(&baseline_prefix);
            let ref_valid = ref_name.is_some_and(|name| {
                !name.is_empty()
                    && !name.starts_with('/')
                    && !name.ends_with('/')
                    && !name.contains("..")
                    && !name.contains("@{")
                    && name.bytes().all(|byte| {
                        byte > b' '
                            && byte != 0x7f
                            && !matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
                    })
                    && name.split('/').all(|component| {
                        !component.is_empty()
                            && !component.starts_with('.')
                            && !component.ends_with('.')
                            && !component.ends_with(".lock")
                    })
            });
            if !destination_valid
                || !oid_valid
                || !ref_valid
                || !baseline_refs.insert((&baseline.destination, &baseline.tracking_ref))
            {
                return Err(ConfigError::InvalidUpstreamBaseline {
                    scope: scope.to_owned(),
                });
            }
        }
    }
    Ok(())
}
