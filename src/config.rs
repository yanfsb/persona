pub use crate::command_policy::{CommandPolicy, CommandPolicyMode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

pub type GitCommandPolicy = CommandPolicy;

pub const CURRENT_CONFIG_VERSION: u32 = 4;
const MAX_EXTENDS_DEPTH: usize = 16;

fn default_true() -> bool {
    true
}

fn is_true(value: &bool) -> bool {
    *value
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone)]
pub struct Config {
    version: u32,
    raw: ConfigV4,
    profiles: Vec<Profile>,
    scopes: Vec<ScopePolicy>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extends: Option<String>,
    pub git: GitPolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github: Option<GitHubBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh: Option<SshPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_hosts: Vec<SshPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub https_credentials: Vec<HttpsCredentialPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github_merge: Option<GitHubMergePolicy>,
    #[serde(default, skip_serializing_if = "CommandPolicy::is_default")]
    pub run: CommandPolicy,
}

impl Profile {
    pub fn ssh_policies(&self) -> Vec<&SshPolicy> {
        self.ssh.iter().chain(self.ssh_hosts.iter()).collect()
    }

    pub fn has_ssh_policy(&self) -> bool {
        !self.ssh_policies().is_empty()
    }

    pub fn https_credential_for_host(&self, host: &str) -> Option<&HttpsCredentialPolicy> {
        self.https_credentials
            .iter()
            .find(|policy| policy.host.eq_ignore_ascii_case(host))
    }
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
    /// GitHub.com repositories or owner wildcards (`OWNER/REPO`, `OWNER/*`, `*`) this profile may address.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repositories: Vec<String>,
    /// Explicitly denied GitHub.com repositories or owner wildcards; always takes precedence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_repositories: Vec<String>,
    /// Optional allowlist/denylist for managed `gh` subcommands.
    #[serde(default, skip_serializing_if = "CommandPolicy::is_default")]
    pub commands: CommandPolicy,
}

impl GitHubBinding {
    pub fn permits_repository(&self, repository: &str) -> bool {
        crate::destination::repository_is_permitted(
            repository,
            &self.repositories,
            &self.deny_repositories,
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpsCredentialPolicy {
    pub host: String,
    pub helper: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
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

#[derive(Debug, Clone, Serialize)]
pub struct ScopePolicy {
    pub name: String,
    pub path: PathBuf,
    pub profile: String,
    pub git: GitPolicy,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GitPolicy {
    pub author: Identity,
    pub committer: Identity,
    pub signing: Option<SigningPolicy>,
    pub push: Option<PushPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remotes: Vec<RemotePolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_destinations: Vec<String>,
    #[serde(default, skip_serializing_if = "CommandPolicy::is_default")]
    pub commands: CommandPolicy,
    #[serde(default, skip_serializing_if = "is_false")]
    pub strict_repo_hooks: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub strict_git_filters: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub strict_merge_drivers: bool,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub inherit_git_config: bool,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub cross_profile_identity_check: bool,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProvenanceMode {
    /// Trust commits reachable from `refs/remotes/<remote>/*` tracking refs, while
    /// enforcing active profile identity/signing on local commits and blocking
    /// cross-profile identity leaks.
    #[default]
    RemoteTracking,
    /// Trust only commits ancestral to explicitly pinned `upstream_baselines` OIDs.
    Pinned,
    /// Do not exempt upstream commits; enforce local policy on all outgoing commits.
    Off,
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
    /// Exact remote name (or `*` for any matching remote) accepted by the push audit.
    pub remote: String,
    /// Allowed destinations or wildcard destination patterns accepted by the push audit.
    pub destinations: Vec<String>,
    /// Explicitly permits upstream/cherry-picked author identities to be preserved.
    #[serde(default, skip_serializing_if = "is_false")]
    pub preserve_authors: bool,
    /// Permit a branch to be published when the remote ref does not exist yet.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub allow_initial_push: bool,
    /// Permit a branch update only when local object evidence proves fast-forward.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub allow_fast_forward: bool,
    /// Permit annotated tags only after signature-policy verification.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_annotated_tags: bool,
    /// Permit lightweight tags only by explicit opt-in.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_lightweight_tags: bool,
    /// Permit branch ref deletion only by explicit opt-in.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_branch_deletion: bool,
    /// Permit tag ref deletion only by explicit opt-in.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_tag_deletion: bool,
    /// Permit rewrites with an expected remote OID lease.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_force_with_lease: bool,
    /// Permit unleased force updates (`--force` / `+refspec`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_force_push: bool,
    /// Require an explicit zero-OID `--force-with-lease` when creating a new remote tag.
    #[serde(default, skip_serializing_if = "is_false")]
    pub require_tag_lease_on_create: bool,
    /// How upstream commit provenance is checked during push audits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_provenance: Option<UpstreamProvenanceMode>,
    /// Explicitly pinned remote-tracking baselines; required when `upstream_provenance = "pinned"`.
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

impl PushPolicy {
    pub fn effective_upstream_provenance(&self) -> UpstreamProvenanceMode {
        self.upstream_provenance
            .unwrap_or(if self.upstream_baselines.is_empty() {
                UpstreamProvenanceMode::RemoteTracking
            } else {
                UpstreamProvenanceMode::Pinned
            })
    }
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
            allow_force_push: false,
            require_tag_lease_on_create: false,
            upstream_provenance: None,
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

// ---------------------------------------------------------------------------
// Schema v4 Wire Representation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ConfigV4 {
    version: u32,
    #[serde(default)]
    profiles: BTreeMap<String, ProfileV4>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    scopes: BTreeMap<String, TopLevelScopeV4>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TopLevelScopeV4 {
    path: PathBuf,
    profile: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct NamedScopeV4 {
    name: String,
    path: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
enum ProfileScopeV4 {
    Path(PathBuf),
    Named(NamedScopeV4),
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ProfileV4 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extends: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    scopes: Vec<ProfileScopeV4>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    author: Option<Identity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    committer: Option<Identity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signing: Option<SigningPolicyV4>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    git: Option<GitPolicyV4>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    github: Option<GitHubPolicyV4>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ssh: Option<SshSectionV4>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    https: Option<BTreeMap<String, HttpsHelperV4>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    run: Option<CommandPolicy>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SigningPolicyV4 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    format: Option<SigningFormat>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_key: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct GitPolicyV4 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remote: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    push: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fetch: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deny: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remotes: Option<BTreeMap<String, RemotePolicyV4>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    preserve_authors: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allow_initial_push: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allow_fast_forward: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allow_annotated_tags: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allow_lightweight_tags: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allow_branch_deletion: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allow_tag_deletion: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allow_force_with_lease: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allow_force_push: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    require_tag_lease_on_create: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    upstream_provenance: Option<UpstreamProvenanceMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    baselines: Option<Vec<UpstreamBaseline>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commands: Option<CommandPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    strict_repo_hooks: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    strict_git_filters: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    strict_merge_drivers: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inherit_git_config: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cross_profile_identity_check: Option<bool>,
}

impl GitPolicyV4 {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RemotePolicyV4 {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    fetch: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    push: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct GitHubPolicyV4 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_selector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    repos: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deny_repos: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commands: Option<CommandPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    merge: Option<BTreeMap<String, GitHubMergeRuleV4>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct GitHubMergeRuleV4 {
    base_branches: Vec<String>,
    strategies: Vec<MergeStrategy>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SshSectionV4 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hosts: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_key: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_socket: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    known_hosts_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extra: Option<Vec<SshEntryV4>>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SshEntryV4 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hosts: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_key: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_socket: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    known_hosts_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HttpsHelperV4 {
    helper: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    args: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct VersionProbe {
    version: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    InvalidToml(String),
    Serialization,
    UnsupportedVersion(u32),
    EmptyProfiles,
    EmptyScopes,
    InvalidProfileName,
    DuplicateProfileName(String),
    MissingProfile(String),
    ProfileInUse(String),
    UnknownParentProfile { profile: String, parent: String },
    CyclicProfileInheritance(String),
    AmbiguousIdentity { profile: String },
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
    InvalidGitCommandPolicy { scope: String },
    InvalidRunCommandPolicy { profile: String },
    InvalidSshPolicy { profile: String },
    InvalidHttpsCredentialPolicy { profile: String },
}

#[derive(Debug)]
pub enum ConfigLoadError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Invalid(ConfigError),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidToml(detail) => {
                write!(f, "configuration file contains invalid TOML: {detail}")
            }
            Self::Serialization => write!(f, "cannot serialize configuration to TOML"),
            Self::UnsupportedVersion(version) => write!(
                f,
                "unsupported configuration version {version} (UnsupportedVersion({version})); Persona 0.2.0 requires `version = {CURRENT_CONFIG_VERSION}`"
            ),
            Self::EmptyProfiles => write!(f, "configuration must define at least one profile"),
            Self::EmptyScopes => write!(f, "configuration must define at least one scope"),
            Self::InvalidProfileName => write!(f, "profile name is empty or invalid"),
            Self::DuplicateProfileName(name) => write!(f, "duplicate profile `{name}`"),
            Self::MissingProfile(name) => write!(f, "profile `{name}` does not exist"),
            Self::ProfileInUse(name) => write!(
                f,
                "cannot remove profile `{name}` while it is referenced by scopes or child profiles"
            ),
            Self::UnknownParentProfile { profile, parent } => {
                write!(f, "profile `{profile}` extends unknown profile `{parent}`")
            }
            Self::CyclicProfileInheritance(profile) => write!(
                f,
                "profile `{profile}` contains cyclic or excessively deep `extends` inheritance"
            ),
            Self::AmbiguousIdentity { profile } => write!(
                f,
                "profile `{profile}` cannot combine top-level `name`/`email` with explicit `author`"
            ),
            Self::UnknownProfile { scope, profile } => write!(
                f,
                "scope `{scope}` references unknown profile `{profile}` (UnknownProfile)"
            ),
            Self::UnknownScope(name) => write!(f, "scope `{name}` does not exist"),
            Self::InvalidScopeName => write!(f, "scope name is empty or invalid"),
            Self::DuplicateScopeName(name) => write!(f, "duplicate scope `{name}`"),
            Self::DuplicateScopeRoot(path) => {
                write!(f, "duplicate scope directory `{}`", path.display())
            }
            Self::RelativeScopePath(path) => write!(
                f,
                "scope path `{}` must be an absolute directory path (or start with `~/`)",
                path.display()
            ),
            Self::EmptyIdentity { scope, role } => {
                write!(
                    f,
                    "profile/scope `{scope}` has an empty Git {role} identity"
                )
            }
            Self::InvalidSigningFingerprint { scope } => write!(
                f,
                "profile/scope `{scope}` has an invalid signing key fingerprint"
            ),
            Self::RelativeSigningKey { scope, path } => write!(
                f,
                "profile/scope `{scope}` signing key path `{}` must be absolute (or start with `~/`)",
                path.display()
            ),
            Self::EmptyPushRemote { scope } => {
                write!(f, "profile/scope `{scope}` push remote cannot be empty")
            }
            Self::EmptyPushDestinations { scope } => write!(
                f,
                "profile/scope `{scope}` push policy requires at least one destination"
            ),
            Self::EmptyPushDestination { scope } => write!(
                f,
                "profile/scope `{scope}` contains an empty or invalid push destination"
            ),
            Self::AnnotatedTagsRequireSigning { scope } => write!(
                f,
                "profile/scope `{scope}` allows annotated tags without a signing policy"
            ),
            Self::InvalidUpstreamBaseline { scope } => write!(
                f,
                "profile/scope `{scope}` contains an invalid upstream baseline entry"
            ),
            Self::InvalidGithubBinding { profile } => write!(
                f,
                "profile `{profile}` has an invalid GitHub account binding or repository rule"
            ),
            Self::InvalidGithubMergePolicy { profile } => write!(
                f,
                "profile `{profile}` has an invalid GitHub server-side merge policy"
            ),
            Self::InvalidRemotePolicy { scope } => {
                write!(f, "profile/scope `{scope}` has an invalid remote policy")
            }
            Self::InvalidGitCommandPolicy { scope } => write!(
                f,
                "profile/scope `{scope}` has an invalid Git command allowlist/denylist rule"
            ),
            Self::InvalidRunCommandPolicy { profile } => write!(
                f,
                "profile `{profile}` has an invalid `persona run` command allowlist/denylist rule"
            ),
            Self::InvalidSshPolicy { profile } => {
                write!(f, "profile `{profile}` has an invalid SSH transport policy")
            }
            Self::InvalidHttpsCredentialPolicy { profile } => write!(
                f,
                "profile `{profile}` has an invalid HTTPS credential helper policy"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

impl std::fmt::Display for ConfigLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(
                    f,
                    "cannot read configuration at {}: {source}",
                    path.display()
                )
            }
            Self::Invalid(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ConfigLoadError {}

impl Config {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        Self::parse_with_home(input, home.as_deref())
    }

    pub fn parse_with_home(input: &str, home: Option<&Path>) -> Result<Self, ConfigError> {
        let probe: VersionProbe =
            toml::from_str(input).map_err(|error| ConfigError::InvalidToml(error.to_string()))?;
        if probe.version != CURRENT_CONFIG_VERSION {
            return Err(ConfigError::UnsupportedVersion(probe.version));
        }
        let raw: ConfigV4 =
            toml::from_str(input).map_err(|error| ConfigError::InvalidToml(error.to_string()))?;
        Self::from_raw_v4(raw, home)
    }

    pub fn load(path: &Path) -> Result<Self, ConfigLoadError> {
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigLoadError::Read {
            path: path.to_path_buf(),
            source,
        })?;

        Self::parse(&contents).map_err(ConfigLoadError::Invalid)
    }

    fn from_raw_v4(raw: ConfigV4, home: Option<&Path>) -> Result<Self, ConfigError> {
        if raw.version != CURRENT_CONFIG_VERSION {
            return Err(ConfigError::UnsupportedVersion(raw.version));
        }
        if raw.profiles.is_empty() {
            return Err(ConfigError::EmptyProfiles);
        }

        // Validate profile names and parent references first.
        for (name, entry) in &raw.profiles {
            if !valid_profile_name(name) {
                return Err(ConfigError::InvalidProfileName);
            }
            if let Some(parent) = &entry.extends {
                if !raw.profiles.contains_key(parent) {
                    return Err(ConfigError::UnknownParentProfile {
                        profile: name.clone(),
                        parent: parent.clone(),
                    });
                }
            }
        }

        // Resolve each profile (including `extends` chain, shorthands, defaults, `~/`).
        let mut resolved_profiles = Vec::with_capacity(raw.profiles.len());
        let mut profile_index_by_name = BTreeMap::new();
        for name in raw.profiles.keys() {
            let merged = merge_profile_chain(name, &raw.profiles)?;
            let profile = materialize_profile(name, merged, home)?;
            validate_profile(&profile)?;
            profile_index_by_name.insert(name.clone(), resolved_profiles.len());
            resolved_profiles.push(profile);
        }

        // Collect all scopes: inline `profiles.<name>.scopes` + top-level `[scopes]`.
        let mut seen_names = HashSet::new();
        let mut seen_roots = HashSet::new();
        let mut resolved_scopes = Vec::new();

        for (profile_name, entry) in &raw.profiles {
            let single_inline = entry.scopes.len() == 1;
            for item in &entry.scopes {
                let (scope_name, raw_path) = match item {
                    ProfileScopeV4::Path(path) => (
                        derive_inline_scope_name(profile_name, path, single_inline),
                        path.as_path(),
                    ),
                    ProfileScopeV4::Named(named) => (named.name.clone(), named.path.as_path()),
                };
                validate_scope_name(&scope_name, &mut seen_names)?;
                let path = resolve_policy_path(raw_path, home)
                    .ok_or_else(|| ConfigError::RelativeScopePath(raw_path.to_path_buf()))?;
                if !seen_roots.insert(path.clone()) {
                    return Err(ConfigError::DuplicateScopeRoot(path));
                }
                let profile = &resolved_profiles[profile_index_by_name[profile_name]];
                validate_git_policy(&scope_name, &profile.git)?;
                resolved_scopes.push(ScopePolicy {
                    name: scope_name,
                    path,
                    profile: profile.name.clone(),
                    git: profile.git.clone(),
                });
            }
        }

        for (scope_name, entry) in &raw.scopes {
            validate_scope_name(scope_name, &mut seen_names)?;
            let path = resolve_policy_path(&entry.path, home)
                .ok_or_else(|| ConfigError::RelativeScopePath(entry.path.clone()))?;
            if !seen_roots.insert(path.clone()) {
                return Err(ConfigError::DuplicateScopeRoot(path));
            }
            let Some(&index) = profile_index_by_name.get(&entry.profile) else {
                return Err(ConfigError::UnknownProfile {
                    scope: scope_name.clone(),
                    profile: entry.profile.clone(),
                });
            };
            let profile = &resolved_profiles[index];
            validate_git_policy(scope_name, &profile.git)?;
            resolved_scopes.push(ScopePolicy {
                name: scope_name.clone(),
                path,
                profile: profile.name.clone(),
                git: profile.git.clone(),
            });
        }

        if resolved_scopes.is_empty() {
            return Err(ConfigError::EmptyScopes);
        }

        Ok(Self {
            version: CURRENT_CONFIG_VERSION,
            raw,
            profiles: resolved_profiles,
            scopes: resolved_scopes,
        })
    }

    pub fn single_scope(
        profile: Profile,
        scope_name: String,
        scope_path: PathBuf,
    ) -> Result<Self, ConfigError> {
        if !valid_profile_name(&profile.name) {
            return Err(ConfigError::InvalidProfileName);
        }
        let mut names = HashSet::new();
        validate_scope_name(&scope_name, &mut names)?;
        let home = std::env::var_os("HOME").map(PathBuf::from);
        if resolve_policy_path(&scope_path, home.as_deref()).is_none() {
            return Err(ConfigError::RelativeScopePath(scope_path));
        }
        let mut raw_profile = profile_to_v4(&profile, None, None);
        raw_profile.scopes = vec![if scope_name == profile.name {
            ProfileScopeV4::Path(scope_path)
        } else {
            ProfileScopeV4::Named(NamedScopeV4 {
                name: scope_name,
                path: scope_path,
            })
        }];
        let mut profiles = BTreeMap::new();
        profiles.insert(profile.name, raw_profile);
        let raw = ConfigV4 {
            version: CURRENT_CONFIG_VERSION,
            profiles,
            scopes: BTreeMap::new(),
        };
        Self::from_raw_v4(raw, home.as_deref())
    }

    pub fn add_profile(&mut self, profile: Profile) -> Result<(), ConfigError> {
        if !valid_profile_name(&profile.name) {
            return Err(ConfigError::InvalidProfileName);
        }
        if self.raw.profiles.contains_key(&profile.name) {
            return Err(ConfigError::DuplicateProfileName(profile.name));
        }
        let parent = profile
            .extends
            .as_deref()
            .and_then(|parent| self.profiles.iter().find(|item| item.name == parent));
        let mut next_raw = self.raw.clone();
        next_raw
            .profiles
            .insert(profile.name.clone(), profile_to_v4(&profile, parent, None));
        let home = std::env::var_os("HOME").map(PathBuf::from);
        *self = Self::from_raw_v4(next_raw, home.as_deref())?;
        Ok(())
    }

    pub fn update_profile(&mut self, profile: Profile) -> Result<(), ConfigError> {
        if !self.raw.profiles.contains_key(&profile.name) {
            return Err(ConfigError::MissingProfile(profile.name));
        }
        let existing_raw = self.raw.profiles.get(&profile.name).cloned();
        let parent = profile
            .extends
            .as_deref()
            .and_then(|parent| self.profiles.iter().find(|item| item.name == parent));
        let mut updated_raw = profile_to_v4(&profile, parent, existing_raw.as_ref());
        if let Some(prev) = existing_raw {
            updated_raw.scopes = prev.scopes;
        }
        let mut next_raw = self.raw.clone();
        next_raw.profiles.insert(profile.name.clone(), updated_raw);
        let home = std::env::var_os("HOME").map(PathBuf::from);
        *self = Self::from_raw_v4(next_raw, home.as_deref())?;
        Ok(())
    }

    pub fn update_profile_baselines(
        &mut self,
        profile_name: &str,
        baselines: Vec<UpstreamBaseline>,
    ) -> Result<(), ConfigError> {
        let Some(existing) = self.raw.profiles.get(profile_name) else {
            return Err(ConfigError::MissingProfile(profile_name.to_owned()));
        };
        let mut next_raw = self.raw.clone();
        let entry = next_raw
            .profiles
            .get_mut(profile_name)
            .expect("profile checked above");
        let _ = existing;
        let git = entry.git.get_or_insert_with(GitPolicyV4::default);
        git.baselines = Some(baselines);
        let home = std::env::var_os("HOME").map(PathBuf::from);
        *self = Self::from_raw_v4(next_raw, home.as_deref())?;
        Ok(())
    }

    pub fn remove_profile(&mut self, name: &str) -> Result<(), ConfigError> {
        if self.scopes.iter().any(|scope| scope.profile == name) {
            return Err(ConfigError::ProfileInUse(name.to_owned()));
        }
        if self
            .raw
            .profiles
            .iter()
            .any(|(other, profile)| other != name && profile.extends.as_deref() == Some(name))
        {
            return Err(ConfigError::ProfileInUse(name.to_owned()));
        }
        if !self.raw.profiles.contains_key(name) {
            return Err(ConfigError::MissingProfile(name.to_owned()));
        }
        if self.raw.profiles.len() == 1 {
            return Err(ConfigError::EmptyProfiles);
        }
        let mut next_raw = self.raw.clone();
        next_raw.profiles.remove(name);
        let home = std::env::var_os("HOME").map(PathBuf::from);
        *self = Self::from_raw_v4(next_raw, home.as_deref())?;
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
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let resolved_path = resolve_policy_path(&path, home.as_deref())
            .ok_or_else(|| ConfigError::RelativeScopePath(path.clone()))?;
        if self.scopes.iter().any(|scope| scope.path == resolved_path) {
            return Err(ConfigError::DuplicateScopeRoot(resolved_path));
        }
        if !self.raw.profiles.contains_key(profile_name) {
            return Err(ConfigError::UnknownProfile {
                scope: name,
                profile: profile_name.to_owned(),
            });
        }
        let mut next_raw = self.raw.clone();
        if !next_raw.scopes.is_empty() {
            next_raw.scopes.insert(
                name,
                TopLevelScopeV4 {
                    path,
                    profile: profile_name.to_owned(),
                },
            );
        } else {
            let entry = next_raw
                .profiles
                .get_mut(profile_name)
                .expect("profile exists");
            if entry.scopes.is_empty() && name == profile_name {
                entry.scopes.push(ProfileScopeV4::Path(path));
            } else {
                // Convert any implicit single-path scope to explicit named if adding a second one
                // so its existing name remains stable.
                if entry.scopes.len() == 1 {
                    if let ProfileScopeV4::Path(existing_path) = entry.scopes[0].clone() {
                        entry.scopes[0] = ProfileScopeV4::Named(NamedScopeV4 {
                            name: profile_name.to_owned(),
                            path: existing_path,
                        });
                    }
                }
                entry
                    .scopes
                    .push(ProfileScopeV4::Named(NamedScopeV4 { name, path }));
            }
        }
        *self = Self::from_raw_v4(next_raw, home.as_deref())?;
        Ok(())
    }

    pub fn update_scope(
        &mut self,
        name: &str,
        path: PathBuf,
        profile_name: &str,
    ) -> Result<(), ConfigError> {
        if !self.scopes.iter().any(|scope| scope.name == name) {
            return Err(ConfigError::UnknownScope(name.to_owned()));
        }
        let home = std::env::var_os("HOME").map(PathBuf::from);
        if resolve_policy_path(&path, home.as_deref()).is_none() {
            return Err(ConfigError::RelativeScopePath(path));
        }
        if !self.raw.profiles.contains_key(profile_name) {
            return Err(ConfigError::UnknownProfile {
                scope: name.to_owned(),
                profile: profile_name.to_owned(),
            });
        }
        let mut next_raw = self.raw.clone();
        if next_raw.scopes.contains_key(name) {
            next_raw.scopes.insert(
                name.to_owned(),
                TopLevelScopeV4 {
                    path,
                    profile: profile_name.to_owned(),
                },
            );
        } else {
            remove_inline_scope_by_name(&mut next_raw.profiles, name);
            let target = next_raw
                .profiles
                .get_mut(profile_name)
                .expect("profile exists");
            if target.scopes.is_empty() && name == profile_name {
                target.scopes.push(ProfileScopeV4::Path(path));
            } else {
                if target.scopes.len() == 1 {
                    if let ProfileScopeV4::Path(existing_path) = target.scopes[0].clone() {
                        target.scopes[0] = ProfileScopeV4::Named(NamedScopeV4 {
                            name: profile_name.to_owned(),
                            path: existing_path,
                        });
                    }
                }
                target.scopes.push(ProfileScopeV4::Named(NamedScopeV4 {
                    name: name.to_owned(),
                    path,
                }));
            }
        }
        *self = Self::from_raw_v4(next_raw, home.as_deref())?;
        Ok(())
    }

    pub fn remove_scope(&mut self, name: &str) -> Result<(), ConfigError> {
        if !self.scopes.iter().any(|scope| scope.name == name) {
            return Err(ConfigError::UnknownScope(name.to_owned()));
        }
        if self.scopes.len() == 1 {
            return Err(ConfigError::EmptyScopes);
        }
        let mut next_raw = self.raw.clone();
        if next_raw.scopes.remove(name).is_none() {
            remove_inline_scope_by_name(&mut next_raw.profiles, name);
        }
        let home = std::env::var_os("HOME").map(PathBuf::from);
        *self = Self::from_raw_v4(next_raw, home.as_deref())?;
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

    /// Serialize the canonical compact v4 configuration, preserving `extends`,
    /// inline scopes, `~/` spellings, and forge shorthands.
    pub fn to_v4_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(&self.raw).map_err(|_| ConfigError::Serialization)
    }

    /// Serialize a single authored profile entry from the v4 configuration.
    pub fn to_profile_v4_toml(&self, name: &str) -> Result<String, ConfigError> {
        let Some(entry) = self.raw.profiles.get(name) else {
            return Err(ConfigError::MissingProfile(name.to_owned()));
        };
        let mut profiles = BTreeMap::new();
        profiles.insert(name.to_owned(), entry.clone());
        let scopes: BTreeMap<String, TopLevelScopeV4> = self
            .raw
            .scopes
            .iter()
            .filter(|(_, scope)| scope.profile == name)
            .map(|(scope_name, scope)| (scope_name.clone(), scope.clone()))
            .collect();
        let subset = ConfigV4 {
            version: CURRENT_CONFIG_VERSION,
            profiles,
            scopes,
        };
        toml::to_string_pretty(&subset).map_err(|_| ConfigError::Serialization)
    }

    /// Serialize a single fully resolved (flattened) profile entry.
    pub fn to_resolved_profile_v4_toml(&self, name: &str) -> Result<String, ConfigError> {
        let Some(profile) = self.profiles.iter().find(|item| item.name == name) else {
            return Err(ConfigError::MissingProfile(name.to_owned()));
        };
        let mut resolved_entry = profile_to_v4(profile, None, None);
        resolved_entry.extends = None;
        let matching_scopes: Vec<&ScopePolicy> = self
            .scopes
            .iter()
            .filter(|scope| scope.profile == profile.name)
            .collect();
        resolved_entry.scopes = matching_scopes
            .iter()
            .map(|scope| {
                if scope.name == profile.name && matching_scopes.len() == 1 {
                    ProfileScopeV4::Path(scope.path.clone())
                } else {
                    ProfileScopeV4::Named(NamedScopeV4 {
                        name: scope.name.clone(),
                        path: scope.path.clone(),
                    })
                }
            })
            .collect();
        let mut profiles = BTreeMap::new();
        profiles.insert(profile.name.clone(), resolved_entry);
        let subset = ConfigV4 {
            version: CURRENT_CONFIG_VERSION,
            profiles,
            scopes: BTreeMap::new(),
        };
        toml::to_string_pretty(&subset).map_err(|_| ConfigError::Serialization)
    }

    /// Serialize a fully resolved (flattened) v4 view of the configuration with
    /// all `extends`, defaults, `~/` paths, and forge shorthands expanded.
    pub fn to_resolved_v4_toml(&self) -> Result<String, ConfigError> {
        let mut profiles = BTreeMap::new();
        for profile in &self.profiles {
            let mut resolved_entry = profile_to_v4(profile, None, None);
            resolved_entry.extends = None;
            resolved_entry.scopes = self
                .scopes
                .iter()
                .filter(|scope| scope.profile == profile.name)
                .map(|scope| {
                    if scope.name == profile.name
                        && self
                            .scopes
                            .iter()
                            .filter(|s| s.profile == profile.name)
                            .count()
                            == 1
                    {
                        ProfileScopeV4::Path(scope.path.clone())
                    } else {
                        ProfileScopeV4::Named(NamedScopeV4 {
                            name: scope.name.clone(),
                            path: scope.path.clone(),
                        })
                    }
                })
                .collect();
            profiles.insert(profile.name.clone(), resolved_entry);
        }
        let resolved = ConfigV4 {
            version: CURRENT_CONFIG_VERSION,
            profiles,
            scopes: BTreeMap::new(),
        };
        toml::to_string_pretty(&resolved).map_err(|_| ConfigError::Serialization)
    }
}

impl GitPolicy {
    pub fn configured_fetch_destinations(&self, remote_name: &str) -> Option<&[String]> {
        self.remotes
            .iter()
            .find(|remote| remote.name == remote_name)
            .or_else(|| self.remotes.iter().find(|remote| remote.name == "*"))
            .map(|remote| remote.fetch_destinations.as_slice())
            .or_else(|| {
                self.push
                    .as_ref()
                    .filter(|push| push.remote == remote_name || push.remote == "*")
                    .map(|push| push.destinations.as_slice())
            })
    }

    pub fn configured_push_destinations(&self, remote_name: &str) -> Option<&[String]> {
        self.remotes
            .iter()
            .find(|remote| remote.name == remote_name)
            .or_else(|| self.remotes.iter().find(|remote| remote.name == "*"))
            .map(|remote| remote.push_destinations.as_slice())
            .or_else(|| {
                self.push
                    .as_ref()
                    .filter(|push| push.remote == remote_name || push.remote == "*")
                    .map(|push| push.destinations.as_slice())
            })
    }

    pub fn permits_fetch_destination(&self, remote_name: &str, destination: &str) -> bool {
        let Some(allowed) = self.configured_fetch_destinations(remote_name) else {
            return false;
        };
        crate::destination::destination_is_permitted(destination, allowed, &self.deny_destinations)
    }

    pub fn permits_push_destination(&self, remote_name: &str, destination: &str) -> bool {
        let Some(allowed) = self.configured_push_destinations(remote_name) else {
            return false;
        };
        crate::destination::destination_is_permitted(destination, allowed, &self.deny_destinations)
    }
}

// ---------------------------------------------------------------------------
// Inheritance, Resolution, Shorthands & Serialization Helpers
// ---------------------------------------------------------------------------

fn valid_profile_name(name: &str) -> bool {
    !name.trim().is_empty() && name.trim() == name
}

fn derive_inline_scope_name(profile_name: &str, path: &Path, is_single: bool) -> String {
    if is_single {
        return profile_name.to_owned();
    }
    let basename = path
        .file_name()
        .and_then(|part| part.to_str())
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .unwrap_or("root");
    format!("{profile_name}:{basename}")
}

fn remove_inline_scope_by_name(profiles: &mut BTreeMap<String, ProfileV4>, target_name: &str) {
    for (profile_name, entry) in profiles.iter_mut() {
        let is_single = entry.scopes.len() == 1;
        entry.scopes.retain(|item| {
            let derived = match item {
                ProfileScopeV4::Path(path) => {
                    derive_inline_scope_name(profile_name, path, is_single)
                }
                ProfileScopeV4::Named(named) => named.name.clone(),
            };
            derived != target_name
        });
    }
}

fn resolve_policy_path(path: &Path, home: Option<&Path>) -> Option<PathBuf> {
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    let text = path.to_str()?;
    let rest = if text == "~" {
        ""
    } else {
        text.strip_prefix("~/")?
    };
    let home = home.filter(|candidate| candidate.is_absolute())?;
    let suffix = Path::new(rest);
    if suffix.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return None;
    }
    Some(if rest.is_empty() {
        home.to_path_buf()
    } else {
        home.join(suffix)
    })
}

fn append_pub_extension(path: &Path) -> PathBuf {
    let mut os = OsString::from(path.as_os_str());
    os.push(".pub");
    PathBuf::from(os)
}

fn default_known_hosts_path(home: Option<&Path>) -> Option<PathBuf> {
    resolve_policy_path(Path::new("~/.ssh/known_hosts"), home)
}

fn expand_destination_list(entries: &[String]) -> Result<Vec<String>, ()> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for entry in entries {
        for expanded in expand_destination_entry(entry)? {
            if seen.insert(expanded.clone()) {
                out.push(expanded);
            }
        }
    }
    Ok(out)
}

/// Expand v4 forge shorthands (`host/owner/*`, `host/*`, `host/owner/repo`)
/// into explicit SSH + HTTPS destination patterns while leaving explicit URLs
/// (`git@...`, `ssh://...`, `https://...`, `file://...`, `/abs/path`, `*`) intact.
fn expand_destination_entry(entry: &str) -> Result<Vec<String>, ()> {
    if entry.is_empty()
        || entry.trim() != entry
        || entry
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(());
    }
    if entry == "*"
        || entry.starts_with("https://")
        || entry.starts_with("ssh://")
        || entry.starts_with("file://")
        || entry.starts_with('/')
        || entry.contains('@')
        || entry.contains(':')
    {
        if !crate::destination::valid_destination_pattern(entry) {
            return Err(());
        }
        return Ok(vec![entry.to_owned()]);
    }
    // Reject obvious relative paths like `./foo`, `../foo`, `~/foo` or `hostless/path`.
    if entry.starts_with('.') || entry.starts_with('~') {
        return Err(());
    }
    let Some((host, path)) = entry.split_once('/') else {
        return Err(());
    };
    if !host.contains('.') || !valid_ssh_host(host) || path.is_empty() {
        return Err(());
    }
    if entry.contains(['?', '#', '%', '\\']) || entry.contains("..") {
        return Err(());
    }
    let expanded = if path == "*" {
        vec![format!("git@{host}:*"), format!("https://{host}/*")]
    } else if path.ends_with("/*") || path.ends_with(".git") {
        vec![
            format!("git@{host}:{path}"),
            format!("https://{host}/{path}"),
        ]
    } else {
        vec![
            format!("git@{host}:{path}.git"),
            format!("https://{host}/{path}.git"),
            format!("git@{host}:{path}"),
            format!("https://{host}/{path}"),
        ]
    };
    if expanded
        .iter()
        .any(|candidate| !crate::destination::valid_destination_pattern(candidate))
    {
        return Err(());
    }
    Ok(expanded)
}

#[derive(Debug, Clone)]
struct MergedProfile {
    extends: Option<String>,
    author: Option<Identity>,
    committer: Option<Identity>,
    signing: Option<SigningPolicyV4>,
    git: GitPolicyV4,
    github: Option<GitHubPolicyV4>,
    ssh: Option<SshSectionV4>,
    https: BTreeMap<String, HttpsHelperV4>,
    run: CommandPolicy,
}

fn merge_profile_chain(
    name: &str,
    profiles: &BTreeMap<String, ProfileV4>,
) -> Result<MergedProfile, ConfigError> {
    let mut chain = Vec::new();
    let mut visited = HashSet::new();
    let mut current = name;
    loop {
        if !visited.insert(current) || chain.len() >= MAX_EXTENDS_DEPTH {
            return Err(ConfigError::CyclicProfileInheritance(name.to_owned()));
        }
        let entry = profiles
            .get(current)
            .ok_or_else(|| ConfigError::UnknownParentProfile {
                profile: name.to_owned(),
                parent: current.to_owned(),
            })?;
        chain.push((current, entry));
        match entry.extends.as_deref() {
            Some(parent) => current = parent,
            None => break,
        }
    }

    let mut merged = MergedProfile {
        extends: profiles[name].extends.clone(),
        author: None,
        committer: None,
        signing: None,
        git: GitPolicyV4::default(),
        github: None,
        ssh: None,
        https: BTreeMap::new(),
        run: CommandPolicy::default(),
    };

    // Apply from root ancestor down to leaf child.
    for (step_name, layer) in chain.into_iter().rev() {
        apply_profile_layer(step_name, &mut merged, layer)?;
    }

    Ok(merged)
}

fn apply_profile_layer(
    profile_name: &str,
    target: &mut MergedProfile,
    layer: &ProfileV4,
) -> Result<(), ConfigError> {
    // Reject ambiguous identity specification within a single profile layer.
    if layer.author.is_some() && (layer.name.is_some() || layer.email.is_some()) {
        return Err(ConfigError::AmbiguousIdentity {
            profile: profile_name.to_owned(),
        });
    }

    if let Some(author) = &layer.author {
        target.author = Some(author.clone());
        if layer.committer.is_none() && target.committer.is_none() {
            target.committer = Some(author.clone());
        }
    } else if layer.name.is_some() || layer.email.is_some() {
        let prev_author = target.author.clone();
        let prev_committer = target.committer.clone();
        let new_author = Identity {
            name: layer
                .name
                .clone()
                .or_else(|| prev_author.as_ref().map(|id| id.name.clone()))
                .unwrap_or_default(),
            email: layer
                .email
                .clone()
                .or_else(|| prev_author.as_ref().map(|id| id.email.clone()))
                .unwrap_or_default(),
        };
        let new_committer = Identity {
            name: layer
                .name
                .clone()
                .or_else(|| prev_committer.as_ref().map(|id| id.name.clone()))
                .unwrap_or_else(|| new_author.name.clone()),
            email: layer
                .email
                .clone()
                .or_else(|| prev_committer.as_ref().map(|id| id.email.clone()))
                .unwrap_or_else(|| new_author.email.clone()),
        };
        target.author = Some(new_author);
        target.committer = Some(new_committer);
    }

    if let Some(committer) = &layer.committer {
        target.committer = Some(committer.clone());
    }

    if let Some(signing) = &layer.signing {
        let base = target.signing.get_or_insert_with(SigningPolicyV4::default);
        if signing.fingerprint.is_some() {
            base.fingerprint = signing.fingerprint.clone();
        }
        if signing.format.is_some() {
            base.format = signing.format;
        }
        if signing.public_key.is_some() {
            base.public_key = signing.public_key.clone();
        }
    }

    if let Some(git) = &layer.git {
        merge_git_layer(&mut target.git, git);
    }

    if let Some(github) = &layer.github {
        let base = target.github.get_or_insert_with(GitHubPolicyV4::default);
        if github.host.is_some() {
            base.host = github.host.clone();
        }
        if github.account_id.is_some() {
            base.account_id = github.account_id.clone();
        }
        if github.account_selector.is_some() {
            base.account_selector = github.account_selector.clone();
        }
        if github.token_fingerprint.is_some() {
            base.token_fingerprint = github.token_fingerprint.clone();
        }
        if github.repos.is_some() {
            base.repos = github.repos.clone();
        }
        if github.deny_repos.is_some() {
            base.deny_repos = github.deny_repos.clone();
        }
        if github.commands.is_some() {
            base.commands = github.commands.clone();
        }
        if github.merge.is_some() {
            base.merge = github.merge.clone();
        }
    }

    if let Some(ssh) = &layer.ssh {
        if ssh.host.is_some() && ssh.hosts.is_some() {
            return Err(ConfigError::InvalidSshPolicy {
                profile: profile_name.to_owned(),
            });
        }
        if ssh.identity_file.is_some() && ssh.agent_socket.is_some() {
            return Err(ConfigError::InvalidSshPolicy {
                profile: profile_name.to_owned(),
            });
        }
        let base = target.ssh.get_or_insert_with(SshSectionV4::default);
        if ssh.host.is_some() {
            base.host = ssh.host.clone();
            base.hosts = None;
        } else if ssh.hosts.is_some() {
            base.hosts = ssh.hosts.clone();
            base.host = None;
        }
        if ssh.user.is_some() {
            base.user = ssh.user.clone();
        }
        if ssh.port.is_some() {
            base.port = ssh.port;
        }
        if ssh.fingerprint.is_some() {
            base.fingerprint = ssh.fingerprint.clone();
        }
        if ssh.public_key.is_some() {
            base.public_key = ssh.public_key.clone();
        }
        if ssh.identity_file.is_some() {
            base.identity_file = ssh.identity_file.clone();
            base.agent_socket = None;
        } else if ssh.agent_socket.is_some() {
            base.agent_socket = ssh.agent_socket.clone();
            base.identity_file = None;
        }
        if ssh.known_hosts_file.is_some() {
            base.known_hosts_file = ssh.known_hosts_file.clone();
        }
        if ssh.extra.is_some() {
            base.extra = ssh.extra.clone();
        }
    }

    if let Some(https) = &layer.https {
        target.https = https.clone();
    }

    if let Some(run) = &layer.run {
        target.run = run.clone();
    }

    Ok(())
}

fn merge_git_layer(target: &mut GitPolicyV4, layer: &GitPolicyV4) {
    if layer.remote.is_some() {
        target.remote = layer.remote.clone();
    }
    if layer.push.is_some() {
        target.push = layer.push.clone();
    }
    if layer.fetch.is_some() {
        target.fetch = layer.fetch.clone();
    }
    if layer.deny.is_some() {
        target.deny = layer.deny.clone();
    }
    if layer.remotes.is_some() {
        target.remotes = layer.remotes.clone();
    }
    if layer.preserve_authors.is_some() {
        target.preserve_authors = layer.preserve_authors;
    }
    if layer.allow_initial_push.is_some() {
        target.allow_initial_push = layer.allow_initial_push;
    }
    if layer.allow_fast_forward.is_some() {
        target.allow_fast_forward = layer.allow_fast_forward;
    }
    if layer.allow_annotated_tags.is_some() {
        target.allow_annotated_tags = layer.allow_annotated_tags;
    }
    if layer.allow_lightweight_tags.is_some() {
        target.allow_lightweight_tags = layer.allow_lightweight_tags;
    }
    if layer.allow_branch_deletion.is_some() {
        target.allow_branch_deletion = layer.allow_branch_deletion;
    }
    if layer.allow_tag_deletion.is_some() {
        target.allow_tag_deletion = layer.allow_tag_deletion;
    }
    if layer.allow_force_with_lease.is_some() {
        target.allow_force_with_lease = layer.allow_force_with_lease;
    }
    if layer.allow_force_push.is_some() {
        target.allow_force_push = layer.allow_force_push;
    }
    if layer.require_tag_lease_on_create.is_some() {
        target.require_tag_lease_on_create = layer.require_tag_lease_on_create;
    }
    if layer.upstream_provenance.is_some() {
        target.upstream_provenance = layer.upstream_provenance;
    }
    if layer.baselines.is_some() {
        target.baselines = layer.baselines.clone();
    }
    if layer.commands.is_some() {
        target.commands = layer.commands.clone();
    }
    if layer.strict_repo_hooks.is_some() {
        target.strict_repo_hooks = layer.strict_repo_hooks;
    }
    if layer.strict_git_filters.is_some() {
        target.strict_git_filters = layer.strict_git_filters;
    }
    if layer.strict_merge_drivers.is_some() {
        target.strict_merge_drivers = layer.strict_merge_drivers;
    }
    if layer.inherit_git_config.is_some() {
        target.inherit_git_config = layer.inherit_git_config;
    }
    if layer.cross_profile_identity_check.is_some() {
        target.cross_profile_identity_check = layer.cross_profile_identity_check;
    }
}

fn materialize_profile(
    profile_name: &str,
    merged: MergedProfile,
    home: Option<&Path>,
) -> Result<Profile, ConfigError> {
    let author = merged.author.unwrap_or(Identity {
        name: String::new(),
        email: String::new(),
    });
    let committer = merged.committer.unwrap_or_else(|| author.clone());

    let signing = if let Some(signing_v4) = merged.signing {
        let fingerprint = signing_v4.fingerprint.unwrap_or_default();
        let format = signing_v4.format.unwrap_or_else(|| {
            if fingerprint.starts_with("SHA256:") {
                SigningFormat::Ssh
            } else {
                SigningFormat::OpenPgp
            }
        });
        let raw_key = signing_v4.public_key.unwrap_or_default();
        let public_key =
            resolve_policy_path(&raw_key, home).ok_or_else(|| ConfigError::RelativeSigningKey {
                scope: profile_name.to_owned(),
                path: raw_key,
            })?;
        Some(SigningPolicy {
            fingerprint,
            format,
            public_key,
        })
    } else {
        None
    };

    let git = materialize_git_policy(profile_name, author, committer, signing, merged.git)?;

    let (github, github_merge) = if let Some(gh) = merged.github {
        let binding = GitHubBinding {
            host: gh.host.unwrap_or_else(|| "github.com".to_owned()),
            account_id: gh.account_id.unwrap_or_default(),
            account_selector: gh.account_selector,
            token_fingerprint: gh.token_fingerprint.unwrap_or_default(),
            repositories: gh.repos.unwrap_or_default(),
            deny_repositories: gh.deny_repos.unwrap_or_default(),
            commands: gh.commands.unwrap_or_default(),
        };
        let merge = gh.merge.and_then(|map| {
            if map.is_empty() {
                None
            } else {
                Some(GitHubMergePolicy {
                    repositories: map
                        .into_iter()
                        .map(|(repository, rule)| GitHubMergeRepository {
                            repository,
                            base_branches: rule.base_branches,
                            strategies: rule.strategies,
                        })
                        .collect(),
                })
            }
        });
        (Some(binding), merge)
    } else {
        (None, None)
    };

    let all_ssh = if let Some(ssh) = merged.ssh {
        materialize_ssh_section(profile_name, ssh, home)?
    } else {
        Vec::new()
    };
    let mut ssh_iter = all_ssh.into_iter();
    let ssh = ssh_iter.next();
    let ssh_hosts = ssh_iter.collect();

    let mut https_credentials = Vec::with_capacity(merged.https.len());
    for (host, entry) in merged.https {
        let helper = resolve_policy_path(&entry.helper, home).ok_or_else(|| {
            ConfigError::InvalidHttpsCredentialPolicy {
                profile: profile_name.to_owned(),
            }
        })?;
        https_credentials.push(HttpsCredentialPolicy {
            host,
            helper,
            args: entry.args,
        });
    }

    Ok(Profile {
        name: profile_name.to_owned(),
        extends: merged.extends,
        git,
        github,
        ssh,
        ssh_hosts,
        https_credentials,
        github_merge,
        run: merged.run,
    })
}

fn materialize_git_policy(
    profile_name: &str,
    author: Identity,
    committer: Identity,
    signing: Option<SigningPolicy>,
    raw: GitPolicyV4,
) -> Result<GitPolicy, ConfigError> {
    let deny_destinations = match &raw.deny {
        Some(entries) => {
            expand_destination_list(entries).map_err(|()| ConfigError::InvalidRemotePolicy {
                scope: profile_name.to_owned(),
            })?
        }
        None => Vec::new(),
    };

    let mut remotes = Vec::new();
    if let Some(remote_map) = &raw.remotes {
        for (remote_name, entry) in remote_map {
            let fetch_destinations = expand_destination_list(&entry.fetch).map_err(|()| {
                ConfigError::InvalidRemotePolicy {
                    scope: profile_name.to_owned(),
                }
            })?;
            let push_destinations = expand_destination_list(&entry.push).map_err(|()| {
                ConfigError::InvalidRemotePolicy {
                    scope: profile_name.to_owned(),
                }
            })?;
            remotes.push(RemotePolicy {
                name: remote_name.clone(),
                fetch_destinations,
                push_destinations,
            });
        }
    }

    let push_flags_present = raw.preserve_authors.is_some()
        || raw.allow_initial_push.is_some()
        || raw.allow_fast_forward.is_some()
        || raw.allow_annotated_tags.is_some()
        || raw.allow_lightweight_tags.is_some()
        || raw.allow_branch_deletion.is_some()
        || raw.allow_tag_deletion.is_some()
        || raw.allow_force_with_lease.is_some()
        || raw.allow_force_push.is_some()
        || raw.require_tag_lease_on_create.is_some()
        || raw.upstream_provenance.is_some()
        || raw.baselines.as_ref().is_some_and(|list| !list.is_empty());

    let (push, derived_remotes) = if let Some(push_entries) = &raw.push {
        if push_entries.is_empty() {
            return Err(ConfigError::EmptyPushDestinations {
                scope: profile_name.to_owned(),
            });
        }
        let remote_name = raw.remote.clone().unwrap_or_else(|| "*".to_owned());
        if remote_name.trim().is_empty() {
            return Err(ConfigError::EmptyPushRemote {
                scope: profile_name.to_owned(),
            });
        }
        let destinations = expand_destination_list(push_entries).map_err(|()| {
            if push_entries.iter().any(String::is_empty) {
                ConfigError::EmptyPushDestination {
                    scope: profile_name.to_owned(),
                }
            } else {
                ConfigError::InvalidRemotePolicy {
                    scope: profile_name.to_owned(),
                }
            }
        })?;
        let push_policy = build_push_policy(remote_name.clone(), destinations.clone(), &raw);

        // If `remotes` was not explicitly supplied and `fetch` was supplied,
        // synthesize a single RemotePolicy so fetch and push stay distinct.
        let mut synth = Vec::new();
        if raw.remotes.is_none() {
            if let Some(fetch_entries) = &raw.fetch {
                let fetch_destinations = expand_destination_list(fetch_entries).map_err(|()| {
                    ConfigError::InvalidRemotePolicy {
                        scope: profile_name.to_owned(),
                    }
                })?;
                synth.push(RemotePolicy {
                    name: remote_name,
                    fetch_destinations,
                    push_destinations: destinations,
                });
            }
        } else if raw.fetch.is_some() {
            return Err(ConfigError::InvalidRemotePolicy {
                scope: profile_name.to_owned(),
            });
        }
        (Some(push_policy), synth)
    } else if !remotes.is_empty() {
        if raw.fetch.is_some() {
            return Err(ConfigError::InvalidRemotePolicy {
                scope: profile_name.to_owned(),
            });
        }
        // Derive PushPolicy automatically from `remotes` when push URLs exist.
        let push_remotes: Vec<&RemotePolicy> = remotes
            .iter()
            .filter(|remote| !remote.push_destinations.is_empty())
            .collect();
        let derived_push = if push_remotes.is_empty() {
            if push_flags_present {
                return Err(ConfigError::EmptyPushDestinations {
                    scope: profile_name.to_owned(),
                });
            }
            None
        } else if let Some(explicit_remote) = &raw.remote {
            if explicit_remote.trim().is_empty() {
                return Err(ConfigError::EmptyPushRemote {
                    scope: profile_name.to_owned(),
                });
            }
            if explicit_remote == "*" {
                let mut combined = Vec::new();
                for remote in &push_remotes {
                    for dest in &remote.push_destinations {
                        if !combined.contains(dest) {
                            combined.push(dest.clone());
                        }
                    }
                }
                Some(build_push_policy("*".to_owned(), combined, &raw))
            } else {
                let matched = push_remotes
                    .iter()
                    .find(|remote| remote.name == *explicit_remote)
                    .ok_or_else(|| ConfigError::InvalidRemotePolicy {
                        scope: profile_name.to_owned(),
                    })?;
                Some(build_push_policy(
                    explicit_remote.clone(),
                    matched.push_destinations.clone(),
                    &raw,
                ))
            }
        } else if push_remotes.len() == 1 {
            let only = push_remotes[0];
            Some(build_push_policy(
                only.name.clone(),
                only.push_destinations.clone(),
                &raw,
            ))
        } else {
            let mut combined = Vec::new();
            for remote in &push_remotes {
                for dest in &remote.push_destinations {
                    if !combined.contains(dest) {
                        combined.push(dest.clone());
                    }
                }
            }
            Some(build_push_policy("*".to_owned(), combined, &raw))
        };
        (derived_push, Vec::new())
    } else if let Some(fetch_entries) = &raw.fetch {
        if push_flags_present {
            return Err(ConfigError::EmptyPushDestinations {
                scope: profile_name.to_owned(),
            });
        }
        let remote_name = raw.remote.clone().unwrap_or_else(|| "*".to_owned());
        let fetch_destinations = expand_destination_list(fetch_entries).map_err(|()| {
            ConfigError::InvalidRemotePolicy {
                scope: profile_name.to_owned(),
            }
        })?;
        (
            None,
            vec![RemotePolicy {
                name: remote_name,
                fetch_destinations,
                push_destinations: Vec::new(),
            }],
        )
    } else {
        if push_flags_present || raw.remote.is_some() {
            return Err(ConfigError::EmptyPushDestinations {
                scope: profile_name.to_owned(),
            });
        }
        (None, Vec::new())
    };

    if remotes.is_empty() {
        remotes = derived_remotes;
    }

    Ok(GitPolicy {
        author,
        committer,
        signing,
        push,
        remotes,
        deny_destinations,
        commands: raw.commands.unwrap_or_default(),
        strict_repo_hooks: raw.strict_repo_hooks.unwrap_or(false),
        strict_git_filters: raw.strict_git_filters.unwrap_or(false),
        strict_merge_drivers: raw.strict_merge_drivers.unwrap_or(false),
        inherit_git_config: raw.inherit_git_config.unwrap_or(true),
        cross_profile_identity_check: raw.cross_profile_identity_check.unwrap_or(true),
    })
}

fn build_push_policy(remote: String, destinations: Vec<String>, raw: &GitPolicyV4) -> PushPolicy {
    let defaults = PushPolicy::default();
    PushPolicy {
        remote,
        destinations,
        preserve_authors: raw.preserve_authors.unwrap_or(defaults.preserve_authors),
        allow_initial_push: raw
            .allow_initial_push
            .unwrap_or(defaults.allow_initial_push),
        allow_fast_forward: raw
            .allow_fast_forward
            .unwrap_or(defaults.allow_fast_forward),
        allow_annotated_tags: raw
            .allow_annotated_tags
            .unwrap_or(defaults.allow_annotated_tags),
        allow_lightweight_tags: raw
            .allow_lightweight_tags
            .unwrap_or(defaults.allow_lightweight_tags),
        allow_branch_deletion: raw
            .allow_branch_deletion
            .unwrap_or(defaults.allow_branch_deletion),
        allow_tag_deletion: raw
            .allow_tag_deletion
            .unwrap_or(defaults.allow_tag_deletion),
        allow_force_with_lease: raw
            .allow_force_with_lease
            .unwrap_or(defaults.allow_force_with_lease),
        allow_force_push: raw.allow_force_push.unwrap_or(defaults.allow_force_push),
        require_tag_lease_on_create: raw
            .require_tag_lease_on_create
            .unwrap_or(defaults.require_tag_lease_on_create),
        upstream_provenance: raw.upstream_provenance,
        upstream_baselines: raw.baselines.clone().unwrap_or_default(),
    }
}

fn materialize_ssh_section(
    profile_name: &str,
    ssh: SshSectionV4,
    home: Option<&Path>,
) -> Result<Vec<SshPolicy>, ConfigError> {
    let mut policies = Vec::new();
    let primary_hosts = collect_ssh_hosts(profile_name, ssh.host, ssh.hosts)?;
    if !primary_hosts.is_empty() {
        let fingerprint = ssh
            .fingerprint
            .ok_or_else(|| ConfigError::InvalidSshPolicy {
                profile: profile_name.to_owned(),
            })?;
        policies.extend(expand_ssh_entry(
            profile_name,
            primary_hosts,
            ssh.user,
            ssh.port,
            fingerprint,
            ssh.public_key,
            ssh.identity_file,
            ssh.agent_socket,
            ssh.known_hosts_file,
            home,
        )?);
    } else if ssh.extra.as_ref().is_none_or(Vec::is_empty) {
        return Err(ConfigError::InvalidSshPolicy {
            profile: profile_name.to_owned(),
        });
    }

    if let Some(extras) = ssh.extra {
        for extra in extras {
            let hosts = collect_ssh_hosts(profile_name, extra.host, extra.hosts)?;
            if hosts.is_empty() {
                return Err(ConfigError::InvalidSshPolicy {
                    profile: profile_name.to_owned(),
                });
            }
            policies.extend(expand_ssh_entry(
                profile_name,
                hosts,
                extra.user,
                extra.port,
                extra.fingerprint,
                extra.public_key,
                extra.identity_file,
                extra.agent_socket,
                extra.known_hosts_file,
                home,
            )?);
        }
    }

    Ok(policies)
}

fn collect_ssh_hosts(
    profile_name: &str,
    host: Option<String>,
    hosts: Option<Vec<String>>,
) -> Result<Vec<String>, ConfigError> {
    match (host, hosts) {
        (Some(_), Some(_)) => Err(ConfigError::InvalidSshPolicy {
            profile: profile_name.to_owned(),
        }),
        (Some(single), None) => Ok(vec![single]),
        (None, Some(many)) => {
            if many.is_empty() {
                return Err(ConfigError::InvalidSshPolicy {
                    profile: profile_name.to_owned(),
                });
            }
            Ok(many)
        }
        (None, None) => Ok(Vec::new()),
    }
}

#[allow(clippy::too_many_arguments)]
fn expand_ssh_entry(
    profile_name: &str,
    hosts: Vec<String>,
    user: Option<String>,
    port: Option<u16>,
    fingerprint: String,
    public_key: Option<PathBuf>,
    identity_file: Option<PathBuf>,
    agent_socket: Option<PathBuf>,
    known_hosts_file: Option<PathBuf>,
    home: Option<&Path>,
) -> Result<Vec<SshPolicy>, ConfigError> {
    let user = user.unwrap_or_else(|| "git".to_owned());
    let port = port.unwrap_or(22);
    let identity_file =
        match identity_file {
            Some(path) => Some(resolve_policy_path(&path, home).ok_or_else(|| {
                ConfigError::InvalidSshPolicy {
                    profile: profile_name.to_owned(),
                }
            })?),
            None => None,
        };
    let agent_socket =
        match agent_socket {
            Some(path) => Some(resolve_policy_path(&path, home).ok_or_else(|| {
                ConfigError::InvalidSshPolicy {
                    profile: profile_name.to_owned(),
                }
            })?),
            None => None,
        };
    let public_key = match public_key {
        Some(path) => {
            resolve_policy_path(&path, home).ok_or_else(|| ConfigError::InvalidSshPolicy {
                profile: profile_name.to_owned(),
            })?
        }
        None => match &identity_file {
            Some(id) => append_pub_extension(id),
            None => {
                return Err(ConfigError::InvalidSshPolicy {
                    profile: profile_name.to_owned(),
                });
            }
        },
    };
    let known_hosts_file = match known_hosts_file {
        Some(path) => {
            resolve_policy_path(&path, home).ok_or_else(|| ConfigError::InvalidSshPolicy {
                profile: profile_name.to_owned(),
            })?
        }
        None => default_known_hosts_path(home).ok_or_else(|| ConfigError::InvalidSshPolicy {
            profile: profile_name.to_owned(),
        })?,
    };

    Ok(hosts
        .into_iter()
        .map(|host| SshPolicy {
            host,
            user: user.clone(),
            port,
            fingerprint: fingerprint.clone(),
            public_key: public_key.clone(),
            identity_file: identity_file.clone(),
            agent_socket: agent_socket.clone(),
            known_hosts_file: known_hosts_file.clone(),
        })
        .collect())
}

fn profile_to_v4(
    profile: &Profile,
    parent: Option<&Profile>,
    existing: Option<&ProfileV4>,
) -> ProfileV4 {
    let mut out = ProfileV4 {
        extends: profile.extends.clone(),
        scopes: existing.map_or_else(Vec::new, |prev| prev.scopes.clone()),
        ..ProfileV4::default()
    };

    // Identity: diff against parent if extending, otherwise emit flat name/email when author == committer.
    let same_as_parent_author = parent.is_some_and(|p| p.git.author == profile.git.author);
    let same_as_parent_committer = parent.is_some_and(|p| p.git.committer == profile.git.committer);
    if !(same_as_parent_author && same_as_parent_committer) {
        if profile.git.author == profile.git.committer {
            if let Some(p) = parent {
                if p.git.author.name != profile.git.author.name
                    || p.git.committer.name != profile.git.committer.name
                {
                    out.name = Some(profile.git.author.name.clone());
                }
                if p.git.author.email != profile.git.author.email
                    || p.git.committer.email != profile.git.committer.email
                {
                    out.email = Some(profile.git.author.email.clone());
                }
            } else {
                out.name = Some(profile.git.author.name.clone());
                out.email = Some(profile.git.author.email.clone());
            }
        } else {
            if !same_as_parent_author {
                out.author = Some(profile.git.author.clone());
            }
            if !same_as_parent_committer {
                out.committer = Some(profile.git.committer.clone());
            }
        }
    }

    // Signing
    let home = std::env::var_os("HOME").map(PathBuf::from);
    if parent.is_none_or(|p| p.git.signing != profile.git.signing) {
        if let Some(signing) = &profile.git.signing {
            let inferred = if signing.fingerprint.starts_with("SHA256:") {
                SigningFormat::Ssh
            } else {
                SigningFormat::OpenPgp
            };
            let preserved_key = existing
                .and_then(|prev| prev.signing.as_ref())
                .and_then(|prev| prev.public_key.as_ref())
                .filter(|prev_key| {
                    resolve_policy_path(prev_key, home.as_deref()).as_ref()
                        == Some(&signing.public_key)
                })
                .cloned();
            out.signing = Some(SigningPolicyV4 {
                fingerprint: Some(signing.fingerprint.clone()),
                format: (signing.format != inferred).then_some(signing.format),
                public_key: Some(preserved_key.unwrap_or_else(|| signing.public_key.clone())),
            });
        }
    }

    // Git policy (push, remotes, deny, commands, hardening)
    let mut git_v4 = git_policy_to_v4(&profile.git, parent.map(|p| &p.git));
    if let Some(prev_git) = existing.and_then(|prev| prev.git.as_ref()) {
        if let (Some(prev_push), Some(curr_push)) = (&prev_git.push, &git_v4.push) {
            if expand_destination_list(prev_push).ok().as_ref() == Some(curr_push) {
                git_v4.push = Some(prev_push.clone());
            }
        }
        if let (Some(prev_fetch), Some(curr_fetch)) = (&prev_git.fetch, &git_v4.fetch) {
            if expand_destination_list(prev_fetch).ok().as_ref() == Some(curr_fetch) {
                git_v4.fetch = Some(prev_fetch.clone());
            }
        }
        if let (Some(prev_deny), Some(curr_deny)) = (&prev_git.deny, &git_v4.deny) {
            if expand_destination_list(prev_deny).ok().as_ref() == Some(curr_deny) {
                git_v4.deny = Some(prev_deny.clone());
            }
        }
    }
    if !git_v4.is_empty() {
        out.git = Some(git_v4);
    }

    // GitHub + merge
    if parent.is_none_or(|p| p.github != profile.github || p.github_merge != profile.github_merge) {
        if let Some(gh) = &profile.github {
            let parent_gh = parent.and_then(|p| p.github.as_ref());
            let mut gh_v4 = GitHubPolicyV4::default();
            if parent_gh.map_or(gh.host != "github.com", |p| p.host != gh.host) {
                gh_v4.host = Some(gh.host.clone());
            }
            if parent_gh.is_none_or(|p| p.account_id != gh.account_id) {
                gh_v4.account_id = Some(gh.account_id.clone());
            }
            if parent_gh.is_none_or(|p| p.account_selector != gh.account_selector) {
                gh_v4.account_selector = gh.account_selector.clone();
            }
            if parent_gh.is_none_or(|p| p.token_fingerprint != gh.token_fingerprint) {
                gh_v4.token_fingerprint = Some(gh.token_fingerprint.clone());
            }
            if parent_gh.map_or(!gh.repositories.is_empty(), |p| {
                p.repositories != gh.repositories
            }) {
                gh_v4.repos = Some(gh.repositories.clone());
            }
            if parent_gh.map_or(!gh.deny_repositories.is_empty(), |p| {
                p.deny_repositories != gh.deny_repositories
            }) {
                gh_v4.deny_repos = Some(gh.deny_repositories.clone());
            }
            if parent_gh.map_or(!gh.commands.is_default(), |p| p.commands != gh.commands) {
                gh_v4.commands = Some(gh.commands.clone());
            }
            if parent.is_none_or(|p| p.github_merge != profile.github_merge) {
                if let Some(merge) = &profile.github_merge {
                    let mut map = BTreeMap::new();
                    for rule in &merge.repositories {
                        map.insert(
                            rule.repository.clone(),
                            GitHubMergeRuleV4 {
                                base_branches: rule.base_branches.clone(),
                                strategies: rule.strategies.clone(),
                            },
                        );
                    }
                    gh_v4.merge = Some(map);
                } else if parent.is_some_and(|p| p.github_merge.is_some()) {
                    gh_v4.merge = Some(BTreeMap::new());
                }
            }
            if gh_v4 != GitHubPolicyV4::default() {
                out.github = Some(gh_v4);
            }
        }
    }

    // SSH
    let current_ssh: Vec<SshPolicy> = profile.ssh_policies().into_iter().cloned().collect();
    let parent_ssh: Vec<SshPolicy> = parent
        .map(|p| p.ssh_policies().into_iter().cloned().collect())
        .unwrap_or_default();
    if current_ssh != parent_ssh && !current_ssh.is_empty() {
        let preserved_ssh = existing
            .and_then(|prev| prev.ssh.as_ref())
            .filter(|prev_ssh| {
                materialize_ssh_section(&profile.name, (*prev_ssh).clone(), home.as_deref())
                    .ok()
                    .as_ref()
                    == Some(&current_ssh)
            })
            .cloned();
        out.ssh = Some(preserved_ssh.unwrap_or_else(|| ssh_policies_to_v4(&current_ssh)));
    }

    // HTTPS credentials
    if parent.is_none_or(|p| p.https_credentials != profile.https_credentials) {
        if !profile.https_credentials.is_empty() {
            let mut map = BTreeMap::new();
            for item in &profile.https_credentials {
                map.insert(
                    item.host.clone(),
                    HttpsHelperV4 {
                        helper: item.helper.clone(),
                        args: item.args.clone(),
                    },
                );
            }
            out.https = Some(map);
        } else if parent.is_some_and(|p| !p.https_credentials.is_empty()) {
            out.https = Some(BTreeMap::new());
        }
    }

    // Run commands
    if parent.map_or(!profile.run.is_default(), |p| p.run != profile.run) {
        out.run = Some(profile.run.clone());
    }

    out
}

fn git_policy_to_v4(git: &GitPolicy, parent: Option<&GitPolicy>) -> GitPolicyV4 {
    let mut out = GitPolicyV4::default();
    let defaults = PushPolicy::default();

    let single_simple_remote = match (&git.push, git.remotes.as_slice()) {
        (Some(push), []) => Some((
            push.remote.as_str(),
            None,
            Some(push.destinations.as_slice()),
        )),
        (Some(push), [only])
            if only.name == push.remote && only.push_destinations == push.destinations =>
        {
            let fetch = if only.fetch_destinations == push.destinations {
                None
            } else {
                Some(only.fetch_destinations.as_slice())
            };
            Some((
                push.remote.as_str(),
                fetch,
                Some(push.destinations.as_slice()),
            ))
        }
        (None, [only]) if only.push_destinations.is_empty() => Some((
            only.name.as_str(),
            Some(only.fetch_destinations.as_slice()),
            None,
        )),
        _ => None,
    };

    if let Some((remote, fetch, push)) = single_simple_remote {
        let parent_remote = parent
            .and_then(|p| p.push.as_ref().map(|push| push.remote.as_str()))
            .unwrap_or("*");
        if remote != parent_remote {
            out.remote = Some(remote.to_owned());
        }
        if let Some(push_dests) = push {
            let same_push = parent
                .and_then(|p| p.push.as_ref())
                .is_some_and(|p| p.destinations.as_slice() == push_dests);
            if !same_push {
                out.push = Some(push_dests.to_vec());
            }
        }
        if let Some(fetch_dests) = fetch {
            let parent_fetch = parent.and_then(|p| p.configured_fetch_destinations(remote));
            if parent_fetch != Some(fetch_dests) {
                out.fetch = Some(fetch_dests.to_vec());
            }
        }
    } else if !git.remotes.is_empty() {
        let mut map = BTreeMap::new();
        for remote in &git.remotes {
            map.insert(
                remote.name.clone(),
                RemotePolicyV4 {
                    fetch: remote.fetch_destinations.clone(),
                    push: remote.push_destinations.clone(),
                },
            );
        }
        out.remotes = Some(map);
        if let Some(push) = &git.push {
            // Only emit explicit remote/push when it differs from the single-push-remote derivation.
            let push_remotes: Vec<&RemotePolicy> = git
                .remotes
                .iter()
                .filter(|r| !r.push_destinations.is_empty())
                .collect();
            let auto_derived = push_remotes.len() == 1
                && push_remotes[0].name == push.remote
                && push_remotes[0].push_destinations == push.destinations;
            if !auto_derived {
                out.remote = Some(push.remote.clone());
                out.push = Some(push.destinations.clone());
            }
        }
    }

    if let Some(push) = &git.push {
        let base = parent.and_then(|p| p.push.as_ref()).unwrap_or(&defaults);
        if push.preserve_authors != base.preserve_authors {
            out.preserve_authors = Some(push.preserve_authors);
        }
        if push.allow_initial_push != base.allow_initial_push {
            out.allow_initial_push = Some(push.allow_initial_push);
        }
        if push.allow_fast_forward != base.allow_fast_forward {
            out.allow_fast_forward = Some(push.allow_fast_forward);
        }
        if push.allow_annotated_tags != base.allow_annotated_tags {
            out.allow_annotated_tags = Some(push.allow_annotated_tags);
        }
        if push.allow_lightweight_tags != base.allow_lightweight_tags {
            out.allow_lightweight_tags = Some(push.allow_lightweight_tags);
        }
        if push.allow_branch_deletion != base.allow_branch_deletion {
            out.allow_branch_deletion = Some(push.allow_branch_deletion);
        }
        if push.allow_tag_deletion != base.allow_tag_deletion {
            out.allow_tag_deletion = Some(push.allow_tag_deletion);
        }
        if push.allow_force_with_lease != base.allow_force_with_lease {
            out.allow_force_with_lease = Some(push.allow_force_with_lease);
        }
        if push.allow_force_push != base.allow_force_push {
            out.allow_force_push = Some(push.allow_force_push);
        }
        if push.require_tag_lease_on_create != base.require_tag_lease_on_create {
            out.require_tag_lease_on_create = Some(push.require_tag_lease_on_create);
        }
        if push.upstream_provenance != base.upstream_provenance {
            out.upstream_provenance = push.upstream_provenance;
        }
        if push.upstream_baselines != base.upstream_baselines {
            out.baselines = Some(push.upstream_baselines.clone());
        }
    }

    if parent.map_or(!git.deny_destinations.is_empty(), |p| {
        p.deny_destinations != git.deny_destinations
    }) {
        out.deny = Some(git.deny_destinations.clone());
    }
    if parent.map_or(!git.commands.is_default(), |p| p.commands != git.commands) {
        out.commands = Some(git.commands.clone());
    }
    if parent.map_or(git.strict_repo_hooks, |p| {
        p.strict_repo_hooks != git.strict_repo_hooks
    }) {
        out.strict_repo_hooks = Some(git.strict_repo_hooks);
    }
    if parent.map_or(git.strict_git_filters, |p| {
        p.strict_git_filters != git.strict_git_filters
    }) {
        out.strict_git_filters = Some(git.strict_git_filters);
    }
    if parent.map_or(git.strict_merge_drivers, |p| {
        p.strict_merge_drivers != git.strict_merge_drivers
    }) {
        out.strict_merge_drivers = Some(git.strict_merge_drivers);
    }
    if parent.map_or(!git.inherit_git_config, |p| {
        p.inherit_git_config != git.inherit_git_config
    }) {
        out.inherit_git_config = Some(git.inherit_git_config);
    }
    if parent.map_or(!git.cross_profile_identity_check, |p| {
        p.cross_profile_identity_check != git.cross_profile_identity_check
    }) {
        out.cross_profile_identity_check = Some(git.cross_profile_identity_check);
    }

    out
}

fn ssh_policies_to_v4(policies: &[SshPolicy]) -> SshSectionV4 {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let default_kh = default_known_hosts_path(home.as_deref());

    // Group policies that share identical (user, port, fingerprint, public_key, identity_file, agent_socket, known_hosts_file).
    let mut groups: Vec<(Vec<String>, &SshPolicy)> = Vec::new();
    for policy in policies {
        if let Some((hosts, _)) = groups.iter_mut().find(|(_, template)| {
            template.user == policy.user
                && template.port == policy.port
                && template.fingerprint == policy.fingerprint
                && template.public_key == policy.public_key
                && template.identity_file == policy.identity_file
                && template.agent_socket == policy.agent_socket
                && template.known_hosts_file == policy.known_hosts_file
        }) {
            hosts.push(policy.host.clone());
        } else {
            groups.push((vec![policy.host.clone()], policy));
        }
    }

    let mut iter = groups.into_iter();
    let (first_hosts, first) = iter.next().expect("non-empty ssh policies");
    let (host, hosts) = if first_hosts.len() == 1 {
        (Some(first_hosts[0].clone()), None)
    } else {
        (None, Some(first_hosts))
    };
    let pub_key_is_default = first
        .identity_file
        .as_ref()
        .is_some_and(|id| append_pub_extension(id) == first.public_key);
    let kh_is_default = default_kh
        .as_ref()
        .is_some_and(|kh| *kh == first.known_hosts_file);

    let extra: Vec<SshEntryV4> = iter
        .map(|(group_hosts, template)| {
            let (ehost, ehosts) = if group_hosts.len() == 1 {
                (Some(group_hosts[0].clone()), None)
            } else {
                (None, Some(group_hosts))
            };
            let epub_default = template
                .identity_file
                .as_ref()
                .is_some_and(|id| append_pub_extension(id) == template.public_key);
            let ekh_default = default_kh
                .as_ref()
                .is_some_and(|kh| *kh == template.known_hosts_file);
            SshEntryV4 {
                host: ehost,
                hosts: ehosts,
                user: (template.user != "git").then(|| template.user.clone()),
                port: (template.port != 22).then_some(template.port),
                fingerprint: template.fingerprint.clone(),
                public_key: (!epub_default).then(|| template.public_key.clone()),
                identity_file: template.identity_file.clone(),
                agent_socket: template.agent_socket.clone(),
                known_hosts_file: (!ekh_default).then(|| template.known_hosts_file.clone()),
            }
        })
        .collect();

    SshSectionV4 {
        host,
        hosts,
        user: (first.user != "git").then(|| first.user.clone()),
        port: (first.port != 22).then_some(first.port),
        fingerprint: Some(first.fingerprint.clone()),
        public_key: (!pub_key_is_default).then(|| first.public_key.clone()),
        identity_file: first.identity_file.clone(),
        agent_socket: first.agent_socket.clone(),
        known_hosts_file: (!kh_is_default).then(|| first.known_hosts_file.clone()),
        extra: (!extra.is_empty()).then_some(extra),
    }
}

// ---------------------------------------------------------------------------
// Validation Rules (preserved invariants)
// ---------------------------------------------------------------------------

fn validate_profile(profile: &Profile) -> Result<(), ConfigError> {
    validate_git_policy(&profile.name, &profile.git)?;
    validate_github_binding(profile)?;
    validate_ssh_policy(profile)?;
    validate_https_credential_policies(profile)?;
    validate_github_merge_policy(profile)?;
    validate_run_command_policy(profile)?;
    if profile
        .git
        .push
        .as_ref()
        .is_some_and(|push| !push_matches_remotes(push, &profile.git.remotes))
    {
        return Err(ConfigError::InvalidRemotePolicy {
            scope: profile.name.clone(),
        });
    }
    Ok(())
}

fn push_matches_remotes(push: &PushPolicy, remotes: &[RemotePolicy]) -> bool {
    if remotes.is_empty() {
        return true;
    }
    if let Some(exact) = remotes.iter().find(|remote| remote.name == push.remote) {
        return same_destination_set(&exact.push_destinations, &push.destinations);
    }
    if push.remote == "*" {
        return push.destinations.iter().all(|destination| {
            remotes.iter().any(|remote| {
                crate::destination::destination_is_permitted(
                    destination,
                    &remote.push_destinations,
                    &[],
                )
            })
        });
    }
    remotes.iter().any(|remote| {
        remote.name == "*"
            && (same_destination_set(&remote.push_destinations, &push.destinations)
                || push.destinations.iter().all(|destination| {
                    crate::destination::destination_is_permitted(
                        destination,
                        &remote.push_destinations,
                        &[],
                    )
                }))
    })
}

fn same_destination_set(left: &[String], right: &[String]) -> bool {
    let left_set: HashSet<&str> = left.iter().map(String::as_str).collect();
    let right_set: HashSet<&str> = right.iter().map(String::as_str).collect();
    left_set == right_set
}

fn validate_run_command_policy(profile: &Profile) -> Result<(), ConfigError> {
    if profile.run.is_valid() {
        Ok(())
    } else {
        Err(ConfigError::InvalidRunCommandPolicy {
            profile: profile.name.clone(),
        })
    }
}

fn validate_git_command_policy(
    scope: &str,
    commands: &GitCommandPolicy,
) -> Result<(), ConfigError> {
    if commands.is_valid() {
        Ok(())
    } else {
        Err(ConfigError::InvalidGitCommandPolicy {
            scope: scope.to_owned(),
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
        crate::destination::valid_repository_pattern(repository)
            && repositories.insert(repository.to_ascii_lowercase())
    });
    let mut deny_repositories = HashSet::new();
    let deny_repositories_valid = binding.deny_repositories.iter().all(|repository| {
        crate::destination::valid_repository_pattern(repository)
            && deny_repositories.insert(repository.to_ascii_lowercase())
    });
    let commands_valid = binding.commands.is_valid();
    if !host_valid
        || !id_valid
        || !selector_valid
        || !fingerprint_valid
        || !repositories_valid
        || !deny_repositories_valid
        || !commands_valid
    {
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
                binding.permits_repository(&rule.repository)
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
    let mut selectors = HashSet::new();
    for ssh in profile.ssh_policies() {
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
                    && suffix.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
                    })
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
        let selector = (ssh.host.to_ascii_lowercase(), ssh.user.clone(), ssh.port);
        if !host_valid
            || !user_valid
            || ssh.port == 0
            || !fingerprint_valid
            || !paths_valid
            || (ssh.identity_file.is_some() == ssh.agent_socket.is_some())
            || !selectors.insert(selector)
        {
            return Err(ConfigError::InvalidSshPolicy {
                profile: profile.name.clone(),
            });
        }
    }
    Ok(())
}

fn validate_https_credential_policies(profile: &Profile) -> Result<(), ConfigError> {
    let bound_github_host = profile
        .github
        .as_ref()
        .map(|binding| binding.host.to_ascii_lowercase());
    let mut hosts = HashSet::new();
    for policy in &profile.https_credentials {
        let host = policy.host.to_ascii_lowercase();
        let helper_valid = policy.helper.is_absolute()
            && policy.helper.to_str().is_some_and(|path| {
                !path.is_empty()
                    && !path
                        .bytes()
                        .any(|byte| byte == 0 || byte.is_ascii_control())
            });
        let args_valid = policy.args.len() <= 16
            && policy.args.iter().all(|argument| {
                !argument.is_empty()
                    && argument.len() <= 256
                    && !argument.bytes().any(|byte| byte.is_ascii_control())
            });
        if !valid_ssh_host(&policy.host)
            || crate::credential::is_known_github_host(&host)
            || bound_github_host.as_deref() == Some(host.as_str())
            || !hosts.insert(host)
            || !helper_valid
            || !args_valid
        {
            return Err(ConfigError::InvalidHttpsCredentialPolicy {
                profile: profile.name.clone(),
            });
        }
    }
    Ok(())
}

fn validate_git_policy(scope: &str, git: &GitPolicy) -> Result<(), ConfigError> {
    validate_git_command_policy(scope, &git.commands)?;
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
        let name_valid = remote.name == "*"
            || (!remote.name.is_empty()
                && remote.name.len() <= 128
                && !remote.name.starts_with('-')
                && remote.name.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                }));
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
                .any(|destination| !crate::destination::valid_destination_pattern(destination))
        {
            return Err(ConfigError::InvalidRemotePolicy {
                scope: scope.to_owned(),
            });
        }
    }
    if git
        .deny_destinations
        .iter()
        .any(|destination| !crate::destination::valid_destination_pattern(destination))
    {
        return Err(ConfigError::InvalidRemotePolicy {
            scope: scope.to_owned(),
        });
    }

    if let Some(push) = &git.push {
        if !push_matches_remotes(push, &git.remotes) {
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
        if push
            .destinations
            .iter()
            .any(|destination| !crate::destination::valid_destination_pattern(destination))
        {
            return Err(ConfigError::InvalidRemotePolicy {
                scope: scope.to_owned(),
            });
        }
        let mut baseline_refs = HashSet::new();
        let baseline_prefix = if push.remote == "*" {
            "refs/remotes/".to_owned()
        } else {
            format!("refs/remotes/{}/", push.remote)
        };
        for baseline in &push.upstream_baselines {
            let destination_valid = push.destinations.iter().any(|destination| {
                destination == &baseline.destination
                    || crate::destination::destination_matches_pattern(
                        &baseline.destination,
                        destination,
                    )
            });
            let oid_valid = matches!(baseline.oid.len(), 40 | 64)
                && baseline.oid.bytes().all(|byte| byte.is_ascii_hexdigit());
            let ref_name = baseline.tracking_ref.strip_prefix(&baseline_prefix);
            let ref_valid = ref_name.is_some_and(|name| {
                !name.is_empty()
                    && !name.starts_with('/')
                    && !name.ends_with('/')
                    && !name.contains("..")
                    && !name.contains("@{")
                    && (push.remote != "*" || name.contains('/'))
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
