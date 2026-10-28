use crate::Scope;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    version: u32,
    scopes: Vec<ScopePolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopePolicy {
    pub name: String,
    pub path: PathBuf,
    pub git: GitPolicy,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitPolicy {
    pub author: Identity,
    pub committer: Identity,
    pub signing: Option<SigningPolicy>,
    pub push: Option<PushPolicy>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PushPolicy {
    /// Exact remote name accepted by the push audit.
    pub remote: String,
    /// Exact effective destinations accepted by the push audit.
    pub destinations: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SigningPolicy {
    /// Full primary OpenPGP fingerprint authorized for this scope.
    pub fingerprint: String,
    /// Absolute path to an exported public-key file. It is imported into a
    /// temporary keyring; the user's GnuPG home is never consulted.
    pub public_key: PathBuf,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub name: String,
    pub email: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    InvalidToml,
    UnsupportedVersion(u32),
    EmptyScopes,
    InvalidScopeName,
    DuplicateScopeName(String),
    RelativeScopePath(PathBuf),
    EmptyIdentity { scope: String, role: String },
    InvalidSigningFingerprint { scope: String },
    RelativeSigningKey { scope: String, path: PathBuf },
    EmptyPushRemote { scope: String },
    EmptyPushDestinations { scope: String },
    EmptyPushDestination { scope: String },
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
        let config: Self = toml::from_str(input).map_err(|_| ConfigError::InvalidToml)?;

        config.validate()?;

        Ok(config)
    }

    pub fn load(path: &Path) -> Result<Self, ConfigLoadError> {
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigLoadError::Read {
            path: path.to_path_buf(),
            source,
        })?;

        Self::parse(&contents).map_err(ConfigLoadError::Invalid)
    }

    pub fn policies(&self) -> &[ScopePolicy] {
        &self.scopes
    }

    pub fn scopes(&self) -> Vec<Scope> {
        let mut scopes = Vec::with_capacity(self.scopes.len());

        for policy in &self.scopes {
            scopes.push(Scope {
                name: policy.name.clone(),
                root: policy.path.clone(),
            });
        }

        scopes
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 1 {
            return Err(ConfigError::UnsupportedVersion(self.version));
        }

        if self.scopes.is_empty() {
            return Err(ConfigError::EmptyScopes);
        }

        let mut seen_names = std::collections::HashSet::new();

        for policy in &self.scopes {
            let name = policy.name.as_str();

            if name.trim().is_empty() || name.trim() != name {
                return Err(ConfigError::InvalidScopeName);
            }

            if !seen_names.insert(name) {
                return Err(ConfigError::DuplicateScopeName(policy.name.clone()));
            }

            if policy.path.is_relative() {
                return Err(ConfigError::RelativeScopePath(policy.path.clone()));
            }

            let identities = [
                ("author", &policy.git.author),
                ("committer", &policy.git.committer),
            ];

            for (role, identity) in identities {
                if identity.name.trim().is_empty() || identity.email.trim().is_empty() {
                    return Err(ConfigError::EmptyIdentity {
                        scope: policy.name.clone(),
                        role: role.to_owned(),
                    });
                }
            }

            if let Some(signing) = &policy.git.signing {
                if signing.fingerprint.len() != 40
                    || !signing
                        .fingerprint
                        .chars()
                        .all(|character| character.is_ascii_hexdigit())
                {
                    return Err(ConfigError::InvalidSigningFingerprint {
                        scope: policy.name.clone(),
                    });
                }
                if signing.public_key.is_relative() {
                    return Err(ConfigError::RelativeSigningKey {
                        scope: policy.name.clone(),
                        path: signing.public_key.clone(),
                    });
                }
            }

            if let Some(push) = &policy.git.push {
                if push.remote.trim().is_empty() {
                    return Err(ConfigError::EmptyPushRemote {
                        scope: policy.name.clone(),
                    });
                }
                if push.destinations.is_empty() {
                    return Err(ConfigError::EmptyPushDestinations {
                        scope: policy.name.clone(),
                    });
                }
                if push
                    .destinations
                    .iter()
                    .any(|destination| destination.is_empty())
                {
                    return Err(ConfigError::EmptyPushDestination {
                        scope: policy.name.clone(),
                    });
                }
            }
        }

        Ok(())
    }
}
