use crate::config::{Config, ScopePolicy, SigningFormat, SigningPolicy};
use crate::context::resolve_context;
use crate::git::{CommitIdentity, EffectiveSigning, GitClient, PushTuple, safe_environment};
use crate::git_command::ExactPushLease;
use crate::gpg::GpgClient;
use crate::push::{PublicationPlan, UpdateClass};
use crate::report::{Finding, Report, Status};
use crate::ssh_signature::SshVerifier;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushRequest {
    pub remote: String,
    pub destination: String,
    pub tuples: Vec<PushTuple>,
    pub leases: Vec<ExactPushLease>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutablePaths {
    pub git: PathBuf,
    pub gpg: Option<PathBuf>,
    pub ssh_keygen: Option<PathBuf>,
}

pub fn build_report(
    config: &Config,
    directory: &Path,
    push: Option<&PushRequest>,
    executables: &ExecutablePaths,
) -> Result<(Report, Option<crate::Scope>), String> {
    let git = GitClient::new(executables.git.clone(), safe_environment());
    let (worktree_root, worktree_error) = match git.checkout_root(directory) {
        Ok(root) => (Some(root), None),
        Err(error) => (None, Some(error)),
    };

    // A physical checkout root is the context for linked worktrees. Only fall
    // back to the requested directory when Git cannot identify a worktree.
    let selection_directory = worktree_root.as_deref().unwrap_or(directory);
    let selected = resolve_context(selection_directory, &config.scopes())
        .map_err(|error| format!("{error:?}"))?;
    let policy = selected.as_ref().and_then(|scope| {
        config
            .policies()
            .iter()
            .find(|policy| policy.name == scope.name)
    });
    let mut findings = Vec::new();

    match selected.as_ref() {
        Some(scope) if policy.is_some() => {
            findings.push(Finding::pass(
                "scope",
                format!("{} ({})", scope.name, scope.root.display()),
                format!("{} ({})", scope.name, scope.root.display()),
                "physical Git checkout root matched the most specific configured scope",
            ));
            let policy = policy.expect("matched scope has a policy");
            findings.push(Finding::pass(
                "policy.profile",
                policy.profile.clone(),
                policy.profile.clone(),
                "resolved scope maps explicitly to this reusable profile",
            ));
        }
        Some(scope) => {
            findings.push(Finding::status(
                "scope",
                Status::Fail,
                None,
                Some(scope.name.clone()),
                "resolved scope has no corresponding policy",
            ));
            findings.push(Finding::status(
                "policy.profile",
                Status::Unknown,
                None,
                None,
                "resolved scope has no profile provenance",
            ));
        }
        None => {
            findings.push(Finding::status(
                "scope",
                Status::Unknown,
                None,
                Some("unmanaged".to_owned()),
                "physical checkout root is outside every configured scope",
            ));
            findings.push(Finding::status(
                "policy.profile",
                Status::Unknown,
                None,
                None,
                "no configured profile applies to this directory",
            ));
        }
    }

    match (&worktree_root, &worktree_error) {
        (Some(root), _) => findings.push(Finding::status(
            "git.worktree",
            if policy.is_some() {
                Status::Pass
            } else {
                Status::Unknown
            },
            policy.map(|policy| policy.path.display().to_string()),
            Some(root.display().to_string()),
            if policy.is_some() {
                "Git worktree was inspected offline with bounded execution"
            } else {
                "Git worktree was observed but no configured policy applies"
            },
        )),
        (None, Some(error)) => findings.push(Finding::status(
            "git.worktree",
            Status::Unknown,
            policy.map(|policy| policy.path.display().to_string()),
            None,
            format!("Git worktree could not be inspected: {error:?}"),
        )),
        (None, None) => unreachable!("worktree result always has a matching error"),
    }

    if let Some(ref root) = worktree_root {
        add_identity_findings(&mut findings, &git, root, policy);
        add_signing_findings(&mut findings, &git, root, policy, executables);
        findings.push(Finding::status(
            "git.signature.remote_verified", Status::Unknown, None, None,
            "hosting-service Verified metadata is distinct from local cryptographic verification and was not queried",
        ));
    } else {
        add_unknown_identity_findings(&mut findings, policy);
        add_unknown_signing_findings(&mut findings, policy);
    }

    add_environment_findings(&mut findings);
    add_remote_transport_finding(
        &mut findings,
        worktree_root.as_deref(),
        &git,
        push.map(|request| request.remote.as_str()),
    );
    add_publication_finding(&mut findings);
    if let Some(push) = push {
        add_push_findings(&mut findings, &git, directory, policy, push, executables);
        findings.push(Finding::status(
            "git.push.signature.remote_verified",
            Status::Unknown,
            None,
            None,
            "hosting-service Verified metadata for outgoing commits was not queried",
        ));
    }
    Ok((Report::new(findings), selected))
}

pub fn build_tag_report(
    config: &Config,
    directory: &Path,
    tag: &str,
    executables: &ExecutablePaths,
) -> Result<(Report, Option<crate::Scope>), String> {
    let (base, selected) = build_report(config, directory, None, executables)?;
    let mut findings = base.findings;
    findings.retain(|finding| {
        !matches!(
            finding.property.as_str(),
            "git.signing.config"
                | "git.signature.present"
                | "git.signature.valid"
                | "git.signature.fingerprint"
                | "git.signature.remote_verified"
        )
    });
    let git = GitClient::new(executables.git.clone(), safe_environment());
    let root = match git.checkout_root(directory) {
        Ok(root) => root,
        Err(_) => directory.to_path_buf(),
    };
    let policy = selected.as_ref().and_then(|scope| {
        config
            .policies()
            .iter()
            .find(|policy| policy.name == scope.name)
    });
    let signing = policy.and_then(|policy| policy.git.signing.as_ref());
    add_tag_findings(&mut findings, &git, &root, tag, signing, executables);
    Ok((Report::new(findings), selected))
}

fn add_tag_findings(
    findings: &mut Vec<Finding>,
    git: &GitClient,
    root: &Path,
    tag: &str,
    policy: Option<&SigningPolicy>,
    executables: &ExecutablePaths,
) {
    let tag_result = git.tag_object(root, tag);
    let (oid, contents) = match tag_result {
        Ok(tag) => tag,
        Err(_) => {
            for property in [
                "git.tag.signature.present",
                "git.tag.signature.valid",
                "git.tag.signature.fingerprint",
            ] {
                findings.push(Finding::status(
                    property,
                    Status::Unknown,
                    None,
                    None,
                    "annotated tag object could not be inspected offline",
                ));
            }
            findings.push(Finding::status(
                "git.tag.remote_verified",
                Status::Unknown,
                None,
                None,
                "remote Verified status was not queried",
            ));
            return;
        }
    };
    let ssh_signature = contents.contains("-----BEGIN SSH SIGNATURE-----");
    let openpgp_signature = contents.contains("-----BEGIN PGP SIGNATURE-----");
    let has_signature = ssh_signature || openpgp_signature;
    findings.push(Finding::status(
        "git.tag.signature.present",
        if has_signature {
            Status::Pass
        } else {
            Status::Fail
        },
        Some("annotated tag signature present".to_owned()),
        Some(if has_signature { "present" } else { "absent" }.to_owned()),
        "annotated tag object was inspected for an embedded cryptographic signature",
    ));
    let Some(policy) = policy else {
        findings.push(Finding::status(
            "git.tag.signing.config",
            Status::Unknown,
            None,
            None,
            "no signing policy is configured for this scope",
        ));
        findings.push(Finding::status(
            "git.tag.signature.valid",
            Status::Unknown,
            Some("valid under an explicit signing policy".to_owned()),
            None,
            "no signing policy is configured for this scope",
        ));
        findings.push(Finding::status(
            "git.tag.signature.fingerprint",
            Status::Unknown,
            None,
            None,
            "no authorized signer fingerprint is configured",
        ));
        findings.push(Finding::status(
            "git.tag.remote_verified",
            Status::Unknown,
            None,
            None,
            "remote Verified status was not queried",
        ));
        return;
    };
    add_tag_signing_config_finding(findings, git, root, policy, executables);
    if !has_signature {
        findings.push(Finding::status(
            "git.tag.signature.valid",
            Status::Unknown,
            Some("valid".to_owned()),
            None,
            "signature validity cannot be checked without a signature",
        ));
        findings.push(Finding::status(
            "git.tag.signature.fingerprint",
            Status::Unknown,
            Some(policy.fingerprint.clone()),
            None,
            "signer cannot be identified without a signature",
        ));
        findings.push(Finding::status(
            "git.tag.remote_verified",
            Status::Unknown,
            None,
            None,
            "remote Verified status was not queried",
        ));
        return;
    }
    match policy.format {
        SigningFormat::OpenPgp if !openpgp_signature => {
            findings.push(Finding::status(
                "git.tag.signature.valid",
                Status::Fail,
                Some("OpenPGP".to_owned()),
                Some("SSH or other signature format".to_owned()),
                "tag signature format does not match the configured OpenPGP policy",
            ));
            findings.push(Finding::status(
                "git.tag.signature.fingerprint",
                Status::Unknown,
                Some(policy.fingerprint.clone()),
                None,
                "mismatched signature format does not establish the configured signer",
            ));
        }
        SigningFormat::Ssh if !ssh_signature => {
            findings.push(Finding::status(
                "git.tag.signature.valid",
                Status::Fail,
                Some("SSH".to_owned()),
                Some("OpenPGP or other signature format".to_owned()),
                "tag signature format does not match the configured SSH policy",
            ));
            findings.push(Finding::status(
                "git.tag.signature.fingerprint",
                Status::Unknown,
                Some(policy.fingerprint.clone()),
                None,
                "mismatched signature format does not establish the configured signer",
            ));
        }
        SigningFormat::OpenPgp => {
            let result = executables.gpg.clone().map(GpgClient::new).and_then(|gpg| {
                gpg.isolated_keyring(&policy.public_key)
                    .ok()
                    .map(|home| (gpg, home))
            });
            match result {
                Some((gpg, keyring)) => match gpg.verify_tag_oid(git, root, &oid, keyring.path()) {
                    Ok(verification) if verification.cryptographically_valid => {
                        add_tag_fingerprint(findings, policy, verification.primary_fingerprint)
                    }
                    Ok(verification) if verification.unavailable_key => add_tag_signature_unknown(
                        findings,
                        policy,
                        "configured public key is unavailable for offline tag verification",
                    ),
                    Ok(_) => {
                        findings.push(Finding::status(
                            "git.tag.signature.valid",
                            Status::Fail,
                            Some("valid".to_owned()),
                            Some("invalid".to_owned()),
                            "OpenPGP tag signature verification failed",
                        ));
                        findings.push(Finding::status(
                            "git.tag.signature.fingerprint",
                            Status::Unknown,
                            Some(policy.fingerprint.clone()),
                            None,
                            "invalid signature does not establish a signer fingerprint",
                        ));
                    }
                    Err(_) => add_tag_signature_unknown(
                        findings,
                        policy,
                        "OpenPGP tag signature verification could not be completed safely",
                    ),
                },
                None => add_tag_signature_unknown(
                    findings,
                    policy,
                    "GPG or the configured public key is unavailable",
                ),
            }
        }
        SigningFormat::Ssh => {
            let principal = contents
                .lines()
                .find_map(|line| line.strip_prefix("tagger "))
                .and_then(|line| crate::git::parse_tag_identity_email(line).ok());
            let result = match (executables.ssh_keygen.clone(), principal) {
                (Some(executable), Some(principal)) => SshVerifier::new(executable)
                    .verify_tag(git, root, &oid, &policy.public_key, &principal)
                    .ok(),
                _ => None,
            };
            match result {
                Some(verification) if verification.cryptographically_valid => {
                    add_tag_fingerprint(findings, policy, verification.fingerprint)
                }
                Some(_) => {
                    findings.push(Finding::status(
                        "git.tag.signature.valid",
                        Status::Fail,
                        Some("valid".to_owned()),
                        Some("invalid".to_owned()),
                        "SSH tag signature verification failed",
                    ));
                    findings.push(Finding::status(
                        "git.tag.signature.fingerprint",
                        Status::Unknown,
                        Some(policy.fingerprint.clone()),
                        None,
                        "invalid signature does not establish a signer fingerprint",
                    ));
                }
                None => add_tag_signature_unknown(
                    findings,
                    policy,
                    "SSH tag verification or tagger identity is unavailable",
                ),
            }
        }
    }
    findings.push(Finding::status(
        "git.tag.remote_verified",
        Status::Unknown,
        None,
        None,
        "remote hosting-service Verified status is distinct and was not queried",
    ));
}

fn add_tag_signing_config_finding(
    findings: &mut Vec<Finding>,
    git: &GitClient,
    root: &Path,
    policy: &SigningPolicy,
    executables: &ExecutablePaths,
) {
    let effective = match git.effective_signing(root) {
        Ok(effective) => effective,
        Err(error) => {
            findings.push(Finding::status(
                "git.tag.signing.config",
                Status::Unknown,
                Some(policy.fingerprint.clone()),
                None,
                format!("effective signing configuration could not be observed: {error:?}"),
            ));
            return;
        }
    };
    let enabled = effective.tag_enabled;
    let format_matches = match policy.format {
        SigningFormat::OpenPgp => effective
            .format
            .as_deref()
            .is_none_or(|format| format.eq_ignore_ascii_case("openpgp")),
        SigningFormat::Ssh => effective
            .format
            .as_deref()
            .is_some_and(|format| format.eq_ignore_ascii_case("ssh")),
    };
    let key_present = effective
        .key
        .as_deref()
        .is_some_and(|key| !key.trim().is_empty());
    let key_matches = match policy.format {
        SigningFormat::Ssh => executables.ssh_keygen.clone().and_then(|path| {
            let verifier = SshVerifier::new(path);
            let authorized = verifier.public_key_fingerprint(&policy.public_key).ok()?;
            let configured = effective.key.as_deref()?.trim_end_matches('!');
            let selected = configured_ssh_fingerprint(root, configured, &verifier)?;
            Some(authorized == policy.fingerprint && selected == policy.fingerprint)
        }),
        SigningFormat::OpenPgp => {
            let configured = effective
                .key
                .as_deref()
                .unwrap_or_default()
                .trim_end_matches('!');
            if configured.eq_ignore_ascii_case(&policy.fingerprint) {
                Some(true)
            } else {
                executables
                    .gpg
                    .clone()
                    .and_then(|path| {
                        let gpg = GpgClient::new(path);
                        let keyring = gpg.isolated_keyring(&policy.public_key).ok()?;
                        gpg.configured_primary_fingerprint(keyring.path(), configured)
                            .ok()
                            .flatten()
                    })
                    .map(|fingerprint| fingerprint.eq_ignore_ascii_case(&policy.fingerprint))
            }
        }
    };
    let known_failure =
        enabled == Some(false) || !format_matches || !key_present || key_matches == Some(false);
    let status = if known_failure {
        Status::Fail
    } else if enabled == Some(true) && key_matches == Some(true) {
        Status::Pass
    } else {
        Status::Unknown
    };
    findings.push(Finding::status(
        "git.tag.signing.config",
        status,
        Some(policy.fingerprint.clone()),
        Some(format!(
            "tag-enabled={:?}, format={:?}, key-present={key_present}, configured-key-matches={key_matches:?}",
            effective.tag_enabled, effective.format
        )),
        "effective Git signing configuration was inspected without mutation",
    ));
}

fn configured_ssh_fingerprint(
    root: &Path,
    configured: &str,
    verifier: &SshVerifier,
) -> Option<String> {
    if configured.starts_with("SHA256:") {
        return Some(configured.to_owned());
    }
    let mut key_path = PathBuf::from(configured);
    if key_path.is_relative() {
        key_path = root.join(key_path);
    }
    let public_path = if key_path
        .extension()
        .is_some_and(|extension| extension == "pub")
    {
        key_path
    } else {
        PathBuf::from(format!("{}.pub", key_path.display()))
    };
    verifier.public_key_fingerprint(&public_path).ok()
}

fn add_tag_fingerprint(
    findings: &mut Vec<Finding>,
    policy: &SigningPolicy,
    observed: Option<String>,
) {
    match observed {
        Some(observed)
            if observed == policy.fingerprint
                || (policy.format == SigningFormat::OpenPgp
                    && observed.eq_ignore_ascii_case(&policy.fingerprint)) =>
        {
            findings.push(Finding::status(
                "git.tag.signature.valid",
                Status::Pass,
                Some("valid".to_owned()),
                Some("valid".to_owned()),
                "tag signature verified offline with the explicit public key",
            ));
            findings.push(Finding::pass(
                "git.tag.signature.fingerprint",
                policy.fingerprint.clone(),
                observed,
                "verified tag signer matches the configured fingerprint",
            ));
        }
        Some(observed) => {
            findings.push(Finding::status(
                "git.tag.signature.valid",
                Status::Pass,
                Some("valid".to_owned()),
                Some("valid".to_owned()),
                "tag signature is cryptographically valid",
            ));
            findings.push(Finding::status(
                "git.tag.signature.fingerprint",
                Status::Fail,
                Some(policy.fingerprint.clone()),
                Some(observed),
                "tag signature is from a different key",
            ));
        }
        None => {
            findings.push(Finding::status(
                "git.tag.signature.valid",
                Status::Pass,
                Some("valid".to_owned()),
                Some("valid".to_owned()),
                "tag signature is cryptographically valid",
            ));
            findings.push(Finding::status(
                "git.tag.signature.fingerprint",
                Status::Unknown,
                Some(policy.fingerprint.clone()),
                None,
                "verified signature did not report a signer fingerprint",
            ));
        }
    }
}

fn add_tag_signature_unknown(findings: &mut Vec<Finding>, policy: &SigningPolicy, reason: &str) {
    findings.push(Finding::status(
        "git.tag.signature.valid",
        Status::Unknown,
        Some("valid".to_owned()),
        None,
        reason,
    ));
    findings.push(Finding::status(
        "git.tag.signature.fingerprint",
        Status::Unknown,
        Some(policy.fingerprint.clone()),
        None,
        reason,
    ));
}

fn add_identity_findings(
    findings: &mut Vec<Finding>,
    git: &GitClient,
    root: &Path,
    policy: Option<&crate::config::ScopePolicy>,
) {
    add_identity_finding(
        findings,
        "git.author",
        git.effective_author(root),
        policy.map(|p| &p.git.author),
    );
    add_identity_finding(
        findings,
        "git.committer",
        git.effective_committer(root),
        policy.map(|p| &p.git.committer),
    );
}

fn add_identity_finding(
    findings: &mut Vec<Finding>,
    property: &str,
    observed: Result<crate::config::Identity, crate::git::GitError>,
    expected: Option<&crate::config::Identity>,
) {
    let expected_text = expected.map(identity_text);
    match observed {
        Ok(identity) if expected.is_some_and(|expected| expected == &identity) => {
            findings.push(Finding::pass(
                property,
                expected_text.expect("matching identity has an expected value"),
                identity_text(&identity),
                "effective Git identity matched the resolved scope policy",
            ))
        }
        Ok(identity) => findings.push(Finding::status(
            property,
            if expected.is_some() {
                Status::Fail
            } else {
                Status::Unknown
            },
            expected_text,
            Some(identity_text(&identity)),
            if expected.is_some() {
                "effective Git identity does not match the resolved scope policy"
            } else {
                "effective Git identity was observed without a configured scope policy"
            },
        )),
        Err(error) => findings.push(Finding::status(
            property,
            Status::Unknown,
            expected_text,
            None,
            format!("effective Git identity could not be observed: {error:?}"),
        )),
    }
}

fn add_unknown_signing_findings(
    findings: &mut Vec<Finding>,
    policy: Option<&crate::config::ScopePolicy>,
) {
    let reason = if policy.is_some() {
        "OpenPGP signing cannot be checked because no Git worktree was found"
    } else {
        "OpenPGP signing is unknown outside a configured scope"
    };
    for property in [
        "git.signing.config",
        "git.signature.present",
        "git.signature.valid",
        "git.signature.fingerprint",
    ] {
        findings.push(Finding::status(
            property,
            Status::Unknown,
            policy
                .and_then(|p| p.git.signing.as_ref())
                .map(|p| p.fingerprint.clone()),
            None,
            reason,
        ));
    }
}

fn add_unknown_identity_findings(
    findings: &mut Vec<Finding>,
    policy: Option<&crate::config::ScopePolicy>,
) {
    for (property, expected) in [
        ("git.author", policy.map(|p| &p.git.author)),
        ("git.committer", policy.map(|p| &p.git.committer)),
    ] {
        findings.push(Finding::status(
            property,
            Status::Unknown,
            expected.map(identity_text),
            None,
            "effective Git identity is unknown because no Git worktree was found",
        ));
    }
}

fn identity_text(identity: &crate::config::Identity) -> String {
    format!("{} <{}>", identity.name, identity.email)
}

fn add_signing_findings(
    findings: &mut Vec<Finding>,
    git: &GitClient,
    root: &Path,
    policy: Option<&crate::config::ScopePolicy>,
    executables: &ExecutablePaths,
) {
    let signing_policy = policy.and_then(|p| p.git.signing.as_ref());
    let Some(signing_policy) = signing_policy else {
        for property in [
            "git.signing.config",
            "git.signature.present",
            "git.signature.valid",
            "git.signature.fingerprint",
        ] {
            findings.push(Finding::status(
                property,
                Status::Unknown,
                None,
                None,
                "no OpenPGP signing policy is configured for this scope",
            ));
        }
        return;
    };
    if signing_policy.format == SigningFormat::Ssh {
        if let Some(scope_policy) = policy {
            add_ssh_signing_findings(
                findings,
                git,
                root,
                scope_policy,
                signing_policy,
                executables,
            );
        } else {
            add_unknown_signing_findings(findings, policy);
        }
        return;
    }

    let effective = git.effective_signing(root);
    let mut gpg_problem = None;
    let gpg_context = match executables.gpg.clone() {
        Some(path) => {
            let gpg = GpgClient::new(path);
            match gpg.isolated_keyring(&signing_policy.public_key) {
                Ok(keyring) => Some((gpg, keyring)),
                Err(error) => {
                    gpg_problem = Some(format!(
                        "configured public key is unavailable or unusable: {error:?}"
                    ));
                    None
                }
            }
        }
        None => {
            gpg_problem = Some(
                "GPG executable is unavailable; cryptographic verification was not attempted"
                    .to_owned(),
            );
            None
        }
    };
    let configured_primary = gpg_context.as_ref().and_then(|(gpg, keyring)| {
        effective
            .as_ref()
            .ok()
            .and_then(|effective| effective.key.as_deref())
            .and_then(|key| {
                gpg.configured_primary_fingerprint(keyring.path(), key)
                    .ok()
                    .flatten()
            })
    });
    add_signing_config_finding(
        findings,
        signing_policy,
        effective.as_ref().ok(),
        configured_primary.as_deref(),
    );

    let present = git.head_has_signature(root);
    match present {
        Ok(true) => findings.push(Finding::status(
            "git.signature.present",
            Status::Pass,
            Some("present".to_owned()),
            Some("present".to_owned()),
            "HEAD contains an OpenPGP signature",
        )),
        Ok(false) => {
            findings.push(Finding::status(
                "git.signature.present",
                Status::Fail,
                Some("present".to_owned()),
                Some("absent".to_owned()),
                "HEAD does not contain an OpenPGP signature",
            ));
            findings.push(Finding::status(
                "git.signature.valid",
                Status::Unknown,
                Some("valid".to_owned()),
                None,
                "cryptographic validity cannot be checked without a signature",
            ));
            findings.push(Finding::status(
                "git.signature.fingerprint",
                Status::Unknown,
                Some(signing_policy.fingerprint.clone()),
                None,
                "signer cannot be identified without a signature",
            ));
        }
        Err(ref error) => {
            let reason = format!("signature presence could not be observed: {error:?}");
            findings.push(Finding::status(
                "git.signature.present",
                Status::Unknown,
                Some("present".to_owned()),
                None,
                reason.clone(),
            ));
            findings.push(Finding::status(
                "git.signature.valid",
                Status::Unknown,
                Some("valid".to_owned()),
                None,
                reason.clone(),
            ));
            findings.push(Finding::status(
                "git.signature.fingerprint",
                Status::Unknown,
                Some(signing_policy.fingerprint.clone()),
                None,
                reason,
            ));
        }
    }

    let has_signature = matches!(&present, Ok(true));
    if has_signature {
        let Some((gpg, keyring)) = gpg_context.as_ref() else {
            add_unknown_signature_verification(
                findings,
                signing_policy,
                gpg_problem.unwrap_or_else(|| "offline GPG verification is unavailable".to_owned()),
            );
            return;
        };
        match gpg.verify_commit(git, root, keyring.path()) {
            Ok(verification) if verification.cryptographically_valid => {
                findings.push(Finding::status(
                    "git.signature.valid",
                    Status::Pass,
                    Some("valid".to_owned()),
                    Some("valid".to_owned()),
                    "HEAD signature verified offline with the explicit public key",
                ));
                let observed = verification.primary_fingerprint;
                match observed {
                    Some(fingerprint)
                        if fingerprint == signing_policy.fingerprint.to_ascii_uppercase() =>
                    {
                        findings.push(Finding::pass(
                            "git.signature.fingerprint",
                            signing_policy.fingerprint.clone(),
                            fingerprint,
                            "verified signature maps to the configured authorized primary fingerprint",
                        ));
                    }
                    Some(fingerprint) => findings.push(Finding::status(
                        "git.signature.fingerprint",
                        Status::Fail,
                        Some(signing_policy.fingerprint.clone()),
                        Some(fingerprint),
                        "verified signature is from a different primary fingerprint",
                    )),
                    None => findings.push(Finding::status(
                        "git.signature.fingerprint",
                        Status::Unknown,
                        Some(signing_policy.fingerprint.clone()),
                        None,
                        "signature verified but no primary fingerprint was reported",
                    )),
                }
            }
            Ok(verification) if verification.unavailable_key => add_unknown_signature_verification(
                findings,
                signing_policy,
                "signature is present but its public key is unavailable in the explicit offline keyring",
            ),
            Ok(_) => {
                findings.push(Finding::status(
                    "git.signature.valid",
                    Status::Fail,
                    Some("valid".to_owned()),
                    Some("invalid".to_owned()),
                    "OpenPGP cryptographic verification failed",
                ));
                findings.push(Finding::status(
                    "git.signature.fingerprint",
                    Status::Unknown,
                    Some(signing_policy.fingerprint.clone()),
                    None,
                    "invalid signatures do not establish a signer fingerprint",
                ));
            }
            Err(error) => add_unknown_signature_verification(
                findings,
                signing_policy,
                format!("offline signature verification could not be completed: {error:?}"),
            ),
        }
    }
}

fn add_ssh_signing_findings(
    findings: &mut Vec<Finding>,
    git: &GitClient,
    root: &Path,
    scope: &ScopePolicy,
    signing: &SigningPolicy,
    executables: &ExecutablePaths,
) {
    let expected = signing.fingerprint.clone();
    match git.effective_signing(root) {
        Ok(effective) => {
            let configured = effective.enabled == Some(true)
                && effective
                    .format
                    .as_deref()
                    .is_some_and(|format| format.eq_ignore_ascii_case("ssh"))
                && effective
                    .key
                    .as_deref()
                    .is_some_and(|key| !key.trim().is_empty());
            findings.push(Finding::status(
                "git.signing.config",
                if configured {
                    Status::Pass
                } else {
                    Status::Fail
                },
                Some(expected.clone()),
                Some(format!(
                    "enabled={:?}, format={:?}, key-present={}",
                    effective.enabled,
                    effective.format,
                    effective
                        .key
                        .as_deref()
                        .is_some_and(|key| !key.trim().is_empty())
                )),
                "effective Git SSH signing configuration was inspected without changing it",
            ));
        }
        Err(error) => findings.push(Finding::status(
            "git.signing.config",
            Status::Unknown,
            Some(expected.clone()),
            None,
            format!("effective Git signing configuration could not be observed: {error:?}"),
        )),
    }

    match git.head_has_signature(root) {
        Ok(true) => findings.push(Finding::status(
            "git.signature.present",
            Status::Pass,
            Some("present".to_owned()),
            Some("present".to_owned()),
            "HEAD contains a Git signature",
        )),
        Ok(false) => {
            findings.push(Finding::status(
                "git.signature.present",
                Status::Fail,
                Some("present".to_owned()),
                Some("absent".to_owned()),
                "HEAD has no signature",
            ));
            findings.push(Finding::status(
                "git.signature.valid",
                Status::Unknown,
                Some("valid".to_owned()),
                None,
                "signature validity cannot be checked without a signature",
            ));
            findings.push(Finding::status(
                "git.signature.fingerprint",
                Status::Unknown,
                Some(expected),
                None,
                "signer cannot be identified without a signature",
            ));
            return;
        }
        Err(error) => {
            let reason = format!("signature presence could not be observed: {error:?}");
            for property in [
                "git.signature.present",
                "git.signature.valid",
                "git.signature.fingerprint",
            ] {
                findings.push(Finding::status(
                    property,
                    Status::Unknown,
                    Some(expected.clone()),
                    None,
                    reason.clone(),
                ));
            }
            return;
        }
    }

    let Some(ssh_keygen) = executables.ssh_keygen.clone() else {
        findings.push(Finding::status(
            "git.signature.valid",
            Status::Unknown,
            Some("valid".to_owned()),
            None,
            "ssh-keygen is unavailable; cryptographic verification was not attempted",
        ));
        findings.push(Finding::status(
            "git.signature.fingerprint",
            Status::Unknown,
            Some(expected),
            None,
            "verified signer fingerprint is unavailable",
        ));
        return;
    };
    let verifier = SshVerifier::new(ssh_keygen);
    match verifier.verify_commit(
        git,
        root,
        "HEAD",
        &signing.public_key,
        &scope.git.committer.email,
    ) {
        Ok(verification) if verification.cryptographically_valid => {
            findings.push(Finding::status(
                "git.signature.valid",
                Status::Pass,
                Some("valid".to_owned()),
                Some("valid".to_owned()),
                "HEAD SSH signature verified offline against the explicit allowed signer",
            ));
            match verification.fingerprint {
                Some(fingerprint) if fingerprint == expected => findings.push(Finding::pass(
                    "git.signature.fingerprint",
                    expected,
                    fingerprint,
                    "verified SSH signature matches the configured key fingerprint",
                )),
                Some(fingerprint) => findings.push(Finding::status(
                    "git.signature.fingerprint",
                    Status::Fail,
                    Some(expected),
                    Some(fingerprint),
                    "verified SSH signature is from a different key",
                )),
                None => findings.push(Finding::status(
                    "git.signature.fingerprint",
                    Status::Unknown,
                    Some(expected),
                    None,
                    "signature verified but no key fingerprint was reported",
                )),
            }
        }
        Ok(_) => {
            findings.push(Finding::status(
                "git.signature.valid",
                Status::Fail,
                Some("valid".to_owned()),
                Some("invalid".to_owned()),
                "SSH cryptographic verification failed",
            ));
            findings.push(Finding::status(
                "git.signature.fingerprint",
                Status::Unknown,
                Some(expected),
                None,
                "invalid signatures do not establish a signer fingerprint",
            ));
        }
        Err(_) => {
            findings.push(Finding::status(
                "git.signature.valid",
                Status::Unknown,
                Some("valid".to_owned()),
                None,
                "offline SSH signature verification could not be completed safely",
            ));
            findings.push(Finding::status(
                "git.signature.fingerprint",
                Status::Unknown,
                Some(expected),
                None,
                "verified signer fingerprint is unavailable",
            ));
        }
    }
}

fn add_signing_config_finding(
    findings: &mut Vec<Finding>,
    policy: &SigningPolicy,
    effective: Option<&EffectiveSigning>,
    configured_primary: Option<&str>,
) {
    let Some(effective) = effective else {
        findings.push(Finding::status(
            "git.signing.config",
            Status::Unknown,
            Some(policy.fingerprint.clone()),
            None,
            "effective Git signing configuration could not be observed",
        ));
        return;
    };
    let configured_key = effective
        .key
        .as_deref()
        .unwrap_or_default()
        .trim_end_matches('!');
    let fingerprint = policy.fingerprint.to_ascii_uppercase();
    let key_matches = configured_key.len() == 40
        && (configured_key.eq_ignore_ascii_case(&fingerprint)
            || configured_primary
                .is_some_and(|primary| primary.eq_ignore_ascii_case(&fingerprint)));
    let matches = effective.enabled == Some(true)
        && effective
            .format
            .as_deref()
            .is_none_or(|format| format.eq_ignore_ascii_case("openpgp"))
        && key_matches;
    let status = if matches {
        Status::Pass
    } else if effective.enabled != Some(true)
        || effective
            .format
            .as_deref()
            .is_some_and(|format| !format.eq_ignore_ascii_case("openpgp"))
        || !key_matches
    {
        Status::Fail
    } else {
        Status::Unknown
    };
    findings.push(Finding::status(
        "git.signing.config",
        status,
        Some(fingerprint),
        Some(format!(
            "enabled={:?}, format={:?}, key={:?}",
            effective.enabled, effective.format, effective.key
        )),
        "effective Git OpenPGP signing configuration was inspected without changing it",
    ));
}

fn add_unknown_signature_verification(
    findings: &mut Vec<Finding>,
    policy: &SigningPolicy,
    reason: impl Into<String>,
) {
    let reason = reason.into();
    findings.push(Finding::status(
        "git.signature.valid",
        Status::Unknown,
        Some("valid".to_owned()),
        None,
        reason.clone(),
    ));
    findings.push(Finding::status(
        "git.signature.fingerprint",
        Status::Unknown,
        Some(policy.fingerprint.clone()),
        None,
        reason,
    ));
}

fn add_push_findings(
    findings: &mut Vec<Finding>,
    git: &GitClient,
    root: &Path,
    policy: Option<&crate::config::ScopePolicy>,
    request: &PushRequest,
    executables: &ExecutablePaths,
) {
    let audit_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let Some(scope_policy) = policy else {
        add_unknown_push_findings(
            findings,
            "no explicit push remote and destination policy is configured for this scope",
        );
        return;
    };
    let Some(push_policy) = scope_policy.git.push.as_ref() else {
        add_unknown_push_findings(
            findings,
            "no explicit push remote and destination policy is configured for this scope",
        );
        return;
    };

    let destination_status = if request.remote != push_policy.remote {
        Finding::status(
            "git.push.destination",
            Status::Fail,
            Some("configured remote and destinations".to_owned()),
            Some("caller remote did not match the configured remote".to_owned()),
            "caller-supplied remote identifier is not the explicitly configured push remote",
        )
    } else {
        match git.effective_push_destinations(root, &request.remote) {
            Ok(effective) if effective.is_empty() => Finding::status(
                "git.push.destination",
                Status::Unknown,
                Some("configured destination".to_owned()),
                None,
                "Git reported no effective push destination",
            ),
            Ok(effective)
                if effective.iter().all(|destination| {
                    push_policy
                        .destinations
                        .iter()
                        .any(|allowed| allowed == destination)
                }) && effective
                    .iter()
                    .any(|destination| destination == &request.destination) =>
            {
                Finding::status(
                    "git.push.destination",
                    Status::Pass,
                    Some("an explicitly allowed effective destination".to_owned()),
                    Some("caller destination matched configured Git push destination".to_owned()),
                    "effective pushurl/url values and relevant local rewrites matched the explicit destination policy; credentials were not tested",
                )
            }
            Ok(_) => Finding::status(
                "git.push.destination",
                Status::Fail,
                Some("an explicitly allowed effective destination".to_owned()),
                Some("caller destination or configured destination was not allowed".to_owned()),
                "effective push destination did not exactly match the explicit destination policy",
            ),
            Err(error) => Finding::status(
                "git.push.destination",
                Status::Unknown,
                Some("an explicitly allowed effective destination".to_owned()),
                None,
                format!("effective push destination could not be inspected offline: {error:?}"),
            ),
        }
    };
    findings.push(destination_status);

    const MAX_PUSH_UPDATES: usize = 16;
    if std::time::Instant::now() >= audit_deadline {
        add_unknown_push_updates(
            findings,
            "publication audit exceeded its operation-wide time budget",
        );
        return;
    }
    if request.tuples.is_empty() {
        add_unknown_push_updates(findings, "no push update tuples were supplied");
        return;
    }
    if request.tuples.len() > MAX_PUSH_UPDATES {
        add_unknown_push_updates(
            findings,
            "push update count exceeds the bounded audit limit",
        );
        return;
    }

    if request.leases.iter().any(|lease| {
        !request.tuples.iter().any(|tuple| {
            tuple.remote_ref == lease.remote_ref && tuple.remote_oid == lease.expected_oid
        })
    }) {
        add_unknown_push_updates(
            findings,
            "force-with-lease evidence does not match the exact audited remote ref and OID",
        );
        return;
    }
    let plan = PublicationPlan::new(
        request.remote.clone(),
        request.destination.clone(),
        &request.tuples,
    )
    .and_then(|plan| {
        request.leases.iter().try_fold(plan, |plan, lease| {
            plan.with_expected_lease(&lease.remote_ref, &lease.expected_oid)
        })
    })
    .and_then(|plan| plan.with_local_history(git, root, audit_deadline));
    let plan = match plan {
        Ok(plan) => plan,
        Err(error) => {
            add_unknown_push_updates(
                findings,
                format!("publication plan or history is ambiguous or invalid: {error:?}"),
            );
            return;
        }
    };
    if std::time::Instant::now() >= audit_deadline {
        add_unknown_push_updates(
            findings,
            "publication audit exceeded its operation-wide time budget",
        );
        return;
    }
    let mut commit_updates = Vec::new();
    let mut reachable_tips = Vec::new();
    for (update, planned) in request.tuples.iter().zip(plan.updates()) {
        if std::time::Instant::now() >= audit_deadline {
            add_unknown_push_updates(
                findings,
                "publication audit exceeded its operation-wide time budget",
            );
            return;
        }
        if !valid_update_shape(update) {
            add_unknown_push_updates(findings, "push update tuple is not in native Git shape");
            return;
        }
        if matches!(
            planned.class(),
            UpdateClass::AnnotatedTag | UpdateClass::LightweightTag
        ) && !update.remote_oid.bytes().all(|byte| byte == b'0')
        {
            if !push_policy.allow_force_with_lease {
                add_denied_push_updates(
                    findings,
                    "updating an existing tag requires explicit force-with-lease policy",
                );
                return;
            }
            if planned.expected_lease_oid() != Some(update.remote_oid.as_str()) {
                add_unknown_push_updates(
                    findings,
                    "tag update requires an exact lease matching the advertised remote OID",
                );
                return;
            }
        }
        match planned.class() {
            UpdateClass::UnchangedBranch => {}
            UpdateClass::InitialBranch if !push_policy.allow_initial_push => {
                add_denied_push_updates(
                    findings,
                    "initial branch publication is disabled by policy",
                );
                return;
            }
            UpdateClass::FastForwardBranch if !push_policy.allow_fast_forward => {
                add_denied_push_updates(
                    findings,
                    "branch fast-forward publication is disabled by policy",
                );
                return;
            }
            UpdateClass::InitialBranch | UpdateClass::FastForwardBranch => {}
            UpdateClass::RewriteBranch if !push_policy.allow_force_with_lease => {
                add_denied_push_updates(
                    findings,
                    "non-fast-forward updates require the explicit force-with-lease policy opt-in",
                );
                return;
            }
            UpdateClass::RewriteBranch
                if planned.expected_lease_oid() != Some(update.remote_oid.as_str()) =>
            {
                add_unknown_push_updates(
                    findings,
                    "branch rewrite lacks an exact lease matching the advertised remote OID",
                );
                return;
            }
            UpdateClass::RewriteBranch => {}
            UpdateClass::ExistingBranch => {
                add_unknown_push_updates(findings, "branch ancestry was not classified");
                return;
            }
            UpdateClass::DeleteBranch if push_policy.allow_branch_deletion => {
                if planned.expected_lease_oid() != Some(update.remote_oid.as_str()) {
                    add_unknown_push_updates(
                        findings,
                        "branch deletion requires an exact lease matching the advertised remote OID",
                    );
                    return;
                }
            }
            UpdateClass::DeleteBranch => {
                add_denied_push_updates(findings, "branch deletion is not enabled by policy");
                return;
            }
            UpdateClass::AnnotatedTag if push_policy.allow_annotated_tags => {
                let Some(tag_name) = update.local_ref.strip_prefix("refs/tags/") else {
                    add_unknown_push_updates(findings, "annotated tag ref is malformed");
                    return;
                };
                let start = findings.len();
                add_tag_findings(
                    findings,
                    git,
                    root,
                    tag_name,
                    scope_policy.git.signing.as_ref(),
                    executables,
                );
                let tag_properties = [
                    "git.tag.signature.present",
                    "git.tag.signature.valid",
                    "git.tag.signature.fingerprint",
                ];
                let verified = tag_properties.iter().all(|property| {
                    findings[start..].iter().any(|finding| {
                        finding.property == *property && finding.status == Status::Pass
                    })
                });
                if verified {
                    findings.push(Finding::pass(
                        "git.push.tag_signature",
                        "annotated tag signature matches the profile key",
                        tag_name,
                        "the exact annotated tag object was locally verified before publication",
                    ));
                } else {
                    let failed = findings[start..].iter().any(|finding| {
                        tag_properties.contains(&finding.property.as_str())
                            && finding.status == Status::Fail
                    });
                    findings.push(Finding::status(
                        "git.push.tag_signature",
                        if failed {
                            Status::Fail
                        } else {
                            Status::Unknown
                        },
                        Some("valid profile-authorized annotated tag signature".to_owned()),
                        None,
                        "annotated tag signature evidence is missing, invalid, or unavailable",
                    ));
                    if failed {
                        add_denied_push_updates(
                            findings,
                            "annotated tag signature failed profile verification",
                        );
                    } else {
                        add_unknown_push_updates(
                            findings,
                            "annotated tag signature verification is incomplete",
                        );
                    }
                    return;
                }
            }
            UpdateClass::AnnotatedTag => {
                add_denied_push_updates(
                    findings,
                    "annotated tag publication is not enabled by policy",
                );
                return;
            }
            UpdateClass::LightweightTag if push_policy.allow_lightweight_tags => {
                findings.push(Finding::pass(
                    "git.push.tag_signature",
                    "lightweight tag explicitly allowed by policy",
                    update.local_ref.clone(),
                    "lightweight tag publication was separately opted into and is not represented as a signed annotated tag",
                ));
            }
            UpdateClass::LightweightTag => {
                add_denied_push_updates(
                    findings,
                    "lightweight tag publication is not enabled by policy",
                );
                return;
            }
            UpdateClass::TagUpdate => {
                add_unknown_push_updates(findings, "tag object kind could not be classified");
                return;
            }
            UpdateClass::DeleteTag if push_policy.allow_tag_deletion => {
                if planned.expected_lease_oid() != Some(update.remote_oid.as_str()) {
                    add_unknown_push_updates(
                        findings,
                        "tag deletion requires an exact lease matching the advertised remote OID",
                    );
                    return;
                }
            }
            UpdateClass::DeleteTag => {
                add_denied_push_updates(findings, "tag deletion is not enabled by policy");
                return;
            }
            UpdateClass::UnsupportedRef => {
                add_unknown_push_updates(findings, "non-branch publication is unsupported");
                return;
            }
        }
        let refs_to_validate = if matches!(
            planned.class(),
            UpdateClass::DeleteBranch | UpdateClass::DeleteTag
        ) {
            vec![update.remote_ref.as_str()]
        } else {
            vec![update.local_ref.as_str(), update.remote_ref.as_str()]
        };
        for refname in refs_to_validate {
            match git.valid_refname(root, refname) {
                Ok(true) => {}
                Ok(false) => {
                    add_unknown_push_updates(
                        findings,
                        "push update contains an invalid Git refname",
                    );
                    return;
                }
                Err(error) => {
                    add_unknown_push_updates(
                        findings,
                        format!("push refnames could not be validated: {error:?}"),
                    );
                    return;
                }
            }
        }
        if matches!(
            planned.class(),
            UpdateClass::DeleteBranch | UpdateClass::DeleteTag
        ) {
            continue;
        }
        if update.local_oid == update.remote_oid {
            continue;
        }
        reachable_tips.push(update.local_oid.clone());
        if matches!(
            planned.class(),
            UpdateClass::AnnotatedTag | UpdateClass::LightweightTag
        ) {
            let commit_oid = match planned.class() {
                UpdateClass::LightweightTag => update.local_oid.clone(),
                UpdateClass::AnnotatedTag => {
                    match git.tag_commit_target_oid(root, &update.local_oid) {
                        Ok(oid) => oid,
                        Err(_) => {
                            add_unknown_push_updates(
                                findings,
                                "annotated tag chain does not resolve to a complete commit object",
                            );
                            return;
                        }
                    }
                }
                _ => unreachable!(),
            };
            commit_updates.push(PushTuple {
                local_ref: update.local_ref.clone(),
                local_oid: commit_oid,
                remote_ref: update.remote_ref.clone(),
                remote_oid: "0".repeat(update.remote_oid.len()),
            });
        } else if update.remote_ref.starts_with("refs/heads/") {
            commit_updates.push(update.clone());
        }
    }
    if std::time::Instant::now() >= audit_deadline {
        add_unknown_push_updates(
            findings,
            "publication audit exceeded its operation-wide time budget",
        );
        return;
    }
    let _reachable_objects = if reachable_tips.is_empty() {
        Vec::new()
    } else {
        match git.reachable_publication_objects_many(root, &reachable_tips, audit_deadline) {
            Ok(graph) if graph.complete => graph.object_ids,
            Ok(_) => {
                add_unknown_push_updates(
                    findings,
                    "reachable Git objects are missing from the local object database",
                );
                return;
            }
            Err(error) => {
                add_unknown_push_updates(
                    findings,
                    format!("reachable Git objects could not be verified: {error:?}"),
                );
                return;
            }
        }
    };
    let commits = if commit_updates.is_empty() {
        Vec::new()
    } else {
        match git.outgoing_commit_identities_many(root, &commit_updates, audit_deadline) {
            Ok(commits) => commits,
            Err(error) => {
                add_unknown_push_updates(
                    findings,
                    format!("outgoing commit bounds or metadata are incomplete offline: {error:?}"),
                );
                return;
            }
        }
    };
    let applicable_baselines = push_policy
        .upstream_baselines
        .iter()
        .filter(|baseline| baseline.destination == request.destination)
        .cloned()
        .collect::<Vec<_>>();
    let trusted_upstream =
        match pinned_upstream_commits(git, root, &commits, &applicable_baselines, audit_deadline) {
            Ok(commits) => commits,
            Err(reason) => {
                add_unknown_push_updates(findings, reason);
                return;
            }
        };
    findings.push(if applicable_baselines.is_empty() {
        Finding::status(
            "git.push.provenance",
            Status::Unknown,
            None,
            None,
            "no explicitly pinned upstream provenance baseline is configured",
        )
    } else {
        Finding::pass(
            "git.push.provenance",
            "only commits ancestral to pinned baselines may use upstream identity provenance",
            format!(
                "{} outgoing commit(s) matched current pinned baseline(s)",
                trusted_upstream.len()
            ),
            "baseline identity exemptions are limited to the exact pinned destination, tracking ref, and object ID; unmatched commits remain subject to local identity policy",
        )
    });
    add_push_identity_findings(
        findings,
        &commits,
        &scope_policy.git.author,
        &scope_policy.git.committer,
        push_policy.preserve_authors,
        &trusted_upstream,
        request.tuples.len(),
    );
    add_push_signature_findings(
        findings,
        git,
        root,
        &commits,
        scope_policy.git.signing.as_ref(),
        &scope_policy.git.committer.email,
        executables,
        audit_deadline,
    );
}

fn pinned_upstream_commits(
    git: &GitClient,
    root: &Path,
    commits: &[CommitIdentity],
    baselines: &[crate::config::UpstreamBaseline],
    deadline: std::time::Instant,
) -> Result<HashSet<String>, String> {
    for baseline in baselines {
        if std::time::Instant::now() >= deadline {
            return Err(
                "upstream baseline validation exceeded the publication deadline".to_owned(),
            );
        }
        let current = git
            .resolve_commit_oid(root, &baseline.tracking_ref)
            .map_err(|_| "pinned upstream tracking ref is missing or invalid".to_owned())?;
        if !current.eq_ignore_ascii_case(&baseline.oid) {
            return Err("pinned upstream tracking ref moved; explicitly update the baseline before publishing".to_owned());
        }
    }
    let mut trusted = HashSet::new();
    for commit in commits {
        if std::time::Instant::now() >= deadline {
            return Err(
                "upstream provenance classification exceeded the publication deadline".to_owned(),
            );
        }
        for baseline in baselines {
            match git.is_ancestor(root, &commit.oid, &baseline.oid) {
                Ok(true) => {
                    trusted.insert(commit.oid.clone());
                    break;
                }
                Ok(false) => {}
                Err(_) => return Err("upstream commit ancestry could not be verified".to_owned()),
            }
            if std::time::Instant::now() >= deadline {
                return Err(
                    "upstream provenance classification exceeded the publication deadline"
                        .to_owned(),
                );
            }
        }
    }
    Ok(trusted)
}

fn add_push_identity_findings(
    findings: &mut Vec<Finding>,
    commits: &[CommitIdentity],
    expected_author: &crate::config::Identity,
    expected_committer: &crate::config::Identity,
    preserve_authors: bool,
    trusted_upstream: &HashSet<String>,
    update_count: usize,
) {
    let bad_author = (!preserve_authors)
        .then(|| {
            commits.iter().find(|commit| {
                &commit.author != expected_author && !trusted_upstream.contains(&commit.oid)
            })
        })
        .flatten();
    let bad_committer = commits.iter().find(|commit| {
        &commit.committer != expected_committer && !trusted_upstream.contains(&commit.oid)
    });
    findings.push(if bad_author.is_none() {
        Finding::status(
            "git.push.author",
            Status::Pass,
            Some(if preserve_authors {
                "outgoing author identities are explicitly preserved".to_owned()
            } else {
                "all outgoing commit authors match the scope policy".to_owned()
            }),
            Some(format!("{} outgoing commit(s) checked", commits.len())),
            if preserve_authors {
                "author metadata is preserved and is not treated as the local persona identity"
            } else {
                "every locally bounded outgoing commit author matched the explicit scope policy"
            },
        )
    } else {
        Finding::status(
            "git.push.author",
            Status::Fail,
            Some("all outgoing commit authors match the scope policy".to_owned()),
            Some("at least one outgoing commit author differed".to_owned()),
            "an outgoing commit author did not match the explicit scope policy",
        )
    });
    findings.push(if bad_committer.is_none() {
        Finding::status(
            "git.push.committer",
            Status::Pass,
            Some("all outgoing commit committers match the scope policy".to_owned()),
            Some(format!("{} outgoing commit(s) checked", commits.len())),
            "every locally bounded outgoing commit committer matched the explicit scope policy",
        )
    } else {
        Finding::status(
            "git.push.committer",
            Status::Fail,
            Some("all outgoing commit committers match the scope policy".to_owned()),
            Some("at least one outgoing commit committer differed".to_owned()),
            "an outgoing commit committer did not match the explicit scope policy",
        )
    });
    findings.push(Finding::pass(
        "git.push.updates",
        format!("{update_count} individually authorized publication update(s)"),
        format!("{update_count} supported publication update(s)"),
        "the exact caller-supplied update tuples were audited without executing a network operation",
    ));
}

fn add_signature_deadline_unknown(findings: &mut Vec<Finding>, fingerprint: &str) {
    for property in [
        "git.push.signature.present",
        "git.push.signature.valid",
        "git.push.signature.fingerprint",
    ] {
        findings.push(Finding::status(
            property,
            Status::Unknown,
            (property.ends_with("fingerprint")).then(|| fingerprint.to_owned()),
            None,
            "outgoing signature verification exceeded the operation-wide deadline",
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn add_push_ssh_signature_findings(
    findings: &mut Vec<Finding>,
    git: &GitClient,
    root: &Path,
    commits: &[CommitIdentity],
    policy: &SigningPolicy,
    principal: &str,
    executables: &ExecutablePaths,
    deadline: std::time::Instant,
) {
    let Some(executable) = executables.ssh_keygen.clone() else {
        for property in [
            "git.push.signature.present",
            "git.push.signature.valid",
            "git.push.signature.fingerprint",
        ] {
            findings.push(Finding::status(
                property,
                Status::Unknown,
                Some(policy.fingerprint.clone()),
                None,
                "ssh-keygen is unavailable for offline outgoing-signature verification",
            ));
        }
        return;
    };
    let verifier = SshVerifier::new(executable);
    let mut presence_failed = false;
    let mut presence_unknown = false;
    let mut valid_failed = false;
    let mut valid_unknown = false;
    let mut fingerprint_failed = false;
    let mut fingerprint_unknown = false;
    let mut checked = 0usize;

    for commit in commits {
        if std::time::Instant::now() >= deadline {
            break;
        }
        match git.commit_has_signature(root, &commit.oid) {
            Ok(true) => {
                checked += 1;
                match verifier.verify_commit(git, root, &commit.oid, &policy.public_key, principal)
                {
                    Ok(result) if result.cryptographically_valid => {
                        if result.fingerprint.as_deref() != Some(policy.fingerprint.as_str()) {
                            fingerprint_failed = result.fingerprint.is_some();
                            fingerprint_unknown = result.fingerprint.is_none();
                        }
                    }
                    Ok(_) => {
                        valid_failed = true;
                        fingerprint_unknown = true;
                    }
                    Err(_) => {
                        valid_unknown = true;
                        fingerprint_unknown = true;
                    }
                }
            }
            Ok(false) => {
                presence_failed = true;
                valid_failed = true;
                fingerprint_unknown = true;
            }
            Err(_) => {
                presence_unknown = true;
                valid_unknown = true;
                fingerprint_unknown = true;
            }
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
    }
    if std::time::Instant::now() >= deadline {
        add_signature_deadline_unknown(findings, &policy.fingerprint);
        return;
    }
    let observed = format!("{checked}/{} outgoing commit(s) inspected", commits.len());
    let status = |failed, unknown| {
        if failed {
            Status::Fail
        } else if unknown {
            Status::Unknown
        } else {
            Status::Pass
        }
    };
    findings.push(Finding::status(
        "git.push.signature.present",
        status(presence_failed, presence_unknown),
        Some("present on every outgoing commit".to_owned()),
        Some(observed.clone()),
        "each outgoing commit was checked for a Git signature",
    ));
    findings.push(Finding::status(
        "git.push.signature.valid",
        status(valid_failed, valid_unknown),
        Some("cryptographically valid under the configured SSH key".to_owned()),
        Some(observed.clone()),
        "each outgoing SSH signature was verified offline against the explicit allowed signer",
    ));
    findings.push(Finding::status(
        "git.push.signature.fingerprint",
        status(fingerprint_failed, fingerprint_unknown),
        Some(policy.fingerprint.clone()),
        Some(observed),
        "each verified outgoing SSH signature matched the configured key fingerprint",
    ));
}

#[allow(clippy::too_many_arguments)]
fn add_push_signature_findings(
    findings: &mut Vec<Finding>,
    git: &GitClient,
    root: &Path,
    commits: &[CommitIdentity],
    signing_policy: Option<&SigningPolicy>,
    signer_principal: &str,
    executables: &ExecutablePaths,
    deadline: std::time::Instant,
) {
    let Some(signing_policy) = signing_policy else {
        for property in [
            "git.push.signature.present",
            "git.push.signature.valid",
            "git.push.signature.fingerprint",
        ] {
            findings.push(Finding::status(
                property,
                Status::Unknown,
                None,
                None,
                "no required OpenPGP signing policy is configured for outgoing commits",
            ));
        }
        return;
    };

    if commits.is_empty() {
        for property in [
            "git.push.signature.present",
            "git.push.signature.valid",
            "git.push.signature.fingerprint",
        ] {
            findings.push(Finding::pass(
                property,
                "all outgoing commits satisfy the signing policy",
                "0 outgoing commits",
                "the supported update contains no new commits to publish",
            ));
        }
        return;
    }
    if signing_policy.format == SigningFormat::Ssh {
        add_push_ssh_signature_findings(
            findings,
            git,
            root,
            commits,
            signing_policy,
            signer_principal,
            executables,
            deadline,
        );
        return;
    }

    let mut presence_failed = false;
    let mut presence_unknown = false;
    let mut valid_failed = false;
    let mut valid_unknown = false;
    let mut fingerprint_failed = false;
    let mut fingerprint_unknown = false;
    let mut checked = 0usize;
    let expected_fingerprint = signing_policy.fingerprint.to_ascii_uppercase();

    let gpg_context = executables.gpg.clone().map(GpgClient::new);
    let keyring = match gpg_context.as_ref() {
        Some(gpg) => gpg.isolated_keyring(&signing_policy.public_key).ok(),
        None => None,
    };
    if std::time::Instant::now() >= deadline {
        add_signature_deadline_unknown(findings, &signing_policy.fingerprint);
        return;
    }

    for commit in commits {
        if std::time::Instant::now() >= deadline {
            break;
        }
        match git.commit_has_signature(root, &commit.oid) {
            Ok(true) => {
                checked += 1;
                if let (Some(gpg), Some(keyring)) = (gpg_context.as_ref(), keyring.as_ref()) {
                    match gpg.verify_commit_oid(git, root, &commit.oid, keyring.path()) {
                        Ok(verification) if verification.cryptographically_valid => {
                            if verification.primary_fingerprint.as_deref()
                                == Some(expected_fingerprint.as_str())
                            {
                                // This commit satisfies all signing requirements.
                            } else if verification.primary_fingerprint.is_some() {
                                fingerprint_failed = true;
                            } else {
                                fingerprint_unknown = true;
                            }
                        }
                        Ok(verification) if verification.unavailable_key => {
                            valid_unknown = true;
                            fingerprint_unknown = true;
                        }
                        Ok(_) => {
                            valid_failed = true;
                            fingerprint_unknown = true;
                        }
                        Err(_) => {
                            valid_unknown = true;
                            fingerprint_unknown = true;
                        }
                    }
                } else {
                    valid_unknown = true;
                    fingerprint_unknown = true;
                }
            }
            Ok(false) => {
                presence_failed = true;
                valid_failed = true;
                fingerprint_unknown = true;
            }
            Err(_) => {
                presence_unknown = true;
                valid_unknown = true;
                fingerprint_unknown = true;
            }
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
    }
    if std::time::Instant::now() >= deadline {
        add_signature_deadline_unknown(findings, &signing_policy.fingerprint);
        return;
    }

    let checked_text = format!("{checked}/{} outgoing commit(s) inspected", commits.len());
    let presence_status = if presence_failed {
        Status::Fail
    } else if presence_unknown {
        Status::Unknown
    } else {
        Status::Pass
    };
    findings.push(Finding::status(
        "git.push.signature.present",
        presence_status,
        Some("present on every outgoing commit".to_owned()),
        Some(checked_text.clone()),
        "every outgoing commit was checked for an embedded OpenPGP signature",
    ));

    let valid_status = if valid_failed {
        Status::Fail
    } else if valid_unknown {
        Status::Unknown
    } else {
        Status::Pass
    };
    findings.push(Finding::status(
        "git.push.signature.valid",
        valid_status,
        Some("cryptographically valid under the configured key".to_owned()),
        Some(checked_text.clone()),
        "every signed outgoing commit was verified with the isolated public keyring",
    ));

    let fingerprint_status = if fingerprint_failed {
        Status::Fail
    } else if fingerprint_unknown {
        Status::Unknown
    } else {
        Status::Pass
    };
    findings.push(Finding::status(
        "git.push.signature.fingerprint",
        fingerprint_status,
        Some(signing_policy.fingerprint.clone()),
        Some(checked_text),
        "every verified outgoing signature mapped to the configured primary fingerprint",
    ));
}

fn add_denied_push_updates(findings: &mut Vec<Finding>, reason: &str) {
    findings.push(Finding::status(
        "git.push.updates",
        Status::Fail,
        Some("update class permitted by publication policy".to_owned()),
        Some("explicitly denied".to_owned()),
        reason,
    ));
    for property in [
        "git.push.author",
        "git.push.committer",
        "git.push.signature.present",
        "git.push.signature.valid",
        "git.push.signature.fingerprint",
    ] {
        findings.push(Finding::status(
            property,
            Status::Unknown,
            None,
            None,
            "update was rejected by policy before commit metadata authorization",
        ));
    }
}

fn add_unknown_push_updates(findings: &mut Vec<Finding>, reason: impl Into<String>) {
    add_unknown_push_findings(findings, reason);
}

fn add_unknown_push_findings(findings: &mut Vec<Finding>, reason: impl Into<String>) {
    let reason = reason.into();
    for property in [
        "git.push.updates",
        "git.push.author",
        "git.push.committer",
        "git.push.signature.present",
        "git.push.signature.valid",
        "git.push.signature.fingerprint",
    ] {
        findings.push(Finding::status(
            property,
            Status::Unknown,
            None,
            None,
            reason.clone(),
        ));
    }
}

fn valid_update_shape(update: &PushTuple) -> bool {
    is_valid_oid(&update.local_oid)
        && is_valid_oid(&update.remote_oid)
        && !update.local_ref.is_empty()
        && update.remote_ref.starts_with("refs/")
}

fn is_valid_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn add_environment_findings(findings: &mut Vec<Finding>) {
    let gh_token = std::env::var_os("GH_TOKEN").is_some();
    let github_token = std::env::var_os("GITHUB_TOKEN").is_some();
    let enterprise_token = std::env::var_os("GH_ENTERPRISE_TOKEN").is_some();
    let github_enterprise_token = std::env::var_os("GITHUB_ENTERPRISE_TOKEN").is_some();
    let gh_host = std::env::var_os("GH_HOST").is_some();
    let gh_config_dir = std::env::var_os("GH_CONFIG_DIR").is_some();

    let token_source = match (gh_token, github_token) {
        (true, true) => {
            "GH_TOKEN present (takes precedence over GITHUB_TOKEN); GITHUB_TOKEN present"
        }
        (true, false) => "GH_TOKEN present; GITHUB_TOKEN absent",
        (false, true) => "GH_TOKEN absent; GITHUB_TOKEN present",
        (false, false) => "GH_TOKEN absent; GITHUB_TOKEN absent",
    };
    let github_observed = format!(
        "{token_source}; GH_ENTERPRISE_TOKEN {}; GITHUB_ENTERPRISE_TOKEN {}; GH_HOST {}; GH_CONFIG_DIR {}",
        presence_label(enterprise_token),
        presence_label(github_enterprise_token),
        presence_label(gh_host),
        presence_label(gh_config_dir),
    );
    findings.push(Finding::status(
        "github.account",
        Status::Unknown,
        Some("authenticated GitHub principal".to_owned()),
        Some(github_observed),
        "only parent-process environment variable presence was inspected; token, host, config path, and authenticated principal were not read",
    ));

    let ssh_observed = [
        ("GIT_SSH", std::env::var_os("GIT_SSH").is_some()),
        (
            "GIT_SSH_COMMAND",
            std::env::var_os("GIT_SSH_COMMAND").is_some(),
        ),
        ("SSH_AUTH_SOCK", std::env::var_os("SSH_AUTH_SOCK").is_some()),
    ]
    .into_iter()
    .map(|(name, present)| format!("{name} {}", presence_label(present)))
    .collect::<Vec<_>>()
    .join(", ");
    findings.push(Finding::status(
        "ssh",
        Status::Unknown,
        Some("authenticated SSH principal".to_owned()),
        Some(ssh_observed),
        "only parent-process SSH environment variable presence was inspected; no SSH config, agent, key, helper, or network probe was used",
    ));
}

fn presence_label(present: bool) -> &'static str {
    if present { "present" } else { "absent" }
}

fn add_remote_transport_finding(
    findings: &mut Vec<Finding>,
    root: Option<&Path>,
    git: &GitClient,
    remote: Option<&str>,
) {
    let Some(root) = root else {
        findings.push(Finding::status(
            "git.remote.transport",
            Status::Unknown,
            None,
            None,
            "configured remote transport is unknown because no Git worktree was found",
        ));
        return;
    };

    match git.remote_transport_schemes(root, remote) {
        Ok(schemes) if schemes.is_empty() => findings.push(Finding::status(
            "git.remote.transport",
            Status::Unknown,
            None,
            None,
            "no configured Git remote transport scheme was found offline",
        )),
        Ok(schemes) => findings.push(Finding::status(
            "git.remote.transport",
            Status::Unknown,
            Some("configured transport scheme only; authentication remains unknown".to_owned()),
            Some(schemes.join(", ")),
            "transport scheme was observed from local Git configuration without exposing remote URL values or performing network I/O",
        )),
        Err(error) => findings.push(Finding::status(
            "git.remote.transport",
            Status::Unknown,
            None,
            None,
            format!("configured remote transport could not be observed offline: {error:?}"),
        )),
    }
}

fn add_publication_finding(findings: &mut Vec<Finding>) {
    findings.push(Finding::status(
        "publication",
        Status::Unknown,
        None,
        None,
        "remote reachability, credentials, and outgoing history are not proven by offline inspection",
    ));
}
