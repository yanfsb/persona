use clap::{Args, Parser, Subcommand, ValueEnum};
use persona::config::{Config, SigningPolicy};
use persona::context::resolve_context;
use persona::git::{CommitIdentity, EffectiveSigning, GitClient, PushTuple, safe_environment};
use persona::gpg::GpgClient;
use persona::report::{Finding, Report, Status, exit_code};
use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const EXIT_ERROR: u8 = 2;

fn error_exit(message: String) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::from(EXIT_ERROR)
}

#[derive(Parser)]
#[command(name = "persona", version, about = "Directory-scoped identity auditor")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Status(AuditArgs),
    Check(AuditArgs),
}

#[derive(Args)]
struct AuditArgs {
    #[arg(long)]
    config: PathBuf,

    #[arg(long, default_value = ".")]
    cwd: PathBuf,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Alias for --format json.
    #[arg(long, conflicts_with = "format")]
    json: bool,

    #[arg(long, value_enum)]
    operation: Option<Operation>,

    #[arg(long)]
    remote: Option<String>,

    #[arg(long)]
    destination: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Operation {
    Status,
    Push,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Status(args) => {
            if args.operation.is_some() || args.remote.is_some() || args.destination.is_some() {
                Err("--operation, --remote and --destination are only valid for check".to_owned())
            } else {
                show_status(
                    &args.config,
                    &args.cwd,
                    if args.json {
                        OutputFormat::Json
                    } else {
                        args.format
                    },
                    None,
                )
            }
        }
        Commands::Check(args) => {
            let operation = args.operation.unwrap_or(Operation::Status);
            match operation {
                Operation::Status if args.remote.is_some() || args.destination.is_some() => {
                    Err("--remote and --destination require --operation push".to_owned())
                }
                Operation::Status => show_status(
                    &args.config,
                    &args.cwd,
                    if args.json {
                        OutputFormat::Json
                    } else {
                        args.format
                    },
                    None,
                ),
                Operation::Push => {
                    let remote = args
                        .remote
                        .ok_or_else(|| "--remote is required with --operation push".to_owned());
                    let destination = args.destination.ok_or_else(|| {
                        "--destination is required with --operation push".to_owned()
                    });
                    match (remote, destination) {
                        (Ok(remote), Ok(destination)) => {
                            let tuples = match read_push_tuples() {
                                Ok(tuples) => tuples,
                                Err(error) => return error_exit(error),
                            };
                            show_status(
                                &args.config,
                                &args.cwd,
                                if args.json {
                                    OutputFormat::Json
                                } else {
                                    args.format
                                },
                                Some(PushRequest {
                                    remote,
                                    destination,
                                    tuples,
                                }),
                            )
                        }
                        (Err(error), _) | (_, Err(error)) => Err(error),
                    }
                }
            }
        }
    };

    match result {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

struct PushRequest {
    remote: String,
    destination: String,
    tuples: Vec<PushTuple>,
}

fn read_push_tuples() -> Result<Vec<PushTuple>, String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| format!("cannot read push update tuples: {error}"))?;
    input
        .lines()
        .map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() != 4 || fields.iter().any(|field| field.is_empty()) {
                return Err("push update input must contain exactly four whitespace-separated fields per line".to_owned());
            }
            Ok(PushTuple {
                local_ref: fields[0].to_owned(),
                local_oid: fields[1].to_owned(),
                remote_ref: fields[2].to_owned(),
                remote_oid: fields[3].to_owned(),
            })
        })
        .collect()
}

fn show_status(
    config_path: &Path,
    directory: &Path,
    format: OutputFormat,
    push: Option<PushRequest>,
) -> Result<u8, String> {
    let current_directory = std::env::current_dir()
        .map_err(|error| format!("cannot determine current directory: {error}"))?;

    let config_path = absolute_path(config_path, &current_directory);
    let directory = absolute_path(directory, &current_directory);
    let config = Config::load(&config_path).map_err(|error| format!("{error:?}"))?;
    let (report, selected) = build_report(&config, &directory, push.as_ref())?;

    match format {
        OutputFormat::Text => print_text(&config, selected.as_ref(), &report),
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&report)
                .map_err(|error| format!("cannot encode report: {error}"))?;
            println!("{json}");
        }
    }

    Ok(exit_code(report.status))
}

fn build_report(
    config: &Config,
    directory: &Path,
    push: Option<&PushRequest>,
) -> Result<(Report, Option<persona::Scope>), String> {
    let git = GitClient::new(git_executable(), safe_environment());
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
        Some(scope) if policy.is_some() => findings.push(Finding::pass(
            "scope",
            format!("{} ({})", scope.name, scope.root.display()),
            format!("{} ({})", scope.name, scope.root.display()),
            "physical Git checkout root matched the most specific configured scope",
        )),
        Some(scope) => findings.push(Finding::status(
            "scope",
            Status::Fail,
            None,
            Some(scope.name.clone()),
            "resolved scope has no corresponding policy",
        )),
        None => findings.push(Finding::status(
            "scope",
            Status::Unknown,
            None,
            Some("unmanaged".to_owned()),
            "physical checkout root is outside every configured scope",
        )),
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
        add_signing_findings(&mut findings, &git, root, policy);
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
        add_push_findings(&mut findings, &git, directory, policy, push);
    }
    Ok((Report::new(findings), selected))
}

fn add_identity_findings(
    findings: &mut Vec<Finding>,
    git: &GitClient,
    root: &Path,
    policy: Option<&persona::config::ScopePolicy>,
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
    observed: Result<persona::config::Identity, persona::git::GitError>,
    expected: Option<&persona::config::Identity>,
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
    policy: Option<&persona::config::ScopePolicy>,
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
    policy: Option<&persona::config::ScopePolicy>,
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

fn identity_text(identity: &persona::config::Identity) -> String {
    format!("{} <{}>", identity.name, identity.email)
}

fn add_signing_findings(
    findings: &mut Vec<Finding>,
    git: &GitClient,
    root: &Path,
    policy: Option<&persona::config::ScopePolicy>,
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

    let effective = git.effective_signing(root);
    let mut gpg_problem = None;
    let gpg_context = match gpg_executable() {
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
    policy: Option<&persona::config::ScopePolicy>,
    request: &PushRequest,
) {
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

    if request.tuples.is_empty() {
        add_unknown_push_updates(findings, "no push update tuples were supplied");
        return;
    }
    if request.tuples.len() != 1 {
        add_unknown_push_updates(
            findings,
            "multiple ref updates are conservatively unsupported by the offline push audit",
        );
        return;
    }

    let update = &request.tuples[0];
    if !valid_update_shape(update) {
        add_unknown_push_updates(findings, "push update tuple is not in native Git shape");
        return;
    }
    if update.local_ref == "(delete)" || is_zero_oid(&update.local_oid) {
        add_unknown_push_updates(
            findings,
            "deletions are not authorized by this offline audit",
        );
        return;
    }
    if !update.local_ref.starts_with("refs/heads/") || !update.remote_ref.starts_with("refs/heads/")
    {
        add_unknown_push_updates(
            findings,
            "tag and non-branch updates are unsupported without tag metadata/signature policy",
        );
        return;
    }
    if is_zero_oid(&update.remote_oid) {
        add_unknown_push_updates(
            findings,
            "new branch updates are conservatively unsupported",
        );
        return;
    }
    if update.local_oid == update.remote_oid {
        add_push_identity_findings(
            findings,
            &[],
            &scope_policy.git.author,
            &scope_policy.git.committer,
        );
        add_push_signature_findings(findings, git, root, &[], scope_policy.git.signing.as_ref());
        return;
    }
    match git.is_ancestor(root, &update.remote_oid, &update.local_oid) {
        Ok(true) => {}
        Ok(false) => {
            add_unknown_push_updates(findings, "force updates are not authorized by this audit");
            return;
        }
        Err(error) => {
            add_unknown_push_updates(
                findings,
                format!("update ancestry could not be established from local objects: {error:?}"),
            );
            return;
        }
    }
    match git.outgoing_commit_identities(root, update) {
        Ok(commits) => {
            add_push_identity_findings(
                findings,
                &commits,
                &scope_policy.git.author,
                &scope_policy.git.committer,
            );
            add_push_signature_findings(
                findings,
                git,
                root,
                &commits,
                scope_policy.git.signing.as_ref(),
            );
        }
        Err(error) => add_unknown_push_updates(
            findings,
            format!("outgoing commit bounds or metadata are incomplete offline: {error:?}"),
        ),
    }
}

fn add_push_identity_findings(
    findings: &mut Vec<Finding>,
    commits: &[CommitIdentity],
    expected_author: &persona::config::Identity,
    expected_committer: &persona::config::Identity,
) {
    let bad_author = commits
        .iter()
        .find(|commit| &commit.author != expected_author);
    let bad_committer = commits
        .iter()
        .find(|commit| &commit.committer != expected_committer);
    findings.push(if bad_author.is_none() {
        Finding::status(
            "git.push.author",
            Status::Pass,
            Some("all outgoing commit authors match the scope policy".to_owned()),
            Some(format!("{} outgoing commit(s) checked", commits.len())),
            "every locally bounded outgoing commit author matched the explicit scope policy",
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
        "one non-deletion, non-force branch update",
        "one supported branch update",
        "the exact caller-supplied update tuple was audited without executing a network operation",
    ));
}

fn add_push_signature_findings(
    findings: &mut Vec<Finding>,
    git: &GitClient,
    root: &Path,
    commits: &[CommitIdentity],
    signing_policy: Option<&SigningPolicy>,
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

    let mut presence_failed = false;
    let mut presence_unknown = false;
    let mut valid_failed = false;
    let mut valid_unknown = false;
    let mut fingerprint_failed = false;
    let mut fingerprint_unknown = false;
    let mut checked = 0usize;
    let expected_fingerprint = signing_policy.fingerprint.to_ascii_uppercase();

    let gpg_context = gpg_executable().map(GpgClient::new);
    let keyring = match gpg_context.as_ref() {
        Some(gpg) => gpg.isolated_keyring(&signing_policy.public_key).ok(),
        None => None,
    };

    for commit in commits {
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

fn is_zero_oid(value: &str) -> bool {
    is_valid_oid(value) && value.chars().all(|character| character == '0')
}

fn add_environment_findings(findings: &mut Vec<Finding>) {
    let gh_token = std::env::var_os("GH_TOKEN").is_some();
    let github_token = std::env::var_os("GITHUB_TOKEN").is_some();
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
        "{token_source}; GH_HOST {}; GH_CONFIG_DIR {}",
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

fn print_text(config: &Config, selected: Option<&persona::Scope>, report: &Report) {
    match selected {
        Some(scope) => {
            println!("scope: {}", scope.name);
            println!("scope root: {}", scope.root.display());
            if let Some(policy) = config.policies().iter().find(|p| p.name == scope.name) {
                println!(
                    "expected author: {} <{}>",
                    policy.git.author.name, policy.git.author.email
                );
                println!(
                    "expected committer: {} <{}>",
                    policy.git.committer.name, policy.git.committer.email
                );
            }
        }
        None => {
            println!("scope: unmanaged");
            println!("identity: no identity assumed");
        }
    }

    println!("result: {}", format!("{:?}", report.status).to_uppercase());
    println!("coverage: per-property offline findings");
    let worktree_checked = report
        .findings
        .iter()
        .any(|finding| finding.property == "git.worktree" && finding.status == Status::Pass);
    let identity_checked = report.findings.iter().any(|finding| {
        (finding.property == "git.author" || finding.property == "git.committer")
            && finding.observed.is_some()
    });
    match (worktree_checked, identity_checked) {
        (true, true) => println!("Git worktree and effective identity checked offline"),
        (true, false) => println!("Git worktree checked offline; effective identity unknown"),
        _ => println!("Git worktree and identity not checked"),
    }
    println!(
        "SSH/gh indicators and remote transport were inspected offline; authentication and publication remain unknown"
    );

    let mut details = String::new();
    for finding in &report.findings {
        let _ = write!(
            details,
            "finding {}: {:?} ({}), ",
            finding.property, finding.status, finding.coverage_reason
        );
        if let Some(expected) = &finding.expected {
            let _ = write!(details, "expected={expected}, ");
        }
        if let Some(observed) = &finding.observed {
            let _ = write!(details, "observed={observed}, ");
        }
        let _ = writeln!(details);
    }
    print!("{details}");
}

fn git_executable() -> PathBuf {
    if let Some(path) = std::env::var_os("PERSONA_GIT") {
        return PathBuf::from(path);
    }
    find_executable("git").unwrap_or_else(|| PathBuf::from("/usr/bin/git"))
}

fn gpg_executable() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PERSONA_GPG") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    find_executable("gpg")
}

fn find_executable(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
}

fn absolute_path(path: &Path, base: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}
