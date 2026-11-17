use crate::audit::{ExecutablePaths, build_tag_report};
use crate::authorization::{Operation as AuthorizationOperation, authorize};
use crate::config::Config;
use crate::git::GitClient;
use crate::runtime::{
    absolute_path, build_managed_path, gh_executable, git_executable, gpg_executable,
    resolve_config_path, ssh_keygen_executable, status_exit_code, validate_managed_shim_directory,
};
use crate::storage::PersonaPaths;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn format_asset_upload_failure(
    uploaded: &[String],
    uncertain: Option<&str>,
    reason: &str,
) -> String {
    let mut message = reason.to_owned();
    if !uploaded.is_empty() {
        message.push_str("; confirmed uploaded assets: ");
        message.push_str(&uploaded.join(", "));
    }
    if let Some(name) = uncertain {
        message.push_str("; uncertain asset: ");
        message.push_str(name);
    }
    message
}

fn infer_github_repository_from_cwd(cwd: &Path) -> Option<String> {
    let git = GitClient::new(git_executable(), crate::git::safe_environment());
    let root = git.checkout_root(cwd).ok()?;
    let remote = git
        .default_fetch_remote(&root)
        .unwrap_or_else(|_| "origin".to_owned());
    let destinations = git.effective_fetch_destinations(&root, &remote).ok()?;
    if destinations.len() != 1 {
        return None;
    }
    crate::gh_adapter::repository_from_destination(&destinations[0])
}

pub fn run_managed_gh() -> Result<u8, String> {
    let shim_directory = validate_managed_shim_directory()?;
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let cwd = std::env::current_dir()
        .map_err(|_| "cannot resolve the GitHub operation directory".to_owned())?;
    let inferred_repository = infer_github_repository_from_cwd(&cwd);
    let request = crate::gh_adapter::parse_with_inferred_repository(
        &arguments,
        inferred_repository.as_deref(),
    )?;
    let native_gh = gh_executable()
        .ok_or_else(|| "an absolute native GitHub CLI executable is required".to_owned())?;
    if !native_gh.is_absolute() || !native_gh.is_file() {
        return Err("native GitHub CLI executable is unavailable".to_owned());
    }
    for variable in [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "GH_HOST",
        "GH_CONFIG_DIR",
        "GH_REPO",
    ] {
        if std::env::var_os(variable).is_some() {
            return Err(format!(
                "inherited {variable} override is not permitted for managed gh"
            ));
        }
    }
    for variable in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
    ] {
        if std::env::var_os(variable).is_some() {
            return Err(format!(
                "inherited {variable} override makes the GitHub operation ambiguous"
            ));
        }
    }

    let config_path = match std::env::var_os("PERSONA_CONFIG_PATH") {
        Some(path) => PathBuf::from(path),
        None => resolve_config_path(None)?,
    };
    let config_path = absolute_path(&config_path, &cwd);
    let config = Config::load(&config_path).map_err(|error| format!("{error:?}"))?;
    let target_directory = request.clone_directory.as_ref().map(|clone_directory| {
        if clone_directory.is_absolute() {
            clone_directory.clone()
        } else {
            cwd.join(clone_directory)
        }
    });
    if target_directory
        .as_ref()
        .is_some_and(|target| target.exists() || std::fs::symlink_metadata(target).is_ok())
    {
        return Err("gh repo clone target already exists".to_owned());
    }
    let selected_scope = crate::context::resolve_operation_context(
        &cwd,
        target_directory.as_deref(),
        &config.scopes(),
    )
    .map_err(|_| "cannot resolve the physical GitHub operation scope".to_owned())?
    .ok_or_else(|| {
        if target_directory.is_some() {
            "gh repo clone target is outside every configured Persona scope".to_owned()
        } else {
            "gh is blocked outside a configured Persona scope".to_owned()
        }
    })?;
    let policy = config
        .policies()
        .iter()
        .find(|policy| policy.name == selected_scope.name)
        .ok_or_else(|| "selected GitHub scope policy is unavailable".to_owned())?;
    let profile = config
        .profiles()
        .iter()
        .find(|profile| profile.name == policy.profile)
        .ok_or_else(|| "selected GitHub profile is unavailable".to_owned())?;
    let binding = profile
        .github
        .as_ref()
        .ok_or_else(|| "selected profile has no enrolled GitHub account binding".to_owned())?;
    if binding.host != "github.com" {
        return Err("managed gh supports only the explicitly bound github.com host".to_owned());
    }

    let flag_refs = request.flags.iter().map(String::as_str).collect::<Vec<_>>();
    binding
        .commands
        .evaluate(&[request.selector.as_str()], &flag_refs)
        .map_err(|denial| denial.describe("GitHub CLI", &request.selector))?;

    if !request.repositories.is_empty()
        && (binding.repositories.is_empty()
            || request
                .repositories
                .iter()
                .any(|repository| !binding.permits_repository(repository)))
    {
        return Err(
            "GitHub repository target is not in the selected profile's explicit allowlist"
                .to_owned(),
        );
    }

    let release_target = request
        .release
        .as_ref()
        .map(|release| (release.repository.as_str(), release.tag.as_str()))
        .or_else(|| {
            request
                .asset_upload
                .as_ref()
                .map(|upload| (upload.repository.as_str(), upload.tag.as_str()))
        });
    let audited_release_tag_oid = if let Some((repository, tag)) = release_target {
        if !binding.permits_repository(repository) {
            return Err("release repository is not in the enrolled profile allowlist".to_owned());
        }
        let push = profile.git.push.as_ref().ok_or_else(|| {
            "release operations require an explicit signed-tag publication policy".to_owned()
        })?;
        if !push.allow_annotated_tags || profile.git.signing.is_none() {
            return Err(
                "release operations require explicit annotated-tag publication and signing policy"
                    .to_owned(),
            );
        }
        let has_destination = profile
            .git
            .configured_push_destinations(&push.remote)
            .unwrap_or(&[])
            .iter()
            .any(|destination| {
                crate::gh_adapter::repository_from_destination(destination).as_deref()
                    == Some(repository)
                    || crate::destination::destination_matches_pattern(
                        &format!("https://github.com/{repository}.git"),
                        destination,
                    )
                    || crate::destination::destination_matches_pattern(
                        &format!("git@github.com:{repository}.git"),
                        destination,
                    )
            });
        if !has_destination {
            return Err(
                "release repository has no matching profile-bound publication destination"
                    .to_owned(),
            );
        }
        let executables = ExecutablePaths {
            git: git_executable(),
            gpg: gpg_executable(),
            ssh_keygen: ssh_keygen_executable(),
        };
        let (tag_report, _) = build_tag_report(&config, &cwd, tag, &executables)?;
        let tag_decision = authorize(
            AuthorizationOperation::GitTagVerification,
            vec![
                "scope".to_owned(),
                "policy.profile".to_owned(),
                "git.worktree".to_owned(),
                "git.tag.signing.config".to_owned(),
                "git.tag.signature.present".to_owned(),
                "git.tag.signature.valid".to_owned(),
                "git.tag.signature.fingerprint".to_owned(),
            ],
            tag_report.findings,
        );
        if !tag_decision.is_allowed() {
            return Err("release tag failed local profile signature and scope audit".to_owned());
        }
        let git = GitClient::new(git_executable(), crate::git::safe_environment());
        let reference = format!("refs/tags/{tag}");
        let oid = git
            .resolve_object_oid(&cwd, &reference)
            .map_err(|_| "release tag object is unavailable".to_owned())?;
        if git
            .object_type(&cwd, &oid)
            .map_err(|_| "cannot inspect release tag object".to_owned())?
            != "tag"
        {
            return Err(
                "release operation accepts only an existing signed annotated tag".to_owned(),
            );
        }
        let commit_oid = git.tag_commit_target_oid(&cwd, &oid).map_err(|_| {
            "release tag does not resolve through a valid annotated-tag chain to a commit"
                .to_owned()
        })?;
        Some((oid, commit_oid))
    } else {
        None
    };

    let asset_snapshots = if let Some(upload) = &request.asset_upload {
        let git = GitClient::new(git_executable(), crate::git::safe_environment());
        let root = git
            .checkout_root(&cwd)
            .map_err(|_| "release asset upload requires a managed Git worktree".to_owned())?;
        Some(
            crate::asset_upload::snapshot_files(&root, &cwd, &upload.files)
                .map_err(|message| format!("cannot preflight release assets: {message}"))?,
        )
    } else {
        None
    };

    let checkout_plan = if let Some(checkout) = &request.checkout {
        let git = GitClient::new(git_executable(), crate::git::safe_environment());
        let root = git
            .checkout_root(&cwd)
            .map_err(|_| "PR checkout requires an existing managed Git worktree".to_owned())?;
        if !git
            .worktree_is_clean(&root)
            .map_err(|_| "cannot verify clean worktree before PR checkout".to_owned())?
        {
            return Err("PR checkout requires a clean worktree".to_owned());
        }
        let branch = checkout
            .branch
            .clone()
            .unwrap_or_else(|| format!("pr-{}", checkout.pull_number));
        let branch_ref = format!("refs/heads/{branch}");
        if !git
            .valid_refname(&root, &branch_ref)
            .map_err(|_| "cannot validate PR checkout branch".to_owned())?
        {
            return Err("PR checkout branch name is invalid".to_owned());
        }
        if git
            .optional_commit_oid(&root, &branch_ref)
            .map_err(|_| "cannot inspect existing PR checkout branch".to_owned())?
            .is_some()
        {
            return Err("PR checkout refuses to overwrite an existing local branch".to_owned());
        }
        let repo_https = format!("https://github.com/{}.git", checkout.repository);
        let repo_ssh = format!("git@github.com:{}.git", checkout.repository);
        let candidates = profile
            .git
            .remotes
            .iter()
            .filter(|remote| remote.name != "*")
            .filter(|remote| {
                remote.fetch_destinations.iter().any(|destination| {
                    crate::gh_adapter::repository_from_destination(destination).as_deref()
                        == Some(checkout.repository.as_str())
                        || crate::destination::destination_matches_pattern(&repo_https, destination)
                        || crate::destination::destination_matches_pattern(&repo_ssh, destination)
                })
            })
            .map(|remote| remote.name.clone())
            .collect::<Vec<_>>();
        let remote = if candidates.is_empty() {
            let repo_remotes = git.configured_remotes(&root).unwrap_or_default();
            if let Some(matching) = repo_remotes.into_iter().find(|remote_name| {
                git.effective_fetch_destinations(&root, remote_name)
                    .ok()
                    .is_some_and(|urls| {
                        urls.len() == 1
                            && crate::gh_adapter::repository_from_destination(&urls[0]).as_deref()
                                == Some(checkout.repository.as_str())
                            && profile.git.permits_fetch_destination(remote_name, &urls[0])
                    })
            }) {
                vec![matching]
            } else if profile.git.remotes.is_empty() {
                profile
                    .git
                    .push
                    .as_ref()
                    .filter(|push| {
                        push.destinations.iter().any(|destination| {
                            crate::gh_adapter::repository_from_destination(destination).as_deref()
                                == Some(checkout.repository.as_str())
                        })
                    })
                    .map(|push| vec![push.remote.clone()])
                    .unwrap_or_default()
            } else {
                Vec::new()
            }
        } else {
            candidates
        };
        if remote.len() != 1 {
            return Err(
                "PR checkout requires exactly one profile-bound fetch remote for the repository"
                    .to_owned(),
            );
        }
        Some((root, remote[0].clone(), branch))
    } else {
        None
    };

    let merge_rule = if let Some(merge) = &request.merge {
        let policy = profile.github_merge.as_ref().ok_or_else(|| {
            "server-side merge requires an explicit profile GitHub merge policy".to_owned()
        })?;
        let rule = policy
            .repositories
            .iter()
            .find(|rule| rule.repository == merge.repository)
            .ok_or_else(|| {
                "server-side merge repository is not authorized by this profile".to_owned()
            })?;
        if !rule.strategies.contains(&merge.strategy) {
            return Err("server-side merge strategy is not authorized by this profile".to_owned());
        }
        Some(rule)
    } else {
        None
    };

    let paths =
        PersonaPaths::discover().map_err(|_| "cannot resolve private Persona state".to_owned())?;
    let selector =
        crate::credential::GithubSelector::discover(native_gh.clone(), binding.host.clone(), paths)
            .map_err(|_| {
                "cannot safely resolve the native GitHub credential selector".to_owned()
            })?;
    let selected_token = selector
        .token_for_binding(binding)
        .map_err(|_| "cannot safely verify the selected native GitHub account".to_owned())?
        .ok_or_else(|| {
            "selected native GitHub credential does not match the enrolled account binding"
                .to_owned()
        })?;

    if let (Some(merge), Some(rule)) = (&request.merge, merge_rule) {
        let (base_branch, expected_head) = selector
            .pull_request_merge_context(&selected_token, &merge.repository, merge.pull_number)
            .map_err(|_| "cannot safely verify the pull request base and head".to_owned())?;
        if !rule.base_branches.contains(&base_branch) {
            return Err(
                "pull request base branch is not authorized for server-side merging".to_owned(),
            );
        }
        let merge_sha = selector
            .merge_pull_request(
                &selected_token,
                &merge.repository,
                merge.pull_number,
                merge.strategy,
                &expected_head,
            )
            .map_err(|_| "GitHub refused the policy-bound server-side merge".to_owned())?;
        println!(
            "Merged {}#{} using {:?}; GitHub created server-side commit {merge_sha} (not locally signed by Persona).",
            merge.repository, merge.pull_number, merge.strategy
        );
        return Ok(0);
    }

    if let (Some(checkout), Some((root, remote, branch))) =
        (&request.checkout, checkout_plan.as_ref())
    {
        let (expected_head, _head_ref) = selector
            .pull_request_checkout_context(
                &selected_token,
                &checkout.repository,
                checkout.pull_number,
            )
            .map_err(|_| "cannot retrieve allowlisted pull request head metadata".to_owned())?;
        let shim_git = shim_directory.join("git");
        let home_dir = std::env::var_os("HOME")
            .ok_or_else(|| "HOME is required for managed Git".to_owned())?;
        let managed_path = std::env::join_paths([
            shim_directory.clone(),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
        ])
        .map_err(|_| "cannot construct managed Git path".to_owned())?;
        let run_git = |args: &[&str]| -> Result<std::process::ExitStatus, String> {
            let mut command = Command::new(&shim_git);
            command
                .args(args)
                .current_dir(root)
                .env_clear()
                .env("HOME", &home_dir)
                .env("PATH", &managed_path)
                .env("PERSONA_SHIM_DIR", &shim_directory)
                .env("PERSONA_GH", &native_gh)
                .env("PERSONA_GIT", git_executable())
                .env("PERSONA_GH_AUTHORIZED", "1")
                .env("PERSONA_CONFIG_PATH", &config_path)
                .env("GH_PROMPT_DISABLED", "1")
                .env("GIT_TERMINAL_PROMPT", "0")
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
            for variable in ["XDG_CONFIG_HOME", "XDG_STATE_HOME"] {
                if let Some(value) = std::env::var_os(variable) {
                    command.env(variable, value);
                }
            }
            command
                .status()
                .map_err(|_| "cannot start managed Git for PR checkout".to_owned())
        };
        let pr_ref = format!("refs/pull/{}/head", checkout.pull_number);
        let fetch_args = ["fetch", remote.as_str(), pr_ref.as_str()];
        let fetch_status = run_git(&fetch_args)?;
        if !fetch_status.success() {
            return Ok(status_exit_code(fetch_status));
        }
        let git = GitClient::new(git_executable(), crate::git::safe_environment());
        let fetched_head = git
            .resolve_commit_oid(root, "FETCH_HEAD")
            .map_err(|_| "fetched PR head is not a complete local commit".to_owned())?;
        if fetched_head != expected_head {
            return Err(
                "pull request head changed between GitHub metadata and managed fetch; no branch was created"
                    .to_owned(),
            );
        }
        let switch_args = ["switch", "--create", branch.as_str(), fetched_head.as_str()];
        let switch_status = run_git(&switch_args)?;
        if !switch_status.success() {
            return Ok(status_exit_code(switch_status));
        }
        println!(
            "Checked out {}#{} as local branch {branch} at {fetched_head}.",
            checkout.repository, checkout.pull_number
        );
        return Ok(0);
    }

    if let Some(review) = &request.review {
        let review_id = selector
            .submit_pull_request_review(
                &selected_token,
                &review.repository,
                review.pull_number,
                review.event,
                review.body.as_deref(),
            )
            .map_err(|_| "GitHub refused the typed pull-request review".to_owned())?;
        println!(
            "Submitted {:?} review {review_id} for {}#{}.",
            review.event, review.repository, review.pull_number
        );
        return Ok(0);
    }

    if let (Some(upload), Some((local_tag_oid, _))) =
        (&request.asset_upload, audited_release_tag_oid.as_ref())
    {
        let remote_tag_oid = selector
            .tag_ref_oid(&selected_token, &upload.repository, &upload.tag)
            .map_err(|_| {
                "release tag is not present as an annotated tag on the allowlisted GitHub repository"
                    .to_owned()
            })?;
        if remote_tag_oid != *local_tag_oid {
            return Err(
                "remote GitHub tag object differs from the locally audited signed tag".to_owned(),
            );
        }
        let release = selector
            .release_asset_context(&selected_token, &upload.repository, &upload.tag)
            .map_err(|_| {
                "cannot verify an existing GitHub release for the exact audited tag".to_owned()
            })?;
        let snapshots = asset_snapshots
            .as_ref()
            .ok_or_else(|| "release asset snapshots are unavailable".to_owned())?;
        if snapshots.iter().any(|asset| {
            release
                .asset_names
                .contains(&asset.name.to_ascii_lowercase())
        }) {
            return Err(
                "release asset name already exists; uploads never overwrite or clobber assets"
                    .to_owned(),
            );
        }
        let mut uploaded = Vec::new();
        let mut upload_failure = None;
        for asset in snapshots {
            match selector.upload_release_asset(
                &selected_token,
                &upload.repository,
                release.release_id,
                asset,
            ) {
                Ok(asset_id) => uploaded.push(format!("{} (id {asset_id})", asset.name)),
                Err(crate::credential::AssetUploadError::Rejected(status)) => {
                    upload_failure = Some((
                        None,
                        format!(
                            "GitHub rejected asset {} with HTTP {status}; no asset was overwritten",
                            asset.name
                        ),
                    ));
                    break;
                }
                Err(crate::credential::AssetUploadError::Uncertain) => {
                    upload_failure = Some((
                        Some(asset.name.clone()),
                        format!(
                            "upload of asset {} has an uncertain outcome; do not retry blindly",
                            asset.name
                        ),
                    ));
                    break;
                }
            }
        }
        let after_tag_oid = selector
            .tag_ref_oid(&selected_token, &upload.repository, &upload.tag)
            .map_err(|_| {
                let reason = upload_failure
                    .as_ref()
                    .map(|(_, reason)| {
                        format!("{reason}; post-upload remote tag verification failed")
                    })
                    .unwrap_or_else(|| {
                        "assets were uploaded but post-upload remote tag verification failed"
                            .to_owned()
                    });
                format_asset_upload_failure(
                    &uploaded,
                    upload_failure
                        .as_ref()
                        .and_then(|(uncertain, _)| uncertain.as_deref()),
                    &reason,
                )
            })?;
        if after_tag_oid != *local_tag_oid {
            let reason = upload_failure
                .as_ref()
                .map(|(_, reason)| {
                    format!("{reason}; remote tag changed concurrently during asset upload")
                })
                .unwrap_or_else(|| {
                    "remote tag changed concurrently during asset upload".to_owned()
                });
            return Err(format_asset_upload_failure(
                &uploaded,
                upload_failure
                    .as_ref()
                    .and_then(|(uncertain, _)| uncertain.as_deref()),
                &format!("{reason}; inspect the release before proceeding"),
            ));
        }
        if let Some((uncertain, reason)) = upload_failure {
            return Err(format_asset_upload_failure(
                &uploaded,
                uncertain.as_deref(),
                &reason,
            ));
        }
        println!(
            "Uploaded {} asset(s) to existing release {}:{} after verifying its locally audited signed tag; no assets were overwritten.",
            uploaded.len(),
            upload.repository,
            upload.tag
        );
        for asset in uploaded {
            println!("Uploaded {asset}");
        }
        return Ok(0);
    }

    if let (Some(release), Some((local_tag_oid, local_tag_commit_oid))) =
        (&request.release, audited_release_tag_oid.as_ref())
    {
        let remote_tag_oid = selector
            .tag_ref_oid(&selected_token, &release.repository, &release.tag)
            .map_err(|_| {
                "release tag is not present as an annotated tag on the allowlisted GitHub repository"
                    .to_owned()
            })?;
        if remote_tag_oid != *local_tag_oid {
            return Err(
                "remote GitHub tag object differs from the locally audited signed tag".to_owned(),
            );
        }
        let release_id = selector
            .create_release(&selected_token, release, local_tag_commit_oid)
            .map_err(|_| "GitHub refused the audited-tag release creation request".to_owned())?;
        let after_tag_oid = selector
            .tag_ref_oid(&selected_token, &release.repository, &release.tag)
            .map_err(|_| {
                "release was created but post-publication tag verification failed".to_owned()
            })?;
        if after_tag_oid != *local_tag_oid {
            return Err(
                "release was created while its remote tag changed concurrently; inspect GitHub before proceeding"
                    .to_owned(),
            );
        }
        println!(
            "Created GitHub release {release_id} for existing locally audited signed tag {}:{}; no tag was created or pushed by Persona.",
            release.repository, release.tag
        );
        return Ok(0);
    }

    let token = std::str::from_utf8(selected_token.expose())
        .map_err(|_| "selected native GitHub credential is not valid UTF-8".to_owned())?;
    let managed_path = build_managed_path(&shim_directory)?;

    let mut command = Command::new(&native_gh);
    command
        .args(&request.arguments)
        .current_dir(&cwd)
        .env_clear()
        .env("GH_PROMPT_DISABLED", "1")
        .env("GH_NO_UPDATE_NOTIFIER", "1")
        .env("GH_TOKEN", token)
        .env("PATH", managed_path)
        .env("PERSONA_SHIM_DIR", &shim_directory)
        .env("PERSONA_GH_AUTHORIZED", "1")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if !std::io::stdout().is_terminal() {
        command.env("GH_PAGER", "cat");
    }
    for variable in [
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_STATE_HOME",
        "PERSONA_CONFIG_PATH",
    ] {
        if let Some(value) = std::env::var_os(variable) {
            command.env(variable, value);
        }
    }
    command.env("PERSONA_GH", &native_gh);
    command.env("PERSONA_GIT", git_executable());
    let status = command
        .status()
        .map_err(|_| "cannot launch the validated native GitHub CLI operation".to_owned())?;
    Ok(status_exit_code(status))
}
