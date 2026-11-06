use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::tempdir;

fn persona_command(directory: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_persona"));

    command.env_clear().current_dir(directory);
    if let Some(git) = std::env::var_os("PERSONA_TEST_GIT") {
        command.env("PERSONA_GIT", git);
    }

    command
}

fn write_policy(path: &Path, scope_root: &Path) {
    let root = scope_root
        .to_str()
        .expect("fixture path should be valid UTF-8");

    let quoted_root = toml::Value::String(root.to_owned());

    let contents = format!(
        r#"
   version = 1

   [[scopes]]
   name = "work"
   path = {quoted_root}

   [scopes.git]
   author = {{ name = "Test Author", email = "author@example.invalid" }}
   committer = {{ name = "Test Committer", email = "committer@example.invalid" }}
   "#
    );

    fs::write(path, contents).expect("write fixture policy");
}

#[test]
fn status_reports_expected_identity_without_claiming_verification() {
    let temporary = tempdir().expect("create temporary directory");

    let scope_root = temporary.path().join("work");
    let project = scope_root.join("project");
    let config_path = temporary.path().join("policy.toml");

    fs::create_dir_all(&project).expect("create project");
    write_policy(&config_path, &scope_root);

    // Também verifica argumentos relativos ao cwd do processo.
    let output = persona_command(temporary.path())
        .args([
            "status",
            "--config",
            "policy.toml",
            "--cwd",
            "work/project",
            "--verbose",
        ])
        .output()
        .expect("run persona");

    assert_eq!(output.status.code(), Some(3));

    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");

    assert!(stdout.contains("scope: work"));
    assert!(stdout.contains("expected author: Test Author <author@example.invalid>"));
    assert!(stdout.contains("expected committer: Test Committer <committer@example.invalid>"));
    assert!(stdout.contains("result: UNKNOWN"));
    assert!(stdout.contains("Git worktree and identity not checked"));
    assert!(!stdout.contains("result: PASS"));
}

#[test]
fn status_does_not_assume_identity_outside_managed_scopes() {
    let temporary = tempdir().expect("create temporary directory");

    let scope_root = temporary.path().join("work");
    let outside = temporary.path().join("outside");
    let config_path = temporary.path().join("policy.toml");

    fs::create_dir(&scope_root).expect("create scope");
    fs::create_dir(&outside).expect("create outside directory");
    write_policy(&config_path, &scope_root);

    let output = persona_command(temporary.path())
        .args(["status", "--config"])
        .arg(&config_path)
        .arg("--cwd")
        .arg(&outside)
        .arg("--verbose")
        .output()
        .expect("run persona");

    assert_eq!(output.status.code(), Some(3));

    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");

    assert!(stdout.contains("scope: unmanaged"));
    assert!(stdout.contains("result: UNKNOWN"));
    assert!(!stdout.contains("expected author:"));
}

#[test]
fn doctor_shows_full_offline_findings() {
    let temporary = tempdir().expect("create temporary directory");
    let scope_root = temporary.path().join("work");
    let config_path = temporary.path().join("policy.toml");
    fs::create_dir(&scope_root).unwrap();
    write_policy(&config_path, &scope_root);

    let output = persona_command(temporary.path())
        .args(["doctor", "--config"])
        .arg(&config_path)
        .args(["--cwd", "work"])
        .env("GH_TOKEN", "synthetic-secret-sentinel")
        .output()
        .expect("run doctor");
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("coverage: per-property offline findings"));
    assert!(stdout.contains("finding git.author:"));
    assert!(stdout.contains("integration.managed_shims:"));
    assert!(stdout.contains("integration.pre_push_hook:"));
    assert!(!stdout.contains("synthetic-secret-sentinel"));
}

#[test]
fn status_json_is_versioned_and_contains_typed_findings() {
    let temporary = tempdir().expect("create temporary directory");
    let scope_root = temporary.path().join("work");
    let outside = temporary.path().join("outside");
    let config_path = temporary.path().join("policy.toml");

    fs::create_dir(&scope_root).expect("create scope");
    fs::create_dir(&outside).expect("create outside directory");
    write_policy(&config_path, &scope_root);

    let output = persona_command(temporary.path())
        .args(["status", "--config"])
        .arg(&config_path)
        .args(["--cwd", "outside", "--format", "json"])
        .output()
        .expect("run persona");

    assert_eq!(output.status.code(), Some(3));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON report should parse");
    assert_eq!(report["version"], 1);
    assert_eq!(report["status"], "UNKNOWN");
    assert!(report["findings"].as_array().is_some_and(|findings| {
        let has_scope = findings.iter().any(|finding| {
            finding["property"] == "scope"
                && finding["status"] == "UNKNOWN"
                && finding["coverage_reason"].is_string()
        });
        let has_installation_coverage = findings
            .iter()
            .any(|finding| finding["property"] == "integration.managed_shims");
        let has_hook_coverage = findings
            .iter()
            .any(|finding| finding["property"] == "integration.pre_push_hook");
        has_scope && has_installation_coverage && has_hook_coverage
    }));
}

#[test]
fn config_migrate_preview_is_explicit_and_does_not_modify_source() {
    let temporary = tempdir().expect("create temporary directory");
    let scope_root = temporary.path().join("work");
    fs::create_dir(&scope_root).expect("create scope");
    let config_path = temporary.path().join("policy.toml");
    write_policy(&config_path, &scope_root);
    let original = fs::read_to_string(&config_path).expect("read source config");

    let output = persona_command(temporary.path())
        .args(["config", "migrate", "--config"])
        .arg(&config_path)
        .args(["--preview"])
        .output()
        .expect("run migration preview");

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(fs::read_to_string(&config_path).unwrap(), original);
    let preview = String::from_utf8(output.stdout).expect("preview is UTF-8");
    let migrated = persona::config::Config::parse(&preview).expect("preview is valid v3");
    assert_eq!(migrated.version(), 3);
    assert_eq!(migrated.policies()[0].git.author.name, "Test Author");
}

#[test]
fn status_reports_invalid_configuration_as_an_error() {
    let temporary = tempdir().expect("create temporary directory");
    let config_path = temporary.path().join("policy.toml");

    fs::write(&config_path, "version = 4\nscopes = []").expect("write invalid policy");

    let output = persona_command(temporary.path())
        .args(["status", "--config"])
        .arg(&config_path)
        .output()
        .expect("run persona");

    assert_eq!(output.status.code(), Some(2));

    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");

    assert!(stderr.contains("UnsupportedVersion(4)"));
    assert!(output.stdout.is_empty());
}

#[test]
fn status_reports_environment_presence_without_claiming_accounts_or_leaking_values() {
    let temporary = tempdir().expect("create temporary directory");
    let scope_root = temporary.path().join("work");
    let outside = temporary.path().join("outside");
    let config_path = temporary.path().join("policy.toml");

    fs::create_dir(&scope_root).expect("create scope");
    fs::create_dir(&outside).expect("create outside directory");
    write_policy(&config_path, &scope_root);

    let output = persona_command(temporary.path())
        .env("GH_TOKEN", "dummy-gh-token")
        .env("GITHUB_TOKEN", "dummy-github-token")
        .env("GH_ENTERPRISE_TOKEN", "dummy-enterprise-token")
        .env("GITHUB_ENTERPRISE_TOKEN", "dummy-github-enterprise-token")
        .env("GH_HOST", "dummy.example.invalid")
        .env("GH_CONFIG_DIR", "/synthetic/gh-config")
        .env("GIT_SSH", "/synthetic/ssh")
        .env("GIT_SSH_COMMAND", "synthetic-ssh-helper")
        .env("SSH_AUTH_SOCK", "/synthetic/agent.sock")
        .args(["status", "--config"])
        .arg(&config_path)
        .args(["--cwd", "outside", "--format", "json"])
        .output()
        .expect("run persona");

    assert_eq!(output.status.code(), Some(3));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON report should parse");
    let account = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["property"] == "github.account")
        .expect("GitHub account finding");
    assert_eq!(account["status"], "UNKNOWN");
    let observed = account["observed"].as_str().unwrap();
    assert!(observed.contains("GH_TOKEN present"));
    assert!(observed.contains("takes precedence over GITHUB_TOKEN"));
    assert!(observed.contains("GH_ENTERPRISE_TOKEN present"));
    assert!(observed.contains("GITHUB_ENTERPRISE_TOKEN present"));
    assert!(observed.contains("GH_HOST present"));
    assert!(observed.contains("GH_CONFIG_DIR present"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("dummy-gh-token"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("dummy-github-token"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("dummy.example.invalid"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic/gh-config"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-ssh-helper"));

    let ssh = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["property"] == "ssh")
        .expect("SSH finding");
    assert_eq!(ssh["status"], "UNKNOWN");
    assert!(
        ssh["observed"]
            .as_str()
            .unwrap()
            .contains("GIT_SSH present")
    );
    assert!(
        ssh["observed"]
            .as_str()
            .unwrap()
            .contains("GIT_SSH_COMMAND present")
    );
    assert!(
        ssh["observed"]
            .as_str()
            .unwrap()
            .contains("SSH_AUTH_SOCK present")
    );
}

#[test]
fn managed_remote_add_requires_exact_scope_destination_without_network() {
    let temporary = tempdir().expect("create temporary directory");
    let repo = temporary.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    let git = std::env::var_os("PERSONA_TEST_GIT").expect("test Git executable");
    let init = Command::new(&git)
        .args(["init", "--quiet"])
        .arg(&repo)
        .output()
        .unwrap();
    assert!(init.status.success());
    let config = temporary.path().join("policy.toml");
    let root = toml::Value::String(repo.to_string_lossy().into_owned());
    fs::write(
        &config,
        format!(
            r#"version = 1
[[scopes]]
name = "work"
path = {root}
[scopes.git]
author = {{ name = "Author", email = "author@example.invalid" }}
committer = {{ name = "Committer", email = "committer@example.invalid" }}
[scopes.git.push]
remote = "origin"
destinations = ["https://github.com/org/repo.git"]
"#
        ),
    )
    .unwrap();

    let allowed = persona_command(&repo)
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args([
            "--",
            "git",
            "remote",
            "add",
            "origin",
            "https://github.com/org/repo.git",
        ])
        .output()
        .unwrap();
    assert_eq!(
        allowed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    let configured = Command::new(&git)
        .args(["-C"])
        .arg(&repo)
        .args(["config", "--get", "remote.origin.url"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&configured.stdout).trim(),
        "https://github.com/org/repo.git"
    );

    let denied = persona_command(&repo)
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args([
            "--",
            "git",
            "remote",
            "add",
            "other",
            "https://evil.example/repo.git",
        ])
        .output()
        .unwrap();
    assert_eq!(denied.status.code(), Some(126));
}

#[test]
fn managed_worktree_add_is_detached_and_confined_to_the_target_scope() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempdir().expect("create temporary directory");
    let repo = temporary.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    let git = std::env::var_os("PERSONA_TEST_GIT").expect("test Git executable");
    let init = Command::new(&git)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(["init", "--quiet", "--initial-branch=main"])
        .arg(&repo)
        .output()
        .unwrap();
    assert!(init.status.success());
    let commit = Command::new(&git)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(["-C"])
        .arg(&repo)
        .args([
            "-c",
            "user.name=Test Author",
            "-c",
            "user.email=author@example.invalid",
            "-c",
            "committer.name=Test Committer",
            "-c",
            "committer.email=committer@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "initial",
        ])
        .output()
        .unwrap();
    assert!(commit.status.success());
    assert!(
        Command::new(&git)
            .env_clear()
            .env("HOME", temporary.path())
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(["-C"])
            .arg(&repo)
            .args(["switch", "-c", "source"])
            .status()
            .unwrap()
            .success()
    );
    fs::write(repo.join("source.txt"), "source commit\\n").unwrap();
    assert!(
        Command::new(&git)
            .env_clear()
            .env("HOME", temporary.path())
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(["-C"])
            .arg(&repo)
            .args(["add", "--", "source.txt"])
            .status()
            .unwrap()
            .success()
    );
    let source_commit = Command::new(&git)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(["-C"])
        .arg(&repo)
        .args([
            "-c",
            "user.name=Upstream Author",
            "-c",
            "user.email=upstream@example.invalid",
            "commit",
            "-m",
            "source",
        ])
        .output()
        .unwrap();
    assert!(source_commit.status.success());
    let source_oid = String::from_utf8_lossy(
        &Command::new(&git)
            .env_clear()
            .env("HOME", temporary.path())
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(["-C"])
            .arg(&repo)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_owned();
    assert!(
        Command::new(&git)
            .env_clear()
            .env("HOME", temporary.path())
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(["-C"])
            .arg(&repo)
            .args(["switch", "main"])
            .status()
            .unwrap()
            .success()
    );
    let config = temporary.path().join("policy.toml");
    write_policy(&config, &repo);
    let mut policy_contents = fs::read_to_string(&config).unwrap();
    policy_contents.push_str("\n[scopes.git.push]\nremote = \"origin\"\ndestinations = [\"file:///synthetic/upstream.git\"]\npreserve_authors = true\n");
    fs::write(&config, policy_contents).unwrap();

    let target = repo.join("linked-worktree");
    let allowed = persona_command(&repo)
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "worktree", "add", "--detach"])
        .arg(&target)
        .arg("HEAD")
        .output()
        .unwrap();
    assert_eq!(
        allowed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert!(target.join(".git").is_file());

    for arguments in [
        &["switch", "--create", "feature"][..],
        &["checkout", "feature"][..],
        &["merge", "--ff-only", "feature"][..],
        &[
            "rebase",
            "--onto",
            "refs/heads/feature",
            "refs/heads/feature",
        ][..],
    ] {
        let result = persona_command(&repo)
            .env("PERSONA_GIT", &git)
            .env("PATH", "/usr/bin:/bin")
            .args(["run", "--config"])
            .arg(&config)
            .args(["--cwd"])
            .arg(&target)
            .args(["--", "git"])
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(0),
            "args={arguments:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let cherry_pick = persona_command(&repo)
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&target)
        .args(["--", "git", "cherry-pick"])
        .arg(&source_oid)
        .output()
        .unwrap();
    assert_eq!(
        cherry_pick.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&cherry_pick.stderr)
    );
    let resulting_identity = Command::new(&git)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(["-C"])
        .arg(&target)
        .args(["show", "-s", "--format=%an|%ae|%cn|%ce", "HEAD"])
        .output()
        .unwrap();
    assert!(resulting_identity.status.success());
    assert_eq!(
        String::from_utf8_lossy(&resulting_identity.stdout).trim(),
        "Upstream Author|upstream@example.invalid|Test Committer|committer@example.invalid"
    );

    let strict_target = repo.join("strict-worktree");
    let add_strict = Command::new(&git)
        .args(["worktree", "add", "--detach"])
        .arg(&strict_target)
        .arg("main")
        .current_dir(&repo)
        .output()
        .unwrap();
    assert!(add_strict.status.success());
    let strict_policy = fs::read_to_string(&config)
        .unwrap()
        .replace("preserve_authors = true", "preserve_authors = false");
    fs::write(&config, strict_policy).unwrap();
    let strict_cherry_pick = persona_command(&repo)
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&strict_target)
        .args(["--", "git", "cherry-pick"])
        .arg(&source_oid)
        .output()
        .unwrap();
    assert_eq!(
        strict_cherry_pick.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&strict_cherry_pick.stderr)
    );
    let strict_identity = Command::new(&git)
        .args(["show", "-s", "--format=%an|%ae|%cn|%ce"])
        .current_dir(&strict_target)
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&strict_identity.stdout).trim(),
        "Test Author|author@example.invalid|Test Committer|committer@example.invalid"
    );

    let hook_marker = temporary.path().join("post-checkout-ran");
    let hook = repo.join(".git/hooks/post-checkout");
    fs::write(
        &hook,
        format!("#!/bin/sh\n: > '{}'\n", hook_marker.display()),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();
    let hook_blocked = persona_command(&repo)
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&target)
        .args(["--", "git", "switch", "main"])
        .output()
        .unwrap();
    assert_eq!(hook_blocked.status.code(), Some(126));
    assert!(
        !hook_marker.exists(),
        "Persona must block before running hooks"
    );

    let outside = temporary.path().join("outside-worktree");
    let denied = persona_command(&repo)
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "worktree", "add", "--detach"])
        .arg(&outside)
        .arg("HEAD")
        .output()
        .unwrap();
    assert_eq!(denied.status.code(), Some(126));
    assert!(!outside.exists());
}

#[test]
fn lightweight_tag_creation_requires_explicit_policy_opt_in() {
    let temporary = tempdir().expect("create temporary directory");
    let repo = temporary.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    let git = std::env::var_os("PERSONA_TEST_GIT").expect("test Git executable");
    let init = Command::new(&git)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(["init", "--quiet", "--initial-branch=main"])
        .arg(&repo)
        .output()
        .unwrap();
    assert!(init.status.success());
    let commit = Command::new(&git)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(["-C"])
        .arg(&repo)
        .args([
            "-c",
            "user.name=Test Author",
            "-c",
            "user.email=author@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "initial",
        ])
        .output()
        .unwrap();
    assert!(commit.status.success());
    let config = temporary.path().join("policy.toml");
    write_policy(&config, &repo);
    let base = fs::read_to_string(&config).unwrap();
    fs::write(
        &config,
        format!(
            "{base}\n[scopes.git.push]\nremote = \"origin\"\ndestinations = [\"file:///tmp/synthetic.git\"]\nallow_lightweight_tags = true\n"
        ),
    )
    .unwrap();
    let denied_policy = temporary.path().join("denied-policy.toml");
    fs::write(
        &denied_policy,
        fs::read_to_string(&config).unwrap().replace(
            "allow_lightweight_tags = true",
            "allow_lightweight_tags = false",
        ),
    )
    .unwrap();

    for (policy, tag, expected) in [(&denied_policy, "v-denied", 126), (&config, "v-opt-in", 0)] {
        let result = persona_command(&repo)
            .env("HOME", temporary.path())
            .env("PERSONA_GIT", &git)
            .env("PATH", "/usr/bin:/bin")
            .args(["run", "--config"])
            .arg(policy)
            .args(["--cwd"])
            .arg(&repo)
            .args(["--", "git", "tag", "--no-sign", tag])
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(expected),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let tag_type = Command::new(&git)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(["-C"])
        .arg(&repo)
        .args(["cat-file", "-t", "refs/tags/v-opt-in"])
        .output()
        .unwrap();
    assert!(tag_type.status.success());
    assert_eq!(String::from_utf8_lossy(&tag_type.stdout).trim(), "commit");
}

#[test]
fn run_routes_local_git_through_managed_adapter_and_blocks_network_commands() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempdir().expect("create temporary directory");
    let repo = temporary.path().join("repo");
    fs::create_dir(&repo).unwrap();
    let git = std::env::var_os("PERSONA_TEST_GIT").expect("test Git executable");
    let init = Command::new(&git)
        .arg("init")
        .arg("-q")
        .current_dir(&repo)
        .output()
        .unwrap();
    assert!(init.status.success());
    let config = temporary.path().join("policy.toml");
    write_policy(&config, &repo);
    let initial = Command::new(&git)
        .args([
            "-c",
            "user.name=Foreign Author",
            "-c",
            "user.email=foreign@example.invalid",
            "-c",
            "user.committername=Foreign Committer",
            "-c",
            "user.committeremail=foreign-committer@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "initial",
        ])
        .current_dir(&repo)
        .env("GIT_AUTHOR_NAME", "Foreign Author")
        .env("GIT_AUTHOR_EMAIL", "foreign@example.invalid")
        .env("GIT_COMMITTER_NAME", "Foreign Committer")
        .env("GIT_COMMITTER_EMAIL", "foreign-committer@example.invalid")
        .output()
        .unwrap();
    assert!(initial.status.success());
    let amended = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args([
            "--",
            "git",
            "commit",
            "--amend",
            "--no-edit",
            "--allow-empty",
        ])
        .output()
        .unwrap();
    assert_eq!(
        amended.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&amended.stderr)
    );
    let amended_identity = Command::new(&git)
        .args(["show", "-s", "--format=%an|%ae|%cn|%ce"])
        .current_dir(&repo)
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&amended_identity.stdout).trim(),
        "Test Author|author@example.invalid|Test Committer|committer@example.invalid"
    );

    let unsafe_status = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "status", "--exec-path"])
        .output()
        .unwrap();
    assert_eq!(unsafe_status.status.code(), Some(126));
    assert!(String::from_utf8_lossy(&unsafe_status.stderr).contains("safe grammar"));

    let echo = temporary.path().join("echo-child");
    fs::write(
        &echo,
        r#"#!/bin/sh
printf '%s|%s' "$PWD" "$1"
"#,
    )
    .unwrap();
    fs::set_permissions(&echo, fs::Permissions::from_mode(0o700)).unwrap();
    let output = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .arg("--")
        .arg(&echo)
        .arg("value with spaces")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            "{}|value with spaces",
            fs::canonicalize(&repo).unwrap().display()
        )
    );

    let mut cat = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .arg("--")
        .arg(
            std::env::var_os("PERSONA_TEST_CAT")
                .unwrap_or_else(|| PathBuf::from("/bin/cat").into_os_string()),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    cat.stdin
        .take()
        .unwrap()
        .write_all(b"stdin passthrough")
        .unwrap();
    let cat_output = cat.wait_with_output().unwrap();
    assert_eq!(cat_output.status.code(), Some(0));
    assert_eq!(cat_output.stdout, b"stdin passthrough");

    let exit_child = temporary.path().join("exit-child");
    fs::write(&exit_child, "#!/bin/sh\nexit 37\n").unwrap();
    fs::set_permissions(&exit_child, fs::Permissions::from_mode(0o700)).unwrap();
    let exit_output = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .arg("--")
        .arg(&exit_child)
        .output()
        .unwrap();
    assert_eq!(exit_output.status.code(), Some(37));

    let git_child = temporary.path().join("calls-git");
    fs::write(&git_child, "#!/bin/sh\ngit status --short\n").unwrap();
    fs::set_permissions(&git_child, fs::Permissions::from_mode(0o700)).unwrap();
    let blocked = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .arg("--")
        .arg(git_child)
        .output()
        .unwrap();
    assert_eq!(
        blocked.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&blocked.stderr)
    );

    let c_option = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "-C"])
        .arg(&repo)
        .args(["status", "--short"])
        .output()
        .unwrap();
    assert_eq!(
        c_option.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&c_option.stderr)
    );

    let new_target = repo.join("new-target");
    fs::create_dir(&new_target).unwrap();
    let initialized = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&new_target)
        .args(["--", "git", "init", "--quiet"])
        .output()
        .unwrap();
    assert_eq!(
        initialized.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    assert!(new_target.join(".git").is_dir());
    fs::remove_dir_all(&new_target).unwrap();

    let hook_marker = temporary.path().join("pre-commit-ran");
    let hook = repo.join(".git/hooks/pre-commit");
    fs::write(
        &hook,
        format!("#!/bin/sh\n: > '{}'\n", hook_marker.display()),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();

    let commit = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args([
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "managed identity",
        ])
        .output()
        .unwrap();
    assert_eq!(
        commit.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&commit.stderr)
    );
    let identity = Command::new(&git)
        .args(["show", "-s", "--format=%an|%ae|%cn|%ce", "HEAD"])
        .current_dir(&repo)
        .output()
        .unwrap();
    assert!(identity.status.success());
    assert_eq!(
        String::from_utf8_lossy(&identity.stdout).trim(),
        "Test Author|author@example.invalid|Test Committer|committer@example.invalid"
    );
    assert!(
        hook_marker.exists(),
        "the repository's native pre-commit hook must run"
    );

    let log = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "log", "--oneline", "-1"])
        .output()
        .unwrap();
    assert_eq!(log.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&log.stdout).contains("managed identity"));

    fs::write(repo.join("tracked.txt"), "synthetic content\n").unwrap();
    let add = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "add", "--", "tracked.txt"])
        .output()
        .unwrap();
    assert_eq!(
        add.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&add.stderr)
    );
    fs::write(repo.join("current-dir.txt"), "normal add path\n").unwrap();
    let add_current_directory = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "add", "."])
        .output()
        .unwrap();
    assert_eq!(
        add_current_directory.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&add_current_directory.stderr)
    );
    let diff = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "diff", "--cached", "--name-only"])
        .output()
        .unwrap();
    assert_eq!(
        diff.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&diff.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&diff.stdout).trim(),
        "current-dir.txt\ntracked.txt"
    );
    fs::write(repo.join("tracked.txt"), "modified tracked content\n").unwrap();
    fs::remove_file(repo.join(".git/hooks/pre-commit")).unwrap();
    let bare_diff = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "diff"])
        .output()
        .unwrap();
    assert_eq!(
        bare_diff.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&bare_diff.stderr)
    );
    assert!(String::from_utf8_lossy(&bare_diff.stdout).contains("tracked.txt"));
    let restore = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "restore", "--", "tracked.txt"])
        .output()
        .unwrap();
    assert_eq!(
        restore.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&restore.stderr)
    );
    assert_eq!(
        fs::read_to_string(repo.join("tracked.txt")).unwrap(),
        "synthetic content\n"
    );
    let remove = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "rm", "--cached", "--", "current-dir.txt"])
        .output()
        .unwrap();
    assert_eq!(
        remove.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&remove.stderr)
    );
    assert!(repo.join("current-dir.txt").exists());
    let show = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "show", "--stat", "HEAD"])
        .output()
        .unwrap();
    assert_eq!(
        show.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&show.stderr)
    );
    let branch_create = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "branch", "feature/managed"])
        .output()
        .unwrap();
    assert_eq!(
        branch_create.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&branch_create.stderr)
    );

    let filter_marker = temporary.path().join("filter-ran");
    let filter = temporary.path().join("filter-fixture");
    fs::write(
        &filter,
        format!("#!/bin/sh\n: > '{}'\ncat\n", filter_marker.display()),
    )
    .unwrap();
    fs::set_permissions(&filter, fs::Permissions::from_mode(0o700)).unwrap();
    let configure_filter = Command::new(&git)
        .args(["-C"])
        .arg(&repo)
        .args(["config", "filter.synthetic.clean"])
        .arg(&filter)
        .output()
        .unwrap();
    assert!(configure_filter.status.success());
    let filtered_add = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "add", "--", "tracked.txt"])
        .output()
        .unwrap();
    assert_eq!(filtered_add.status.code(), Some(126));
    assert!(
        !filter_marker.exists(),
        "managed staging must refuse before invoking repository filters"
    );

    let branch_list = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "branch", "--list"])
        .output()
        .unwrap();
    assert_eq!(branch_list.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&branch_list.stdout).contains('*'));

    let worktrees = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "worktree", "list", "--porcelain"])
        .output()
        .unwrap();
    assert_eq!(worktrees.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&worktrees.stdout).contains("worktree "));

    let attacker_commit = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args([
            "--",
            "git",
            "commit",
            "--author=Attacker <attacker@example.invalid>",
            "-m",
            "bypass",
        ])
        .output()
        .unwrap();
    assert_eq!(attacker_commit.status.code(), Some(126));

    let network_child = temporary.path().join("calls-network-git");
    fs::write(&network_child, "#!/bin/sh\ngit fetch origin\n").unwrap();
    fs::set_permissions(&network_child, fs::Permissions::from_mode(0o700)).unwrap();
    let blocked_network = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .arg("--")
        .arg(network_child)
        .output()
        .unwrap();
    assert_eq!(blocked_network.status.code(), Some(126));
    assert!(
        String::from_utf8_lossy(&blocked_network.stderr)
            .contains("fetch requires a profile-bound remote fetch policy")
    );

    let outside = temporary.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let refused = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&outside)
        .arg("--")
        .arg(&echo)
        .arg("should-not-run")
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&refused.stdout).contains("should-not-run"));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("persona run blocked"));
}

#[test]
fn github_credential_selector_is_not_read_until_destination_gate_passes() {
    let temporary = tempdir().expect("create temporary directory");
    let repo = temporary.path().join("repo");
    fs::create_dir(&repo).unwrap();
    let git = std::env::var_os("PERSONA_TEST_GIT").expect("test Git executable");
    assert!(
        Command::new(&git)
            .args(["init", "-q"])
            .current_dir(&repo)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(&git)
            .args(["config", "user.name", "Synthetic Author"])
            .current_dir(&repo)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(&git)
            .args(["config", "user.email", "author@example.invalid"])
            .current_dir(&repo)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(&git)
            .args(["remote", "add", "origin", "file:///allowed.git"])
            .current_dir(&repo)
            .status()
            .unwrap()
            .success()
    );
    let root = toml::Value::String(repo.to_string_lossy().into_owned());
    let config = temporary.path().join("policy-v2.toml");
    fs::write(&config, format!(
        "version = 2\n[[profiles]]\nname = \"work\"\n[profiles.git]\nauthor = {{ name = \"Synthetic Author\", email = \"author@example.invalid\" }}\ncommitter = {{ name = \"Synthetic Author\", email = \"author@example.invalid\" }}\n[profiles.git.push]\nremote = \"origin\"\ndestinations = [\"file:///allowed.git\"]\n[profiles.github]\nhost = \"github.com\"\naccount_id = \"4242\"\ntoken_fingerprint = \"hmac-sha256:{}\"\n[[scopes]]\nname = \"work\"\npath = {}\nprofile = \"work\"\n", "0".repeat(64), root
    )).unwrap();
    let marker = temporary.path().join("gh-was-called");
    let fake_gh = temporary.path().join("gh-fake");
    fs::write(
        &fake_gh,
        format!("#!/bin/sh\n: > '{}'\nexit 0\n", marker.display()),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&fake_gh, fs::Permissions::from_mode(0o700)).unwrap();
    }

    let mut child = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PERSONA_GH", &fake_gh)
        .args(["check", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args([
            "--operation",
            "push",
            "--remote",
            "origin",
            "--destination",
            "https://github.com/org/repo.git",
            "--format",
            "json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"refs/heads/main bad refs/heads/main 0000000000000000000000000000000000000000\n",
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        !marker.exists(),
        "credential selector must not run before destination and local gates pass"
    );
    let decision: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = decision["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["property"] == "github.credential.binding")
        .unwrap();
    assert_eq!(finding["status"], "UNKNOWN");
    assert!(
        finding["coverage_reason"]
            .as_str()
            .unwrap()
            .contains("offline diagnostic does not query native credentials")
    );
}

#[test]
fn pre_push_hook_consumes_authenticated_handoff_for_github_without_token() {
    use persona::push_handoff::{HandoffGithubBinding, HandoffTuple, PushHandoff, write};
    use persona::storage::PersonaPaths;
    use sha2::{Digest, Sha256};
    use std::path::Path;

    let temporary = tempdir().unwrap();
    let repo = temporary.path().join("repo");
    let home = temporary.path().join("home");
    let state_home = home.join("state");
    fs::create_dir_all(&repo).unwrap();
    fs::create_dir_all(&home).unwrap();
    let git = std::env::var_os("PERSONA_TEST_GIT").expect("test Git executable");
    let run_git = |args: &[&str]| {
        Command::new(&git)
            .env_clear()
            .env("HOME", &home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .current_dir(&repo)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(run_git(&["init", "-q", "-b", "main"]).status.success());
    assert!(
        run_git(&["config", "user.name", "Synthetic"])
            .status
            .success()
    );
    assert!(
        run_git(&["config", "user.email", "synthetic@example.invalid"])
            .status
            .success()
    );
    assert!(
        run_git(&["remote", "add", "origin", "https://github.com/org/repo.git"])
            .status
            .success()
    );
    assert!(
        run_git(&["commit", "--allow-empty", "-m", "fixture"])
            .status
            .success()
    );
    let oid = String::from_utf8(run_git(&["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_owned();

    let config = temporary.path().join("policy.toml");
    let scope = toml::Value::String(repo.canonicalize().unwrap().to_string_lossy().into_owned());
    let contents = format!(
        r#"version = 2
[[profiles]]
name = "work"
[profiles.git]
author = {{ name = "Synthetic", email = "synthetic@example.invalid" }}
committer = {{ name = "Synthetic", email = "synthetic@example.invalid" }}
[profiles.git.push]
remote = "origin"
destinations = ["https://github.com/org/repo.git"]
[profiles.github]
host = "github.com"
account_id = "4242"
account_selector = "synthetic"
token_fingerprint = "hmac-sha256:{}"
[[scopes]]
name = "work"
path = {}
profile = "work"
"#,
        "0".repeat(64),
        scope
    );
    fs::write(&config, &contents).unwrap();
    let install = persona_command(temporary.path())
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .args(["hooks", "install", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .output()
        .unwrap();
    assert!(
        install.status.success(),
        "{}",
        String::from_utf8_lossy(&install.stderr)
    );
    let git_client =
        persona::git::GitClient::new(PathBuf::from(&git), persona::git::safe_environment());
    let hook_paths =
        persona::hooks::resolve_paths(&git_client, &repo.canonicalize().unwrap()).unwrap();
    let hook_manifest_path = hook_paths.manifest.canonicalize().unwrap();
    let hook_manifest_bytes = fs::read(&hook_manifest_path).unwrap();
    let hook_manifest_sha256 = format!("{:x}", Sha256::digest(&hook_manifest_bytes));
    let digest = format!("{:x}", Sha256::digest(contents.as_bytes()));
    let paths = PersonaPaths::from_environment(Some(&home), None, Some(&state_home)).unwrap();
    let handoff = PushHandoff {
        config_path: config.canonicalize().unwrap(),
        config_sha256: digest,
        hook_manifest_path: hook_manifest_path.clone(),
        hook_manifest_sha256,
        checkout_root: repo.canonicalize().unwrap(),
        profile: "work".into(),
        remote: "origin".into(),
        destination: "https://github.com/org/repo.git".into(),
        tuples: vec![HandoffTuple {
            local_ref: "refs/heads/main".into(),
            local_oid: oid.clone(),
            remote_ref: "refs/heads/main".into(),
            remote_oid: "0".repeat(40),
            expected_lease_oid: None,
        }],
        github_binding: Some(HandoffGithubBinding {
            host: "github.com".into(),
            account_id: "4242".into(),
        }),
    };
    let handoff_file = write(&paths, &handoff).unwrap();
    let input = format!("refs/heads/main {oid} refs/heads/main {}\n", "0".repeat(40));
    let spawn_hook = |handoff_path: &Path, input: &str| {
        let mut child = Command::new(&hook_paths.hook)
            .env_clear()
            .env("HOME", &home)
            .env("XDG_STATE_HOME", &state_home)
            .env("PERSONA_GIT", &git)
            .env("PERSONA_PUSH_HANDOFF", handoff_path)
            .current_dir(&repo)
            .args(["origin", "https://github.com/org/repo.git"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child
    };
    let run_hook = |handoff_path: &Path, input: &str| {
        spawn_hook(handoff_path, input).wait_with_output().unwrap()
    };
    let output = run_hook(handoff_file.path(), &input);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(
        !handoff_file.path().exists(),
        "successful authorization must consume the handoff"
    );

    let changed_tuple = format!(
        "refs/heads/main {} refs/heads/main {}\n",
        "0".repeat(40),
        "0".repeat(40)
    );
    let tuple_handoff = write(&paths, &handoff).unwrap();
    assert!(
        !run_hook(tuple_handoff.path(), &changed_tuple)
            .status
            .success()
    );
    let omitted_handoff = write(&paths, &handoff).unwrap();
    assert!(
        !run_hook(omitted_handoff.path(), "").status.success(),
        "omitting an authorized ref from native hook input must block"
    );

    let race_handoff = write(&paths, &handoff).unwrap();
    let first = spawn_hook(race_handoff.path(), &input);
    let second = spawn_hook(race_handoff.path(), &input);
    let first = first.wait_with_output().unwrap();
    let second = second.wait_with_output().unwrap();
    assert_ne!(
        first.status.success(),
        second.status.success(),
        "a one-time handoff must authorize at most one concurrent hook invocation"
    );

    let original_config = fs::read(&config).unwrap();
    let config_handoff = write(&paths, &handoff).unwrap();
    fs::write(&config, [original_config.as_slice(), b"\n"].concat()).unwrap();
    assert!(!run_hook(config_handoff.path(), &input).status.success());
    fs::write(&config, original_config).unwrap();

    let manifest_handoff = write(&paths, &handoff).unwrap();
    let original_manifest = fs::read(&hook_manifest_path).unwrap();
    fs::write(&hook_manifest_path, b"{}").unwrap();
    assert!(!run_hook(manifest_handoff.path(), &input).status.success());
    fs::write(&hook_manifest_path, original_manifest).unwrap();
}

#[test]
fn setup_creates_private_v3_configuration_without_changing_native_settings() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempdir().expect("create temporary directory");
    let scope = temporary.path().join("project");
    let home = temporary.path().join("home");
    let xdg = temporary.path().join("xdg-config");
    fs::create_dir(&scope).expect("create target scope");

    let output = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args([
            "setup",
            "--profile",
            "work",
            "--scope-name",
            "project",
            "--scope",
            "project",
            "--author-name",
            "Synthetic Author",
            "--author-email",
            "author@example.invalid",
            "--committer-name",
            "Synthetic Committer",
            "--committer-email",
            "committer@example.invalid",
        ])
        .output()
        .expect("run setup");

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("No Git, SSH, GPG, GitHub, or credential settings were changed.")
    );
    let config_file = xdg.join("persona/config.toml");
    assert_eq!(
        fs::metadata(config_file.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&config_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let config = persona::config::Config::load(&config_file).unwrap();
    assert_eq!(config.version(), 3);
    assert_eq!(
        config.policies()[0].git.author.email,
        "author@example.invalid"
    );

    let original = fs::read(&config_file).unwrap();
    let second = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args([
            "setup",
            "--profile",
            "work",
            "--scope-name",
            "project",
            "--scope",
            "project",
            "--author-name",
            "Synthetic Author",
            "--author-email",
            "author@example.invalid",
            "--committer-name",
            "Synthetic Committer",
            "--committer-email",
            "committer@example.invalid",
        ])
        .output()
        .expect("rerun setup");
    assert_eq!(second.status.code(), Some(2));
    assert_eq!(fs::read(config_file).unwrap(), original);
}

#[test]
fn auth_enrollment_uses_synthetic_gh_and_local_verification_never_calls_api() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempdir().expect("create temporary directory");
    let home = temporary.path().join("home");
    let xdg = temporary.path().join("xdg-config");
    let state = temporary.path().join("state");
    let gh_config = temporary.path().join("gh-config");
    fs::create_dir(&gh_config).unwrap();
    fs::set_permissions(&gh_config, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        gh_config.join("hosts.yml"),
        "github.com:\n  user: synthetic-user\n",
    )
    .unwrap();
    let gh = temporary.path().join("gh-fixture");
    let api_marker = temporary.path().join("api-called");
    fs::write(&gh, format!("#!/bin/sh\nif [ \"$1 $2\" = \"auth token\" ]; then [ \"$5\" = \"--user\" ] && [ \"$6\" = \"synthetic-user\" ] || exit 63; printf 'synthetic-token\\n'; exit 0; fi\nif [ \"$1 $2\" = \"api user\" ]; then : > '{}'; printf '4242\\n'; exit 0; fi\nexit 64\n", api_marker.display())).unwrap();
    fs::set_permissions(&gh, fs::Permissions::from_mode(0o700)).unwrap();
    let scope = temporary.path().join("work");
    fs::create_dir(&scope).unwrap();
    let config_file = xdg.join("persona/config.toml");
    fs::create_dir_all(config_file.parent().unwrap()).unwrap();
    fs::set_permissions(
        config_file.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    write_policy(&config_file, &scope);
    fs::set_permissions(&config_file, fs::Permissions::from_mode(0o600)).unwrap();

    let enroll = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("GH_CONFIG_DIR", &gh_config)
        .env("PERSONA_GH", &gh)
        .args([
            "auth",
            "enroll",
            "--profile",
            "work",
            "--host",
            "github.com",
            "--user",
            "synthetic-user",
            "--confirm-online",
        ])
        .output()
        .unwrap();
    assert_eq!(
        enroll.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&enroll.stderr)
    );
    assert!(String::from_utf8_lossy(&enroll.stdout).contains("4242"));
    let contents = fs::read_to_string(&config_file).unwrap();
    assert!(!contents.contains("synthetic-token"));
    let config = persona::config::Config::load(&config_file).unwrap();
    assert_eq!(
        config.profiles()[0].github.as_ref().unwrap().account_id,
        "4242"
    );
    assert_eq!(
        config.profiles()[0]
            .github
            .as_ref()
            .unwrap()
            .account_selector
            .as_deref(),
        Some("synthetic-user")
    );

    fs::remove_file(&api_marker).unwrap();
    let verify = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("GH_CONFIG_DIR", &gh_config)
        .env("PERSONA_GH", &gh)
        .args(["auth", "verify", "--profile", "work"])
        .output()
        .unwrap();
    assert_eq!(
        verify.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(
        !api_marker.exists(),
        "local selector verification must not call the API"
    );

    let changed_gh = temporary.path().join("gh-changed");
    let script = fs::read_to_string(&gh)
        .unwrap()
        .replace("synthetic-token", "replacement-token");
    fs::write(&changed_gh, script).unwrap();
    fs::set_permissions(&changed_gh, fs::Permissions::from_mode(0o700)).unwrap();
    let stale = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("GH_CONFIG_DIR", &gh_config)
        .env("PERSONA_GH", &changed_gh)
        .args(["auth", "verify", "--profile", "work"])
        .output()
        .unwrap();
    assert_eq!(stale.status.code(), Some(1));
}

#[test]
fn managed_github_push_creates_and_consumes_primary_handoff_with_synthetic_credential() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempdir().unwrap();
    let home = temporary.path().join("home");
    let xdg = temporary.path().join("xdg-config");
    let state = temporary.path().join("state");
    let gh_config = temporary.path().join("gh-config");
    let repo = temporary.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    fs::create_dir(&gh_config).unwrap();
    fs::set_permissions(&gh_config, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        gh_config.join("hosts.yml"),
        "github.com:\n  user: synthetic-user\n",
    )
    .unwrap();
    let real_git = PathBuf::from(std::env::var_os("PERSONA_TEST_GIT").expect("PERSONA_TEST_GIT"));
    let mut git = Command::new(&real_git);
    git.current_dir(&repo).args(["init", "-q", "-b", "main"]);
    assert!(git.status().unwrap().success());
    assert!(
        Command::new(&real_git)
            .current_dir(&repo)
            .args(["remote", "add", "origin", "https://github.com/org/repo.git"])
            .status()
            .unwrap()
            .success()
    );
    let commit = Command::new(&real_git)
        .current_dir(&repo)
        .args([
            "-c",
            "user.name=Test Committer",
            "-c",
            "user.email=committer@example.invalid",
            "commit",
            "--allow-empty",
            "--author=Test Author <author@example.invalid>",
            "-m",
            "fixture",
        ])
        .status()
        .unwrap();
    assert!(commit.success());
    assert!(
        Command::new(&real_git)
            .current_dir(&repo)
            .args(["checkout", "-b", "feature"])
            .status()
            .unwrap()
            .success()
    );
    let feature_commit = Command::new(&real_git)
        .current_dir(&repo)
        .args([
            "-c",
            "user.name=Test Committer",
            "-c",
            "user.email=committer@example.invalid",
            "commit",
            "--allow-empty",
            "--author=Test Author <author@example.invalid>",
            "-m",
            "feature fixture",
        ])
        .status()
        .unwrap();
    assert!(feature_commit.success());
    assert!(
        Command::new(&real_git)
            .current_dir(&repo)
            .args(["checkout", "main"])
            .status()
            .unwrap()
            .success()
    );

    let config = xdg.join("persona/config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    write_policy(&config, &repo);
    let contents = fs::read_to_string(&config).unwrap();
    fs::write(
        &config,
        format!(
            r#"{contents}
[scopes.git.push]
remote = "origin"
destinations = ["https://github.com/org/repo.git"]
"#
        ),
    )
    .unwrap();
    fs::set_permissions(config.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

    let gh = temporary.path().join("gh-fixture");
    let verified_calls = temporary.path().join("verified-calls");
    fs::write(
        &gh,
        format!(
            r#"#!/bin/sh
if [ "$1 $2" = "auth token" ]; then printf 'synthetic-token\n'; exit 0; fi
if [ "$1 $2" = "api user" ]; then printf '4242\n'; exit 0; fi
case "$2" in repos/org/repo/commits/*) printf '%s\n' "$*" >> '{}'; printf 'true\n'; exit 0;; esac
exit 64
"#,
            verified_calls.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&gh, fs::Permissions::from_mode(0o700)).unwrap();
    let enrollment = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("GH_CONFIG_DIR", &gh_config)
        .env("PERSONA_GH", &gh)
        .args([
            "auth",
            "enroll",
            "--profile",
            "work",
            "--host",
            "github.com",
            "--user",
            "synthetic-user",
            "--confirm-online",
        ])
        .output()
        .unwrap();
    assert!(
        enrollment.status.success(),
        "{}",
        String::from_utf8_lossy(&enrollment.stderr)
    );
    let profile_update = persona_command(&repo)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("GH_CONFIG_DIR", &gh_config)
        .env("PERSONA_GH", &gh)
        .env("PERSONA_GIT", &real_git)
        .args([
            "profile",
            "update",
            "work",
            "--author-name",
            "Test Author",
            "--author-email",
            "author@example.invalid",
            "--committer-name",
            "Test Committer",
            "--committer-email",
            "committer@example.invalid",
            "--github-repo",
            "org/repo",
            "--remote-policy",
            "origin|https://github.com/org/repo.git|https://github.com/org/repo.git",
        ])
        .output()
        .unwrap();
    assert!(
        profile_update.status.success(),
        "{}",
        String::from_utf8_lossy(&profile_update.stderr)
    );

    let feature_oid = Command::new(&real_git)
        .current_dir(&repo)
        .args(["rev-parse", "refs/heads/feature"])
        .output()
        .unwrap();
    assert!(feature_oid.status.success());
    let feature_oid = String::from_utf8(feature_oid.stdout)
        .unwrap()
        .trim()
        .to_owned();
    let tuple = format!(
        "refs/heads/feature {feature_oid} refs/heads/feature {}\n",
        "0".repeat(feature_oid.len())
    );
    let mut online_check = persona_command(&repo)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("GH_CONFIG_DIR", &gh_config)
        .env("PERSONA_GH", &gh)
        .env("PERSONA_GIT", &real_git)
        .args([
            "check",
            "--operation",
            "push",
            "--remote",
            "origin",
            "--destination",
            "https://github.com/org/repo.git",
            "--online-verified",
            "--format",
            "json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    online_check
        .stdin
        .take()
        .unwrap()
        .write_all(tuple.as_bytes())
        .unwrap();
    let online_check = online_check.wait_with_output().unwrap();
    assert_eq!(
        online_check.status.code(),
        Some(0),
        "stdout: {}; stderr: {}",
        String::from_utf8_lossy(&online_check.stdout),
        String::from_utf8_lossy(&online_check.stderr)
    );
    let online_json = String::from_utf8_lossy(&online_check.stdout);
    assert!(online_json.contains("github.commit.verified"));
    assert!(online_json.contains("PASS"));
    assert!(
        verified_calls.exists(),
        "online Verified must query the synthetic GitHub API"
    );
    let gh_unverified = temporary.path().join("gh-unverified");
    let unverified_script = fs::read_to_string(&gh)
        .unwrap()
        .replace("printf 'true\\n'", "printf 'false\\n'");
    fs::write(&gh_unverified, unverified_script).unwrap();
    fs::set_permissions(&gh_unverified, fs::Permissions::from_mode(0o700)).unwrap();
    let mut unverified_check = persona_command(&repo)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("GH_CONFIG_DIR", &gh_config)
        .env("PERSONA_GH", &gh_unverified)
        .env("PERSONA_GIT", &real_git)
        .args([
            "check",
            "--operation",
            "push",
            "--remote",
            "origin",
            "--destination",
            "https://github.com/org/repo.git",
            "--online-verified",
            "--format",
            "json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    unverified_check
        .stdin
        .take()
        .unwrap()
        .write_all(tuple.as_bytes())
        .unwrap();
    let unverified_check = unverified_check.wait_with_output().unwrap();
    assert_eq!(unverified_check.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&unverified_check.stdout).contains("github.commit.verified"));
    assert!(String::from_utf8_lossy(&unverified_check.stdout).contains("FAIL"));

    let install_hook = persona_command(temporary.path())
        .env("HOME", &home)
        .env("PERSONA_GIT", &real_git)
        .env("PATH", "/usr/bin:/bin")
        .args(["hooks", "install", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .output()
        .unwrap();
    assert!(
        install_hook.status.success(),
        "{}",
        String::from_utf8_lossy(&install_hook.stderr)
    );

    let real_git_literal = format!("'{}'", real_git.to_string_lossy().replace('\'', "'\\\\''"));
    let repo_literal = format!("'{}'", repo.to_string_lossy().replace('\'', "'\\\\''"));
    let marker = temporary.path().join("native-push-reached");
    let marker_literal = format!("'{}'", marker.to_string_lossy().replace('\'', "'\\\\''"));
    let fake_git = temporary.path().join("git-fixture");
    let script = format!(
        r#"#!/bin/sh
for arg in "$@"; do [ "$arg" = push ] && is_push=1; done
if [ "${{is_push:-}}" = 1 ]; then
  printf '%s\n' "$*" > {marker_literal}
  oid_main=$({real_git_literal} rev-parse refs/heads/main) || exit 70
  oid_feature=$({real_git_literal} rev-parse refs/heads/feature) || exit 70
  {{ printf 'refs/heads/main %s refs/heads/main %s\n' "$oid_main" '{zeros}'; printf 'refs/heads/feature %s refs/heads/review %s\n' "$oid_feature" '{zeros}'; }} | {repo_literal}/.git/hooks/pre-push origin https://github.com/org/repo.git
  exit $?
fi
exec {real_git_literal} "$@"
"#,
        zeros = "0".repeat(40),
    );
    fs::write(&fake_git, script).unwrap();
    fs::set_permissions(&fake_git, fs::Permissions::from_mode(0o700)).unwrap();
    let managed_push = || {
        persona_command(&repo)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &xdg)
            .env("XDG_STATE_HOME", &state)
            .env("GH_CONFIG_DIR", &gh_config)
            .env("PERSONA_GH", &gh)
            .env("PERSONA_GIT", &fake_git)
            .args([
                "run",
                "--",
                "git",
                "push",
                "--atomic",
                "origin",
                "refs/heads/main:refs/heads/main",
                "refs/heads/feature:refs/heads/review",
            ])
            .output()
            .unwrap()
    };
    let non_atomic = persona_command(&repo)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("GH_CONFIG_DIR", &gh_config)
        .env("PERSONA_GH", &gh)
        .env("PERSONA_GIT", &fake_git)
        .args([
            "run",
            "--",
            "git",
            "push",
            "origin",
            "refs/heads/main:refs/heads/main",
            "refs/heads/feature:refs/heads/review",
        ])
        .output()
        .unwrap();
    assert!(!non_atomic.status.success());
    assert!(
        String::from_utf8_lossy(&non_atomic.stderr)
            .contains("outside the currently supported safe grammar")
    );
    assert!(
        !marker.exists(),
        "non-atomic multi-ref push must be refused before transport"
    );

    let push = managed_push();
    assert!(
        push.status.success(),
        "stdout: {}; stderr: {}",
        String::from_utf8_lossy(&push.stdout),
        String::from_utf8_lossy(&push.stderr)
    );
    let native_arguments = fs::read_to_string(&marker).unwrap();
    assert!(native_arguments.contains("--atomic"));
    assert!(native_arguments.contains("refs/heads/main:refs/heads/main"));
    assert!(native_arguments.contains("refs/heads/feature:refs/heads/review"));
    assert!(!String::from_utf8_lossy(&push.stdout).contains("synthetic-token"));
    assert!(!String::from_utf8_lossy(&push.stderr).contains("synthetic-token"));

    fs::remove_file(&marker).unwrap();
    let changed_gh = temporary.path().join("gh-changed");
    let changed_script = fs::read_to_string(&gh)
        .unwrap()
        .replace("synthetic-token", "rotated-token");
    fs::write(&changed_gh, changed_script).unwrap();
    fs::set_permissions(&changed_gh, fs::Permissions::from_mode(0o700)).unwrap();
    let rejected = persona_command(&repo)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("GH_CONFIG_DIR", &gh_config)
        .env("PERSONA_GH", &changed_gh)
        .env("PERSONA_GIT", &fake_git)
        .args([
            "run",
            "--",
            "git",
            "push",
            "origin",
            "refs/heads/main:refs/heads/main",
        ])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("selected GitHub credential does not match the enrolled account"),
        "failure must be attributable to the credential-binding mismatch: {}",
        String::from_utf8_lossy(&rejected.stderr)
    );
    assert!(
        !marker.exists(),
        "credential mismatch must block before the native push/hook path"
    );
}

#[test]
fn https_git_credential_helper_checks_destination_before_returning_synthetic_token() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempdir().unwrap();
    let home = temporary.path().join("home");
    let xdg = temporary.path().join("xdg-config");
    let state = temporary.path().join("state");
    let gh_config = temporary.path().join("gh-config");
    let git = PathBuf::from(std::env::var_os("PERSONA_TEST_GIT").expect("PERSONA_TEST_GIT"));
    let scope = temporary.path().join("repo");
    fs::create_dir_all(&scope).unwrap();
    fs::create_dir(&gh_config).unwrap();
    fs::set_permissions(&gh_config, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        gh_config.join("hosts.yml"),
        "github.com:\n  user: synthetic-user\n",
    )
    .unwrap();
    let marker = temporary.path().join("gh-called");
    let gh = temporary.path().join("gh-fixture");
    let gh_script = format!(
        r#"#!/bin/sh
: > '{}'
if [ "$1 $2" = "auth token" ]; then printf 'synthetic-token\n'; exit 0; fi
if [ "$1 $2" = "api user" ]; then printf '4242\n'; exit 0; fi
exit 64
"#,
        marker.display()
    );
    fs::write(&gh, gh_script).unwrap();
    fs::set_permissions(&gh, fs::Permissions::from_mode(0o700)).unwrap();

    let config_dir = xdg.join("persona");
    fs::create_dir_all(&config_dir).unwrap();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let config_file = config_dir.join("config.toml");
    let scope_toml = toml::Value::String(scope.to_str().unwrap().to_owned());
    fs::write(
        &config_file,
        format!(
            r#"
version = 2
[[profiles]]
name = "work"
[profiles.git]
author = {{ name = "Synthetic", email = "synthetic@example.invalid" }}
committer = {{ name = "Synthetic", email = "synthetic@example.invalid" }}
[profiles.git.push]
remote = "origin"
destinations = ["https://github.com/org/repo.git"]
[[scopes]]
name = "work"
path = {scope_toml}
profile = "work"
"#
        ),
    )
    .unwrap();
    fs::set_permissions(&config_file, fs::Permissions::from_mode(0o600)).unwrap();
    let environment = || {
        vec![
            ("HOME", home.as_path()),
            ("XDG_CONFIG_HOME", xdg.as_path()),
            ("XDG_STATE_HOME", state.as_path()),
            ("GH_CONFIG_DIR", gh_config.as_path()),
            ("PERSONA_GH", gh.as_path()),
            ("PERSONA_GIT", git.as_path()),
            ("PATH", Path::new("/usr/bin:/bin")),
        ]
    };
    let enroll = persona_command(&scope)
        .envs(environment())
        .args([
            "auth",
            "enroll",
            "--profile",
            "work",
            "--user",
            "synthetic-user",
            "--confirm-online",
        ])
        .output()
        .unwrap();
    assert_eq!(
        enroll.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&enroll.stderr)
    );
    fs::remove_file(&marker).unwrap();

    let diagnostic = persona_command(&scope)
        .envs(environment())
        .args([
            "check",
            "--cwd",
            scope.to_str().unwrap(),
            "--format",
            "json",
            "--operation",
            "push",
            "--remote",
            "origin",
            "--destination",
            "https://github.com/org/repo.git",
        ])
        .output()
        .unwrap();
    assert_ne!(diagnostic.status.code(), Some(0));
    assert!(
        !marker.exists(),
        "offline push diagnostics must never query a native credential selector"
    );

    let invalid = persona_command(&scope)
        .envs(environment())
        .args(["credential-helper", "get"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"protocol=https\nhost=github.com\npath=org/other.git\n\n")?;
            child.wait_with_output()
        })
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    assert!(
        !marker.exists(),
        "unauthorized URL must not retrieve a token"
    );

    let token_override = persona_command(&scope)
        .envs(environment())
        .env("GH_TOKEN", "synthetic-override-token")
        .args(["credential-helper", "get"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"protocol=https\nhost=github.com\npath=org/repo.git\n\n")?;
            child.wait_with_output()
        })
        .unwrap();
    assert_eq!(token_override.status.code(), Some(2));
    assert!(token_override.stdout.is_empty());
    assert!(!marker.exists(), "environment token must not invoke gh");

    let enterprise_token_override = persona_command(&scope)
        .envs(environment())
        .env("GH_ENTERPRISE_TOKEN", "synthetic-enterprise-override-token")
        .args(["credential-helper", "get"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"protocol=https\\nhost=github.com\\npath=org/repo.git\\n\\n")?;
            child.wait_with_output()
        })
        .unwrap();
    assert_eq!(enterprise_token_override.status.code(), Some(2));
    assert!(enterprise_token_override.stdout.is_empty());
    assert!(
        !marker.exists(),
        "enterprise environment token must not invoke gh"
    );

    let valid = persona_command(&scope)
        .envs(environment())
        .args(["credential-helper", "get"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().unwrap().write_all(
                b"protocol=https\nhost=github.com:443\npath=org/repo.git\nusername=x-access-token\n\n",
            )?;
            child.wait_with_output()
        })
        .unwrap();
    assert_eq!(
        valid.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&valid.stderr)
    );
    assert_eq!(
        valid.stdout,
        b"username=x-access-token\npassword=synthetic-token\n\n"
    );
    assert!(marker.exists());
    fs::remove_file(&marker).unwrap();

    let shim_dir = temporary.path().join("credential-shim");
    fs::create_dir(&shim_dir).unwrap();
    let shim = shim_dir.join("git-credential-persona");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_persona"), &shim).unwrap();
    let shim_output = Command::new(&shim)
        .arg("get")
        .current_dir(&scope)
        .envs(environment())
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_CONFIG_PATH", &config_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().unwrap().write_all(
                b"protocol=https\nhost=github.com\npath=org/repo.git\nusername=x-access-token\n\n",
            )?;
            child.wait_with_output()
        })
        .unwrap();
    assert_eq!(
        shim_output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&shim_output.stderr)
    );
    assert_eq!(
        shim_output.stdout,
        b"username=x-access-token\npassword=synthetic-token\n\n"
    );
    assert!(marker.exists());
}

#[test]
fn profile_and_scope_cli_manages_reusable_private_configuration() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempdir().expect("create temporary directory");
    let scope = temporary.path().join("initial");
    let second = temporary.path().join("second");
    let home = temporary.path().join("home");
    let xdg = temporary.path().join("xdg-config");
    fs::create_dir(&scope).unwrap();
    fs::create_dir(&second).unwrap();

    let setup = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args([
            "setup",
            "--profile",
            "work",
            "--scope-name",
            "initial",
            "--scope",
            "initial",
            "--author-name",
            "Work Author",
            "--author-email",
            "work@example.invalid",
            "--committer-name",
            "Work Committer",
            "--committer-email",
            "work@example.invalid",
        ])
        .output()
        .unwrap();
    assert_eq!(setup.status.code(), Some(0));
    let config_dir = xdg.join("persona");
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let config_file = config_dir.join("config.toml");
    fs::set_permissions(&config_file, fs::Permissions::from_mode(0o600)).unwrap();

    let before_preview = fs::read(&config_file).unwrap();
    let preview = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args([
            "profile",
            "add",
            "personal",
            "--author-name",
            "Personal Author",
            "--author-email",
            "personal@example.invalid",
            "--committer-name",
            "Personal Committer",
            "--committer-email",
            "personal@example.invalid",
            "--signing-fingerprint",
            "0000000000000000000000000000000000000000",
            "--public-key",
            "/tmp/synthetic-persona-public.asc",
            "--push-remote",
            "origin",
            "--push-destination",
            "file:///tmp/synthetic-destination.git",
            "--preview",
        ])
        .output()
        .unwrap();
    assert_eq!(
        preview.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    assert!(String::from_utf8_lossy(&preview.stdout).contains("Preview only"));
    assert_eq!(fs::read(&config_file).unwrap(), before_preview);

    let added = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args([
            "profile",
            "add",
            "personal",
            "--author-name",
            "Personal Author",
            "--author-email",
            "personal@example.invalid",
            "--committer-name",
            "Personal Committer",
            "--committer-email",
            "personal@example.invalid",
            "--signing-fingerprint",
            "0000000000000000000000000000000000000000",
            "--public-key",
            "/tmp/synthetic-persona-public.asc",
            "--push-remote",
            "origin",
            "--push-destination",
            "file:///tmp/synthetic-destination.git",
            "--remote-policy",
            "origin|file:///tmp/synthetic-destination.git|file:///tmp/synthetic-destination.git",
            "--allow-force-with-lease",
            "true",
            "--ssh-host",
            "github.com",
            "--ssh-user",
            "git",
            "--ssh-port",
            "22",
            "--ssh-fingerprint",
            "SHA256:abcDEF0123+/=",
            "--ssh-public-key",
            "/tmp/synthetic-ssh.pub",
            "--ssh-identity-file",
            "/tmp/synthetic-ssh",
            "--ssh-known-hosts-file",
            "/tmp/synthetic-known-hosts",
        ])
        .output()
        .unwrap();
    assert_eq!(
        added.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );

    let update = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args([
            "profile",
            "update",
            "personal",
            "--author-name",
            "Updated Personal Author",
            "--author-email",
            "personal@example.invalid",
            "--committer-name",
            "Personal Committer",
            "--committer-email",
            "personal@example.invalid",
        ])
        .output()
        .unwrap();
    assert_eq!(
        update.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&update.stderr)
    );
    let updated = persona::config::Config::load(&config_file).unwrap();
    let personal = updated
        .profiles()
        .iter()
        .find(|profile| profile.name == "personal")
        .unwrap();
    assert!(personal.git.signing.is_some());
    assert!(personal.git.push.is_some());
    assert!(personal.git.push.as_ref().unwrap().allow_force_with_lease);
    assert_eq!(personal.git.remotes.len(), 1);
    assert_eq!(personal.git.remotes[0].name, "origin");
    assert_eq!(
        personal.git.remotes[0].fetch_destinations,
        ["file:///tmp/synthetic-destination.git"]
    );
    assert_eq!(personal.ssh.as_ref().unwrap().host, "github.com");
    assert_eq!(personal.git.author.name, "Updated Personal Author");

    let scope_added = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args(["scope", "add", "second", "second", "--profile", "personal"])
        .output()
        .unwrap();
    assert_eq!(
        scope_added.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&scope_added.stderr)
    );

    let listing = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args(["scope", "list"])
        .output()
        .unwrap();
    let listing = String::from_utf8(listing.stdout).unwrap();
    assert!(listing.contains("initial"));
    assert!(listing.contains("second"));
    assert!(listing.contains("personal"));

    let blocked_remove = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args(["profile", "remove", "personal"])
        .output()
        .unwrap();
    assert_eq!(blocked_remove.status.code(), Some(2));

    let scope_removed = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args(["scope", "remove", "second"])
        .output()
        .unwrap();
    assert_eq!(scope_removed.status.code(), Some(0));
    let profile_removed = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args(["profile", "remove", "personal"])
        .output()
        .unwrap();
    assert_eq!(profile_removed.status.code(), Some(0));
}

#[test]
fn migration_apply_and_rollback_use_private_backups() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempdir().expect("create temporary directory");
    let home = temporary.path().join("home");
    let xdg = temporary.path().join("xdg-config");
    let config_dir = xdg.join("persona");
    fs::create_dir_all(&config_dir).expect("create config directory");
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let config_file = config_dir.join("config.toml");
    write_policy(&config_file, temporary.path());
    fs::set_permissions(&config_file, fs::Permissions::from_mode(0o600)).unwrap();
    let original = fs::read(&config_file).unwrap();

    let migrated = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args(["config", "migrate", "--apply"])
        .output()
        .expect("apply migration");
    assert_eq!(
        migrated.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&migrated.stderr)
    );
    let current = persona::config::Config::load(&config_file).unwrap();
    assert_eq!(current.version(), 3);
    let output = String::from_utf8(migrated.stdout).unwrap();
    let backup = output
        .lines()
        .find_map(|line| line.strip_prefix("Backup: "))
        .expect("backup path");

    let rolled_back = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args(["config", "rollback", "--backup", backup])
        .output()
        .expect("rollback migration");
    assert_eq!(
        rolled_back.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&rolled_back.stderr)
    );
    assert_eq!(fs::read(config_file).unwrap(), original);
}

#[test]
fn status_discovers_the_private_xdg_configuration_without_an_override() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempdir().expect("create temporary directory");
    let home = temporary.path().join("home");
    let scope_root = temporary.path().join("work");
    fs::create_dir(&scope_root).expect("create managed scope");
    let xdg = temporary.path().join("xdg-config");
    let config_dir = xdg.join("persona");
    fs::create_dir_all(&config_dir).expect("create private config directory");
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700))
        .expect("protect config directory");
    let config_path = config_dir.join("config.toml");
    write_policy(&config_path, &scope_root);
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))
        .expect("protect config file");

    let output = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .arg("status")
        .output()
        .expect("run persona");

    assert_eq!(
        output.status.code(),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Persona: unmanaged"));
    assert!(!stdout.contains("finding "));

    let default_output = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .output()
        .expect("run default status");
    assert_eq!(default_output.status.code(), Some(3));
    assert!(
        String::from_utf8(default_output.stdout)
            .unwrap()
            .contains("Persona: unmanaged")
    );
}

#[test]
fn help_and_version_exit_successfully() {
    let temporary = tempdir().expect("create temporary directory");

    for argument in ["--help", "--version"] {
        let output = persona_command(temporary.path())
            .arg(argument)
            .output()
            .expect("run persona");

        assert_eq!(output.status.code(), Some(0));

        let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");

        assert!(stdout.contains("persona"));
    }
}
