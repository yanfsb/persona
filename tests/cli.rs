use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn persona_command(directory: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_persona"));

    command.env_clear().current_dir(directory);

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
        .args(["status", "--config", "policy.toml", "--cwd", "work/project"])
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
        .output()
        .expect("run persona");

    assert_eq!(output.status.code(), Some(3));

    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");

    assert!(stdout.contains("scope: unmanaged"));
    assert!(stdout.contains("result: UNKNOWN"));
    assert!(!stdout.contains("expected author:"));
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
        findings.iter().any(|finding| {
            finding["property"] == "scope"
                && finding["status"] == "UNKNOWN"
                && finding["coverage_reason"].is_string()
        })
    }));
}

#[test]
fn status_reports_invalid_configuration_as_an_error() {
    let temporary = tempdir().expect("create temporary directory");
    let config_path = temporary.path().join("policy.toml");

    fs::write(&config_path, "version = 2\nscopes = []").expect("write invalid policy");

    let output = persona_command(temporary.path())
        .args(["status", "--config"])
        .arg(&config_path)
        .output()
        .expect("run persona");

    assert_eq!(output.status.code(), Some(2));

    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");

    assert!(stderr.contains("UnsupportedVersion(2)"));
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
fn status_requires_an_explicit_configuration_file() {
    let temporary = tempdir().expect("create temporary directory");

    let output = persona_command(temporary.path())
        .arg("status")
        .output()
        .expect("run persona");

    assert_eq!(output.status.code(), Some(2));

    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");

    assert!(stderr.contains("--config"));
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
