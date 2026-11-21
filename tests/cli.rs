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

#[cfg(all(unix, feature = "test-support"))]
#[test]
fn concurrent_scope_add_commands_preserve_both_updates() {
    use persona::config::Config;
    use persona::storage::PersonaPaths;
    use std::time::{Duration, Instant};

    let temporary = tempdir().unwrap();
    let home = temporary.path().join("home");
    let config_home = temporary.path().join("config-home");
    let state_home = temporary.path().join("state-home");
    let base_scope = temporary.path().join("base");
    let first_scope = temporary.path().join("first-scope");
    let second_scope = temporary.path().join("second-scope");
    for directory in [&home, &base_scope, &first_scope, &second_scope] {
        fs::create_dir_all(directory).unwrap();
    }
    let paths =
        PersonaPaths::from_environment(Some(&home), Some(&config_home), Some(&state_home)).unwrap();
    let base_path = toml::Value::String(
        base_scope
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
    );
    let config = format!(
        r#"version = 4

[profiles.work]
author = {{ name = "Synthetic", email = "author@example.invalid" }}
committer = {{ name = "Synthetic", email = "committer@example.invalid" }}
scopes = [{{ name = "base", path = {base_path} }}]
"#
    );
    paths.create_config(config.as_bytes()).unwrap();

    let gate = temporary.path().join("git-gate");
    fs::create_dir(&gate).unwrap();
    let real_git =
        PathBuf::from(std::env::var_os("PERSONA_TEST_GIT").expect("test Git executable"));
    let shell_quote = |value: &str| format!("'{}'", value.replace('\'', "'\\''"));

    // The first CLI pauses in Git after loading config while holding the
    // update lock. The second signals only after the kernel confirms contention.
    let launch =
        |gate_id: &str, scope_name: &str, scope_path: &Path, contention_marker: Option<&Path>| {
            let git_wrapper = temporary.path().join(format!("git-wrapper-{gate_id}"));
            let wrapper_script = format!(
                r#"#!/bin/sh
set -eu
gate_dir={}
gate_id={}
real_git={}
printf '%s\n' "$*" >> "$gate_dir/calls-$gate_id"
if [ "$1" = "rev-parse" ] && [ "$2" = "--show-toplevel" ]; then
    : > "$gate_dir/entered-$gate_id"
    attempt=0
    while [ ! -f "$gate_dir/release" ]; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 2000 ] || exit 98
        /bin/sleep 0.01
    done
fi
exec "$real_git" "$@"
"#,
                shell_quote(&gate.to_string_lossy()),
                shell_quote(gate_id),
                shell_quote(&real_git.to_string_lossy()),
            );
            fs::write(&git_wrapper, wrapper_script).unwrap();
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&git_wrapper, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let mut command = Command::new(env!("CARGO_BIN_EXE_persona"));
            command
                .env_clear()
                .current_dir(temporary.path())
                .args(["scope", "add", scope_name])
                .arg(scope_path)
                .args(["--profile", "work"])
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &home)
                .env("XDG_CONFIG_HOME", &config_home)
                .env("XDG_STATE_HOME", &state_home)
                .env("PERSONA_GIT", &git_wrapper);
            if let Some(marker) = contention_marker {
                command.env("PERSONA_TEST_CONFIG_LOCK_CONTENDED", marker);
            }
            command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        };

    let first = launch("first", "first", &first_scope, None);
    let first_entered = gate.join("entered-first");
    let first_deadline = Instant::now() + Duration::from_secs(10);
    while !first_entered.exists() {
        if Instant::now() >= first_deadline {
            fs::write(gate.join("release"), b"release").unwrap();
            let output = first.wait_with_output().unwrap();
            panic!(
                "first CLI never reached gated Git: calls={:?}, status={}, stderr={}",
                fs::read_to_string(gate.join("calls-first")),
                output.status,
                String::from_utf8_lossy(&output.stderr),
            );
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    let contention_marker = temporary.path().join("config-lock-contended");
    let second = launch("second", "second", &second_scope, Some(&contention_marker));
    let contention_deadline = Instant::now() + Duration::from_secs(10);
    while !contention_marker.exists() {
        if Instant::now() >= contention_deadline {
            fs::write(gate.join("release"), b"release").unwrap();
            drop(first.wait_with_output().unwrap());
            let second_output = second.wait_with_output().unwrap();
            panic!(
                "second CLI never observed config-lock contention; second entered Git={}, status={}, stderr={}",
                gate.join("entered-second").exists(),
                second_output.status,
                String::from_utf8_lossy(&second_output.stderr),
            );
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    fs::write(gate.join("release"), b"release").unwrap();

    let first_output = first.wait_with_output().unwrap();
    let second_output = second.wait_with_output().unwrap();
    assert!(
        first_output.status.success(),
        "{}",
        String::from_utf8_lossy(&first_output.stderr)
    );
    assert!(
        second_output.status.success(),
        "{}",
        String::from_utf8_lossy(&second_output.stderr)
    );

    let config = Config::load(&paths.config_file).unwrap();
    for expected in ["base", "first", "second"] {
        assert!(
            config.policies().iter().any(|scope| scope.name == expected),
            "concurrent updates lost scope `{expected}`"
        );
    }
}

#[test]
fn handoff_lock_helper_process() {
    let Ok(handoff_path) = std::env::var("PERSONA_TEST_HANDOFF_LOCK_PATH") else {
        return;
    };
    use persona::push_handoff::read_locked;
    use persona::storage::PersonaPaths;
    use std::time::{Duration, Instant};

    let paths = PersonaPaths::discover().unwrap();
    let guard = read_locked(&paths, Path::new(&handoff_path)).unwrap();
    let ready = PathBuf::from(std::env::var_os("PERSONA_TEST_HANDOFF_LOCK_READY").unwrap());
    let release = PathBuf::from(std::env::var_os("PERSONA_TEST_HANDOFF_LOCK_RELEASE").unwrap());
    fs::write(ready, b"locked").unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !release.exists() {
        assert!(
            Instant::now() < deadline,
            "parent did not release handoff lock"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(guard);
}

fn write_policy(path: &Path, scope_root: &Path) {
    let root = scope_root
        .to_str()
        .expect("fixture path should be valid UTF-8");

    let quoted_root = toml::Value::String(root.to_owned());

    let contents = format!(
        r#"version = 4

[profiles.work]
author = {{ name = "Test Author", email = "author@example.invalid" }}
committer = {{ name = "Test Committer", email = "committer@example.invalid" }}
scopes = [{quoted_root}]
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
fn config_path_validate_and_show_commands_support_v4_and_extends() {
    let temporary = tempdir().expect("create temporary directory");
    let base_scope = temporary.path().join("base");
    let child_scope = temporary.path().join("child");
    fs::create_dir(&base_scope).expect("create base scope");
    fs::create_dir(&child_scope).expect("create child scope");
    let config_path = temporary.path().join("policy.toml");
    let base_root = toml::Value::String(base_scope.to_string_lossy().into_owned());
    let child_root = toml::Value::String(child_scope.to_string_lossy().into_owned());
    fs::write(
        &config_path,
        format!(
            r#"version = 4

[profiles.base]
name = "Base Author"
email = "base@example.invalid"
scopes = [{base_root}]

[profiles.base.git]
remote = "origin"
push = ["github.com/example/*"]

[profiles.child]
extends = "base"
email = "child@example.invalid"
scopes = [{child_root}]
"#
        ),
    )
    .expect("write v4 fixture");
    let original = fs::read_to_string(&config_path).expect("read source config");

    // `config path --config` reports the resolved path without mutating anything.
    let path_output = persona_command(temporary.path())
        .args(["config", "path", "--config"])
        .arg(&config_path)
        .output()
        .expect("run config path");
    assert_eq!(path_output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(path_output.stdout).unwrap().trim(),
        config_path.to_string_lossy()
    );

    // `config validate` validates syntax and invariants offline.
    let validate_output = persona_command(temporary.path())
        .args(["config", "validate", "--config"])
        .arg(&config_path)
        .output()
        .expect("run config validate");
    assert_eq!(
        validate_output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&validate_output.stderr)
    );
    let validate_stdout = String::from_utf8(validate_output.stdout).unwrap();
    assert!(validate_stdout.contains("is valid (v4, 2 profile(s), 2 scope(s))"));

    // `config show` preserves `extends` and shorthands in authored view.
    let show_authored = persona_command(temporary.path())
        .args(["config", "show", "--config"])
        .arg(&config_path)
        .output()
        .expect("run config show");
    assert_eq!(show_authored.status.code(), Some(0));
    let authored_toml = String::from_utf8(show_authored.stdout).unwrap();
    assert!(authored_toml.contains("version = 4"));
    assert!(authored_toml.contains("extends = \"base\""));
    let parsed_authored =
        persona::config::Config::parse(&authored_toml).expect("authored output is valid v4");
    assert_eq!(parsed_authored.version(), 4);

    // `config show --resolved` flattens `extends` and expands shorthands.
    let show_resolved = persona_command(temporary.path())
        .args(["config", "show", "--config"])
        .arg(&config_path)
        .arg("--resolved")
        .output()
        .expect("run config show --resolved");
    assert_eq!(show_resolved.status.code(), Some(0));
    let resolved_toml = String::from_utf8(show_resolved.stdout).unwrap();
    assert!(!resolved_toml.contains("extends ="));
    assert!(resolved_toml.contains("git@github.com:example/*"));
    assert!(resolved_toml.contains("https://github.com/example/*"));
    let parsed_resolved =
        persona::config::Config::parse(&resolved_toml).expect("resolved output is valid v4");
    assert_eq!(parsed_resolved.version(), 4);

    // `config show --profile child --resolved` yields a standalone resolved profile.
    let show_child_resolved = persona_command(temporary.path())
        .args(["config", "show", "--config"])
        .arg(&config_path)
        .args(["--profile", "child", "--resolved"])
        .output()
        .expect("run config show --profile child --resolved");
    assert_eq!(show_child_resolved.status.code(), Some(0));
    let child_toml = String::from_utf8(show_child_resolved.stdout).unwrap();
    let parsed_child =
        persona::config::Config::parse(&child_toml).expect("resolved child is standalone v4");
    assert_eq!(parsed_child.profiles().len(), 1);
    assert_eq!(parsed_child.profiles()[0].name, "child");
    assert_eq!(parsed_child.profiles()[0].git.author.name, "Base Author");
    assert_eq!(
        parsed_child.profiles()[0].git.author.email,
        "child@example.invalid"
    );

    // `config show --json` and `--profile child --json` emit structured JSON.
    let show_json = persona_command(temporary.path())
        .args(["config", "show", "--config"])
        .arg(&config_path)
        .args(["--profile", "child", "--json"])
        .output()
        .expect("run config show --profile child --json");
    assert_eq!(show_json.status.code(), Some(0));
    let payload: serde_json::Value = serde_json::from_slice(&show_json.stdout).expect("valid JSON");
    assert_eq!(payload["version"], 4);
    assert_eq!(payload["profile"]["name"], "child");
    assert_eq!(payload["profile"]["extends"], "base");
    assert_eq!(payload["profile"]["git"]["author"]["name"], "Base Author");
    assert_eq!(
        payload["profile"]["git"]["author"]["email"],
        "child@example.invalid"
    );

    assert_eq!(fs::read_to_string(&config_path).unwrap(), original);
}

#[test]
fn status_reports_invalid_configuration_as_an_error() {
    let temporary = tempdir().expect("create temporary directory");
    let config_path = temporary.path().join("policy.toml");

    for unsupported in [3u32, 5u32] {
        fs::write(&config_path, format!("version = {unsupported}\n"))
            .expect("write invalid policy");

        let output = persona_command(temporary.path())
            .args(["status", "--config"])
            .arg(&config_path)
            .output()
            .expect("run persona");

        assert_eq!(output.status.code(), Some(2));

        let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");

        assert!(
            stderr.contains(&format!("UnsupportedVersion({unsupported})")),
            "expected UnsupportedVersion({unsupported}) in stderr: {stderr}"
        );
        assert!(output.stdout.is_empty());

        let validate = persona_command(temporary.path())
            .args(["config", "validate", "--config"])
            .arg(&config_path)
            .output()
            .expect("run config validate");
        assert_eq!(validate.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&validate.stderr)
                .contains(&format!("UnsupportedVersion({unsupported})"))
        );
    }
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
            r#"version = 4

[profiles.work]
author = {{ name = "Author", email = "author@example.invalid" }}
committer = {{ name = "Committer", email = "committer@example.invalid" }}
scopes = [{root}]

[profiles.work.git]
remote = "origin"
push = ["https://github.com/org/repo.git"]
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
    policy_contents.push_str("\n[profiles.work.git]\nremote = \"origin\"\npush = [\"file:///synthetic/upstream.git\"]\npreserve_authors = true\n");
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
    let everyday_switch = persona_command(&repo)
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "switch", "-c", "day-to-day-hook"])
        .output()
        .unwrap();
    assert_eq!(
        everyday_switch.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&everyday_switch.stderr)
    );
    assert!(
        hook_marker.exists(),
        "day-to-day repo hooks should run by default when strict_repo_hooks is false"
    );
    fs::remove_file(&hook_marker).unwrap();

    let strict_config_path = temporary.path().join("strict-hooks-policy.toml");
    let mut strict_config = persona::config::Config::load(&config).unwrap();
    let mut strict_profile = strict_config.profiles()[0].clone();
    strict_profile.git.strict_repo_hooks = true;
    strict_config.update_profile(strict_profile).unwrap();
    fs::write(&strict_config_path, strict_config.to_v4_toml().unwrap()).unwrap();
    let hook_blocked = persona_command(&repo)
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&strict_config_path)
        .args(["--cwd"])
        .arg(&target)
        .args(["--", "git", "switch", "main"])
        .output()
        .unwrap();
    assert_eq!(hook_blocked.status.code(), Some(126));
    assert!(
        !hook_marker.exists(),
        "Persona must block before running hooks when strict_repo_hooks = true"
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
            "{base}\n[profiles.work.git]\nremote = \"origin\"\npush = [\"file:///tmp/synthetic.git\"]\nallow_lightweight_tags = true\n"
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
        .args(["--", "git", "--exec-path=/tmp", "status"])
        .output()
        .unwrap();
    assert_eq!(unsafe_status.status.code(), Some(126));
    assert!(
        String::from_utf8_lossy(&unsafe_status.stderr).contains("unsupported Git global option")
    );

    let everyday_status = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "status", "-sb"])
        .output()
        .unwrap();
    assert_eq!(everyday_status.status.code(), Some(0));

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
    let permissive_add = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "add", "--", "tracked.txt"])
        .output()
        .unwrap();
    assert_eq!(permissive_add.status.code(), Some(0));

    let strict_filter_config_path = temporary.path().join("strict-filters.toml");
    let mut strict_filter_config = persona::config::Config::load(&config).unwrap();
    let mut strict_filter_profile = strict_filter_config.profiles()[0].clone();
    strict_filter_profile.git.strict_git_filters = true;
    strict_filter_config
        .update_profile(strict_filter_profile)
        .unwrap();
    fs::write(
        &strict_filter_config_path,
        strict_filter_config.to_v4_toml().unwrap(),
    )
    .unwrap();
    let filtered_add = persona_command(temporary.path())
        .env("PERSONA_GIT", &git)
        .env("PATH", "/usr/bin:/bin")
        .args(["run", "--config"])
        .arg(&strict_filter_config_path)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "add", "--", "tracked.txt"])
        .output()
        .unwrap();
    assert_eq!(filtered_add.status.code(), Some(126));
    assert!(
        !filter_marker.exists(),
        "managed staging must refuse before invoking repository filters when strict_git_filters = true"
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
    let blocked_stderr = String::from_utf8_lossy(&blocked_network.stderr);
    assert!(
        blocked_stderr.contains("no profile-bound destination policy"),
        "unexpected stderr: {blocked_stderr}"
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
    let config = temporary.path().join("policy-v4.toml");
    fs::write(
        &config,
        format!(
            r#"version = 4

[profiles.work]
name = "Synthetic Author"
email = "author@example.invalid"
scopes = [{root}]

[profiles.work.git]
remote = "origin"
push = ["file:///allowed.git"]

[profiles.work.github]
host = "github.com"
account_id = "4242"
token_fingerprint = "hmac-sha256:{}"
"#,
            "0".repeat(64)
        ),
    )
    .unwrap();
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
        r#"version = 4

[profiles.work]
name = "Synthetic"
email = "synthetic@example.invalid"
scopes = [{scope}]

[profiles.work.git]
remote = "origin"
push = ["https://github.com/org/repo.git"]

[profiles.work.github]
host = "github.com"
account_id = "4242"
account_selector = "synthetic"
token_fingerprint = "hmac-sha256:{}"
"#,
        "0".repeat(64)
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
        dynamic_tuples: false,
        force_requested: false,
        bare_force_with_lease: false,
        lease_refs: Vec::new(),
        empty_lease_refs: Vec::new(),
        exact_leases: Vec::new(),
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
    let helper_binary = std::env::current_exe().unwrap();
    let ready = temporary.path().join("handoff-lock.ready");
    let release = temporary.path().join("handoff-lock.release");
    let mut holder = Command::new(helper_binary)
        .env_clear()
        .env("HOME", &home)
        .env("XDG_STATE_HOME", &state_home)
        .env("PERSONA_TEST_HANDOFF_LOCK_PATH", race_handoff.path())
        .env("PERSONA_TEST_HANDOFF_LOCK_READY", &ready)
        .env("PERSONA_TEST_HANDOFF_LOCK_RELEASE", &release)
        .args(["--exact", "handoff_lock_helper_process", "--nocapture"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !ready.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "handoff-lock helper never acquired the handoff"
        );
        assert!(
            holder.try_wait().unwrap().is_none(),
            "handoff-lock helper exited early"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let competing_hook = run_hook(race_handoff.path(), &input);
    fs::write(&release, b"release").unwrap();
    let holder_output = holder.wait_with_output().unwrap();
    assert!(
        holder_output.status.success(),
        "{}",
        String::from_utf8_lossy(&holder_output.stderr)
    );
    assert!(
        !competing_hook.status.success(),
        "a hook must fail while another process holds the one-time handoff lock"
    );
    let after_release = run_hook(race_handoff.path(), &input);
    assert_eq!(
        after_release.status.code(),
        Some(0),
        "a failed concurrent contender must not consume the held handoff: {}",
        String::from_utf8_lossy(&after_release.stderr)
    );
    assert!(!race_handoff.path().exists());

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
fn setup_creates_private_v4_configuration_without_changing_native_settings() {
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
    assert_eq!(config.version(), 4);
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
[profiles.work.git]
remote = "origin"
push = ["https://github.com/org/repo.git"]
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
    let unleased_force = persona_command(&repo)
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
            "--force",
            "origin",
            "refs/heads/main:refs/heads/main",
        ])
        .output()
        .unwrap();
    assert!(!unleased_force.status.success());
    assert!(
        !marker.exists(),
        "unleased force push must be refused before transport when allow_force_push = false"
    );

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
    assert!(
        non_atomic.status.success(),
        "non-atomic multi-ref push should pass everyday workflow checks while keeping pre-push enforcement: stdout={}, stderr={}",
        String::from_utf8_lossy(&non_atomic.stdout),
        String::from_utf8_lossy(&non_atomic.stderr)
    );
    fs::remove_file(&marker).unwrap();

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
            r#"version = 4

[profiles.work]
name = "Synthetic"
email = "synthetic@example.invalid"
scopes = [{scope_toml}]

[profiles.work.git]
remote = "origin"
push = ["https://github.com/org/repo.git"]
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
                .write_all(b"protocol=https\nhost=github.com\npath=org/repo.git\n\n")?;
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
                b"capability[]=authtype\ncapability[]=state\nprotocol=https\nhost=github.com:443\npath=org/repo.git\nusername=untrusted-hint\nwwwauth[]=Basic realm=fixture\nwwwauth[]=Bearer realm=fixture\nstate[]=opaque=value\nunknown[]=ignored\n\n",
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
                b"capability[]=authtype\ncapability[]=state\nprotocol=https\nhost=github.com\npath=org/repo.git\nusername=untrusted-hint\nwwwauth[]=Basic realm=fixture\n\n",
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

    fs::remove_file(&marker).unwrap();
    let native_git = Command::new(&git)
        .current_dir(&scope)
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("GH_CONFIG_DIR", &gh_config)
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("PERSONA_CONFIG_PATH", &config_file)
        .env("PERSONA_GH", &gh)
        .args(["-c", "credential.helper="])
        .arg("-c")
        .arg(format!("credential.helper={}", shim.display()))
        .args([
            "-c",
            "credential.useHttpPath=true",
            "credential",
            "fill",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().unwrap().write_all(
                b"capability[]=authtype\ncapability[]=state\nprotocol=https\nhost=github.com\npath=org/repo.git\nwwwauth[]=Basic realm=fixture\n\n",
            )?;
            child.wait_with_output()
        })
        .unwrap();
    assert_eq!(
        native_git.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&native_git.stderr)
    );
    assert!(String::from_utf8_lossy(&native_git.stdout).contains("password=synthetic-token"));
    assert!(!String::from_utf8_lossy(&native_git.stdout).contains("wwwauth"));
    assert!(
        marker.exists(),
        "native Git should invoke Persona's synthetic helper"
    );

    let initialized = Command::new(&git)
        .current_dir(&scope)
        .arg("init")
        .output()
        .unwrap();
    assert!(initialized.status.success());

    let shim_directory = temporary.path().join("managed-shims");
    let gh_directory = temporary.path().join("caller-bin");
    fs::create_dir(&shim_directory).unwrap();
    fs::set_permissions(&shim_directory, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(&gh_directory).unwrap();
    let persona_binary = env!("CARGO_BIN_EXE_persona");
    for name in ["git", "gh", "ssh", "git-credential-persona"] {
        std::os::unix::fs::symlink(persona_binary, shim_directory.join(name)).unwrap();
    }
    let native_gh = gh_directory.join("gh");
    fs::write(&native_gh, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&native_gh, fs::Permissions::from_mode(0o700)).unwrap();

    let forwarding_marker = temporary.path().join("forwarded-gh-path");
    let real_git = git.to_string_lossy();
    let fake_git = temporary.path().join("git-observes-gh");
    fs::write(
        &fake_git,
        format!(
            r#"#!/bin/sh
if [ "${{PERSONA_GH:-}}" = "{}" ]; then : > "{}"; fi
exec "{}" "$@"
"#,
            native_gh.display(),
            forwarding_marker.display(),
            real_git
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_git, fs::Permissions::from_mode(0o700)).unwrap();

    let caller_path = std::env::join_paths([
        gh_directory.as_path(),
        shim_directory.as_path(),
        Path::new("/usr/bin"),
        Path::new("/bin"),
    ])
    .unwrap();
    let direct_shim = Command::new(shim_directory.join("git"))
        .arg("status")
        .current_dir(&scope)
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("GH_CONFIG_DIR", &gh_config)
        .env("PATH", caller_path)
        .env("PERSONA_CONFIG_PATH", &config_file)
        .env("PERSONA_SHIM_DIR", &shim_directory)
        .env("PERSONA_GIT", &fake_git)
        .output()
        .unwrap();
    assert_eq!(
        direct_shim.status.code(),
        Some(0),
        "stdout: {}; stderr: {}",
        String::from_utf8_lossy(&direct_shim.stdout),
        String::from_utf8_lossy(&direct_shim.stderr)
    );
    assert!(
        forwarding_marker.exists(),
        "direct Git shim should forward only the discovered absolute gh path"
    );
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
    assert_eq!(
        personal.git.configured_fetch_destinations("origin"),
        Some(["file:///tmp/synthetic-destination.git".to_owned()].as_slice())
    );
    assert_eq!(
        personal.git.configured_push_destinations("origin"),
        Some(["file:///tmp/synthetic-destination.git".to_owned()].as_slice())
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

    let child_added = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args([
            "profile",
            "add",
            "personal-oss",
            "--extends",
            "personal",
            "--author-email",
            "oss@example.invalid",
            "--committer-email",
            "oss@example.invalid",
        ])
        .output()
        .unwrap();
    assert_eq!(
        child_added.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&child_added.stderr)
    );
    let child_show = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args(["profile", "show", "personal-oss"])
        .output()
        .unwrap();
    assert_eq!(child_show.status.code(), Some(0));
    let child_show_stdout = String::from_utf8(child_show.stdout).unwrap();
    assert!(child_show_stdout.contains("extends: personal"));
    assert!(child_show_stdout.contains("author: Updated Personal Author <oss@example.invalid>"));
    assert!(child_show_stdout.contains("signing policy: configured"));
    assert!(child_show_stdout.contains("SSH transport hosts: github.com"));

    let scope_removed = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args(["scope", "remove", "second"])
        .output()
        .unwrap();
    assert_eq!(scope_removed.status.code(), Some(0));

    // Parent profile cannot be removed while a child profile still extends it.
    let blocked_parent_remove = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args(["profile", "remove", "personal"])
        .output()
        .unwrap();
    assert_eq!(blocked_parent_remove.status.code(), Some(2));

    let child_removed = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args(["profile", "remove", "personal-oss"])
        .output()
        .unwrap();
    assert_eq!(child_removed.status.code(), Some(0));

    let profile_removed = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .args(["profile", "remove", "personal"])
        .output()
        .unwrap();
    assert_eq!(profile_removed.status.code(), Some(0));
}

#[test]
fn config_edit_validates_creates_private_backup_and_rolls_back() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempdir().expect("create temporary directory");
    let home = temporary.path().join("home");
    let xdg = temporary.path().join("xdg-config");
    let state = temporary.path().join("xdg-state");
    let config_dir = xdg.join("persona");
    fs::create_dir_all(&config_dir).expect("create config directory");
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let config_file = config_dir.join("config.toml");
    write_policy(&config_file, temporary.path());
    fs::set_permissions(&config_file, fs::Permissions::from_mode(0o600)).unwrap();
    let original = fs::read(&config_file).unwrap();

    // 1. Invalid edited content is rejected and leaves the original config untouched.
    let invalid_editor = temporary.path().join("editor-invalid");
    fs::write(
        &invalid_editor,
        "#!/bin/sh\nprintf 'version = 3\\n' > \"$1\"\n",
    )
    .unwrap();
    fs::set_permissions(&invalid_editor, fs::Permissions::from_mode(0o700)).unwrap();
    let rejected = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("EDITOR", &invalid_editor)
        .args(["config", "edit"])
        .output()
        .expect("run invalid config edit");
    assert_eq!(rejected.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("refusing invalid edited configuration")
    );
    assert_eq!(fs::read(&config_file).unwrap(), original);

    // 2. Unchanged edit exits cleanly without creating an unnecessary rewrite.
    let noop_editor = temporary.path().join("editor-noop");
    fs::write(&noop_editor, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&noop_editor, fs::Permissions::from_mode(0o700)).unwrap();
    let noop = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("EDITOR", &noop_editor)
        .args(["config", "edit"])
        .output()
        .expect("run noop config edit");
    assert_eq!(noop.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&noop.stdout).contains("No changes made"));
    assert_eq!(fs::read(&config_file).unwrap(), original);

    // 3. Valid edit atomically saves v4 config, records a private backup, and rolls back cleanly.
    let valid_editor = temporary.path().join("editor-valid");
    let updated_contents = String::from_utf8(original.clone())
        .unwrap()
        .replace("Test Author", "Edited Author");
    let replacement_file = temporary.path().join("replacement.toml");
    fs::write(&replacement_file, &updated_contents).unwrap();
    fs::write(
        &valid_editor,
        format!(
            "#!/bin/sh\nexec > \"$1\"\nwhile IFS= read -r line || [ -n \"$line\" ]; do printf '%s\\n' \"$line\"; done < '{}'\n",
            replacement_file.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&valid_editor, fs::Permissions::from_mode(0o700)).unwrap();
    let edited = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("VISUAL", &valid_editor)
        .args(["config", "edit"])
        .output()
        .expect("apply valid config edit");
    assert_eq!(
        edited.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&edited.stderr)
    );
    let current = persona::config::Config::load(&config_file).unwrap();
    assert_eq!(current.version(), 4);
    assert_eq!(current.profiles()[0].git.author.name, "Edited Author");
    let output = String::from_utf8(edited.stdout).unwrap();
    let backup = output
        .lines()
        .find_map(|line| line.strip_prefix("Backup: "))
        .expect("backup path");

    let rolled_back = persona_command(temporary.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .args(["config", "rollback", "--backup", backup])
        .output()
        .expect("rollback config edit");
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

#[test]
fn everyday_git_workflow_and_command_denylist_allowlist() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempdir().unwrap();
    let home = temporary.path().join("home");
    let config_home = temporary.path().join("config");
    let state_home = temporary.path().join("state");
    let repo = temporary.path().join("repo");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&repo).unwrap();
    let git = PathBuf::from(std::env::var_os("PERSONA_TEST_GIT").expect("PERSONA_TEST_GIT"));

    assert!(
        Command::new(&git)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&repo)
            .args(["init", "-q", "-b", "main"])
            .status()
            .unwrap()
            .success()
    );

    let config_dir = config_home.join("persona");
    fs::create_dir_all(&config_dir).unwrap();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let config_path = config_dir.join("config.toml");
    let config = format!(
        r#"version = 4

[profiles.yanfsb]
name = "yanfsb"
email = "yanfsb@example.invalid"
scopes = [{{ name = "work", path = {scope:?} }}]
"#,
        scope = repo.canonicalize().unwrap().to_string_lossy()
    );
    fs::write(&config_path, config).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

    let run_in_repo = |args: &[&str]| {
        persona_command(&repo)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &config_home)
            .env("XDG_STATE_HOME", &state_home)
            .env("PATH", "/usr/bin:/bin")
            .args(args)
            .output()
            .unwrap()
    };

    fs::write(repo.join("notes.txt"), "hello\n").unwrap();
    assert!(
        run_in_repo(&["run", "--", "git", "add", "notes.txt"])
            .status
            .success()
    );
    assert!(
        run_in_repo(&["run", "--", "git", "commit", "-m", "init"])
            .status
            .success()
    );

    // Day-to-day commands (log -p, diff, show, branch -a, stash) work out of the box in Denylist mode.
    for cmd in [
        &["run", "--", "git", "log", "-n", "1", "-p"][..],
        &["run", "--", "git", "diff"][..],
        &["run", "--", "git", "show", "--stat", "HEAD"][..],
        &["run", "--", "git", "branch", "-a"][..],
        &["run", "--", "git", "stash", "list"][..],
    ] {
        let out = run_in_repo(cmd);
        assert!(
            out.status.success(),
            "{cmd:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // Configure denylist for git + run via `persona profile commands`.
    let set_cmd = run_in_repo(&[
        "profile",
        "commands",
        "yanfsb",
        "--git-mode",
        "denylist",
        "--git-deny",
        "stash",
        "--git-deny",
        "log --stat",
        "--run-deny",
        "env",
    ]);
    assert!(
        set_cmd.status.success(),
        "{}",
        String::from_utf8_lossy(&set_cmd.stderr)
    );

    let denied_stash = run_in_repo(&["run", "--", "git", "stash", "list"]);
    assert_eq!(denied_stash.status.code(), Some(126));
    let denied_flag = run_in_repo(&["run", "--", "git", "log", "--stat"]);
    assert_eq!(denied_flag.status.code(), Some(126));
    let allowed_log = run_in_repo(&["run", "--", "git", "log", "-n", "1"]);
    assert_eq!(allowed_log.status.code(), Some(0));

    let denied_run = run_in_repo(&["run", "--", "env"]);
    assert!(!denied_run.status.success());
    assert!(
        String::from_utf8_lossy(&denied_run.stderr).contains("blocked by profile deny rule"),
        "{}",
        String::from_utf8_lossy(&denied_run.stderr)
    );

    // Switch to allowlist mode and verify unknown commands are denied while allowlisted ones succeed.
    assert!(
        run_in_repo(&["profile", "commands", "yanfsb", "--clear-run",])
            .status
            .success()
    );
    assert!(
        run_in_repo(&[
            "profile",
            "commands",
            "yanfsb",
            "--git-mode",
            "allowlist",
            "--git-allow",
            "status",
            "--git-deny",
            "stash",
        ])
        .status
        .success()
    );
    assert_eq!(
        run_in_repo(&["run", "--", "git", "status"]).status.code(),
        Some(0)
    );
    assert_eq!(
        run_in_repo(&["run", "--", "git", "log"]).status.code(),
        Some(126)
    );

    let show = run_in_repo(&["profile", "show", "yanfsb"]);
    assert!(show.status.success());
    let stdout = String::from_utf8_lossy(&show.stdout);
    assert!(stdout.contains("git commands: mode=allowlist"));
}

#[test]
fn baseline_update_pins_current_remote_tracking_refs_without_manual_sed() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempdir().unwrap();
    let home = temporary.path().join("home");
    let config_home = temporary.path().join("config");
    let state_home = temporary.path().join("state");
    let repo = temporary.path().join("repo");
    let remote = temporary.path().join("remote.git");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&repo).unwrap();
    let git = PathBuf::from(std::env::var_os("PERSONA_TEST_GIT").expect("PERSONA_TEST_GIT"));

    assert!(
        Command::new(&git)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .args(["init", "--bare", remote.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(&git)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&repo)
            .args(["init", "-q", "-b", "main"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(&git)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&repo)
            .args([
                "-c",
                "user.name=yanfsb",
                "-c",
                "user.email=yanfsb@example.invalid",
                "commit",
                "--allow-empty",
                "-m",
                "upstream",
            ])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(&git)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&repo)
            .args(["remote", "add", "origin", remote.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(&git)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&repo)
            .args(["push", "origin", "HEAD:main"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(&git)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&repo)
            .args(["fetch", "origin"])
            .status()
            .unwrap()
            .success()
    );
    let expected_oid = String::from_utf8_lossy(
        &Command::new(&git)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&repo)
            .args(["rev-parse", "refs/remotes/origin/main"])
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_owned();

    let config_dir = config_home.join("persona");
    fs::create_dir_all(&config_dir).unwrap();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let config_path = config_dir.join("config.toml");
    fs::write(
        &config_path,
        format!(
            r#"version = 4

[profiles.yanfsb]
name = "yanfsb"
email = "yanfsb@example.invalid"
scopes = [{{ name = "work", path = {scope:?} }}]

[profiles.yanfsb.git]
remote = "origin"
push = [{dest:?}, "https://github.com/yanfsb/other.git"]
upstream_provenance = "pinned"
baselines = [
  {{ destination = {dest:?}, tracking_ref = "refs/remotes/origin/main", oid = "1111111111111111111111111111111111111111" }},
  {{ destination = "https://github.com/yanfsb/other.git", tracking_ref = "refs/remotes/origin/main", oid = "2222222222222222222222222222222222222222" }}
]
"#,
            dest = remote.to_string_lossy(),
            scope = repo.canonicalize().unwrap().to_string_lossy(),
        ),
    )
    .unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

    let preview = persona_command(&repo)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", &state_home)
        .env("PATH", "/usr/bin:/bin")
        .args(["baseline", "update", "--cwd", ".", "--preview"])
        .output()
        .unwrap();
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    assert!(String::from_utf8_lossy(&preview.stdout).contains(&expected_oid));

    let applied = persona_command(&repo)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", &state_home)
        .env("PATH", "/usr/bin:/bin")
        .args(["baseline", "update", "--cwd", "."])
        .output()
        .unwrap();
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );

    let reloaded = persona::config::Config::load(&config_path).unwrap();
    let baselines = &reloaded.profiles()[0]
        .git
        .push
        .as_ref()
        .unwrap()
        .upstream_baselines;
    assert_eq!(baselines[0].oid, expected_oid);
    assert_eq!(baselines[1].oid, "2222222222222222222222222222222222222222");
}

#[test]
fn clig_ergonomics_shims_exit_codes_json_partial_update_and_completions() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempdir().unwrap();
    let home = temporary.path().join("home");
    let config_home = temporary.path().join("config");
    let state_home = temporary.path().join("state");
    let repo = temporary.path().join("repo");
    let outside = temporary.path().join("outside");
    let bin_dir = temporary.path().join("bin");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&repo).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::create_dir_all(&bin_dir).unwrap();

    let git = std::env::var_os("PERSONA_TEST_GIT").expect("PERSONA_TEST_GIT");
    for args in [
        vec!["init", "-b", "main"],
        vec!["config", "user.name", "Test Author"],
        vec!["config", "user.email", "author@example.invalid"],
    ] {
        assert!(
            Command::new(&git)
                .env_clear()
                .env("HOME", &home)
                .env("PATH", "/usr/bin:/bin")
                .current_dir(&repo)
                .args(&args)
                .status()
                .unwrap()
                .success()
        );
    }
    fs::write(repo.join("README.md"), "hello\n").unwrap();
    assert!(
        Command::new(&git)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&repo)
            .args(["add", "README.md"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(&git)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&repo)
            .args(["commit", "-m", "initial"])
            .status()
            .unwrap()
            .success()
    );

    let custom_config = temporary.path().join("custom.toml");
    let repo_canon = repo.canonicalize().unwrap();
    fs::write(
        &custom_config,
        format!(
            r#"version = 4

[profiles.work]
name = "Test Author"
email = "author@example.invalid"
scopes = [{{ name = "repo", path = {scope:?} }}]

[profiles.work.git]
remote = "origin"
push = ["https://github.com/example/*"]
"#,
            scope = repo_canon.to_string_lossy()
        ),
    )
    .unwrap();
    fs::set_permissions(&custom_config, fs::Permissions::from_mode(0o600)).unwrap();

    // 1. Healthy managed Git worktree exits 0 on status/doctor; --strict exits 3.
    let healthy_status = persona_command(&repo)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", &state_home)
        .env("PERSONA_CONFIG_PATH", &custom_config)
        .env("NO_COLOR", "1")
        .arg("status")
        .output()
        .unwrap();
    assert_eq!(
        healthy_status.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&healthy_status.stdout),
        String::from_utf8_lossy(&healthy_status.stderr)
    );
    assert!(String::from_utf8_lossy(&healthy_status.stdout).contains("Pass"));

    let strict_status = persona_command(&repo)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", &state_home)
        .env("PERSONA_CONFIG_PATH", &custom_config)
        .args(["doctor", "--strict"])
        .output()
        .unwrap();
    assert_eq!(strict_status.status.code(), Some(3));

    // 2. Non-verbose `check --operation push` prints blockers directly.
    let mut blocked_check = persona_command(&repo)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", &state_home)
        .env("PERSONA_CONFIG_PATH", &custom_config)
        .args([
            "check",
            "--operation",
            "push",
            "--remote",
            "origin",
            "--destination",
            "https://github.com/wrong/repo.git",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(blocked_check.stdin.take());
    let blocked_out = blocked_check.wait_with_output().unwrap();
    assert_eq!(blocked_out.status.code(), Some(1));
    let blocked_stdout = String::from_utf8_lossy(&blocked_out.stdout);
    assert!(blocked_stdout.contains("authorization: BLOCK"));
    assert!(blocked_stdout.contains("blocked "));

    // 3. --config and --json work on profile/scope inspection.
    let prof_json = persona_command(&repo)
        .args(["profile", "list", "--config"])
        .arg(&custom_config)
        .arg("--json")
        .output()
        .unwrap();
    assert!(prof_json.status.success());
    let names: Vec<String> = serde_json::from_slice(&prof_json.stdout).unwrap();
    assert_eq!(names, vec!["work"]);

    let scope_json = persona_command(&repo)
        .args(["scope", "show", "repo", "--config"])
        .arg(&custom_config)
        .arg("--json")
        .output()
        .unwrap();
    assert!(scope_json.status.success());
    let scope_val: serde_json::Value = serde_json::from_slice(&scope_json.stdout).unwrap();
    assert_eq!(scope_val["profile"], "work");

    // 4. Partial `profile update` works without re-specifying author/committer.
    let private_cfg_dir = config_home.join("persona");
    fs::create_dir_all(&private_cfg_dir).unwrap();
    fs::set_permissions(&private_cfg_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let private_cfg = private_cfg_dir.join("config.toml");
    fs::copy(&custom_config, &private_cfg).unwrap();
    fs::set_permissions(&private_cfg, fs::Permissions::from_mode(0o600)).unwrap();

    let partial_update = persona_command(&repo)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", &state_home)
        .args([
            "profile",
            "update",
            "work",
            "--allow-force-with-lease",
            "true",
            "-n",
        ])
        .output()
        .unwrap();
    assert!(
        partial_update.status.success(),
        "{}",
        String::from_utf8_lossy(&partial_update.stderr)
    );
    assert!(
        String::from_utf8_lossy(&partial_update.stdout).contains("allow_force_with_lease = true")
    );

    // 5. Shims allow git --version / -v / --help / -h / -P and gh --version / --help even outside a scope.
    let persona_exe = PathBuf::from(env!("CARGO_BIN_EXE_persona"));
    fs::set_permissions(&bin_dir, fs::Permissions::from_mode(0o755)).unwrap();
    for shim_name in ["git", "gh", "ssh", "git-credential-persona"] {
        std::os::unix::fs::symlink(&persona_exe, bin_dir.join(shim_name)).unwrap();
    }
    let git_shim = bin_dir.join("git");
    for args in [
        vec!["--version"],
        vec!["-v"],
        vec!["--help"],
        vec!["-h"],
        vec!["version"],
    ] {
        let out = Command::new(&git_shim)
            .env_clear()
            .env("HOME", &home)
            .env("PERSONA_GIT", &git)
            .env("PERSONA_SHIM_DIR", &bin_dir)
            .current_dir(&outside)
            .args(&args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?} failed outside scope: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let git_p = Command::new(&git_shim)
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", &state_home)
        .env("PERSONA_CONFIG_PATH", &custom_config)
        .env("PERSONA_GIT", &git)
        .env("PERSONA_SHIM_DIR", &bin_dir)
        .current_dir(&repo)
        .args(["-P", "status", "-sb"])
        .output()
        .unwrap();
    assert!(
        git_p.status.success(),
        "{}",
        String::from_utf8_lossy(&git_p.stderr)
    );

    if let Some(native_gh) = std::env::var_os("PERSONA_TEST_NATIVE_GH") {
        let gh_shim = bin_dir.join("gh");
        let gh_ver = Command::new(&gh_shim)
            .env_clear()
            .env("HOME", &home)
            .env("PERSONA_GIT", &git)
            .env("PERSONA_GH", &native_gh)
            .env("PERSONA_SHIM_DIR", &bin_dir)
            .current_dir(&outside)
            .arg("--version")
            .output()
            .unwrap();
        assert!(
            gh_ver.status.success(),
            "{}",
            String::from_utf8_lossy(&gh_ver.stderr)
        );
    }

    // 6. Completions generate non-empty scripts.
    for shell in ["bash", "zsh", "fish"] {
        let comp = persona_command(&repo)
            .args(["completions", shell])
            .output()
            .unwrap();
        assert!(comp.status.success());
        assert!(!comp.stdout.is_empty());
    }

    // 7. --git-dir / --work-tree work for unmanaged repos (e.g., nvim plugins) & same-scope repos,
    //    while cross-scope --git-dir redirects remain blocked.
    let unmanaged_repo = temporary.path().join("unmanaged-plugin");
    fs::create_dir_all(&unmanaged_repo).unwrap();
    for args in [
        vec!["init", "-b", "main"],
        vec!["config", "user.name", "Plugin"],
        vec!["config", "user.email", "plugin@example.invalid"],
    ] {
        assert!(
            Command::new(&git)
                .env_clear()
                .env("HOME", &home)
                .env("PATH", "/usr/bin:/bin")
                .current_dir(&unmanaged_repo)
                .args(&args)
                .status()
                .unwrap()
                .success()
        );
    }
    fs::write(unmanaged_repo.join("init.lua"), "return {}\n").unwrap();
    assert!(
        Command::new(&git)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&unmanaged_repo)
            .args(["add", "init.lua"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(&git)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&unmanaged_repo)
            .args(["commit", "-m", "plugin"])
            .status()
            .unwrap()
            .success()
    );

    let plugin_sha = Command::new(&git_shim)
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", &state_home)
        .env("PERSONA_CONFIG_PATH", &custom_config)
        .env("PERSONA_GIT", &git)
        .env("PERSONA_SHIM_DIR", &bin_dir)
        .current_dir(&outside)
        .args([
            "--git-dir",
            unmanaged_repo.join(".git").to_str().unwrap(),
            "--work-tree",
            unmanaged_repo.to_str().unwrap(),
            "rev-parse",
            "HEAD",
        ])
        .output()
        .unwrap();
    assert!(
        plugin_sha.status.success(),
        "{}",
        String::from_utf8_lossy(&plugin_sha.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&plugin_sha.stdout).trim().len(), 40);

    let same_scope_sha = Command::new(&git_shim)
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", &state_home)
        .env("PERSONA_CONFIG_PATH", &custom_config)
        .env("PERSONA_GIT", &git)
        .env("PERSONA_SHIM_DIR", &bin_dir)
        .current_dir(&outside)
        .args([
            "--git-dir",
            repo.join(".git").to_str().unwrap(),
            "--work-tree",
            repo.to_str().unwrap(),
            "rev-parse",
            "HEAD",
        ])
        .output()
        .unwrap();
    assert!(
        same_scope_sha.status.success(),
        "{}",
        String::from_utf8_lossy(&same_scope_sha.stderr)
    );

    let cross_scope_redirect = Command::new(&git_shim)
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", &state_home)
        .env("PERSONA_CONFIG_PATH", &custom_config)
        .env("PERSONA_GIT", &git)
        .env("PERSONA_SHIM_DIR", &bin_dir)
        .current_dir(&repo)
        .args([
            "--git-dir",
            unmanaged_repo.join(".git").to_str().unwrap(),
            "--work-tree",
            repo.to_str().unwrap(),
            "status",
        ])
        .output()
        .unwrap();
    assert_eq!(cross_scope_redirect.status.code(), Some(126));

    // 8. `git pull` works without passing fetch-only `--no-prune-tags` to `git pull`.
    let pull_remote = temporary.path().join("pull-remote.git");
    let pull_local = temporary.path().join("pull-local");
    let pull_other = temporary.path().join("pull-other");
    assert!(
        Command::new(&git)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .args(["init", "--bare", "-b", "main"])
            .arg(&pull_remote)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(&git)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .args(["clone"])
            .arg(&pull_remote)
            .arg(&pull_other)
            .status()
            .unwrap()
            .success()
    );
    for args in [
        vec!["config", "user.name", "Test Author"],
        vec!["config", "user.email", "author@example.invalid"],
    ] {
        assert!(
            Command::new(&git)
                .env_clear()
                .env("HOME", &home)
                .env("PATH", "/usr/bin:/bin")
                .current_dir(&pull_other)
                .args(&args)
                .status()
                .unwrap()
                .success()
        );
    }
    fs::write(pull_other.join("seed.txt"), "one\n").unwrap();
    for args in [
        vec!["add", "seed.txt"],
        vec!["commit", "-m", "seed"],
        vec!["push", "origin", "main"],
    ] {
        assert!(
            Command::new(&git)
                .env_clear()
                .env("HOME", &home)
                .env("PATH", "/usr/bin:/bin")
                .current_dir(&pull_other)
                .args(&args)
                .status()
                .unwrap()
                .success()
        );
    }
    assert!(
        Command::new(&git)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .args(["clone"])
            .arg(&pull_remote)
            .arg(&pull_local)
            .status()
            .unwrap()
            .success()
    );
    fs::write(pull_other.join("seed.txt"), "two\n").unwrap();
    for args in [
        vec!["add", "seed.txt"],
        vec!["commit", "-m", "second"],
        vec!["push", "origin", "main"],
    ] {
        assert!(
            Command::new(&git)
                .env_clear()
                .env("HOME", &home)
                .env("PATH", "/usr/bin:/bin")
                .current_dir(&pull_other)
                .args(&args)
                .status()
                .unwrap()
                .success()
        );
    }
    // 8a. Native `git pull` accepts `managed_pull_safety_arguments` and completes cleanly.
    let direct_pull = Command::new(&git)
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .current_dir(&pull_local)
        .arg("pull")
        .args(persona::git_adapter::managed_pull_safety_arguments(&[]))
        .output()
        .unwrap();
    assert!(
        direct_pull.status.success(),
        "direct git pull with safety args failed: {}",
        String::from_utf8_lossy(&direct_pull.stderr)
    );
    assert_eq!(
        fs::read_to_string(pull_local.join("seed.txt")).unwrap(),
        "two\n"
    );

    // 8b. Managed `git pull` through shim does not pass fetch-only `--no-prune-tags`.
    assert!(
        Command::new(&git)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&pull_local)
            .args([
                "remote",
                "set-url",
                "origin",
                "https://127.0.0.1:1/org/repo.git",
            ])
            .status()
            .unwrap()
            .success()
    );
    let pull_config = temporary.path().join("pull-config.toml");
    let pull_local_canon = pull_local.canonicalize().unwrap();
    fs::write(
        &pull_config,
        format!(
            r#"version = 4

[profiles.work]
name = "Test Author"
email = "author@example.invalid"
scopes = [{{ name = "pull", path = {scope:?} }}]

[profiles.work.git.remotes.origin]
fetch = ["https://127.0.0.1:1/org/repo.git"]
push = []
"#,
            scope = pull_local_canon.to_string_lossy()
        ),
    )
    .unwrap();
    fs::set_permissions(&pull_config, fs::Permissions::from_mode(0o600)).unwrap();
    let pull_out = Command::new(&git_shim)
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", &state_home)
        .env("PERSONA_CONFIG_PATH", &pull_config)
        .env("PERSONA_GIT", &git)
        .env("PERSONA_SHIM_DIR", &bin_dir)
        .current_dir(&pull_local)
        .arg("pull")
        .output()
        .unwrap();
    let pull_stderr = String::from_utf8_lossy(&pull_out.stderr);
    assert!(
        !pull_stderr.contains("unknown option") && !pull_stderr.contains("no-prune-tags"),
        "managed git pull passed unsupported option: {pull_stderr}"
    );
}

#[cfg(unix)]
#[test]
fn external_https_credentials_are_opt_in_and_github_binding_remains_host_scoped() {
    use serde_json::Value;
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempdir().unwrap();
    let home = temporary.path().join("home");
    let xdg = temporary.path().join("xdg-config");
    let state = temporary.path().join("state");
    let repo = temporary.path().join("repo");
    let helper_marker = temporary.path().join("external-helper-called");
    let helper = temporary.path().join("external-credential-helper");
    let git = PathBuf::from(std::env::var_os("PERSONA_TEST_GIT").expect("PERSONA_TEST_GIT"));
    fs::create_dir_all(&repo).unwrap();

    let run_git = |args: &[&str]| {
        Command::new(&git)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
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
        run_git(&[
            "remote",
            "add",
            "origin",
            "git@forge.example.invalid:org/repo.git"
        ])
        .status
        .success()
    );
    assert!(
        run_git(&[
            "remote",
            "set-url",
            "--push",
            "origin",
            "git@forge.example.invalid:org/repo.git",
        ])
        .status
        .success()
    );
    assert!(
        run_git(&[
            "remote",
            "set-url",
            "--add",
            "--push",
            "origin",
            "https://github.com/org/repo.git",
        ])
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

    fs::write(
        &helper,
        format!(
            "#!/bin/sh\n[ \"$1\" = fixture-command ] && [ \"$2\" = get ] || exit 64\n: > '{}'\ncat >/dev/null\nprintf '%s\\n' 'username=synthetic-user' 'password=synthetic-password' ''\n",
            helper_marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();

    let config_dir = xdg.join("persona");
    fs::create_dir_all(&config_dir).unwrap();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let config = config_dir.join("config.toml");
    let scope_value =
        toml::Value::String(repo.canonicalize().unwrap().to_string_lossy().into_owned());
    let helper_value = toml::Value::String(helper.to_string_lossy().into_owned());
    let ssh_public_key = toml::Value::String(
        temporary
            .path()
            .join("synthetic.pub")
            .to_string_lossy()
            .into_owned(),
    );
    let ssh_identity = toml::Value::String(
        temporary
            .path()
            .join("synthetic.key")
            .to_string_lossy()
            .into_owned(),
    );
    let known_hosts = toml::Value::String(
        temporary
            .path()
            .join("known_hosts")
            .to_string_lossy()
            .into_owned(),
    );
    let contents = format!(
        r#"version = 4

[profiles.work]
name = "Synthetic"
email = "synthetic@example.invalid"
scopes = [{{ name = "fixture", path = {scope_value} }}]

[profiles.work.git]
remote = "origin"
deny = ["https://forge.example.invalid/org/denied.git"]
allow_initial_push = true

[profiles.work.git.remotes.origin]
fetch = [
  "https://forge.example.invalid/org/repo.git",
  "https://forge.example.invalid/org/denied.git",
]
push = [
  "git@forge.example.invalid:org/repo.git",
  "https://forge.example.invalid/org/repo.git",
  "https://github.com/org/repo.git",
]

[profiles.work.github]
host = "github.com"
account_id = "4242"
account_selector = "synthetic-user"
token_fingerprint = "hmac-sha256:{fingerprint}"

[profiles.work.ssh]
hosts = ["github.com", "forge.example.invalid"]
user = "git"
port = 22
fingerprint = "SHA256:syntheticfingerprint"
public_key = {ssh_public_key}
identity_file = {ssh_identity}
known_hosts_file = {known_hosts}

[profiles.work.https."forge.example.invalid"]
helper = {helper_value}
args = ["fixture-command"]
"#,
        fingerprint = "0".repeat(64),
    );
    fs::write(&config, contents).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let environment = || {
        vec![
            ("HOME", home.as_path()),
            ("XDG_CONFIG_HOME", xdg.as_path()),
            ("XDG_STATE_HOME", state.as_path()),
            ("PERSONA_GIT", git.as_path()),
            ("PATH", Path::new("/usr/bin:/bin")),
        ]
    };

    let push_check = |destination: &str| {
        let tuple = format!(
            "refs/heads/main {oid} refs/heads/main {}\n",
            "0".repeat(oid.len())
        );
        persona_command(&repo)
            .envs(environment())
            .args([
                "check",
                "--cwd",
                repo.to_str().unwrap(),
                "--operation",
                "push",
                "--remote",
                "origin",
                "--destination",
                destination,
                "--format",
                "json",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                child.stdin.take().unwrap().write_all(tuple.as_bytes())?;
                child.wait_with_output()
            })
            .unwrap()
    };

    let forge_check = push_check("git@forge.example.invalid:org/repo.git");
    let forge_decision: Value = serde_json::from_slice(&forge_check.stdout).unwrap();
    assert!(
        !forge_decision["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|property| property == "github.credential.binding"),
        "non-GitHub destination must not require GitHub account evidence: {forge_decision}"
    );
    assert!(
        !forge_decision["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["property"] == "github.credential.binding"),
        "non-GitHub destination must not emit GitHub account findings: {forge_decision}"
    );

    let github_check = push_check("https://github.com/org/repo.git");
    let github_decision: Value = serde_json::from_slice(&github_check.stdout).unwrap();
    assert!(
        github_decision["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|property| property == "github.credential.binding"),
        "GitHub destinations must keep the enrolled-account requirement: {github_decision}"
    );
    assert!(
        github_decision["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker["property"] == "github.credential.binding"),
        "offline GitHub push check must fail closed without credential evidence: {github_decision}"
    );

    let credential_request = |path: &str| {
        let mut child = persona_command(&repo)
            .envs(environment())
            .env("PERSONA_GIT_CREDENTIAL_DIRECTION", "fetch")
            .env("PERSONA_GIT_CREDENTIAL_REMOTE", "origin")
            .args(["credential-helper", "get"])
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
                format!("protocol=https\nhost=forge.example.invalid\npath={path}\n\n").as_bytes(),
            )
            .unwrap();
        child.wait_with_output().unwrap()
    };

    let allowed = credential_request("org/repo.git");
    assert!(
        allowed.status.success(),
        "allowed external helper failed: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert_eq!(
        allowed.stdout,
        b"username=synthetic-user\npassword=synthetic-password\n\n"
    );
    assert!(helper_marker.exists());

    fs::remove_file(&helper_marker).unwrap();
    let not_allowed = credential_request("org/not-allowed.git");
    assert_eq!(not_allowed.status.code(), Some(2));
    assert!(not_allowed.stdout.is_empty());
    assert!(
        !helper_marker.exists(),
        "destination outside fetch allowlist must be rejected before helper invocation"
    );

    let denied = credential_request("org/denied.git");
    assert_eq!(denied.status.code(), Some(2));
    assert!(denied.stdout.is_empty());
    assert!(
        !helper_marker.exists(),
        "deny_destinations must be checked before helper invocation"
    );

    let show_json = persona_command(&repo)
        .envs(environment())
        .args(["profile", "show", "work", "--json"])
        .output()
        .unwrap();
    assert!(show_json.status.success());
    let profile: Value = serde_json::from_slice(&show_json.stdout).unwrap();
    assert_eq!(
        profile["ssh_hosts"],
        serde_json::json!(["github.com", "forge.example.invalid"])
    );
    assert_eq!(
        profile["https_credential_hosts"],
        serde_json::json!(["forge.example.invalid"])
    );

    let show_text = persona_command(&repo)
        .envs(environment())
        .args(["profile", "show", "work"])
        .output()
        .unwrap();
    assert!(show_text.status.success());
    let text = String::from_utf8_lossy(&show_text.stdout);
    assert!(
        text.contains("github.com, forge.example.invalid"),
        "profile output: {text}"
    );
    assert!(
        text.contains("HTTPS credential helpers: forge.example.invalid"),
        "profile output: {text}"
    );
}
