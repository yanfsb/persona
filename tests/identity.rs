use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::tempdir;

fn git_binary() -> PathBuf {
    std::env::var_os("PERSONA_TEST_GIT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/bin/git"))
}

fn git(home: &Path, directory: Option<&Path>) -> Command {
    let mut command = Command::new(git_binary());
    command.env_clear();
    command.env("HOME", home);
    command.env("PATH", "/usr/bin:/bin");
    command.env("LC_ALL", "C");
    command.env("GIT_CONFIG_NOSYSTEM", "1");
    command.env("GIT_CONFIG_GLOBAL", "/dev/null");
    if let Some(directory) = directory {
        command.current_dir(directory);
    }
    command
}

fn run_git(home: &Path, directory: Option<&Path>, args: &[&str]) {
    let output = git(home, directory)
        .args(args)
        .output()
        .expect("run fixture Git");
    assert!(
        output.status.success(),
        "Git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn init_repo(home: &Path, root: &Path) {
    run_git(
        home,
        None,
        &[
            "init",
            "--template=",
            "--initial-branch=main",
            root.to_str().unwrap(),
        ],
    );
}

fn set_identity(home: &Path, root: &Path, name: &str, email: &str) {
    run_git(home, Some(root), &["config", "user.name", name]);
    run_git(home, Some(root), &["config", "user.email", email]);
}

fn set_worktree_identity(home: &Path, root: &Path, name: &str, email: &str) {
    run_git(
        home,
        Some(root),
        &["config", "--worktree", "user.name", name],
    );
    run_git(
        home,
        Some(root),
        &["config", "--worktree", "user.email", email],
    );
}

fn write_policy(path: &Path, scopes: &[(&str, &Path, &str, &str)]) {
    let mut contents = String::from("version = 1\n\n");
    for (name, root, author_name, author_email) in scopes {
        let root = toml::Value::String(root.to_string_lossy().into_owned());
        contents.push_str(&format!(
            "[[scopes]]\nname = {name:?}\npath = {root}\n\n[scopes.git]\nauthor = {{ name = {author_name:?}, email = {author_email:?} }}\ncommitter = {{ name = {author_name:?}, email = {author_email:?} }}\n\n"
        ));
    }
    fs::write(path, contents).expect("write policy");
}

fn run_persona(
    cwd: &Path,
    config: &Path,
    command_name: &str,
    extra_environment: &[(&str, &str)],
) -> Output {
    run_persona_at(cwd, Path::new("."), config, command_name, extra_environment)
}

fn run_persona_at(
    process_cwd: &Path,
    query: &Path,
    config: &Path,
    command_name: &str,
    extra_environment: &[(&str, &str)],
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_persona"));
    command
        .env_clear()
        .current_dir(process_cwd)
        .env("PERSONA_GIT", git_binary())
        .env("PATH", "/usr/bin:/bin")
        .args([command_name, "--config"])
        .arg(config)
        .args(["--cwd"])
        .arg(query)
        .args(["--format", "json"]);
    for (name, value) in extra_environment {
        command.env(name, value);
    }
    command.output().expect("run persona")
}

fn report(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("JSON report should parse")
}

fn finding<'a>(report: &'a Value, property: &str) -> &'a Value {
    report["findings"]
        .as_array()
        .expect("findings should be an array")
        .iter()
        .find(|finding| finding["property"] == property)
        .expect("finding should exist")
}

#[test]
fn checks_root_and_subdirectory_using_the_physical_checkout_root() {
    let temporary = tempdir().expect("create temporary directory");
    let repo = temporary.path().join("scope/project");
    let nested = repo.join("src");
    let config = temporary.path().join("policy.toml");
    fs::create_dir_all(&nested).expect("create nested directory");
    init_repo(temporary.path(), &repo);
    set_identity(
        temporary.path(),
        &repo,
        "Expected",
        "expected@example.invalid",
    );
    write_policy(
        &config,
        &[(
            "scope",
            &temporary.path().join("scope"),
            "Expected",
            "expected@example.invalid",
        )],
    );

    for directory in [&repo, &nested] {
        let output = run_persona(directory, &config, "check", &[]);
        let report = report(&output);
        assert_eq!(finding(&report, "scope")["status"], "PASS");
        assert_eq!(finding(&report, "git.worktree")["status"], "PASS");
        assert_eq!(finding(&report, "git.author")["status"], "PASS");
        assert_eq!(finding(&report, "git.committer")["status"], "PASS");
    }
}

#[test]
fn checkout_root_wins_over_a_more_specific_scope_containing_the_query() {
    let temporary = tempdir().expect("create temporary directory");
    let repo = temporary.path().join("repo");
    let query = repo.join("nested");
    let config = temporary.path().join("policy.toml");
    fs::create_dir_all(&query).expect("create query directory");
    init_repo(temporary.path(), &repo);
    set_identity(temporary.path(), &repo, "Broad", "broad@example.invalid");
    write_policy(
        &config,
        &[
            ("broad", temporary.path(), "Broad", "broad@example.invalid"),
            ("nested", &query, "Nested", "nested@example.invalid"),
        ],
    );

    let output = run_persona(&query, &config, "status", &[]);
    let report = report(&output);
    assert!(
        finding(&report, "scope")["observed"]
            .as_str()
            .is_some_and(|value| value.starts_with("broad ("))
    );
    assert_eq!(finding(&report, "git.author")["status"], "PASS");
}

#[test]
fn linked_worktree_physical_path_selects_its_scope() {
    let temporary = tempdir().expect("create temporary directory");
    let main = temporary.path().join("personal/main");
    let linked = temporary.path().join("persona/review");
    let config = temporary.path().join("policy.toml");
    fs::create_dir_all(main.parent().unwrap()).expect("create main parent");
    fs::create_dir_all(linked.parent().unwrap()).expect("create linked parent");
    init_repo(temporary.path(), &main);
    set_identity(
        temporary.path(),
        &main,
        "Personal",
        "personal@example.invalid",
    );
    run_git(
        temporary.path(),
        Some(&main),
        &["config", "extensions.worktreeConfig", "true"],
    );
    run_git(
        temporary.path(),
        Some(&main),
        &["commit", "--allow-empty", "-m", "seed"],
    );
    run_git(
        temporary.path(),
        Some(&main),
        &["worktree", "add", "-b", "review", linked.to_str().unwrap()],
    );
    set_worktree_identity(
        temporary.path(),
        &linked,
        "Persona",
        "persona@example.invalid",
    );
    write_policy(
        &config,
        &[
            (
                "personal",
                main.parent().unwrap(),
                "Personal",
                "personal@example.invalid",
            ),
            (
                "persona",
                linked.parent().unwrap(),
                "Persona",
                "persona@example.invalid",
            ),
        ],
    );

    let output = run_persona(&linked, &config, "check", &[]);
    let report = report(&output);
    assert!(
        finding(&report, "scope")["observed"]
            .as_str()
            .is_some_and(|value| value.starts_with("persona ("))
    );
    assert_eq!(finding(&report, "git.author")["status"], "PASS");
}

#[test]
fn local_config_and_independent_environment_overrides_fail_separately() {
    let temporary = tempdir().expect("create temporary directory");
    let repo = temporary.path().join("repo");
    let config = temporary.path().join("policy.toml");
    fs::create_dir(&repo).expect("create repo");
    init_repo(temporary.path(), &repo);
    set_identity(
        temporary.path(),
        &repo,
        "Expected",
        "expected@example.invalid",
    );
    write_policy(
        &config,
        &[(
            "scope",
            temporary.path(),
            "Expected",
            "expected@example.invalid",
        )],
    );

    let output = run_persona(&repo, &config, "check", &[("GIT_AUTHOR_NAME", "Override")]);
    let first_report = report(&output);
    assert_eq!(finding(&first_report, "git.author")["status"], "FAIL");
    assert_eq!(finding(&first_report, "git.committer")["status"], "PASS");

    let output = run_persona(
        &repo,
        &config,
        "check",
        &[
            ("GIT_COMMITTER_NAME", "Other Committer"),
            ("GIT_COMMITTER_EMAIL", "other@example.invalid"),
        ],
    );
    let report = report(&output);
    assert_eq!(finding(&report, "git.author")["status"], "PASS");
    assert_eq!(finding(&report, "git.committer")["status"], "FAIL");
}

#[test]
fn no_git_and_unmanaged_directories_remain_unknown() {
    let temporary = tempdir().expect("create temporary directory");
    let managed = temporary.path().join("managed");
    let outside = temporary.path().join("outside");
    let config = temporary.path().join("policy.toml");
    fs::create_dir(&managed).expect("create managed directory");
    fs::create_dir(&outside).expect("create outside directory");
    write_policy(
        &config,
        &[("managed", &managed, "Expected", "expected@example.invalid")],
    );

    let managed_report = report(&run_persona(&managed, &config, "status", &[]));
    assert_eq!(finding(&managed_report, "scope")["status"], "PASS");
    assert_eq!(
        finding(&managed_report, "git.worktree")["status"],
        "UNKNOWN"
    );
    assert_eq!(
        finding(&managed_report, "git.author")["expected"],
        "Expected <expected@example.invalid>"
    );
    assert!(finding(&managed_report, "git.author")["observed"].is_null());

    let outside_report = report(&run_persona(&outside, &config, "status", &[]));
    assert_eq!(finding(&outside_report, "scope")["status"], "UNKNOWN");
    assert!(finding(&outside_report, "git.author")["expected"].is_null());
    assert_eq!(finding(&outside_report, "git.author")["status"], "UNKNOWN");
}

#[test]
fn missing_directory_is_an_error_without_mutating_state() {
    let temporary = tempdir().expect("create temporary directory");
    let config = temporary.path().join("policy.toml");
    let missing = temporary.path().join("missing");
    write_policy(
        &config,
        &[(
            "scope",
            temporary.path(),
            "Expected",
            "expected@example.invalid",
        )],
    );

    let output = run_persona_at(temporary.path(), &missing, &config, "check", &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!missing.exists());
}
