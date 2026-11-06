use persona::git::{GitClient, GitError, PushTuple};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;

fn git_binary() -> PathBuf {
    let executable = std::env::var_os("PERSONA_TEST_GIT")
        .expect("set PERSONA_TEST_GIT to an absolute Git executable");

    let executable = PathBuf::from(executable);

    assert!(
        executable.is_absolute(),
        "PERSONA_TEST_GIT must be absolute"
    );

    executable
}

fn isolated_environment(home: &Path) -> Vec<(OsString, OsString)> {
    vec![
        ("HOME".into(), home.as_os_str().to_owned()),
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("LC_ALL".into(), "C".into()),
        ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
        ("GIT_CONFIG_GLOBAL".into(), "/dev/null".into()),
        ("GIT_TERMINAL_PROMPT".into(), "0".into()),
        (
            "GIT_CEILING_DIRECTORIES".into(),
            home.as_os_str().to_owned(),
        ),
    ]
}

fn client(home: &Path) -> GitClient {
    GitClient::new(git_binary(), isolated_environment(home))
}

fn fixture_git(home: &Path) -> Command {
    let mut command = Command::new(git_binary());

    command.env_clear();

    for (name, value) in isolated_environment(home) {
        command.env(name, value);
    }

    command.args([
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "commit.gpgSign=false",
        "-c",
        "maintenance.auto=false",
        "-c",
        "gc.auto=0",
    ]);

    command
}

fn run_fixture(command: &mut Command) {
    let output = command.output().expect("run fixture Git");

    assert!(
        output.status.success(),
        "fixture Git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn init_repo(home: &Path, directory: &Path) {
    run_fixture(
        fixture_git(home)
            .args(["init", "--template=", "-b", "main"])
            .arg(directory),
    );
}

#[test]
fn resolves_only_existing_commit_objects_without_option_injection() {
    let temporary = tempdir().expect("create temporary directory");
    let repo = temporary.path().join("repo");
    init_repo(temporary.path(), &repo);
    run_fixture(fixture_git(temporary.path()).arg("-C").arg(&repo).args([
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--allow-empty",
        "-m",
        "seed",
    ]));
    let client = client(temporary.path());
    let oid = client.resolve_commit_oid(&repo, "HEAD").unwrap();
    assert!(matches!(oid.len(), 40 | 64));
    assert!(matches!(
        client.resolve_commit_oid(&repo, "--help"),
        Err(GitError::InvalidOutput)
    ));
    assert!(matches!(
        client.resolve_commit_oid(&repo, "deadbeef"),
        Err(GitError::MissingObject)
    ));
}

#[test]
fn detects_custom_merge_drivers_without_returning_configured_values() {
    let temporary = tempdir().expect("create temporary directory");
    let repo = temporary.path().join("repo");
    init_repo(temporary.path(), &repo);
    assert!(
        !client(temporary.path())
            .has_custom_merge_driver(&repo)
            .unwrap()
    );
    run_fixture(fixture_git(temporary.path()).arg("-C").arg(&repo).args([
        "config",
        "merge.synthetic.driver",
        "echo fixture",
    ]));
    assert!(
        client(temporary.path())
            .has_custom_merge_driver(&repo)
            .unwrap()
    );
}

#[test]
fn detects_implicit_push_options_and_remote_mirror_mode_by_key_name_only() {
    let temporary = tempdir().expect("create temporary directory");
    let repo = temporary.path().join("repo");
    init_repo(temporary.path(), &repo);
    let git = client(temporary.path());
    assert!(!git.has_push_options(&repo).unwrap());
    assert!(!git.has_remote_mirror_push(&repo, "origin").unwrap());

    run_fixture(fixture_git(temporary.path()).arg("-C").arg(&repo).args([
        "config",
        "push.pushOption",
        "synthetic-hidden-side-effect",
    ]));
    assert!(git.has_push_options(&repo).unwrap());
    run_fixture(fixture_git(temporary.path()).arg("-C").arg(&repo).args([
        "config",
        "remote.origin.mirror",
        "true",
    ]));
    assert!(git.has_remote_mirror_push(&repo, "origin").unwrap());
}

#[test]
fn discovers_the_checkout_root_from_a_subdirectory() {
    let temporary = tempdir().expect("create temporary directory");
    let repo = temporary.path().join("project");
    let nested = repo.join("src/components");

    init_repo(temporary.path(), &repo);
    fs::create_dir_all(&nested).expect("create nested directory");

    let root = client(temporary.path())
        .checkout_root(&nested)
        .expect("discover checkout root");

    assert_eq!(
        root,
        fs::canonicalize(&repo).expect("canonicalize expected root")
    );
}

#[test]
fn discovers_the_linked_worktree_instead_of_the_main_checkout() {
    let temporary = tempdir().expect("create temporary directory");

    let main = temporary.path().join("main");
    let linked = temporary.path().join("other/review");

    init_repo(temporary.path(), &main);

    run_fixture(fixture_git(temporary.path()).arg("-C").arg(&main).args([
        "-c",
        "user.name=Fixture Author",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--allow-empty",
        "-m",
        "seed fixture",
    ]));

    fs::create_dir_all(temporary.path().join("other")).expect("create worktree parent");

    run_fixture(
        fixture_git(temporary.path())
            .arg("-C")
            .arg(&main)
            .args(["worktree", "add", "-b", "review"])
            .arg(&linked),
    );

    let root = client(temporary.path())
        .checkout_root(&linked)
        .expect("discover linked worktree root");

    assert_eq!(
        root,
        fs::canonicalize(&linked).expect("canonicalize linked worktree")
    );
}

#[test]
fn resolves_only_explicit_remote_fetch_destinations_after_rewrite() {
    let temporary = tempdir().expect("create temporary directory");
    let repo = temporary.path().join("fetch-repo");
    init_repo(temporary.path(), &repo);
    run_fixture(fixture_git(temporary.path()).current_dir(&repo).args([
        "remote",
        "add",
        "origin",
        "git@rewrite.invalid:org/repo.git",
    ]));
    run_fixture(fixture_git(temporary.path()).current_dir(&repo).args([
        "config",
        "url.https://github.com/.insteadOf",
        "git@rewrite.invalid:",
    ]));
    let destinations = client(temporary.path())
        .effective_fetch_destinations(&repo, "origin")
        .unwrap();
    assert_eq!(destinations, ["https://github.com/org/repo.git"]);
}

#[test]
fn reports_remote_transport_schemes_without_returning_urls() {
    let temporary = tempdir().expect("create temporary directory");
    let repo = temporary.path().join("project");
    init_repo(temporary.path(), &repo);
    run_fixture(fixture_git(temporary.path()).arg("-C").arg(&repo).args([
        "remote",
        "add",
        "ssh-origin",
        "git@example.invalid:repo.git",
    ]));
    run_fixture(fixture_git(temporary.path()).arg("-C").arg(&repo).args([
        "remote",
        "add",
        "https-origin",
        "https://user@example.invalid:443/repo.git",
    ]));

    let schemes = client(temporary.path())
        .remote_transport_schemes(&repo, None)
        .expect("inspect remote schemes");

    assert_eq!(schemes, vec!["https", "ssh"]);
}

#[test]
fn malformed_uri_scheme_is_redacted_as_unknown() {
    let temporary = tempdir().expect("create temporary directory");
    let repo = temporary.path().join("project");
    init_repo(temporary.path(), &repo);
    let secret_fragment = "credential:secret";
    run_fixture(fixture_git(temporary.path()).arg("-C").arg(&repo).args([
        "remote",
        "add",
        "malformed",
        &format!("{secret_fragment}://host/repo.git"),
    ]));

    let schemes = client(temporary.path())
        .remote_transport_schemes(&repo, None)
        .expect("inspect remote schemes");

    assert_eq!(schemes, vec!["unknown"]);
    assert!(
        !schemes
            .iter()
            .any(|scheme| scheme.contains(secret_fragment))
    );
}

#[test]
fn rejects_directories_without_a_working_tree() {
    let temporary = tempdir().expect("create temporary directory");

    let outside = temporary.path().join("outside");
    let bare = temporary.path().join("bare.git");

    fs::create_dir(&outside).expect("create outside directory");

    run_fixture(
        fixture_git(temporary.path())
            .args(["init", "--bare", "--template="])
            .arg(&bare),
    );

    let git = client(temporary.path());

    for directory in [&outside, &bare] {
        assert!(matches!(
            git.checkout_root(directory),
            Err(GitError::CommandFailed(_))
        ));
    }
}

#[test]
fn identifies_unsafe_https_settings_without_exposing_config_values() {
    let temporary = tempdir().expect("create temporary directory");
    let repo = temporary.path().join("repo");
    init_repo(temporary.path(), &repo);
    let git = client(temporary.path());
    assert!(!git.has_unsafe_https_transport_config(&repo).unwrap());

    run_fixture(fixture_git(temporary.path()).current_dir(&repo).args([
        "config",
        "http.extraHeader",
        "Authorization: synthetic-secret",
    ]));
    run_fixture(fixture_git(temporary.path()).current_dir(&repo).args([
        "config",
        "credential.helper",
        "store --file=/tmp/synthetic",
    ]));
    assert!(git.has_unsafe_https_transport_config(&repo).unwrap());

    let worktree_repo = temporary.path().join("worktree-config-repo");
    init_repo(temporary.path(), &worktree_repo);
    run_fixture(
        fixture_git(temporary.path())
            .current_dir(&worktree_repo)
            .args(["config", "extensions.worktreeConfig", "true"]),
    );
    run_fixture(
        fixture_git(temporary.path())
            .current_dir(&worktree_repo)
            .args([
                "config",
                "--worktree",
                "http.extraHeader",
                "Authorization: synthetic-worktree-secret",
            ]),
    );
    assert!(
        git.has_unsafe_https_transport_config(&worktree_repo)
            .unwrap()
    );
}

#[test]
fn refuses_environment_that_redirects_the_repository() {
    let temporary = tempdir().expect("create temporary directory");
    let repo = temporary.path().join("project");

    init_repo(temporary.path(), &repo);

    for variable in ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"] {
        let mut environment = isolated_environment(temporary.path());
        environment.push((variable.into(), "ignored".into()));

        let git = GitClient::new(git_binary(), environment);

        assert!(matches!(
            git.checkout_root(&repo),
            Err(GitError::RedirectedEnvironment(name))
                if name == variable
        ));
    }
}

#[test]
fn requires_an_absolute_git_executable() {
    let temporary = tempdir().expect("create temporary directory");

    let git = GitClient::new(PathBuf::from("git"), isolated_environment(temporary.path()));

    assert!(matches!(
        git.checkout_root(temporary.path()),
        Err(GitError::RelativeExecutable(_))
    ));
}

#[test]
fn enumerates_bounded_outgoing_commit_oids_for_online_verification() {
    let temporary = tempdir().expect("create temporary directory");
    let repo = temporary.path().join("repo");
    init_repo(temporary.path(), &repo);
    run_fixture(fixture_git(temporary.path()).arg("-C").arg(&repo).args([
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--allow-empty",
        "-m",
        "seed",
    ]));
    let git = client(temporary.path());
    let oid = git.resolve_commit_oid(&repo, "HEAD").unwrap();
    let tuple = PushTuple {
        local_ref: "refs/heads/main".to_owned(),
        local_oid: oid.clone(),
        remote_ref: "refs/heads/main".to_owned(),
        remote_oid: "0".repeat(oid.len()),
    };
    let commits = git
        .outgoing_commit_oids_many(
            &repo,
            &[tuple],
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .unwrap();
    assert_eq!(commits, [oid]);
}
