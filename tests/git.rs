use persona::git::{GitClient, GitError};
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
