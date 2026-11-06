#![cfg(unix)]

use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::tempdir;

fn git() -> PathBuf {
    PathBuf::from(std::env::var_os("PERSONA_TEST_GIT").expect("PERSONA_TEST_GIT"))
}

fn fixture_path() -> String {
    match std::env::var("PERSONA_TEST_COREUTILS") {
        Ok(coreutils) => format!("{coreutils}:/usr/bin:/bin"),
        Err(_) => "/usr/bin:/bin".to_owned(),
    }
}

fn run_git(git: &Path, cwd: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(git)
        .env_clear()
        .env("HOME", home)
        .env("PATH", fixture_path())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("PERSONA_HOOK_ENV_SENTINEL", "present")
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("run Git")
}

fn must_succeed(output: Output) -> Output {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn commit(git: &Path, repo: &Path, home: &Path, author: &str, message: &str) {
    must_succeed(run_git(
        git,
        repo,
        home,
        &[
            "-c",
            "user.name=Persona Committer",
            "-c",
            "user.email=committer@example.invalid",
            "commit",
            "--allow-empty",
            &format!("--author={author}"),
            "-m",
            message,
        ],
    ));
}

#[test]
fn installed_pre_push_composes_restores_and_honors_documented_bypasses() {
    let temporary = tempdir().unwrap();
    let repo = temporary.path().join("repo");
    let remote = temporary.path().join("remote.git");
    fs::create_dir(&repo).unwrap();
    let git = git();
    must_succeed(run_git(
        &git,
        temporary.path(),
        temporary.path(),
        &[
            "init",
            "--quiet",
            "--template=",
            "-b",
            "main",
            repo.to_str().unwrap(),
        ],
    ));
    must_succeed(run_git(
        &git,
        temporary.path(),
        temporary.path(),
        &["init", "--quiet", "--bare", remote.to_str().unwrap()],
    ));
    must_succeed(run_git(
        &git,
        &repo,
        temporary.path(),
        &["remote", "add", "origin", remote.to_str().unwrap()],
    ));
    commit(
        &git,
        &repo,
        temporary.path(),
        "Persona Committer <committer@example.invalid>",
        "good",
    );

    let hooks = repo.join(".git/hooks");
    fs::create_dir_all(&hooks).unwrap();
    let original = hooks.join("pre-push");
    let hook_marker = temporary.path().join("original-hook-input");
    let hook_arguments = temporary.path().join("original-hook-arguments");
    let fail_original_hook = temporary.path().join("fail-original-hook");
    fs::write(
        &original,
        format!(
            "#!/bin/sh\nprintf '%s\\n%s\\n%s\\n' \"$1\" \"$2\" \"$PERSONA_HOOK_ENV_SENTINEL\" > '{}'\ncat > '{}'\n[ ! -e '{}' ] || exit 42\n",
            hook_arguments.display(),
            hook_marker.display(),
            fail_original_hook.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
    let original_contents = fs::read(&original).unwrap();
    let config = temporary.path().join("persona.toml");
    fs::write(
        &config,
        format!(
            "version=1\n[[scopes]]\nname=\"scope\"\npath={:?}\n[scopes.git]\nauthor={{name=\"Persona Committer\",email=\"committer@example.invalid\"}}\ncommitter={{name=\"Persona Committer\",email=\"committer@example.invalid\"}}\n[scopes.git.push]\nremote=\"origin\"\ndestinations=[{:?}]\n",
            repo.to_string_lossy(),
            remote.to_string_lossy(),
        ),
    )
    .unwrap();

    let persona = env!("CARGO_BIN_EXE_persona");
    must_succeed(run_git(
        &git,
        &repo,
        temporary.path(),
        &[
            "config",
            "core.hooksPath",
            temporary.path().join("alternate-hooks").to_str().unwrap(),
        ],
    ));
    let custom_hook_install = Command::new(persona)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .current_dir(&repo)
        .args(["hooks", "install", "--config"])
        .arg(&config)
        .args(["--cwd", repo.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!custom_hook_install.status.success());
    assert!(
        !fs::symlink_metadata(&original)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    must_succeed(run_git(
        &git,
        &repo,
        temporary.path(),
        &["config", "--unset", "core.hooksPath"],
    ));
    let preview = Command::new(persona)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .current_dir(&repo)
        .args(["hooks", "install", "--config"])
        .arg(&config)
        .args(["--cwd", repo.to_str().unwrap(), "--preview"])
        .output()
        .unwrap();
    must_succeed(preview);
    assert!(
        !fs::symlink_metadata(&original)
            .unwrap()
            .file_type()
            .is_symlink()
    );

    let install = Command::new(persona)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .current_dir(&repo)
        .args(["hooks", "install", "--config"])
        .arg(&config)
        .args(["--cwd", repo.to_str().unwrap()])
        .output()
        .unwrap();
    must_succeed(install);
    assert!(
        fs::symlink_metadata(&original)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let updated_persona = temporary.path().join("persona-updated");
    fs::copy(persona, &updated_persona).unwrap();
    fs::set_permissions(&updated_persona, fs::Permissions::from_mode(0o700)).unwrap();
    let refreshed = Command::new(&updated_persona)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .current_dir(&repo)
        .args(["hooks", "install", "--config"])
        .arg(&config)
        .args(["--cwd", repo.to_str().unwrap()])
        .output()
        .unwrap();
    must_succeed(refreshed);
    assert_eq!(
        fs::read_link(&original).unwrap(),
        fs::canonicalize(&updated_persona).unwrap()
    );
    let paths = persona::hooks::resolve_paths(
        &persona::git::GitClient::new(
            git.clone(),
            vec![
                ("HOME".into(), temporary.path().as_os_str().into()),
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
                ("GIT_CONFIG_SYSTEM".into(), "/dev/null".into()),
                ("GIT_CONFIG_GLOBAL".into(), "/dev/null".into()),
            ],
        ),
        &repo,
    )
    .unwrap();
    let manifest = persona::hooks::load_manifest(&paths).unwrap();
    let preserved = manifest.original_hook(&paths).unwrap();
    assert_eq!(fs::read(preserved).unwrap(), original_contents);
    assert_eq!(
        fs::metadata(preserved).unwrap().permissions().mode() & 0o777,
        0o700,
        "the preserved executable hook backup is private while installed"
    );
    let coverage = Command::new(&updated_persona)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .env("GH_TOKEN", "synthetic-secret-sentinel")
        .current_dir(&repo)
        .args(["status", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--format", "json"])
        .output()
        .unwrap();
    let coverage_json: serde_json::Value = serde_json::from_slice(&coverage.stdout).unwrap();
    assert!(
        coverage_json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["property"] == "integration.pre_push_hook" && finding["status"] == "PASS"
            })
    );
    assert!(!String::from_utf8_lossy(&coverage.stdout).contains("synthetic-secret-sentinel"));

    let positive_push = run_git(&git, &repo, temporary.path(), &["push", "origin", "main"]);
    must_succeed(positive_push);
    let original_input = fs::read_to_string(&hook_marker).unwrap();
    assert!(original_input.contains("refs/heads/main"));
    let args = fs::read_to_string(&hook_arguments).unwrap();
    let mut args = args.lines();
    assert_eq!(args.next(), Some("origin"));
    assert_eq!(args.next(), Some(remote.to_str().unwrap()));
    assert_eq!(args.next(), Some("present"));
    assert!(args.next().is_none());

    commit(
        &git,
        &repo,
        temporary.path(),
        "Persona Committer <committer@example.invalid>",
        "authorized commit rejected by the original hook",
    );
    fs::write(&fail_original_hook, "fail").unwrap();
    let original_hook_failure = run_git(&git, &repo, temporary.path(), &["push", "origin", "main"]);
    assert!(!original_hook_failure.status.success());
    fs::remove_file(&fail_original_hook).unwrap();
    let remote_head_after_hook_failure = String::from_utf8_lossy(
        &must_succeed(run_git(
            &git,
            &remote,
            temporary.path(),
            &["rev-parse", "refs/heads/main"],
        ))
        .stdout,
    )
    .trim()
    .to_owned();
    let local_parent = String::from_utf8_lossy(
        &must_succeed(run_git(
            &git,
            &repo,
            temporary.path(),
            &["rev-parse", "HEAD^"],
        ))
        .stdout,
    )
    .trim()
    .to_owned();
    assert_eq!(remote_head_after_hook_failure, local_parent);

    commit(
        &git,
        &repo,
        temporary.path(),
        "Wrong Author <wrong@example.invalid>",
        "unauthorized author",
    );
    let original_input_before_rejection = fs::read(&hook_marker).unwrap();
    let hook_blocked_push = run_git(&git, &repo, temporary.path(), &["push", "origin", "main"]);
    assert!(
        !hook_blocked_push.status.success(),
        "the actual pre-push hook must reject the unauthorized author"
    );
    assert_eq!(
        fs::read(&hook_marker).unwrap(),
        original_input_before_rejection,
        "the preserved hook runs only after Persona authorizes"
    );
    let remote_head = String::from_utf8_lossy(
        &must_succeed(run_git(
            &git,
            &remote,
            temporary.path(),
            &["rev-parse", "refs/heads/main"],
        ))
        .stdout,
    )
    .trim()
    .to_owned();
    let local_parent = String::from_utf8_lossy(
        &must_succeed(run_git(
            &git,
            &repo,
            temporary.path(),
            &["rev-parse", "HEAD^^"],
        ))
        .stdout,
    )
    .trim()
    .to_owned();
    assert_eq!(
        remote_head, local_parent,
        "the native pre-push hook must block the update"
    );

    let pretransport_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    pretransport_listener.set_nonblocking(true).unwrap();
    let pretransport_destination = format!(
        "https://127.0.0.1:{}/remote.git",
        pretransport_listener.local_addr().unwrap().port()
    );
    must_succeed(run_git(
        &git,
        &repo,
        temporary.path(),
        &["remote", "set-url", "origin", &pretransport_destination],
    ));
    let guarded_push = Command::new(persona)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .current_dir(&repo)
        .args(["run", "--config"])
        .arg(&config)
        .args([
            "--cwd",
            repo.to_str().unwrap(),
            "--",
            "git",
            "push",
            "origin",
            "main",
        ])
        .output()
        .unwrap();
    assert!(!guarded_push.status.success());
    assert_eq!(
        pretransport_listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "the primary managed PATH adapter must refuse before opening a transport"
    );
    must_succeed(run_git(
        &git,
        &repo,
        temporary.path(),
        &["remote", "set-url", "origin", remote.to_str().unwrap()],
    ));
    let remote_head = String::from_utf8_lossy(
        &must_succeed(run_git(
            &git,
            &remote,
            temporary.path(),
            &["rev-parse", "refs/heads/main"],
        ))
        .stdout,
    )
    .trim()
    .to_owned();
    let local_parent = String::from_utf8_lossy(
        &must_succeed(run_git(
            &git,
            &repo,
            temporary.path(),
            &["rev-parse", "HEAD^^"],
        ))
        .stdout,
    )
    .trim()
    .to_owned();
    assert_eq!(
        remote_head, local_parent,
        "Persona's primary PATH adapter must block before updating the remote"
    );

    let hook_input_before = fs::read(&hook_marker).unwrap();
    let bypass = run_git(
        &git,
        &repo,
        temporary.path(),
        &["push", "--no-verify", "origin", "main"],
    );
    must_succeed(bypass);
    assert_eq!(
        fs::read(&hook_marker).unwrap(),
        hook_input_before,
        "--no-verify is a documented hook bypass"
    );

    let remove = Command::new(persona)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .current_dir(&repo)
        .args(["hooks", "remove", "--cwd", repo.to_str().unwrap()])
        .output()
        .unwrap();
    must_succeed(remove);
    assert!(
        !fs::symlink_metadata(&original)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&original).unwrap(), original_contents);

    let reinstall = Command::new(persona)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .current_dir(&repo)
        .args(["hooks", "install", "--config"])
        .arg(&config)
        .args(["--cwd", repo.to_str().unwrap()])
        .output()
        .unwrap();
    must_succeed(reinstall);
    fs::remove_file(&original).unwrap();
    fs::write(&original, "external replacement\n").unwrap();
    let conflicted_remove = Command::new(persona)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .current_dir(&repo)
        .args(["hooks", "remove", "--cwd", repo.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!conflicted_remove.status.success());
    assert_eq!(fs::read(&original).unwrap(), b"external replacement\n");
    fs::remove_file(&original).unwrap();
    fs::write(&original, &original_contents).unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();

    commit(
        &git,
        &repo,
        temporary.path(),
        "Direct Binary <direct@example.invalid>",
        "explicit direct-binary bypass fixture",
    );
    must_succeed(run_git(
        &git,
        &repo,
        temporary.path(),
        &["push", "origin", "main"],
    ));
    let published = String::from_utf8_lossy(
        &must_succeed(run_git(
            &git,
            &remote,
            temporary.path(),
            &["rev-parse", "refs/heads/main"],
        ))
        .stdout,
    )
    .trim()
    .to_owned();
    let local = String::from_utf8_lossy(
        &must_succeed(run_git(
            &git,
            &repo,
            temporary.path(),
            &["rev-parse", "HEAD"],
        ))
        .stdout,
    )
    .trim()
    .to_owned();
    assert_eq!(
        published, local,
        "direct native Git bypasses the removed Persona adapter and hook"
    );
}
