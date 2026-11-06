#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tempfile::tempdir;

const SHIMS: [&str; 4] = ["git", "gh", "ssh", "git-credential-persona"];

fn persona() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_persona"))
}

fn call(executable: &Path, home: &Path, config: &Path, state: &Path, args: &[&str]) -> Output {
    Command::new(executable)
        .env_clear()
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", config)
        .env("XDG_STATE_HOME", state)
        .current_dir(home)
        .args(args)
        .output()
        .unwrap()
}

fn backup_path(output: &Output) -> PathBuf {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|line| line.starts_with("Backup: "))
        .unwrap();
    PathBuf::from(line.strip_prefix("Backup: ").unwrap())
}

fn assert_shims(bin: &Path, target: &Path) {
    let target = fs::canonicalize(target).unwrap();
    for name in SHIMS {
        let path = bin.join(name);
        assert!(
            fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::canonicalize(path).unwrap(), target);
    }
}

#[test]
fn installer_preview_apply_refresh_remove_and_rollback_are_reversible() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let config = temp.path().join("config");
    let state = temp.path().join("state");
    let bin = temp.path().join("user-bin");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir(&bin).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
    let original = persona();

    let preview = call(
        &original,
        &home,
        &config,
        &state,
        &["install", "preview", "--bin-dir", bin.to_str().unwrap()],
    );
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    assert!(!state.exists(), "preview must not create state directories");
    assert!(SHIMS.iter().all(|name| !bin.join(name).exists()));

    let applied = call(
        &original,
        &home,
        &config,
        &state,
        &["install", "apply", "--bin-dir", bin.to_str().unwrap()],
    );
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    assert_shims(&bin, &original);
    let manifest = state.join("persona/install.toml");
    let metadata = fs::metadata(&manifest).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    let first_backup = backup_path(&applied);
    let backup_metadata = fs::metadata(&first_backup).unwrap();
    assert_eq!(backup_metadata.mode() & 0o777, 0o600);
    assert_eq!(
        fs::metadata(first_backup.parent().unwrap()).unwrap().mode() & 0o777,
        0o700
    );

    let idempotent = call(
        &original,
        &home,
        &config,
        &state,
        &["install", "apply", "--bin-dir", bin.to_str().unwrap()],
    );
    assert!(
        idempotent.status.success(),
        "{}",
        String::from_utf8_lossy(&idempotent.stderr)
    );
    assert!(!String::from_utf8_lossy(&idempotent.stdout).contains("Backup:"));

    let updated_dir = temp.path().join("updated");
    fs::create_dir(&updated_dir).unwrap();
    let updated = updated_dir.join("persona");
    fs::copy(&original, &updated).unwrap();
    fs::set_permissions(&updated, fs::Permissions::from_mode(0o700)).unwrap();
    let refresh_preview = call(
        &updated,
        &home,
        &config,
        &state,
        &["install", "refresh", "--preview"],
    );
    assert!(
        refresh_preview.status.success(),
        "{}",
        String::from_utf8_lossy(&refresh_preview.stderr)
    );
    assert_shims(&bin, &original);

    let refreshed = call(
        &updated,
        &home,
        &config,
        &state,
        &["install", "refresh", "--apply"],
    );
    assert!(
        refreshed.status.success(),
        "{}",
        String::from_utf8_lossy(&refreshed.stderr)
    );
    assert_shims(&bin, &updated);
    let refresh_backup = backup_path(&refreshed);

    let rolled_back = call(
        &original,
        &home,
        &config,
        &state,
        &[
            "install",
            "rollback",
            "--backup",
            refresh_backup.to_str().unwrap(),
            "--apply",
        ],
    );
    assert!(
        rolled_back.status.success(),
        "{}",
        String::from_utf8_lossy(&rolled_back.stderr)
    );
    assert_shims(&bin, &original);

    let removal_preview = call(
        &original,
        &home,
        &config,
        &state,
        &["install", "remove", "--preview"],
    );
    assert!(
        removal_preview.status.success(),
        "{}",
        String::from_utf8_lossy(&removal_preview.stderr)
    );
    assert_shims(&bin, &original);

    let removed = call(
        &original,
        &home,
        &config,
        &state,
        &["install", "remove", "--apply"],
    );
    assert!(
        removed.status.success(),
        "{}",
        String::from_utf8_lossy(&removed.stderr)
    );
    assert!(
        SHIMS
            .iter()
            .all(|name| fs::symlink_metadata(bin.join(name)).is_err())
    );
    assert!(!manifest.exists());
    let remove_backup = backup_path(&removed);

    let restored = call(
        &original,
        &home,
        &config,
        &state,
        &[
            "install",
            "rollback",
            "--backup",
            remove_backup.to_str().unwrap(),
            "--apply",
        ],
    );
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    assert_shims(&bin, &original);

    let uninstalled = call(
        &original,
        &home,
        &config,
        &state,
        &[
            "install",
            "rollback",
            "--backup",
            first_backup.to_str().unwrap(),
            "--apply",
        ],
    );
    assert!(
        uninstalled.status.success(),
        "{}",
        String::from_utf8_lossy(&uninstalled.stderr)
    );
    assert!(
        SHIMS
            .iter()
            .all(|name| fs::symlink_metadata(bin.join(name)).is_err())
    );
    assert!(!manifest.exists());
}

#[test]
fn installed_path_shim_dispatches_without_a_persona_run_wrapper() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let config_home = temp.path().join("config");
    let state = temp.path().join("state");
    let bin = temp.path().join("user-bin");
    let scope = home.join("work");
    fs::create_dir_all(&scope).unwrap();
    fs::create_dir(&bin).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();

    let config_dir = config_home.join("persona");
    fs::create_dir_all(&config_dir).unwrap();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let root = toml::Value::String(scope.to_string_lossy().into_owned());
    fs::write(
        config_dir.join("config.toml"),
        format!(
            r#"version = 1
[[scopes]]
name = "work"
path = {root}
[scopes.git]
author = {{ name = "Test Author", email = "author@example.invalid" }}
committer = {{ name = "Test Committer", email = "committer@example.invalid" }}
"#
        ),
    )
    .unwrap();
    fs::set_permissions(
        config_dir.join("config.toml"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let native_git = PathBuf::from(std::env::var_os("PERSONA_TEST_GIT").expect("PERSONA_TEST_GIT"));
    let git = Command::new(&native_git)
        .args(["init", "--quiet"])
        .current_dir(&scope)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .status()
        .unwrap();
    assert!(git.success());

    let installed = call(
        &persona(),
        &home,
        &config_home,
        &state,
        &["install", "apply", "--bin-dir", bin.to_str().unwrap()],
    );
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );

    let path = std::env::join_paths([&bin, Path::new("/usr/bin"), Path::new("/bin")]).unwrap();
    let status = Command::new(bin.join("git"))
        .args(["status", "--short"])
        .current_dir(&scope)
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", &state)
        .env("PERSONA_GIT", &native_git)
        .env("PATH", path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(
        status.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
}

#[test]
fn refresh_repairs_dangling_shims_after_the_previous_binary_is_removed() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let config = temp.path().join("config");
    let state = temp.path().join("state");
    let bin = temp.path().join("user-bin");
    let old_dir = temp.path().join("old");
    let new_dir = temp.path().join("new");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir(&bin).unwrap();
    fs::create_dir(&old_dir).unwrap();
    fs::create_dir(&new_dir).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
    let old_binary = old_dir.join("persona");
    let new_binary = new_dir.join("persona");
    fs::copy(persona(), &old_binary).unwrap();
    fs::copy(persona(), &new_binary).unwrap();
    fs::set_permissions(&old_binary, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&new_binary, fs::Permissions::from_mode(0o700)).unwrap();

    let installed = call(
        &old_binary,
        &home,
        &config,
        &state,
        &["install", "apply", "--bin-dir", bin.to_str().unwrap()],
    );
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    fs::remove_file(&old_binary).unwrap();
    assert!(
        fs::symlink_metadata(bin.join("git"))
            .unwrap()
            .file_type()
            .is_symlink()
    );

    let refreshed = call(
        &new_binary,
        &home,
        &config,
        &state,
        &["install", "refresh", "--apply"],
    );
    assert!(
        refreshed.status.success(),
        "{}",
        String::from_utf8_lossy(&refreshed.stderr)
    );
    assert_shims(&bin, &new_binary);
}

#[test]
fn installer_conflicts_preserve_external_edits_and_unowned_files() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let config = temp.path().join("config");
    let state = temp.path().join("state");
    let bin = temp.path().join("user-bin");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir(&bin).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
    let executable = persona();

    let conflict = bin.join("gh");
    fs::write(&conflict, "pre-existing user command").unwrap();
    let refused = call(
        &executable,
        &home,
        &config,
        &state,
        &["install", "apply", "--bin-dir", bin.to_str().unwrap()],
    );
    assert!(!refused.status.success());
    assert_eq!(
        fs::read_to_string(&conflict).unwrap(),
        "pre-existing user command"
    );
    assert!(!state.join("persona/install.toml").exists());
    fs::remove_file(conflict).unwrap();

    let applied = call(
        &executable,
        &home,
        &config,
        &state,
        &["install", "apply", "--bin-dir", bin.to_str().unwrap()],
    );
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let edited = bin.join("gh");
    fs::remove_file(&edited).unwrap();
    fs::write(&edited, "external replacement").unwrap();
    let refused_remove = call(
        &executable,
        &home,
        &config,
        &state,
        &["install", "remove", "--apply"],
    );
    assert!(!refused_remove.status.success());
    assert_eq!(fs::read_to_string(&edited).unwrap(), "external replacement");
    assert!(
        bin.join("git").exists(),
        "conflict detection must happen before any removal"
    );
}
