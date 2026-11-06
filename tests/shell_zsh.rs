#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;

fn persona() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_persona"))
}

fn resolve_program(program: std::ffi::OsString) -> PathBuf {
    let path = PathBuf::from(&program);
    if path.components().count() > 1 {
        return path;
    }
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join(&program))
        .find(|candidate| candidate.is_file())
        .unwrap_or(path)
}

#[test]
fn zsh_hook_is_quiet_idempotent_and_composes_with_existing_hooks() {
    let zsh = resolve_program(std::env::var_os("PERSONA_TEST_ZSH").unwrap_or_else(|| "zsh".into()));
    if Command::new(&zsh).arg("--version").output().is_err() {
        eprintln!("skipping Zsh integration: set PERSONA_TEST_ZSH to an installed zsh");
        return;
    }

    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let config = temp.path().join("config");
    let state = temp.path().join("state");
    let bin = temp.path().join("bin");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&bin).unwrap();
    let init = Command::new(persona())
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_STATE_HOME", &state)
        .args(["shell", "zsh", "init"])
        .output()
        .unwrap();
    assert!(init.status.success());
    assert!(
        init.stderr.is_empty(),
        "sourcing template generation must be quiet"
    );
    let snippet = temp.path().join("persona.zsh");
    fs::write(&snippet, init.stdout).unwrap();
    fs::write(bin.join("persona"), "#!/bin/sh\nprintf '[scope]\\n'\n").unwrap();
    fs::set_permissions(bin.join("persona"), fs::Permissions::from_mode(0o700)).unwrap();
    let log = temp.path().join("hooks.log");
    let script = r#"
      autoload -Uz add-zsh-hook
      function user_hook { print -r -- user >> "$PERSONA_TEST_LOG" }
      function direnv_hook { print -r -- direnv >> "$PERSONA_TEST_LOG" }
      add-zsh-hook precmd user_hook
      add-zsh-hook precmd direnv_hook
      source "$PERSONA_ZSH_SNIPPET"
      source "$PERSONA_ZSH_SNIPPET"
      local_count=0
      for hook in $precmd_functions; do
        [[ $hook == _persona_zsh_refresh_marker ]] && (( local_count += 1 ))
      done
      print -r -- "managed_hooks=$local_count"
      for hook in $precmd_functions; do "$hook"; done
      print -r -- "marker=$(persona_prompt_marker)"
      persona_zsh_deactivate
      remaining=0
      for hook in $precmd_functions; do
        [[ $hook == user_hook || $hook == direnv_hook ]] && (( remaining += 1 ))
      done
      print -r -- "remaining_hooks=$remaining"
      for hook in $precmd_functions; do
        [[ $hook == _persona_zsh_refresh_marker ]] && print -r -- "persona_hook_leaked=yes"
      done
      true
    "#;
    let output = Command::new(zsh)
        .arg("-f")
        .arg("-c")
        .arg(script)
        .env_clear()
        .env("HOME", &home)
        .env("PATH", &bin)
        .env("PERSONA_TEST_LOG", &log)
        .env("PERSONA_ZSH_SNIPPET", &snippet)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exit={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout,
        "managed_hooks=1\nmarker=[scope]\nremaining_hooks=2\n"
    );
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hooks = fs::read_to_string(log).unwrap();
    assert_eq!(hooks.lines().filter(|line| *line == "user").count(), 1);
    assert_eq!(hooks.lines().filter(|line| *line == "direnv").count(), 1);
}

#[test]
fn zsh_adapter_preserves_unowned_public_function_names() {
    let zsh = resolve_program(std::env::var_os("PERSONA_TEST_ZSH").unwrap_or_else(|| "zsh".into()));
    if Command::new(&zsh).arg("--version").output().is_err() {
        eprintln!("skipping Zsh integration: set PERSONA_TEST_ZSH to an installed zsh");
        return;
    }
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    fs::create_dir(&home).unwrap();
    let init = Command::new(persona())
        .env_clear()
        .env("HOME", &home)
        .args(["shell", "zsh", "init"])
        .output()
        .unwrap();
    assert!(init.status.success());
    let snippet = temp.path().join("persona.zsh");
    fs::write(&snippet, init.stdout).unwrap();
    let script = r#"
      typeset -g _PERSONA_ZSH_ADAPTER_ACTIVE=1
      function persona_zsh_deactivate { print -r -- preserved }
      source "$PERSONA_ZSH_SNIPPET"
      persona_zsh_deactivate
      print -r -- "user_marker=${+functions[persona_prompt_marker]}"
      print -r -- "adapter=${_PERSONA_ZSH_ADAPTER_ACTIVE-absent}"
    "#;
    let output = Command::new(zsh)
        .arg("-f")
        .arg("-c")
        .arg(script)
        .env_clear()
        .env("HOME", &home)
        .env("PERSONA_ZSH_SNIPPET", &snippet)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"preserved\nuser_marker=0\nadapter=1\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn zsh_marker_reports_only_a_matching_directory_scope() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let config_root = temp.path().join("config");
    let state = temp.path().join("state");
    let repo = temp.path().join("repo");
    let elsewhere = temp.path().join("elsewhere");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&config_root).unwrap();
    fs::create_dir(&repo).unwrap();
    fs::create_dir(&elsewhere).unwrap();
    let config = config_root.join("persona/config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(
        &config,
        format!(
            "version = 2\n\n[[profiles]]\nname = \"work\"\n[profiles.git]\nauthor = {{ name = \"Fixture\", email = \"fixture@example.invalid\" }}\ncommitter = {{ name = \"Fixture\", email = \"fixture@example.invalid\" }}\n\n[[scopes]]\nname = \"repo\"\npath = {:?}\nprofile = \"work\"\n",
            repo.display().to_string()
        ),
    )
    .unwrap();
    fs::set_permissions(
        config_root.join("persona"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

    let managed = Command::new(persona())
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_root)
        .env("XDG_STATE_HOME", &state)
        .current_dir(&repo)
        .args(["shell", "zsh", "marker"])
        .output()
        .unwrap();
    assert!(
        managed.status.success(),
        "{}",
        String::from_utf8_lossy(&managed.stderr)
    );
    assert_eq!(managed.stdout, b"[scope]");

    let unmanaged = Command::new(persona())
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_root)
        .env("XDG_STATE_HOME", &state)
        .current_dir(&elsewhere)
        .args(["shell", "zsh", "marker"])
        .output()
        .unwrap();
    assert!(unmanaged.status.success());
    assert!(unmanaged.stdout.is_empty());
}
