use std::fs;
use std::path::{Path, PathBuf};

fn markdown_files(root: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).expect("read repository directory") {
        let entry = entry.expect("read directory entry");
        let path = entry.path();
        if path
            .file_name()
            .is_some_and(|name| name == ".git" || name == "target")
        {
            continue;
        }
        if path.is_dir() {
            markdown_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "md") {
            files.push(path);
        }
    }
}

#[test]
fn public_documentation_navigation_exists() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for path in [
        "docs/README.md",
        "docs/getting-started.md",
        "docs/installation.md",
        "docs/configuration.md",
        "docs/cli.md",
        "docs/managed-commands.md",
        "docs/security-model.md",
        "docs/troubleshooting.md",
        "docs/releasing.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "LICENSE-MIT",
        "LICENSE-APACHE",
    ] {
        assert!(
            root.join(path).is_file(),
            "missing expected public file: {path}"
        );
    }
}

#[test]
fn documented_configuration_example_parses() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let document =
        fs::read_to_string(root.join("docs/configuration.md")).expect("read configuration guide");
    let example = document
        .split("## Minimal synthetic example")
        .nth(1)
        .and_then(|section| section.split("```toml").nth(1))
        .and_then(|section| section.split("```").next())
        .expect("configuration guide has a TOML example");
    persona::config::Config::parse(example).expect("documented TOML example parses");
}

#[test]
fn documented_quickstart_commands_match_the_cli() {
    let help = std::process::Command::new(env!("CARGO_BIN_EXE_persona"))
        .arg("--help")
        .output()
        .expect("run Persona help");
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).expect("help is UTF-8");
    for command in [
        "status", "doctor", "setup", "profile", "scope", "install", "hooks",
    ] {
        assert!(
            help.contains(command),
            "CLI help omits documented command {command}"
        );
    }
}

#[test]
fn getting_started_setup_example_runs_with_a_disposable_home() {
    let temporary = tempfile::tempdir().expect("create temporary home");
    let home = temporary.path().join("home");
    let config = temporary.path().join("config");
    let state = temporary.path().join("state");
    let scope = temporary.path().join("project");
    fs::create_dir_all(&scope).expect("create test scope");

    let setup = std::process::Command::new(env!("CARGO_BIN_EXE_persona"))
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_STATE_HOME", &state)
        .current_dir(&scope)
        .args([
            "setup",
            "--profile",
            "example",
            "--scope-name",
            "example",
            "--scope",
            scope.to_str().expect("scope path is UTF-8"),
            "--author-name",
            "Example Author",
            "--author-email",
            "author@example.invalid",
            "--committer-name",
            "Example Committer",
            "--committer-email",
            "committer@example.invalid",
        ])
        .output()
        .expect("run documented setup command");
    assert!(
        setup.status.success(),
        "{}",
        String::from_utf8_lossy(&setup.stderr)
    );

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_persona"))
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", config)
        .env("XDG_STATE_HOME", state)
        .current_dir(&scope)
        .arg("status")
        .output()
        .expect("run documented status command");
    assert!(
        status.status.success() || status.status.code() == Some(3),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
}

#[test]
fn markdown_local_links_resolve() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    markdown_files(root, &mut files);

    for file in files {
        let contents = fs::read_to_string(&file).expect("read Markdown file");
        for destination in contents
            .split("](")
            .skip(1)
            .filter_map(|part| part.split(')').next())
        {
            let destination = destination.trim_matches(['<', '>']);
            if destination.is_empty()
                || destination.starts_with('#')
                || destination.contains("://")
                || destination.starts_with("mailto:")
            {
                continue;
            }
            let path = destination.split('#').next().unwrap_or_default();
            if path.is_empty() {
                continue;
            }
            let target = file.parent().expect("Markdown parent").join(path);
            assert!(
                target.exists(),
                "broken local link in {}: {destination}",
                file.strip_prefix(root).unwrap_or(&file).display()
            );
        }
    }
}
