use persona::config::{Config, ConfigError, ConfigLoadError};
use persona::context::resolve_context;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use tempfile::tempdir;

fn policy_for(scope_root: &Path) -> String {
    let root = scope_root
        .to_str()
        .expect("fixture path should be valid UTF-8");

    // Produz uma string TOML corretamente escapada.
    let quoted_root = toml::Value::String(root.to_owned());

    format!(
        r#"
   version = 1

   [[scopes]]
   name = "work"
   path = {quoted_root}

   [scopes.git]
   author = {{ name = "Test Author", email = "author@example.invalid" }}
   committer = {{ name = "Test Committer", email = "committer@example.invalid" }}
   "#
    )
}

#[test]
fn loads_a_policy_and_resolves_its_scope() {
    let temporary = tempdir().expect("create temporary directory");

    let scope_root = temporary.path().join("work");
    let project = scope_root.join("project");
    let config_path = temporary.path().join("policy.toml");

    fs::create_dir_all(&project).expect("create project directory");

    fs::write(&config_path, policy_for(&scope_root)).expect("write fixture policy");

    let config = Config::load(&config_path).expect("load valid policy");

    let scopes = config.scopes();

    let selected = resolve_context(&project, &scopes)
        .expect("valid filesystem context")
        .expect("project should have a scope");

    assert_eq!(selected.name, "work");

    assert_eq!(
        selected.root,
        fs::canonicalize(&scope_root).expect("canonicalize expected root")
    );

    assert_eq!(
        config.policies()[0].git.author.email,
        "author@example.invalid"
    );
}

#[test]
fn reports_a_missing_configuration_file() {
    let temporary = tempdir().expect("create temporary directory");
    let missing = temporary.path().join("missing.toml");

    let result = Config::load(&missing);

    assert!(matches!(
        result,
        Err(ConfigLoadError::Read { source, .. })
            if source.kind() == ErrorKind::NotFound
    ));
}

#[test]
fn preserves_policy_validation_errors() {
    let temporary = tempdir().expect("create temporary directory");
    let config_path = temporary.path().join("policy.toml");

    fs::write(&config_path, "version = 4\nscopes = []").expect("write invalid policy");

    let result = Config::load(&config_path);

    assert!(matches!(
        result,
        Err(ConfigLoadError::Invalid(ConfigError::UnsupportedVersion(4)))
    ));
}

#[test]
fn reports_malformed_toml() {
    let temporary = tempdir().expect("create temporary directory");
    let config_path = temporary.path().join("policy.toml");

    fs::write(&config_path, "version = [").expect("write malformed policy");

    let result = Config::load(&config_path);

    assert!(matches!(
        result,
        Err(ConfigLoadError::Invalid(ConfigError::InvalidToml))
    ));
}

#[test]
fn rejects_non_utf8_configuration_files() {
    let temporary = tempdir().expect("create temporary directory");
    let config_path = temporary.path().join("policy.toml");

    fs::write(&config_path, [0xff_u8, 0xfe_u8]).expect("write non-UTF-8 fixture");

    let result = Config::load(&config_path);

    assert!(matches!(
        result,
        Err(ConfigLoadError::Read { source, .. })
            if source.kind() == ErrorKind::InvalidData
    ));
}
