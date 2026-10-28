use persona::config::{Config, ConfigError};
use std::path::Path;

const VALID_CONFIG: &str = r#"
   version = 1

   [[scopes]]
   name = "work"
   path = "/work"

   [scopes.git]
   author = { name = "Test Author", email = "author@example.invalid" }
   committer = { name = "Test Committer", email = "committer@example.invalid" }
   "#;

#[test]
fn parses_expected_identities_and_converts_scopes() {
    let config = Config::parse(VALID_CONFIG).expect("valid policy");

    let policy = &config.policies()[0];

    assert_eq!(policy.name, "work");
    assert_eq!(policy.git.author.name, "Test Author");
    assert_eq!(policy.git.author.email, "author@example.invalid");
    assert_eq!(policy.git.committer.name, "Test Committer");
    assert_eq!(policy.git.committer.email, "committer@example.invalid");

    let scopes = config.scopes();

    assert_eq!(scopes.len(), 1);
    assert_eq!(scopes[0].name, "work");
    assert_eq!(scopes[0].root.as_path(), Path::new("/work"));
}

#[test]
fn rejects_unsupported_versions() {
    let input = VALID_CONFIG.replace("version = 1", "version = 2");

    assert_eq!(
        Config::parse(&input).unwrap_err(),
        ConfigError::UnsupportedVersion(2)
    );
}

#[test]
fn rejects_unknown_fields_at_different_levels() {
    let inputs = [
        VALID_CONFIG.replace("version = 1", "version = 1\nunexpected = true"),
        VALID_CONFIG.replace(
            "name = \"Test Author\"",
            "name = \"Test Author\", unexpected = true",
        ),
    ];

    for input in inputs {
        assert_eq!(Config::parse(&input).unwrap_err(), ConfigError::InvalidToml);
    }
}

#[test]
fn rejects_an_empty_scope_list() {
    let input = "version = 1\nscopes = []";

    assert_eq!(Config::parse(input).unwrap_err(), ConfigError::EmptyScopes);
}

#[test]
fn rejects_duplicate_scope_names() {
    let second_scope = VALID_CONFIG.replacen("version = 1", "", 1);
    let input = format!("{VALID_CONFIG}\n{second_scope}");

    assert_eq!(
        Config::parse(&input).unwrap_err(),
        ConfigError::DuplicateScopeName("work".to_owned())
    );
}

#[test]
fn rejects_empty_or_padded_scope_names() {
    for name in ["", " ", " work "] {
        let input = VALID_CONFIG.replace("name = \"work\"", &format!("name = \"{name}\""));

        assert_eq!(
            Config::parse(&input).unwrap_err(),
            ConfigError::InvalidScopeName
        );
    }
}

#[test]
fn rejects_paths_that_are_not_absolute() {
    for path in ["work", "~/work", "$HOME/work"] {
        let input = VALID_CONFIG.replace("path = \"/work\"", &format!("path = \"{path}\""));

        assert_eq!(
            Config::parse(&input).unwrap_err(),
            ConfigError::RelativeScopePath(path.into())
        );
    }
}

#[test]
fn accepts_an_explicit_full_fingerprint_and_public_key() {
    let input = format!(
        "{VALID_CONFIG}\n[scopes.git.signing]\nfingerprint = \"0123456789abcdef0123456789abcdef01234567\"\npublic_key = \"/tmp/public.asc\"\n"
    );
    let config = Config::parse(&input).expect("valid signing policy");
    let signing = config.policies()[0]
        .git
        .signing
        .as_ref()
        .expect("signing policy");
    assert_eq!(
        signing.fingerprint,
        "0123456789abcdef0123456789abcdef01234567"
    );
    assert_eq!(signing.public_key, Path::new("/tmp/public.asc"));
}

#[test]
fn rejects_malformed_signing_policy() {
    for (field, value) in [
        ("fingerprint", "\"short\""),
        ("public_key", "\"relative.asc\""),
    ] {
        let input = format!(
            "{VALID_CONFIG}\n[scopes.git.signing]\nfingerprint = \"0123456789abcdef0123456789abcdef01234567\"\npublic_key = \"/tmp/public.asc\"\n"
        )
        .replace(
            &format!("{field} = {}", if field == "fingerprint" { "\"0123456789abcdef0123456789abcdef01234567\"" } else { "\"/tmp/public.asc\"" }),
            &format!("{field} = {value}"),
        );
        assert!(Config::parse(&input).is_err(), "{field} should be rejected");
    }
}

#[test]
fn rejects_empty_author_or_committer_fields() {
    for (email, role) in [
        ("author@example.invalid", "author"),
        ("committer@example.invalid", "committer"),
    ] {
        let input = VALID_CONFIG.replace(email, "");

        assert_eq!(
            Config::parse(&input).unwrap_err(),
            ConfigError::EmptyIdentity {
                scope: "work".to_owned(),
                role: role.to_owned(),
            }
        );
    }
}
