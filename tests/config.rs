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

const VALID_V2: &str = r#"
version = 2

[[profiles]]
name = "work"
[profiles.git]
author = { name = "Test Author", email = "author@example.invalid" }
committer = { name = "Test Committer", email = "committer@example.invalid" }

[[scopes]]
name = "work-one"
path = "/work/one"
profile = "work"

[[scopes]]
name = "work-two"
path = "/work/two"
profile = "work"
"#;

const VALID_V3: &str = r#"
version = 3

[[profiles]]
name = "work"
[profiles.git]
author = { name = "Test Author", email = "author@example.invalid" }
committer = { name = "Test Committer", email = "committer@example.invalid" }
remotes = [{ name = "upstream", fetch_destinations = ["https://github.com/acme/project.git"], push_destinations = [] }, { name = "origin", fetch_destinations = ["https://github.com/ybarbara/project.git"], push_destinations = ["https://github.com/ybarbara/project.git"] }]
[profiles.git.push]
remote = "origin"
destinations = ["https://github.com/ybarbara/project.git"]
[profiles.github]
host = "github.com"
account_id = "4242"
account_selector = "work-user"
token_fingerprint = "hmac-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
repositories = ["acme/project", "ybarbara/project"]
[profiles.github_merge]
repositories = [{ repository = "acme/project", base_branches = ["main"], strategies = ["squash"] }]

[[scopes]]
name = "work"
path = "/work"
profile = "work"
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
    let input = VALID_CONFIG.replace("version = 1", "version = 4");

    assert_eq!(
        Config::parse(&input).unwrap_err(),
        ConfigError::UnsupportedVersion(4)
    );
}

#[test]
fn v2_profiles_can_be_reused_by_scopes_without_inheritance() {
    let config = Config::parse(VALID_V2).expect("valid v2 policy");

    assert_eq!(config.version(), 2);
    assert_eq!(config.profiles().len(), 1);
    assert_eq!(config.policies().len(), 2);
    assert_eq!(config.policies()[0].name, "work-one");
    assert_eq!(config.policies()[1].name, "work-two");
    assert_eq!(config.policies()[0].git.author.name, "Test Author");
    assert_eq!(
        config.policies()[1].git.committer.email,
        "committer@example.invalid"
    );
}

#[test]
fn v3_remotes_and_github_merge_policy_round_trip_without_implicit_grants() {
    let config = Config::parse(VALID_V3).expect("valid v3 policy");
    assert_eq!(config.version(), 3);
    let profile = &config.profiles()[0];
    let remotes = &profile.git.remotes;
    assert_eq!(remotes.len(), 2);
    assert!(remotes[0].push_destinations.is_empty());
    assert_eq!(remotes[1].name, "origin");
    let merge = profile
        .github_merge
        .as_ref()
        .expect("explicit merge policy");
    assert_eq!(merge.repositories[0].repository, "acme/project");
    assert_eq!(merge.repositories[0].base_branches, ["main"]);
    assert_eq!(
        merge.repositories[0].strategies,
        [persona::config::MergeStrategy::Squash]
    );

    let serialized = config.to_v3_toml().expect("serialize v3");
    let reparsed = Config::parse(&serialized).expect("reparse v3");
    assert_eq!(reparsed.version(), 3);
    assert_eq!(reparsed.profiles()[0].git.remotes, remotes.clone());
    assert_eq!(reparsed.profiles()[0].github_merge, profile.github_merge);
}

#[test]
fn v2_configuration_upgrades_to_v3_without_granting_merge_permissions() {
    let legacy = Config::parse(VALID_V2).expect("valid v2 policy");
    let upgraded_text = legacy.to_v3_toml().expect("serialize upgraded policy");
    let upgraded = Config::parse(&upgraded_text).expect("parse upgraded policy");

    assert_eq!(upgraded.version(), 3);
    assert_eq!(upgraded.profiles().len(), 1);
    assert!(upgraded.profiles()[0].github_merge.is_none());
    assert!(upgraded.profiles()[0].git.remotes.is_empty());
    assert_eq!(upgraded.policies().len(), 2);
    assert!(
        upgraded
            .policies()
            .iter()
            .all(|scope| scope.git.push.is_none())
    );
}

#[test]
fn v3_merge_policy_requires_enrolled_allowlisted_repository() {
    let missing_binding = VALID_V3.replace("[profiles.github]\n", "").replace("host = \"github.com\"\n", "").replace("account_id = \"4242\"\n", "").replace("account_selector = \"work-user\"\n", "").replace("token_fingerprint = \"hmac-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n", "").replace("repositories = [\"acme/project\", \"ybarbara/project\"]\n", "");
    assert!(Config::parse(&missing_binding).is_err());
    let non_allowlisted = VALID_V3.replace(
        "repository = \"acme/project\"",
        "repository = \"other/project\"",
    );
    assert!(Config::parse(&non_allowlisted).is_err());
    let mismatched_remote = VALID_V3.replace(
        "push_destinations = [\"https://github.com/ybarbara/project.git\"]",
        "push_destinations = [\"https://github.com/other/project.git\"]",
    );
    assert!(Config::parse(&mismatched_remote).is_err());
}

#[test]
fn v2_ssh_policy_requires_exact_host_key_and_private_transport_paths() {
    let valid = r#"
version = 2
[[profiles]]
name = "work"
[profiles.git]
author = { name = "Synthetic", email = "synthetic@example.invalid" }
committer = { name = "Synthetic", email = "synthetic@example.invalid" }
[profiles.ssh]
host = "github.com"
user = "git"
port = 22
fingerprint = "SHA256:abcDEF0123+/="
public_key = "/tmp/synthetic.pub"
identity_file = "/tmp/synthetic"
known_hosts_file = "/tmp/known_hosts"
[[scopes]]
name = "work"
path = "/tmp/work"
profile = "work"
"#;
    let config = Config::parse(valid).expect("valid SSH policy");
    assert_eq!(
        config.profiles()[0].ssh.as_ref().unwrap().host,
        "github.com"
    );

    let missing_identity = valid.replace(
        "identity_file = \"/tmp/synthetic\"",
        "# no identity or agent",
    );
    assert!(matches!(
        Config::parse(&missing_identity),
        Err(ConfigError::InvalidSshPolicy { .. })
    ));
    let unsafe_host = valid.replace("host = \"github.com\"", "host = \"github.com;proxy\"");
    assert!(matches!(
        Config::parse(&unsafe_host),
        Err(ConfigError::InvalidSshPolicy { .. })
    ));
    let ambiguous_identity = valid.replace(
        "identity_file = \"/tmp/synthetic\"",
        "identity_file = \"/tmp/synthetic\"\nagent_socket = \"/tmp/agent.sock\"",
    );
    assert!(matches!(
        Config::parse(&ambiguous_identity),
        Err(ConfigError::InvalidSshPolicy { .. })
    ));
}

#[test]
fn upstream_baselines_are_pinned_to_the_configured_remote_and_valid_oid() {
    let valid = r#"
version = 2
[[profiles]]
name = "work"
[profiles.git]
author = { name = "Synthetic", email = "synthetic@example.invalid" }
committer = { name = "Synthetic", email = "synthetic@example.invalid" }
[profiles.git.push]
remote = "origin"
destinations = ["https://example.invalid/repo.git"]
upstream_baselines = [{ destination = "https://example.invalid/repo.git", tracking_ref = "refs/remotes/origin/main", oid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }]
[[scopes]]
name = "work"
path = "/tmp/work"
profile = "work"
"#;
    let config = Config::parse(valid).expect("valid pinned baseline");
    let policy = config.profiles()[0].git.push.as_ref().unwrap();
    assert_eq!(policy.upstream_baselines.len(), 1);
    assert_eq!(
        policy.upstream_baselines[0].tracking_ref,
        "refs/remotes/origin/main"
    );
    assert_eq!(
        policy.upstream_baselines[0].destination,
        "https://example.invalid/repo.git"
    );

    for invalid in [
        valid.replace("refs/remotes/origin/main", "refs/remotes/other/main"),
        valid.replace("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "not-an-oid"),
    ] {
        assert!(matches!(
            Config::parse(&invalid),
            Err(ConfigError::InvalidUpstreamBaseline { .. })
        ));
    }
}

#[test]
fn annotated_tag_push_opt_in_requires_a_signing_policy() {
    let input = format!(
        "{VALID_CONFIG}\n[scopes.git.push]\nremote = \"origin\"\ndestinations = [\"file:///synthetic.git\"]\nallow_annotated_tags = true\n"
    );
    assert!(matches!(
        Config::parse(&input),
        Err(ConfigError::AnnotatedTagsRequireSigning { .. })
    ));
}

#[test]
fn publication_policy_defaults_are_conservative_and_survive_v2_migration() {
    let legacy = format!(
        "{VALID_CONFIG}\n[scopes.git.push]\nremote = \"origin\"\ndestinations = [\"https://github.com/example/repo.git\"]\n"
    );
    let parsed = Config::parse(&legacy).expect("legacy push policy");
    let policy = parsed.policies()[0].git.push.as_ref().unwrap();
    assert!(policy.allow_initial_push);
    assert!(policy.allow_fast_forward);
    assert!(!policy.allow_annotated_tags);
    assert!(!policy.allow_lightweight_tags);
    assert!(!policy.allow_branch_deletion);
    assert!(!policy.allow_tag_deletion);
    assert!(!policy.allow_force_with_lease);

    let migrated = parsed.to_v2_toml().expect("serialize v2 policy");
    let reparsed = Config::parse(&migrated).expect("reparse migrated policy");
    assert_eq!(
        reparsed.policies()[0].git.push,
        parsed.policies()[0].git.push
    );
}

#[test]
fn v1_configuration_can_be_migrated_explicitly_to_v2() {
    let legacy = Config::parse(VALID_CONFIG).expect("valid v1 policy");
    let migrated = legacy.to_v2_toml().expect("serialize v2 preview");
    let current = Config::parse(&migrated).expect("migrated config parses");

    assert_eq!(current.version(), 2);
    assert_eq!(current.profiles().len(), 1);
    assert_eq!(current.profiles()[0].name, "work");
    assert_eq!(current.policies()[0].name, "work");
    assert_eq!(
        current.policies()[0].git.author.email,
        "author@example.invalid"
    );
}

#[test]
fn profile_and_scope_edits_are_validated_and_v1_edits_become_v3() {
    let mut config = Config::parse(VALID_CONFIG).expect("legacy config");
    let profile = persona::config::Profile {
        name: "personal".to_owned(),
        git: config.policies()[0].git.clone(),
        github: None,
        ssh: None,
        github_merge: None,
    };
    config.add_profile(profile.clone()).expect("add profile");
    config
        .add_scope(
            "personal-project".to_owned(),
            "/personal/project".into(),
            "personal",
        )
        .expect("add profile-backed scope");
    assert_eq!(config.version(), 3);
    assert_eq!(config.policies()[1].profile, "personal");
    assert_eq!(
        config.remove_profile("personal"),
        Err(ConfigError::ProfileInUse("personal".to_owned()))
    );

    let mut changed = profile;
    changed.git.author.name = "Updated Author".to_owned();
    config.update_profile(changed).expect("update profile");
    assert_eq!(config.policies()[1].git.author.name, "Updated Author");
    config
        .remove_scope("personal-project")
        .expect("remove scope");
    config
        .remove_profile("personal")
        .expect("remove unused profile");
    assert_eq!(config.profiles().len(), 1);
}

#[test]
fn v2_rejects_missing_profile_references_and_unknown_fields() {
    let missing = VALID_V2.replace("profile = \"work\"", "profile = \"missing\"");
    assert!(matches!(
        Config::parse(&missing),
        Err(ConfigError::UnknownProfile { .. })
    ));

    let unknown = VALID_V2.replace("name = \"work\"", "name = \"work\"\nunexpected = true");
    assert_eq!(
        Config::parse(&unknown).unwrap_err(),
        ConfigError::InvalidToml
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
