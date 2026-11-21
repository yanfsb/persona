use persona::config::{Config, ConfigError, SigningFormat};
use std::path::Path;

const MINIMAL_V4: &str = r#"
version = 4

[profiles.work]
scopes = ["/work"]
author = { name = "Test Author", email = "author@example.invalid" }
committer = { name = "Test Committer", email = "committer@example.invalid" }
"#;

const MULTI_SCOPE_V4: &str = r#"
version = 4

[profiles.work]
author = { name = "Test Author", email = "author@example.invalid" }
committer = { name = "Test Committer", email = "committer@example.invalid" }

[scopes]
work-one = { path = "/work/one", profile = "work" }
work-two = { path = "/work/two", profile = "work" }
"#;

const FULL_V4: &str = r#"
version = 4

[profiles.work]
scopes = ["/work"]
author = { name = "Test Author", email = "author@example.invalid" }
committer = { name = "Test Committer", email = "committer@example.invalid" }

[profiles.work.git.remotes.upstream]
fetch = ["https://github.com/acme/project.git"]

[profiles.work.git.remotes.origin]
fetch = ["https://github.com/example/project.git"]
push = ["https://github.com/example/project.git"]

[profiles.work.github]
account_id = "4242"
account_selector = "work-user"
token_fingerprint = "hmac-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
repos = ["acme/project", "example/project"]

[profiles.work.github.merge."acme/project"]
base_branches = ["main"]
strategies = ["squash"]
"#;

#[test]
fn parses_expected_identities_and_converts_scopes() {
    let config = Config::parse(MINIMAL_V4).expect("valid v4 policy");

    assert_eq!(config.version(), 4);
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
fn flat_name_and_email_populate_both_author_and_committer() {
    let input = r#"
version = 4

[profiles.personal]
scopes = ["/personal"]
name = "Synthetic Dev"
email = "dev@example.invalid"
"#;
    let config = Config::parse(input).expect("flat identity parses");
    let git = &config.profiles()[0].git;
    assert_eq!(git.author.name, "Synthetic Dev");
    assert_eq!(git.author.email, "dev@example.invalid");
    assert_eq!(git.committer, git.author);
}

#[test]
fn rejects_ambiguous_flat_and_explicit_author_identity() {
    let input = r#"
version = 4

[profiles.work]
scopes = ["/work"]
name = "Flat"
author = { name = "Explicit", email = "author@example.invalid" }
"#;
    assert!(matches!(
        Config::parse(input),
        Err(ConfigError::AmbiguousIdentity { .. })
    ));
}

#[test]
fn rejects_unsupported_versions() {
    for legacy in [1, 2, 3, 5] {
        let input = MINIMAL_V4.replace("version = 4", &format!("version = {legacy}"));
        assert_eq!(
            Config::parse(&input).unwrap_err(),
            ConfigError::UnsupportedVersion(legacy)
        );
    }
}

#[test]
fn profiles_can_be_reused_by_multiple_scopes() {
    let config = Config::parse(MULTI_SCOPE_V4).expect("valid multi-scope v4 policy");

    assert_eq!(config.version(), 4);
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
fn profile_extends_inherits_scalars_replaces_lists_and_keeps_scopes_independent() {
    let input = r#"
version = 4

[profiles.base]
scopes = ["/work"]
name = "Base Dev"
email = "base@example.invalid"

[profiles.base.signing]
fingerprint = "0123456789abcdef0123456789abcdef01234567"
public_key = "/tmp/base.asc"

[profiles.base.ssh]
hosts = ["github.com", "forge.example.invalid"]
fingerprint = "SHA256:abcDEF0123+/="
identity_file = "/tmp/id_ed25519"
known_hosts_file = "/tmp/known_hosts"

[profiles.base.github]
account_id = "1001"
account_selector = "base-user"
token_fingerprint = "hmac-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
repos = ["org-a/*", "org-b/*"]

[profiles.base.git]
fetch = ["github.com/*", "forge.example.invalid/*"]
push = ["github.com/org-a/*", "forge.example.invalid/team/*"]
preserve_authors = true
allow_annotated_tags = true
allow_branch_deletion = true
allow_force_with_lease = true
allow_force_push = true

[profiles.base.https."forge.example.invalid"]
helper = "/usr/local/bin/forge-helper"
args = ["credential-helper"]

[profiles.strict]
extends = "base"
scopes = [{ name = "strict-repo", path = "/work/strict" }]
github.repos = ["org-a/strict"]
git.remote = "origin"
git.push = ["git@github.com:org-a/strict.git"]
git.fetch = ["git@github.com:org-a/strict.git"]
git.preserve_authors = false
git.allow_branch_deletion = false
git.allow_force_with_lease = false
git.allow_force_push = false

[profiles.alt]
extends = "base"
scopes = ["/alt"]
name = "Alt Name"
"#;

    let config = Config::parse(input).expect("inherited v4 policy parses");
    assert_eq!(config.profiles().len(), 3);
    assert_eq!(config.policies().len(), 3);

    let strict = config
        .profiles()
        .iter()
        .find(|p| p.name == "strict")
        .unwrap();
    assert_eq!(strict.extends.as_deref(), Some("base"));
    assert_eq!(strict.git.author.name, "Base Dev");
    assert_eq!(strict.git.author.email, "base@example.invalid");
    assert_eq!(
        strict.git.signing.as_ref().unwrap().format,
        SigningFormat::OpenPgp
    );
    assert_eq!(strict.ssh_policies().len(), 2);
    assert_eq!(
        strict.ssh.as_ref().unwrap().public_key,
        Path::new("/tmp/id_ed25519.pub")
    );
    assert_eq!(strict.ssh.as_ref().unwrap().user, "git");
    assert_eq!(strict.ssh.as_ref().unwrap().port, 22);
    assert_eq!(
        strict.github.as_ref().unwrap().repositories,
        ["org-a/strict"]
    );
    assert_eq!(strict.github.as_ref().unwrap().account_id, "1001");
    let push = strict.git.push.as_ref().unwrap();
    assert_eq!(push.remote, "origin");
    assert_eq!(push.destinations, ["git@github.com:org-a/strict.git"]);
    assert!(push.allow_annotated_tags);
    assert!(!push.preserve_authors);
    assert!(!push.allow_branch_deletion);
    assert!(!push.allow_force_with_lease);
    assert!(!push.allow_force_push);
    assert!(
        strict
            .git
            .permits_push_destination("origin", "git@github.com:org-a/strict.git")
    );
    assert!(
        !strict
            .git
            .permits_push_destination("origin", "https://github.com/org-a/strict.git")
    );
    assert!(
        !strict
            .git
            .permits_push_destination("origin", "git@github.com:org-a/other.git")
    );

    let alt = config.profiles().iter().find(|p| p.name == "alt").unwrap();
    assert_eq!(alt.git.author.name, "Alt Name");
    assert_eq!(alt.git.author.email, "base@example.invalid");
    assert_eq!(alt.git.committer.name, "Alt Name");
    assert_eq!(alt.git.committer.email, "base@example.invalid");

    // Round-trip preserves `extends` and remains compact.
    let serialized = config.to_v4_toml().expect("serialize v4");
    assert!(serialized.contains("extends = \"base\""));
    let reparsed = Config::parse(&serialized).expect("reparse v4");
    assert_eq!(reparsed.profiles(), config.profiles());

    // Resolved view flattens inheritance.
    let resolved_toml = config.to_resolved_v4_toml().expect("serialize resolved v4");
    assert!(!resolved_toml.contains("extends ="));
    let reparsed_resolved = Config::parse(&resolved_toml).expect("reparse resolved v4");
    assert_eq!(reparsed_resolved.profiles().len(), 3);
}

#[test]
fn rejects_unknown_and_cyclic_profile_extends() {
    let missing_parent = r#"
version = 4

[profiles.child]
extends = "nonexistent"
scopes = ["/work"]
name = "Child"
email = "child@example.invalid"
"#;
    assert!(matches!(
        Config::parse(missing_parent),
        Err(ConfigError::UnknownParentProfile { .. })
    ));

    let cyclic = r#"
version = 4

[profiles.a]
extends = "b"
scopes = ["/a"]
name = "A"
email = "a@example.invalid"

[profiles.b]
extends = "a"
scopes = ["/b"]
"#;
    assert!(matches!(
        Config::parse(cyclic),
        Err(ConfigError::CyclicProfileInheritance(_))
    ));
}

#[test]
fn forge_shorthands_expand_to_ssh_and_https_while_explicit_urls_stay_protocol_scoped() {
    let input = r#"
version = 4

[profiles.dev]
scopes = ["/work"]
name = "Dev"
email = "dev@example.invalid"

[profiles.dev.git]
fetch = ["github.com/*"]
push = ["github.com/org-a/*", "github.com/org-b/repo", "git@forge.example.invalid:team/ssh-only.git"]
deny = ["github.com/org-a/secret"]
"#;
    let config = Config::parse(input).expect("shorthands parse");
    let git = &config.profiles()[0].git;

    // Wildcard shorthand matches both SSH and HTTPS.
    assert!(git.permits_push_destination("origin", "git@github.com:org-a/app.git"));
    assert!(git.permits_push_destination("origin", "https://github.com/org-a/app.git"));
    // Exact shorthand matches with or without `.git` over both protocols.
    assert!(git.permits_push_destination("origin", "git@github.com:org-b/repo.git"));
    assert!(git.permits_push_destination("origin", "https://github.com/org-b/repo.git"));
    assert!(git.permits_push_destination("origin", "https://github.com/org-b/repo"));
    // Deny shorthand blocks both SSH and HTTPS.
    assert!(!git.permits_push_destination("origin", "git@github.com:org-a/secret.git"));
    assert!(!git.permits_push_destination("origin", "https://github.com/org-a/secret.git"));
    // Explicit SSH URL blocks HTTPS.
    assert!(git.permits_push_destination("origin", "git@forge.example.invalid:team/ssh-only.git"));
    assert!(
        !git.permits_push_destination("origin", "https://forge.example.invalid/team/ssh-only.git")
    );
    // Fetch wildcard allows any GitHub repo.
    assert!(git.permits_fetch_destination("upstream", "https://github.com/other/project.git"));
    assert!(git.permits_fetch_destination("upstream", "git@github.com:other/project.git"));
}

#[test]
fn expands_leading_tilde_against_home_and_rejects_relative_or_env_paths() {
    let input = r#"
version = 4

[profiles.home]
scopes = ["~/projects"]
name = "Home"
email = "home@example.invalid"

[profiles.home.signing]
fingerprint = "0123456789abcdef0123456789abcdef01234567"
public_key = "~/.config/persona/keys/pub.asc"

[profiles.home.ssh]
host = "github.com"
fingerprint = "SHA256:abcDEF0123+/="
identity_file = "~/.ssh/id_ed25519"
"#;
    let config =
        Config::parse_with_home(input, Some(Path::new("/home/synthetic"))).expect("tilde parses");
    assert_eq!(
        config.policies()[0].path,
        Path::new("/home/synthetic/projects")
    );
    assert_eq!(
        config.profiles()[0]
            .git
            .signing
            .as_ref()
            .unwrap()
            .public_key,
        Path::new("/home/synthetic/.config/persona/keys/pub.asc")
    );
    let ssh = config.profiles()[0].ssh.as_ref().unwrap();
    assert_eq!(
        ssh.identity_file.as_deref(),
        Some(Path::new("/home/synthetic/.ssh/id_ed25519"))
    );
    assert_eq!(
        ssh.public_key,
        Path::new("/home/synthetic/.ssh/id_ed25519.pub")
    );
    assert_eq!(
        ssh.known_hosts_file,
        Path::new("/home/synthetic/.ssh/known_hosts")
    );

    // Fails closed if HOME is unavailable when `~/` is used.
    assert!(matches!(
        Config::parse_with_home(input, None),
        Err(ConfigError::RelativeSigningKey { .. } | ConfigError::RelativeScopePath(_))
    ));
    let tilde_scope_only = MINIMAL_V4.replace("\"/work\"", "\"~/work\"");
    assert!(matches!(
        Config::parse_with_home(&tilde_scope_only, None),
        Err(ConfigError::RelativeScopePath(_))
    ));

    // Still rejects relative paths, `$HOME`, `~other`, and `~/../escape`.
    for bad in ["work", "./work", "$HOME/work", "~other/work", "~/../escape"] {
        let invalid = MINIMAL_V4.replace("\"/work\"", &format!("{bad:?}"));
        assert!(
            matches!(
                Config::parse_with_home(&invalid, Some(Path::new("/home/synthetic"))),
                Err(ConfigError::RelativeScopePath(_))
            ),
            "expected RelativeScopePath for {bad:?}"
        );
    }
}

#[test]
fn git_command_policy_supports_allow_deny_precedence_and_round_trips() {
    let input = format!(
        "{FULL_V4}\n[profiles.work.git.commands]\nallow = [\"status\", \"fetch.all\"]\ndeny = [\"push\"]\n"
    );
    let config = Config::parse(&input).expect("valid command policy");
    let commands = &config.profiles()[0].git.commands;
    assert!(commands.permits("status"));
    assert!(commands.permits("fetch.all"));
    assert!(!commands.permits("fetch"));
    assert!(!commands.permits("push"));

    let serialized = config.to_v4_toml().expect("serialize v4");
    let reparsed = Config::parse(&serialized).expect("reparse v4");
    assert_eq!(reparsed.profiles()[0].git.commands, *commands);
}

#[test]
fn git_command_policy_rejects_unknown_and_duplicate_selectors() {
    for commands in [
        "[profiles.work.git.commands]\nallow = [\"status;id\"]",
        "[profiles.work.git.commands]\ndeny = [\"*status\"]",
        "[profiles.work.git.commands]\ndeny = [\"status\", \"status\"]",
    ] {
        let input = format!("{FULL_V4}\n{commands}\n");
        assert!(Config::parse(&input).is_err());
    }
}

#[test]
fn command_policy_empty_allowlist_denies_all_and_broad_deny_wins() {
    let empty_allow = persona::config::GitCommandPolicy {
        mode: None,
        allow: Some(Vec::new()),
        deny: Vec::new(),
    };
    assert!(!empty_allow.permits("status"));

    let deny_fetch = persona::config::GitCommandPolicy {
        mode: None,
        allow: Some(vec!["fetch.all".to_owned()]),
        deny: vec!["fetch".to_owned()],
    };
    assert!(!deny_fetch.permits("fetch.all"));

    let allow_fetch = persona::config::GitCommandPolicy {
        mode: None,
        allow: Some(vec!["fetch".to_owned()]),
        deny: Vec::new(),
    };
    assert!(allow_fetch.permits("fetch.all"));
}

#[test]
fn remotes_auto_derive_push_policy_and_merge_policy_round_trips() {
    let config = Config::parse(FULL_V4).expect("valid full v4 policy");
    assert_eq!(config.version(), 4);
    let profile = &config.profiles()[0];
    assert_eq!(profile.git.remotes.len(), 2);
    let push = profile
        .git
        .push
        .as_ref()
        .expect("push policy derived from origin remote");
    assert_eq!(push.remote, "origin");
    assert_eq!(
        push.destinations,
        ["https://github.com/example/project.git"]
    );
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

    let serialized = config.to_v4_toml().expect("serialize v4");
    let reparsed = Config::parse(&serialized).expect("reparse v4");
    assert_eq!(reparsed.profiles()[0].git.remotes, profile.git.remotes);
    assert_eq!(reparsed.profiles()[0].github_merge, profile.github_merge);
}

#[test]
fn merge_policy_requires_enrolled_allowlisted_repository() {
    let non_allowlisted = FULL_V4.replace(
        "[profiles.work.github.merge.\"acme/project\"]",
        "[profiles.work.github.merge.\"other/project\"]",
    );
    assert!(matches!(
        Config::parse(&non_allowlisted),
        Err(ConfigError::InvalidGithubMergePolicy { .. })
    ));

    let mismatched_push = format!(
        "{FULL_V4}\n[profiles.work.git]\nremote = \"origin\"\npush = [\"https://github.com/other/project.git\"]\n"
    );
    assert!(Config::parse(&mismatched_push).is_err());
}

#[test]
fn ssh_policy_supports_multi_host_extra_and_rejects_duplicates_or_ambiguous_auth() {
    let valid = r#"
version = 4

[profiles.work]
scopes = ["/tmp/work"]
name = "Synthetic"
email = "synthetic@example.invalid"

[profiles.work.ssh]
hosts = ["github.com", "forge.example.invalid"]
fingerprint = "SHA256:abcDEF0123+/="
public_key = "/tmp/github.pub"
identity_file = "/tmp/github"
known_hosts_file = "/tmp/known_hosts"

[[profiles.work.ssh.extra]]
host = "alt.example.invalid"
port = 2222
fingerprint = "SHA256:xyzDEF0123+/="
public_key = "/tmp/alt.pub"
agent_socket = "/tmp/agent.sock"
known_hosts_file = "/tmp/known_hosts"

[profiles.work.https."forge.example.invalid"]
helper = "/nix/store/example/bin/origin"
args = ["auth", "git-credential"]
"#;
    let config = Config::parse(valid).expect("multi-forge profile parses");
    let profile = &config.profiles()[0];
    assert!(profile.has_ssh_policy());
    assert_eq!(profile.ssh_policies().len(), 3);
    assert_eq!(profile.ssh_policies()[1].host, "forge.example.invalid");
    assert_eq!(profile.ssh_policies()[2].port, 2222);
    assert_eq!(
        profile
            .https_credential_for_host("FORGE.EXAMPLE.INVALID")
            .unwrap()
            .args,
        ["auth", "git-credential"]
    );
    let reparsed = Config::parse(&config.to_v4_toml().unwrap()).unwrap();
    assert_eq!(reparsed.profiles()[0].ssh_policies().len(), 3);

    // Reject duplicate SSH selector across hosts / extra.
    let duplicate_ssh = valid.replace(
        "host = \"alt.example.invalid\"\nport = 2222",
        "host = \"GITHUB.COM\"",
    );
    assert!(matches!(
        Config::parse(&duplicate_ssh),
        Err(ConfigError::InvalidSshPolicy { .. })
    ));

    // Reject both identity_file and agent_socket.
    let ambiguous = valid.replace(
        "identity_file = \"/tmp/github\"",
        "identity_file = \"/tmp/github\"\nagent_socket = \"/tmp/agent.sock\"",
    );
    assert!(matches!(
        Config::parse(&ambiguous),
        Err(ConfigError::InvalidSshPolicy { .. })
    ));

    // Reject GitHub host in https credentials.
    let github_helper = r#"
version = 4

[profiles.work]
scopes = ["/tmp/work"]
name = "Synthetic"
email = "synthetic@example.invalid"

[profiles.work.https."api.ghe.com"]
helper = "/usr/bin/git"
"#;
    assert!(matches!(
        Config::parse(github_helper),
        Err(ConfigError::InvalidHttpsCredentialPolicy { .. })
    ));
}

#[test]
fn upstream_baselines_and_annotated_tags_are_validated() {
    let valid = r#"
version = 4

[profiles.work]
scopes = ["/tmp/work"]
name = "Synthetic"
email = "synthetic@example.invalid"

[profiles.work.git]
remote = "origin"
push = ["https://example.invalid/repo.git"]
baselines = [{ destination = "https://example.invalid/repo.git", tracking_ref = "refs/remotes/origin/main", oid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }]
"#;
    let config = Config::parse(valid).expect("valid pinned baseline");
    let policy = config.profiles()[0].git.push.as_ref().unwrap();
    assert_eq!(policy.upstream_baselines.len(), 1);

    for invalid in [
        valid.replace("refs/remotes/origin/main", "refs/remotes/other/main"),
        valid.replace("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "not-an-oid"),
    ] {
        assert!(matches!(
            Config::parse(&invalid),
            Err(ConfigError::InvalidUpstreamBaseline { .. })
        ));
    }

    let tags_without_signing = format!("{valid}\nallow_annotated_tags = true\n");
    assert!(matches!(
        Config::parse(&tags_without_signing),
        Err(ConfigError::AnnotatedTagsRequireSigning { .. })
    ));
}

#[test]
fn publication_policy_defaults_are_conservative_and_omitted_on_serialization() {
    let input = r#"
version = 4

[profiles.work]
scopes = ["/work"]
name = "Test"
email = "test@example.invalid"

[profiles.work.git]
remote = "origin"
push = ["https://github.com/example/repo.git"]
"#;
    let parsed = Config::parse(input).expect("push policy");
    let policy = parsed.policies()[0].git.push.as_ref().unwrap();
    assert!(policy.allow_initial_push);
    assert!(policy.allow_fast_forward);
    assert!(!policy.allow_annotated_tags);
    assert!(!policy.allow_lightweight_tags);
    assert!(!policy.allow_branch_deletion);
    assert!(!policy.allow_tag_deletion);
    assert!(!policy.allow_force_with_lease);
    assert!(!policy.allow_force_push);

    let serialized = parsed.to_v4_toml().expect("serialize v4");
    assert!(!serialized.contains("allow_fast_forward"));
    assert!(!serialized.contains("allow_force_with_lease"));
    assert!(!serialized.contains("preserve_authors"));
}

#[test]
fn profile_and_scope_mutations_validate_and_block_removing_parent_or_in_use_profile() {
    let mut config = Config::parse(MINIMAL_V4).expect("base config");
    let mut personal = config.profiles()[0].clone();
    personal.name = "personal".to_owned();
    personal.extends = Some("work".to_owned());
    config
        .add_profile(personal.clone())
        .expect("add child profile");

    // Removing `work` while `personal` extends it must fail.
    config
        .add_scope(
            "personal-project".to_owned(),
            "/personal/project".into(),
            "personal",
        )
        .expect("add profile-backed scope");
    assert_eq!(
        config.remove_profile("personal"),
        Err(ConfigError::ProfileInUse("personal".to_owned()))
    );

    let mut changed = personal;
    changed.git.author.name = "Updated Author".to_owned();
    config.update_profile(changed).expect("update profile");
    assert_eq!(
        config
            .policies()
            .iter()
            .find(|scope| scope.name == "personal-project")
            .unwrap()
            .git
            .author
            .name,
        "Updated Author"
    );

    config
        .remove_scope("personal-project")
        .expect("remove scope");
    config
        .remove_profile("personal")
        .expect("remove unused profile");
    assert_eq!(config.profiles().len(), 1);
}

#[test]
fn rejects_unknown_fields_empty_scopes_duplicate_names_and_empty_identities() {
    let unknown = MINIMAL_V4.replace("version = 4", "version = 4\nunexpected = true");
    assert!(matches!(
        Config::parse(&unknown),
        Err(ConfigError::InvalidToml(msg)) if msg.contains("unexpected")
    ));

    let no_scopes = "version = 4\n[profiles.work]\nname = \"A\"\nemail = \"a@example.invalid\"\n";
    assert_eq!(
        Config::parse(no_scopes).unwrap_err(),
        ConfigError::EmptyScopes
    );

    let missing_profile =
        format!("{MINIMAL_V4}\n[scopes]\nextra = {{ path = \"/extra\", profile = \"missing\" }}\n");
    assert!(matches!(
        Config::parse(&missing_profile),
        Err(ConfigError::UnknownProfile { .. })
    ));

    let empty_email = MINIMAL_V4.replace("author@example.invalid", "");
    assert_eq!(
        Config::parse(&empty_email).unwrap_err(),
        ConfigError::EmptyIdentity {
            scope: "work".to_owned(),
            role: "author".to_owned(),
        }
    );

    let invalid_run = format!("{MINIMAL_V4}\n[profiles.work.run]\ndeny = [\"curl;id\"]\n");
    assert!(matches!(
        Config::parse(&invalid_run),
        Err(ConfigError::InvalidRunCommandPolicy { .. })
    ));
}

#[test]
fn signing_format_is_inferred_from_fingerprint_when_omitted() {
    let ssh_sig = format!(
        "{MINIMAL_V4}\n[profiles.work.signing]\nfingerprint = \"SHA256:abcDEF0123+/=\"\npublic_key = \"/tmp/signing.pub\"\n"
    );
    let config = Config::parse(&ssh_sig).expect("ssh signing inferred");
    assert_eq!(
        config.profiles()[0].git.signing.as_ref().unwrap().format,
        SigningFormat::Ssh
    );

    let pgp_sig = format!(
        "{MINIMAL_V4}\n[profiles.work.signing]\nfingerprint = \"0123456789abcdef0123456789abcdef01234567\"\npublic_key = \"/tmp/public.asc\"\n"
    );
    let config = Config::parse(&pgp_sig).expect("openpgp signing inferred");
    assert_eq!(
        config.profiles()[0].git.signing.as_ref().unwrap().format,
        SigningFormat::OpenPgp
    );
}
