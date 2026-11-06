use persona::git::{GitClient, PushTuple, safe_environment};
use persona::push::{PublicationPlan, UpdateClass};
use serde_json::Value;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

fn git() -> PathBuf {
    std::env::var_os("PERSONA_TEST_GIT")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::split_paths(&std::env::var_os("PATH").unwrap())
                .map(|p| p.join("git"))
                .find(|p| p.is_file())
        })
        .expect("Git executable")
}

fn run_git(root: &Path, args: &[&str]) -> Output {
    Command::new(git())
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .current_dir(root)
        .args(args)
        .output()
        .expect("run Git")
}

fn run_git_with_input(root: &Path, args: &[&str], input: &[u8]) -> Output {
    use std::io::Write;
    let mut child = Command::new(git())
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .current_dir(root)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn Git input fixture");
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().expect("collect Git fixture")
}

fn success(output: Output) -> Output {
    assert!(
        output.status.success(),
        "Git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

struct Fixture {
    _temporary: TempDir,
    repo: PathBuf,
    remote: PathBuf,
    policy: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary fixture");
        let repo = temporary.path().join("repo");
        let remote = temporary.path().join("remote.git");
        let policy = temporary.path().join("policy.toml");
        fs::create_dir_all(&repo).expect("repo directory");
        success(run_git(
            temporary.path(),
            &["init", "--template=", "-b", "main", repo.to_str().unwrap()],
        ));
        success(run_git(&repo, &["config", "user.name", "Good Author"]));
        success(run_git(
            &repo,
            &["config", "user.email", "good@example.invalid"],
        ));
        success(run_git(
            temporary.path(),
            &["init", "--bare", remote.to_str().unwrap()],
        ));
        success(run_git(
            &repo,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        ));
        Self {
            _temporary: temporary,
            repo,
            remote,
            policy,
        }
    }

    fn write_policy(&self, destinations: &str) {
        self.write_policy_with_author_preservation(destinations, false);
    }

    fn write_policy_with_author_preservation(&self, destinations: &str, preserve_authors: bool) {
        let root = self.repo.to_string_lossy();
        fs::write(&self.policy, format!(
            "version=1\n[[scopes]]\nname=\"scope\"\npath=\"{root}\"\n[scopes.git]\nauthor={{name=\"Good Author\",email=\"good@example.invalid\"}}\ncommitter={{name=\"Good Author\",email=\"good@example.invalid\"}}\n[scopes.git.push]\nremote=\"origin\"\ndestinations={destinations}\npreserve_authors={preserve_authors}\n"
        )).expect("policy");
    }

    fn commit(&self, name: &str, email: &str) -> String {
        success(run_git(
            &self.repo,
            &[
                "-c",
                "user.name=Good Author",
                "-c",
                &format!("user.email={email}"),
                "commit",
                "--allow-empty",
                "-m",
                name,
            ],
        ));
        String::from_utf8_lossy(&success(run_git(&self.repo, &["rev-parse", "HEAD"])).stdout)
            .trim()
            .to_owned()
    }

    fn run_audit(&self, tuples: &str, destination: &str) -> Value {
        let output = Command::new(env!("CARGO_BIN_EXE_persona"))
            .env_clear()
            .env("PERSONA_GIT", git())
            .env("GIT_NO_REPLACE_OBJECTS", "0")
            .env("PATH", "/usr/bin:/bin")
            .args(["check", "--config"])
            .arg(&self.policy)
            .args(["--cwd"])
            .arg(&self.repo)
            .args([
                "--format",
                "json",
                "--operation",
                "push",
                "--remote",
                "origin",
                "--destination",
                destination,
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child.stdin.take().unwrap().write_all(tuples.as_bytes())?;
                child.wait_with_output()
            })
            .expect("run persona");
        let report: Value = serde_json::from_slice(&output.stdout).expect("JSON report");
        let expected_exit = if report["verdict"] == "ALLOW" { 0 } else { 1 };
        assert_eq!(output.status.code(), Some(expected_exit), "{report:#}");
        report
    }
}

fn finding<'a>(report: &'a Value, property: &str) -> &'a Value {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["property"] == property)
        .unwrap_or_else(|| panic!("finding {property} missing from {report}"))
}

#[test]
fn publication_policy_blocks_first_push_when_disabled() {
    let fixture = Fixture::new();
    let head = fixture.commit("first", "good@example.invalid");
    let destination = fixture.remote.to_string_lossy().into_owned();
    fixture.write_policy(&format!("[{:?}]", destination));
    let policy = fs::read_to_string(&fixture.policy).unwrap();
    fs::write(
        &fixture.policy,
        policy.replace(
            "preserve_authors=false",
            "preserve_authors=false\nallow_initial_push=false",
        ),
    )
    .unwrap();
    let report = fixture.run_audit(
        &format!(
            "refs/heads/main {head} refs/heads/main {}\n",
            "0".repeat(40)
        ),
        &destination,
    );
    assert_eq!(finding(&report, "git.push.updates")["status"], "FAIL");
    assert_eq!(report["verdict"], "BLOCK");
}

#[test]
fn fast_forward_is_blocked_when_fast_forward_policy_is_disabled() {
    let fixture = Fixture::new();
    let base = fixture.commit("base", "good@example.invalid");
    let head = fixture.commit("advance", "good@example.invalid");
    let destination = fixture.remote.to_string_lossy().into_owned();
    fixture.write_policy(&format!("[{:?}]", destination));
    let policy = fs::read_to_string(&fixture.policy).unwrap();
    fs::write(
        &fixture.policy,
        policy.replace(
            "preserve_authors=false",
            "preserve_authors=false\nallow_fast_forward=false",
        ),
    )
    .unwrap();

    let report = fixture.run_audit(
        &format!("refs/heads/main {head} refs/heads/main {base}\n"),
        &destination,
    );

    assert_eq!(finding(&report, "git.push.updates")["status"], "FAIL");
    assert_eq!(report["verdict"], "BLOCK");
}

#[test]
fn incomplete_or_corrupt_reachable_tree_or_blob_never_authorizes_initial_publication() {
    for (expression, corrupt) in [
        ("HEAD:payload", false),
        ("HEAD:payload", true),
        ("HEAD^{tree}", false),
        ("HEAD^{tree}", true),
    ] {
        let fixture = Fixture::new();
        fs::write(fixture.repo.join("payload"), "synthetic payload\n").unwrap();
        success(run_git(&fixture.repo, &["add", "payload"]));
        success(run_git(&fixture.repo, &["commit", "-m", "payload"]));
        let head = String::from_utf8_lossy(
            &success(run_git(&fixture.repo, &["rev-parse", "HEAD"])).stdout,
        )
        .trim()
        .to_owned();
        let object_oid = String::from_utf8_lossy(
            &success(run_git(&fixture.repo, &["rev-parse", expression])).stdout,
        )
        .trim()
        .to_owned();
        let object = fixture
            .repo
            .join(".git/objects")
            .join(&object_oid[..2])
            .join(&object_oid[2..]);
        if corrupt {
            fs::set_permissions(&object, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&object, b"corrupt synthetic object").unwrap();
        } else {
            fs::remove_file(object).unwrap();
        }
        let destination = fixture.remote.to_string_lossy().into_owned();
        fixture.write_policy(&format!("[{:?}]", destination));

        let report = fixture.run_audit(
            &format!(
                "refs/heads/main {head} refs/heads/main {}\n",
                "0".repeat(40)
            ),
            &destination,
        );

        assert_ne!(report["verdict"], "ALLOW", "{expression} corrupt={corrupt}");
        assert_ne!(
            finding(&report, "git.push.updates")["status"],
            "PASS",
            "{expression} corrupt={corrupt}"
        );
    }
}

#[test]
fn publication_plan_distinguishes_annotated_and_lightweight_tags() {
    let fixture = Fixture::new();
    let head = fixture.commit("tag target", "good@example.invalid");
    success(run_git(&fixture.repo, &["tag", "v-light", &head]));
    success(run_git(
        &fixture.repo,
        &["tag", "-a", "-m", "annotated", "v-annotated", &head],
    ));
    let git = GitClient::new(git(), safe_environment());
    let zero = "0".repeat(40);
    for (name, expected) in [
        ("v-light", UpdateClass::LightweightTag),
        ("v-annotated", UpdateClass::AnnotatedTag),
    ] {
        let oid = String::from_utf8_lossy(
            &success(run_git(
                &fixture.repo,
                &["rev-parse", &format!("refs/tags/{name}")],
            ))
            .stdout,
        )
        .trim()
        .to_owned();
        let plan = PublicationPlan::new(
            "origin",
            "file:///synthetic.git",
            &[PushTuple {
                local_ref: format!("refs/tags/{name}"),
                local_oid: oid,
                remote_ref: format!("refs/tags/{name}"),
                remote_oid: zero.clone(),
            }],
        )
        .unwrap()
        .with_local_history(
            &git,
            &fixture.repo,
            std::time::Instant::now() + std::time::Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(plan.updates()[0].class(), expected);
    }
}

#[test]
fn tag_message_text_cannot_masquerade_as_a_commit_target_header() {
    let fixture = Fixture::new();
    let commit = fixture.commit("tag target", "good@example.invalid");
    let tree = String::from_utf8_lossy(
        &success(run_git(
            &fixture.repo,
            &["rev-parse", &format!("{commit}^{{tree}}")],
        ))
        .stdout,
    )
    .trim()
    .to_owned();
    let malformed_tag = format!(
        "object {tree}\ntype tree\ntag fake-commit\ntagger Synthetic <tag@example.invalid> 1 +0000\n\nmessage text\n\ntype commit\n"
    );
    let oid = String::from_utf8_lossy(
        &success(run_git_with_input(
            &fixture.repo,
            &["hash-object", "-t", "tag", "-w", "--stdin"],
            malformed_tag.as_bytes(),
        ))
        .stdout,
    )
    .trim()
    .to_owned();
    success(run_git(
        &fixture.repo,
        &["update-ref", "refs/tags/fake-commit", &oid],
    ));
    let git = GitClient::new(git(), safe_environment());
    let plan = PublicationPlan::new(
        "origin",
        "file:///synthetic.git",
        &[PushTuple {
            local_ref: "refs/tags/fake-commit".to_owned(),
            local_oid: oid,
            remote_ref: "refs/tags/fake-commit".to_owned(),
            remote_oid: "0".repeat(40),
        }],
    )
    .unwrap()
    .with_local_history(
        &git,
        &fixture.repo,
        std::time::Instant::now() + std::time::Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(plan.updates()[0].class(), UpdateClass::UnsupportedRef);
}

#[test]
fn tag_policy_denials_and_unimplemented_opt_ins_never_authorize() {
    let fixture = Fixture::new();
    let head = fixture.commit("tag target", "good@example.invalid");
    success(run_git(&fixture.repo, &["tag", "light", &head]));
    success(run_git(
        &fixture.repo,
        &["tag", "-a", "-m", "signed later", "annotated", &head],
    ));
    let destination = fixture.remote.to_string_lossy().into_owned();
    fixture.write_policy(&format!("[{:?}]", destination));
    let zero = "0".repeat(40);
    let tag_oid = |name: &str| {
        String::from_utf8_lossy(
            &success(run_git(
                &fixture.repo,
                &["rev-parse", &format!("refs/tags/{name}")],
            ))
            .stdout,
        )
        .trim()
        .to_owned()
    };

    for (name, oid) in [
        ("light", tag_oid("light")),
        ("annotated", tag_oid("annotated")),
    ] {
        let tuple = format!("refs/tags/{name} {oid} refs/tags/{name} {zero}\n");
        let denied = fixture.run_audit(&tuple, &destination);
        assert_eq!(finding(&denied, "git.push.updates")["status"], "FAIL");
    }
    let deleted = fixture.run_audit(
        &format!("(delete) {zero} refs/tags/old {}\n", "a".repeat(40)),
        &destination,
    );
    assert_eq!(finding(&deleted, "git.push.updates")["status"], "FAIL");

    let policy = fs::read_to_string(&fixture.policy).unwrap();
    fs::write(
        &fixture.policy,
        format!(
            "{}\n[scopes.git.signing]\nfingerprint=\"{}\"\npublic_key=\"/tmp/persona-synthetic-public-key.asc\"\n",
            policy.replace(
                "preserve_authors=false",
                "preserve_authors=false\nallow_lightweight_tags=true\nallow_annotated_tags=true\nallow_tag_deletion=true",
            ),
            "A".repeat(40),
        ),
    )
    .unwrap();
    for (name, oid) in [
        ("light", tag_oid("light")),
        ("annotated", tag_oid("annotated")),
    ] {
        let tuple = format!("refs/tags/{name} {oid} refs/tags/{name} {zero}\n");
        let opted_in = fixture.run_audit(&tuple, &destination);
        let update_status = if name == "light" { "PASS" } else { "FAIL" };
        assert_eq!(
            finding(&opted_in, "git.push.updates")["status"],
            update_status
        );
        assert_eq!(opted_in["verdict"], "BLOCK");
    }
    let deletion = fixture.run_audit(
        &format!("(delete) {zero} refs/tags/old {}\n", "a".repeat(40)),
        &destination,
    );
    assert_eq!(finding(&deletion, "git.push.updates")["status"], "UNKNOWN");
    assert_eq!(deletion["verdict"], "BLOCK");
}

#[test]
fn pinned_upstream_baseline_allows_foreign_identity_but_blocks_when_ref_moves() {
    let fixture = Fixture::new();
    success(run_git(
        &fixture.repo,
        &[
            "-c",
            "user.name=Upstream Author",
            "-c",
            "user.email=upstream@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "pinned upstream commit",
        ],
    ));
    let oid =
        String::from_utf8_lossy(&success(run_git(&fixture.repo, &["rev-parse", "HEAD"])).stdout)
            .trim()
            .to_owned();
    success(run_git(
        &fixture.repo,
        &["update-ref", "refs/remotes/origin/main", &oid],
    ));
    let destination = fixture.remote.to_string_lossy().into_owned();
    fs::write(
        &fixture.policy,
        format!(
            r#"version=1
[[scopes]]
name="scope"
path={:?}
[scopes.git]
author={{name="Good Author",email="good@example.invalid"}}
committer={{name="Good Author",email="good@example.invalid"}}
[scopes.git.push]
remote="origin"
destinations=[{:?}]
[[scopes.git.push.upstream_baselines]]
destination={:?}
tracking_ref="refs/remotes/origin/main"
oid="{oid}"
"#,
            fixture.repo, destination, destination
        ),
    )
    .unwrap();
    let first = fixture.run_audit(
        &format!("refs/heads/main {oid} refs/heads/main {}\n", "0".repeat(40)),
        &destination,
    );
    assert_eq!(finding(&first, "git.push.provenance")["status"], "PASS");
    assert_eq!(finding(&first, "git.push.committer")["status"], "PASS");
    assert_eq!(first["verdict"], "ALLOW");

    success(run_git(
        &fixture.repo,
        &["checkout", "--orphan", "unrelated"],
    ));
    let unrelated = fixture.commit("unrelated local history", "good@example.invalid");
    let unrelated_report = fixture.run_audit(
        &format!(
            "refs/heads/unrelated {unrelated} refs/heads/unrelated {}\n",
            "0".repeat(40)
        ),
        &destination,
    );
    assert_eq!(
        finding(&unrelated_report, "git.push.provenance")["observed"],
        "0 outgoing commit(s) matched current pinned baseline(s)"
    );
    assert_eq!(unrelated_report["verdict"], "ALLOW");

    success(run_git(
        &fixture.repo,
        &[
            "-c",
            "user.name=Foreign Committer",
            "-c",
            "user.email=foreign@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "untrusted post-baseline commit",
        ],
    ));
    let leaked =
        String::from_utf8_lossy(&success(run_git(&fixture.repo, &["rev-parse", "HEAD"])).stdout)
            .trim()
            .to_owned();
    let leak_report = fixture.run_audit(
        &format!(
            "refs/heads/unrelated {leaked} refs/heads/unrelated {}\n",
            "0".repeat(40)
        ),
        &destination,
    );
    assert_eq!(
        finding(&leak_report, "git.push.committer")["status"],
        "FAIL"
    );
    assert_eq!(leak_report["verdict"], "BLOCK");

    let moved = fixture.commit("moved tracking ref", "good@example.invalid");
    success(run_git(
        &fixture.repo,
        &["update-ref", "refs/remotes/origin/main", &moved],
    ));
    let stale = fixture.run_audit(
        &format!("refs/heads/main {oid} refs/heads/main {}\n", "0".repeat(40)),
        &destination,
    );
    assert_eq!(stale["verdict"], "BLOCK");
    assert_eq!(finding(&stale, "git.push.updates")["status"], "UNKNOWN");
}

#[test]
fn offline_rewrite_audit_requires_exact_command_bound_lease() {
    let fixture = Fixture::new();
    let destination = fixture.remote.to_string_lossy().into_owned();
    let baseline = fixture.commit("remote baseline", "good@example.invalid");
    success(run_git(
        &fixture.repo,
        &["update-ref", "refs/remotes/origin/main", &baseline],
    ));
    success(run_git(
        &fixture.repo,
        &["checkout", "--orphan", "rewritten"],
    ));
    let rewritten = fixture.commit("rewritten history", "good@example.invalid");
    fixture.write_policy(&format!("[{:?}]", destination));
    let config = fs::read_to_string(&fixture.policy).unwrap();
    fs::write(
        &fixture.policy,
        config.replace(
            &format!("destinations=[{:?}]", destination),
            &format!(
                "destinations=[{:?}]\nallow_force_with_lease=true",
                destination
            ),
        ),
    )
    .unwrap();
    let config = persona::config::Config::load(&fixture.policy).unwrap();
    let executables = persona::audit::ExecutablePaths {
        git: git(),
        gpg: None,
        ssh_keygen: None,
    };
    let tuple = PushTuple {
        local_ref: "refs/heads/rewritten".into(),
        local_oid: rewritten,
        remote_ref: "refs/heads/main".into(),
        remote_oid: baseline.clone(),
    };
    let request = |expected_oid: String| persona::audit::PushRequest {
        remote: "origin".into(),
        destination: destination.clone(),
        tuples: vec![tuple.clone()],
        leases: vec![persona::git_command::ExactPushLease {
            remote_ref: "refs/heads/main".into(),
            expected_oid,
        }],
    };
    let (matching, _) = persona::audit::build_report(
        &config,
        &fixture.repo,
        Some(&request(baseline.clone())),
        &executables,
    )
    .unwrap();
    assert_eq!(
        matching
            .findings
            .iter()
            .find(|item| item.property == "git.push.updates")
            .unwrap()
            .status,
        persona::report::Status::Pass
    );

    let (stale, _) = persona::audit::build_report(
        &config,
        &fixture.repo,
        Some(&request("0".repeat(40))),
        &executables,
    )
    .unwrap();
    assert_ne!(
        stale
            .findings
            .iter()
            .find(|item| item.property == "git.push.updates")
            .unwrap()
            .status,
        persona::report::Status::Pass
    );
}

#[test]
fn explicit_author_preservation_allows_upstream_author_but_keeps_committer_policy() {
    let fixture = Fixture::new();
    success(run_git(
        &fixture.repo,
        &[
            "-c",
            "user.name=Good Author",
            "-c",
            "user.email=good@example.invalid",
            "commit",
            "--allow-empty",
            "--author=Upstream Author <upstream@example.invalid>",
            "-m",
            "preserved upstream author",
        ],
    ));
    let head =
        String::from_utf8_lossy(&success(run_git(&fixture.repo, &["rev-parse", "HEAD"])).stdout)
            .trim()
            .to_owned();
    let zero = "0000000000000000000000000000000000000000";
    let tuple = format!("refs/heads/main {head} refs/heads/main {zero}\n");
    let destination = fixture.remote.to_string_lossy().into_owned();

    fixture.write_policy(&format!("[{:?}]", destination));
    let strict = fixture.run_audit(&tuple, &destination);
    assert_eq!(finding(&strict, "git.push.author")["status"], "FAIL");

    fixture.write_policy_with_author_preservation(&format!("[{:?}]", destination), true);
    let preserve = fixture.run_audit(&tuple, &destination);
    assert_eq!(finding(&preserve, "git.push.author")["status"], "PASS");
    assert_eq!(finding(&preserve, "git.push.committer")["status"], "PASS");
    assert_eq!(preserve["verdict"], "ALLOW");
}

#[test]
fn checks_every_outgoing_commit_not_only_head() {
    let fixture = Fixture::new();
    let first = fixture.commit("first", "good@example.invalid");
    success(run_git(&fixture.repo, &["push", "origin", "main"]));
    let _bad = fixture.commit("bad", "bad@example.invalid");
    let head = fixture.commit("good", "good@example.invalid");
    fixture.write_policy(&format!("[\"{}\"]", fixture.remote.display()));
    let report = fixture.run_audit(
        &format!("refs/heads/main {head} refs/heads/main {first}\n"),
        &fixture.remote.to_string_lossy(),
    );
    assert_eq!(finding(&report, "git.push.author")["status"], "FAIL");
    assert_eq!(finding(&report, "git.push.committer")["status"], "FAIL");
    assert_eq!(report["verdict"], "BLOCK");
}

#[test]
fn replacement_refs_do_not_hide_original_outgoing_commit_identity() {
    let fixture = Fixture::new();
    let base = fixture.commit("base", "good@example.invalid");
    let bad = fixture.commit("bad author", "bad@example.invalid");
    let tree = String::from_utf8_lossy(
        &success(run_git(
            &fixture.repo,
            &["rev-parse", &format!("{bad}^{{tree}}")],
        ))
        .stdout,
    )
    .trim()
    .to_owned();
    let replacement = String::from_utf8_lossy(
        &success(run_git(
            &fixture.repo,
            &[
                "commit-tree",
                &tree,
                "-p",
                &base,
                "-m",
                "replacement fixture",
            ],
        ))
        .stdout,
    )
    .trim()
    .to_owned();
    success(run_git(&fixture.repo, &["replace", &bad, &replacement]));
    fixture.write_policy(&format!("[{:?}]", fixture.remote.to_string_lossy()));

    let report = fixture.run_audit(
        &format!("refs/heads/main {bad} refs/heads/main {base}\n"),
        &fixture.remote.to_string_lossy(),
    );
    assert_eq!(finding(&report, "git.push.author")["status"], "FAIL");
    assert_eq!(finding(&report, "git.push.committer")["status"], "FAIL");
    assert_eq!(report["verdict"], "BLOCK");
}

#[test]
fn explicit_pushurl_is_not_rewritten_by_push_instead_of() {
    let fixture = Fixture::new();
    let base = fixture.commit("base", "good@example.invalid");
    let head = fixture.commit("head", "good@example.invalid");
    success(run_git(
        &fixture.repo,
        &[
            "config",
            "remote.origin.pushurl",
            "https://explicit.invalid/repo.git",
        ],
    ));
    success(run_git(
        &fixture.repo,
        &[
            "config",
            "url.https://unexpected.invalid/.pushInsteadOf",
            "https://explicit.invalid/",
        ],
    ));
    let native = String::from_utf8_lossy(
        &success(run_git(
            &fixture.repo,
            &["remote", "get-url", "--push", "--all", "origin"],
        ))
        .stdout,
    )
    .trim()
    .to_owned();
    assert_eq!(native, "https://explicit.invalid/repo.git");
    fixture.write_policy(&format!("[{:?}]", native));

    let report = fixture.run_audit(
        &format!("refs/heads/main {head} refs/heads/main {base}\n"),
        &native,
    );
    assert_eq!(finding(&report, "git.push.destination")["status"], "PASS");
    assert_eq!(finding(&report, "git.push.author")["status"], "PASS");
    assert_eq!(finding(&report, "git.push.committer")["status"], "PASS");
    assert_eq!(report["version"], 2);
    assert_eq!(report["operation"], "git_push");
    assert_eq!(
        report["verdict"], "ALLOW",
        "blockers: {}",
        report["blockers"]
    );
    assert_eq!(finding(&report, "ssh")["status"], "UNKNOWN");
}

#[test]
fn permits_a_bounded_first_push_of_multiple_branch_refs() {
    let fixture = Fixture::new();
    let head = fixture.commit("shared first-push head", "good@example.invalid");
    fixture.write_policy(&format!("[{:?}]", fixture.remote.to_string_lossy()));
    let zero = "0000000000000000000000000000000000000000";
    let report = fixture.run_audit(
        &format!(
            "refs/heads/main {head} refs/heads/main {zero}\nrefs/heads/feature {head} refs/heads/feature {zero}\n"
        ),
        &fixture.remote.to_string_lossy(),
    );
    assert_eq!(finding(&report, "git.push.updates")["status"], "PASS");
    assert_eq!(
        finding(&report, "git.push.updates")["observed"],
        "2 supported publication update(s)"
    );
    assert_eq!(finding(&report, "git.push.author")["status"], "PASS");
    assert_eq!(finding(&report, "git.push.committer")["status"], "PASS");
    assert_eq!(report["verdict"], "ALLOW");

    let mut oversized = String::new();
    for index in 0..65 {
        writeln!(
            &mut oversized,
            "refs/heads/branch-{index} {head} refs/heads/branch-{index} {zero}"
        )
        .unwrap();
    }
    let report = fixture.run_audit(&oversized, &fixture.remote.to_string_lossy());
    assert_eq!(finding(&report, "git.push.updates")["status"], "UNKNOWN");
    assert_eq!(report["verdict"], "BLOCK");
}

#[test]
fn rejects_deletion_and_force_updates_as_unknown() {
    let fixture = Fixture::new();
    let first = fixture.commit("first", "good@example.invalid");
    let second = fixture.commit("second", "good@example.invalid");
    fixture.write_policy(&format!("[\"{}\"]", fixture.remote.display()));
    let zero = "0000000000000000000000000000000000000000";
    let deletion = format!("(delete) {zero} refs/heads/main {first}\n");
    let blocked_deletion = fixture.run_audit(&deletion, &fixture.remote.to_string_lossy());
    assert_eq!(
        finding(&blocked_deletion, "git.push.updates")["status"],
        "FAIL"
    );
    let rewrite = format!("refs/heads/main {first} refs/heads/main {second}\n");
    let blocked_rewrite = fixture.run_audit(&rewrite, &fixture.remote.to_string_lossy());
    assert_eq!(
        finding(&blocked_rewrite, "git.push.updates")["status"],
        "FAIL"
    );

    let policy = fs::read_to_string(&fixture.policy).unwrap();
    fs::write(
        &fixture.policy,
        policy.replace(
            "preserve_authors=false",
            "preserve_authors=false\nallow_force_with_lease=true\nallow_branch_deletion=true",
        ),
    )
    .unwrap();
    let lease_missing = fixture.run_audit(&rewrite, &fixture.remote.to_string_lossy());
    assert_eq!(
        finding(&lease_missing, "git.push.updates")["status"],
        "UNKNOWN"
    );
    let still_blocked = fixture.run_audit(&deletion, &fixture.remote.to_string_lossy());
    assert_eq!(
        finding(&still_blocked, "git.push.updates")["status"],
        "UNKNOWN"
    );
    assert_eq!(still_blocked["verdict"], "BLOCK");
}

#[test]
fn checks_all_configured_pushurls_and_unknown_missing_bounds_offline() {
    let fixture = Fixture::new();
    let first = fixture.commit("first", "good@example.invalid");
    let second = fixture.commit("second", "good@example.invalid");
    let first_url = "file:///tmp/first.git";
    let second_url = "file:///tmp/second.git";
    success(run_git(
        &fixture.repo,
        &["config", "--add", "remote.origin.pushurl", first_url],
    ));
    success(run_git(
        &fixture.repo,
        &["config", "--add", "remote.origin.pushurl", second_url],
    ));
    fixture.write_policy("[\"file:///tmp/first.git\", \"file:///tmp/second.git\"]");
    let report = fixture.run_audit(
        &format!("refs/heads/main {second} refs/heads/main {first}\n"),
        first_url,
    );
    assert_eq!(finding(&report, "git.push.destination")["status"], "PASS");

    let missing = "1111111111111111111111111111111111111111";
    let report = fixture.run_audit(
        &format!("refs/heads/main {second} refs/heads/main {missing}\n"),
        first_url,
    );
    assert_eq!(finding(&report, "git.push.updates")["status"], "UNKNOWN");
}

#[test]
fn destination_policy_is_checked_after_push_rewrite_without_network() {
    let fixture = Fixture::new();
    let first = fixture.commit("first", "good@example.invalid");
    let second = fixture.commit("second", "good@example.invalid");
    success(run_git(
        &fixture.repo,
        &[
            "config",
            "remote.origin.url",
            "https://example.invalid/repo.git",
        ],
    ));
    success(run_git(
        &fixture.repo,
        &[
            "config",
            "url.file:///tmp/rewritten/.pushInsteadOf",
            "https://example.invalid/",
        ],
    ));
    let rewritten = "file:///tmp/rewritten/repo.git";
    fixture.write_policy("[\"file:///tmp/rewritten/repo.git\"]");
    let report = fixture.run_audit(
        &format!("refs/heads/main {second} refs/heads/main {first}\n"),
        rewritten,
    );
    assert_eq!(finding(&report, "git.push.destination")["status"], "PASS");
}
