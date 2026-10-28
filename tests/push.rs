use serde_json::Value;
use std::fs;
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
        let root = self.repo.to_string_lossy();
        fs::write(&self.policy, format!(
            "version=1\n[[scopes]]\nname=\"scope\"\npath=\"{root}\"\n[scopes.git]\nauthor={{name=\"Good Author\",email=\"good@example.invalid\"}}\ncommitter={{name=\"Good Author\",email=\"good@example.invalid\"}}\n[scopes.git.push]\nremote=\"origin\"\ndestinations={destinations}\n"
        )).expect("policy");
    }

    fn commit(&self, name: &str, email: &str) -> String {
        success(run_git(
            &self.repo,
            &[
                "-c",
                &format!("user.name={name}"),
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
        serde_json::from_slice(&output.stdout).expect("JSON report")
    }
}

fn finding<'a>(report: &'a Value, property: &str) -> &'a Value {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["property"] == property)
        .unwrap()
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
}

#[test]
fn rejects_deletion_new_branch_force_and_multiple_updates_as_unknown() {
    let fixture = Fixture::new();
    let first = fixture.commit("first", "good@example.invalid");
    let second = fixture.commit("second", "good@example.invalid");
    fixture.write_policy(&format!("[\"{}\"]", fixture.remote.display()));
    let zero = "0000000000000000000000000000000000000000";
    for tuples in [
        format!("(delete) {zero} refs/heads/main {first}\n"),
        format!("refs/heads/main {first} refs/heads/main {zero}\n"),
        format!("refs/heads/main {first} refs/heads/main {second}\n"),
        format!(
            "refs/heads/main {second} refs/heads/main {first}\nrefs/heads/x {second} refs/heads/x {first}\n"
        ),
    ] {
        let report = fixture.run_audit(&tuples, &fixture.remote.to_string_lossy());
        assert_eq!(finding(&report, "git.push.updates")["status"], "UNKNOWN");
        assert_ne!(finding(&report, "git.push.updates")["status"], "PASS");
    }
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
