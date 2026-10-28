use persona::gpg::{GpgClient, GpgError};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::tempdir;

fn executable(name: &str, override_name: &str) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(override_name) {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
}

fn gpg_binary() -> Option<PathBuf> {
    executable("gpg", "PERSONA_TEST_GPG")
}

fn git_binary() -> PathBuf {
    std::env::var_os("PERSONA_TEST_GIT")
        .map(PathBuf::from)
        .or_else(|| executable("git", "PERSONA_TEST_GIT"))
        .expect("Git is required for signing fixtures")
}

fn gpg(home: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(gpg_binary().expect("GPG is required for this test"));
    command
        .env_clear()
        .env("HOME", home)
        .env("GNUPGHOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .args(args);
    command.output().expect("run fixture GPG")
}

fn git(home: &Path, root: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(git_binary());
    command
        .env_clear()
        .env("HOME", home)
        .env("GNUPGHOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .current_dir(root)
        .args(args);
    command.output().expect("run fixture Git")
}

fn success(output: Output, command: &str) -> Output {
    assert!(
        output.status.success(),
        "{command} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn checked(output: Output) -> Output {
    success(output, "fixture Git command")
}

fn fingerprints(home: &Path, name: &str) -> Vec<String> {
    let output = success(
        gpg(
            home,
            &["--batch", "--with-colons", "--list-secret-keys", name],
        ),
        "gpg key listing",
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split(':').collect();
            (fields.first() == Some(&"fpr")).then(|| fields[9].to_owned())
        })
        .collect()
}

fn create_key(home: &Path, name: &str) -> String {
    success(
        gpg(
            home,
            &[
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                name,
                "rsa2048",
                "sign",
                "0",
            ],
        ),
        "gpg key generation",
    );
    fingerprints(home, name)
        .into_iter()
        .next()
        .expect("generated key fingerprint")
}

fn create_subkey_key(home: &Path, name: &str) -> (String, String) {
    success(
        gpg(
            home,
            &[
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                name,
                "rsa2048",
                "cert",
                "0",
            ],
        ),
        "gpg primary key generation",
    );
    let primary = fingerprints(home, name)
        .into_iter()
        .next()
        .expect("generated primary fingerprint");
    success(
        gpg(
            home,
            &[
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-add-key",
                &primary,
                "rsa2048",
                "sign",
                "0",
            ],
        ),
        "gpg signing subkey generation",
    );
    let subkey = fingerprints(home, name)
        .into_iter()
        .nth(1)
        .expect("generated signing subkey fingerprint");
    (primary, subkey)
}

fn export_key(home: &Path, fingerprint: &str, destination: &Path) {
    let output = success(
        gpg(home, &["--batch", "--armor", "--export", fingerprint]),
        "gpg public key export",
    );
    fs::write(destination, output.stdout).expect("write temporary public key");
}

fn export_secret_key(home: &Path, fingerprint: &str, destination: &Path) {
    let output = success(
        gpg(
            home,
            &["--batch", "--armor", "--export-secret-keys", fingerprint],
        ),
        "gpg secret key export",
    );
    fs::write(destination, output.stdout).expect("write temporary secret key");
}

fn init_repo(home: &Path, root: &Path, fingerprint: &str, gpg_path: &Path) {
    fs::create_dir_all(root).expect("create repository directory");
    success(
        git(
            home,
            root,
            &["init", "--template=", "--initial-branch=main"],
        ),
        "git init",
    );
    for (key, value) in [
        ("user.name", "Synthetic Signer"),
        ("user.email", "signer@example.invalid"),
        ("user.signingkey", fingerprint),
        ("commit.gpgSign", "true"),
        ("gpg.format", "openpgp"),
    ] {
        success(git(home, root, &["config", key, value]), "git config");
    }
    let gpg_path = gpg_path.to_str().expect("GPG path should be UTF-8");
    success(
        git(home, root, &["config", "gpg.program", gpg_path]),
        "git GPG config",
    );
}

fn signed_commit(home: &Path, root: &Path) {
    success(
        git(
            home,
            root,
            &["commit", "--allow-empty", "-S", "-m", "signed"],
        ),
        "signed commit",
    );
}

fn invalidate_head(home: &Path, root: &Path, temporary: &Path) {
    let mut commit = success(
        git(home, root, &["cat-file", "commit", "HEAD"]),
        "read commit",
    )
    .stdout;
    let separator = commit
        .windows(2)
        .position(|window| window == b"\n\n")
        .expect("commit message separator")
        + 2;
    let message = &mut commit[separator..];
    assert!(message.starts_with(b"signed"));
    message[..6].copy_from_slice(b"broken");
    let object = temporary.join("invalid-commit");
    fs::write(&object, commit).expect("write invalid commit fixture");
    let hash = String::from_utf8_lossy(
        &success(
            git(
                home,
                root,
                &[
                    "hash-object",
                    "-t",
                    "commit",
                    "-w",
                    object.to_str().expect("path"),
                ],
            ),
            "write invalid commit",
        )
        .stdout,
    )
    .trim()
    .to_owned();
    success(
        git(home, root, &["update-ref", "refs/heads/main", &hash]),
        "replace HEAD",
    );
}

fn write_policy(path: &Path, scope: &Path, fingerprint: &str, public_key: &Path) {
    let contents = format!(
        "version = 1\n[[scopes]]\nname = \"scope\"\npath = {:?}\n[scopes.git]\nauthor = {{ name = \"Synthetic Signer\", email = \"signer@example.invalid\" }}\ncommitter = {{ name = \"Synthetic Signer\", email = \"signer@example.invalid\" }}\n[scopes.git.signing]\nfingerprint = \"{fingerprint}\"\npublic_key = {:?}\n",
        scope.to_string_lossy(),
        public_key.to_string_lossy()
    );
    fs::write(path, contents).expect("write temporary policy");
}

fn run_persona(root: &Path, policy: &Path, gpg: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_persona"))
        .env_clear()
        .env("PERSONA_GIT", git_binary())
        .env("PERSONA_GPG", gpg)
        .env("PATH", "/usr/bin:/bin")
        .args(["check", "--config"])
        .arg(policy)
        .args(["--cwd"])
        .arg(root)
        .args(["--format", "json"])
        .output()
        .expect("run persona")
}

fn finding<'a>(report: &'a Value, property: &str) -> &'a Value {
    report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .find(|finding| finding["property"] == property)
        .expect("finding exists")
}

#[cfg(unix)]
fn write_gpg_stub(path: &Path, marker: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let script = format!(
        "#!/bin/sh\nprintf '%s' invoked > {}\nexit 77\n",
        marker.display()
    );
    fs::write(path, script).expect("write gpg stub");
    let mut permissions = fs::metadata(path).expect("stat gpg stub").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("make gpg stub executable");
}

#[cfg(unix)]
fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

#[cfg(unix)]
fn write_gpg_replacement_wrapper(
    path: &Path,
    source: &Path,
    replacement: &Path,
    marker: &Path,
    real_gpg: &Path,
) {
    use std::os::unix::fs::PermissionsExt;

    let script = format!(
        "#!/bin/sh\nif [ ! -e {marker} ]; then\n  : > {marker}\n  cp {replacement} {source}\nfi\nexec {real_gpg} \"$@\"\n",
        marker = shell_quote(marker),
        replacement = shell_quote(replacement),
        source = shell_quote(source),
        real_gpg = shell_quote(real_gpg),
    );
    fs::write(path, script).expect("write replacement GPG wrapper");
    let mut permissions = fs::metadata(path)
        .expect("stat replacement GPG wrapper")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("make replacement GPG wrapper executable");
}

fn write_push_policy(
    path: &Path,
    scope: &Path,
    fingerprint: &str,
    public_key: &Path,
    destination: &Path,
) {
    let contents = format!(
        "version = 1\n[[scopes]]\nname = \"scope\"\npath = {:?}\n[scopes.git]\nauthor = {{ name = \"Synthetic Signer\", email = \"signer@example.invalid\" }}\ncommitter = {{ name = \"Synthetic Signer\", email = \"signer@example.invalid\" }}\n[scopes.git.signing]\nfingerprint = \"{fingerprint}\"\npublic_key = {:?}\n[scopes.git.push]\nremote = \"origin\"\ndestinations = [{:?}]\n",
        scope.to_string_lossy(),
        public_key.to_string_lossy(),
        destination.to_string_lossy(),
    );
    fs::write(path, contents).expect("write temporary push policy");
}

fn commit_oid(home: &Path, repo: &Path) -> String {
    String::from_utf8_lossy(
        &success(git(home, repo, &["rev-parse", "HEAD"]), "rev-parse HEAD").stdout,
    )
    .trim()
    .to_owned()
}

fn run_persona_push(
    repo: &Path,
    policy: &Path,
    gpg_path: &Path,
    local_oid: &str,
    remote_oid: &str,
    destination: &Path,
) -> Value {
    let input = format!("refs/heads/main {local_oid} refs/heads/main {remote_oid}\n");
    let mut child = Command::new(env!("CARGO_BIN_EXE_persona"))
        .env_clear()
        .env("PERSONA_GIT", git_binary())
        .env("PERSONA_GPG", gpg_path)
        .env("PATH", "/usr/bin:/bin")
        .args(["check", "--config"])
        .arg(policy)
        .args([
            "--cwd",
            repo.to_str().expect("repo path should be UTF-8"),
            "--format",
            "json",
            "--operation",
            "push",
            "--remote",
            "origin",
            "--destination",
            destination.to_str().expect("destination should be UTF-8"),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("run persona push audit");
    use std::io::Write;
    child
        .stdin
        .take()
        .expect("push audit stdin")
        .write_all(input.as_bytes())
        .expect("write push tuple");
    let output = child.wait_with_output().expect("wait for persona");
    serde_json::from_slice(&output.stdout).expect("JSON push report")
}

fn setup() -> (tempfile::TempDir, PathBuf, PathBuf, String) {
    let gpg = gpg_binary().expect(
        "GPG is required for signing integration tests; set PERSONA_TEST_GPG to an absolute executable path",
    );
    let temporary = tempdir().expect("temporary fixture directory");
    let home = temporary.path().join("gnupg");
    fs::create_dir(&home).expect("create GnuPG home");
    let repo = temporary.path().join("repo");
    let public_key = temporary.path().join("public.asc");
    let policy = temporary.path().join("policy.toml");
    let fingerprint = create_key(&home, "Synthetic Signer <signer@example.invalid>");
    export_key(&home, &fingerprint, &public_key);
    init_repo(&home, &repo, &fingerprint, &gpg);
    signed_commit(&home, &repo);
    (temporary, policy, public_key, fingerprint)
}

#[test]
fn rejects_an_armored_private_key_as_a_public_key_policy_file() {
    let (temporary, _policy, _public_key, fingerprint) = setup();
    let home = temporary.path().join("gnupg");
    let secret_key = temporary.path().join("secret.asc");
    export_secret_key(&home, &fingerprint, &secret_key);

    let result = GpgClient::new(gpg_binary().expect("GPG is required for signing tests"))
        .isolated_keyring(&secret_key);
    assert!(matches!(result, Err(GpgError::InvalidPublicKey)));
}

#[cfg(unix)]
#[test]
fn stages_key_bytes_before_the_configured_path_can_be_replaced() {
    let (temporary, _policy, public_key, fingerprint) = setup();
    let home = temporary.path().join("gnupg");
    let secret_key = temporary.path().join("secret.asc");
    export_secret_key(&home, &fingerprint, &secret_key);

    let wrapper = temporary.path().join("racing-gpg");
    let marker = temporary.path().join("replacement-started");
    let real_gpg = gpg_binary().expect("GPG is required for signing tests");
    write_gpg_replacement_wrapper(&wrapper, &public_key, &secret_key, &marker, &real_gpg);

    let keyring = GpgClient::new(wrapper)
        .isolated_keyring(&public_key)
        .expect("staged public bytes should survive source replacement");
    assert!(marker.exists(), "replacement wrapper was not invoked");
    assert_eq!(
        GpgClient::new(real_gpg)
            .configured_primary_fingerprint(keyring.path(), &fingerprint)
            .expect("inspect staged keyring"),
        Some(fingerprint.clone()),
    );

    let public_listing = success(
        gpg(keyring.path(), &["--batch", "--with-colons", "--list-keys"]),
        "list staged public keyring",
    );
    let public_primary_fingerprints = String::from_utf8_lossy(&public_listing.stdout)
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split(':').collect();
            (fields.first() == Some(&"fpr") && fields.len() > 9)
                .then(|| fields[9].to_ascii_uppercase())
        })
        .collect::<Vec<_>>();
    assert_eq!(public_primary_fingerprints, vec![fingerprint.clone()]);

    let secret_listing = success(
        gpg(
            keyring.path(),
            &["--batch", "--with-colons", "--list-secret-keys"],
        ),
        "list staged secret keyring",
    );
    assert!(
        !String::from_utf8_lossy(&secret_listing.stdout)
            .lines()
            .any(|line| matches!(line.split(':').next(), Some("sec" | "ssb")))
    );

    let configured_bytes = fs::read(&public_key).expect("read replaced source");
    assert_eq!(
        configured_bytes,
        fs::read(&secret_key).expect("read secret fixture")
    );
}

#[test]
fn verifies_valid_signature_and_authorized_primary_fingerprint() {
    let (temporary, policy, public_key, fingerprint) = setup();
    let repo = temporary.path().join("repo");
    write_policy(&policy, &repo, &fingerprint, &public_key);
    let output = run_persona(&repo, &policy, &gpg_binary().expect("GPG"));
    let report: Value = serde_json::from_slice(&output.stdout).expect("JSON report");
    assert_eq!(finding(&report, "git.signing.config")["status"], "PASS");
    assert_eq!(finding(&report, "git.signature.present")["status"], "PASS");
    assert_eq!(finding(&report, "git.signature.valid")["status"], "PASS");
    assert_eq!(
        finding(&report, "git.signature.fingerprint")["status"],
        "PASS"
    );
}

#[cfg(unix)]
#[test]
fn verification_ignores_repository_gpg_program_and_uses_selected_binary() {
    let (temporary, policy, public_key, fingerprint) = setup();
    let repo = temporary.path().join("repo");
    let stub = temporary.path().join("repository-gpg-stub");
    let marker = temporary.path().join("stub-invoked");
    write_gpg_stub(&stub, &marker);
    let stub_path = stub.to_str().expect("stub path should be UTF-8");
    success(
        git(
            &temporary.path().join("gnupg"),
            &repo,
            &["config", "gpg.program", stub_path],
        ),
        "configure repository GPG stub",
    );

    write_policy(&policy, &repo, &fingerprint, &public_key);
    let selected_gpg = gpg_binary().expect("GPG is required for signing integration tests");
    let report: Value = serde_json::from_slice(&run_persona(&repo, &policy, &selected_gpg).stdout)
        .expect("JSON report");

    assert_eq!(finding(&report, "git.signature.valid")["status"], "PASS");
    assert!(
        !marker.exists(),
        "repository-selected GPG helper was invoked"
    );
}

#[test]
fn maps_a_signing_subkey_to_its_authorized_primary_fingerprint() {
    let gpg_path = gpg_binary().expect(
        "GPG is required for signing integration tests; set PERSONA_TEST_GPG to an absolute executable path",
    );
    let temporary = tempdir().expect("temporary fixture directory");
    let home = temporary.path().join("gnupg");
    fs::create_dir(&home).expect("create GnuPG home");
    let repo = temporary.path().join("repo");
    let public_key = temporary.path().join("public.asc");
    let policy = temporary.path().join("policy.toml");
    let (primary, _subkey) = create_subkey_key(&home, "Subkey Signer <subkey@example.invalid>");
    export_key(&home, &primary, &public_key);
    init_repo(&home, &repo, &primary, &gpg_path);
    signed_commit(&home, &repo);
    write_policy(&policy, &repo, &primary, &public_key);
    let report: Value = serde_json::from_slice(&run_persona(&repo, &policy, &gpg_path).stdout)
        .expect("JSON report");
    assert_eq!(finding(&report, "git.signature.valid")["status"], "PASS");
    assert_eq!(
        finding(&report, "git.signature.fingerprint")["status"],
        "PASS"
    );
}

#[test]
fn reports_absent_signature_separately_from_validity() {
    let (temporary, policy, public_key, fingerprint) = setup();
    let repo = temporary.path().join("repo");
    let home = temporary.path().join("gnupg");
    success(
        git(&home, &repo, &["config", "commit.gpgSign", "false"]),
        "disable signing",
    );
    success(
        git(&home, &repo, &["commit", "--allow-empty", "-m", "unsigned"]),
        "unsigned commit",
    );
    write_policy(&policy, &repo, &fingerprint, &public_key);
    let report: Value =
        serde_json::from_slice(&run_persona(&repo, &policy, &gpg_binary().expect("GPG")).stdout)
            .expect("JSON report");
    assert_eq!(finding(&report, "git.signature.present")["status"], "FAIL");
    assert_eq!(finding(&report, "git.signature.valid")["status"], "UNKNOWN");
}

#[test]
fn reports_a_wrong_but_cryptographically_valid_signer() {
    let (temporary, policy, public_key, allowed) = setup();
    let repo = temporary.path().join("repo");
    let home = temporary.path().join("gnupg");
    let wrong = create_key(&home, "Wrong Signer <wrong@example.invalid>");
    let wrong_public = temporary.path().join("wrong.asc");
    export_key(&home, &wrong, &wrong_public);
    let mut both = fs::read(&public_key).expect("read fixture public key");
    both.extend(fs::read(&wrong_public).expect("read wrong public key"));
    fs::write(&public_key, both).expect("combine public keys");
    success(
        git(&home, &repo, &["config", "user.signingkey", &wrong]),
        "select wrong signer",
    );
    signed_commit(&home, &repo);
    write_policy(&policy, &repo, &allowed, &public_key);
    let report: Value =
        serde_json::from_slice(&run_persona(&repo, &policy, &gpg_binary().expect("GPG")).stdout)
            .expect("JSON report");
    assert_eq!(finding(&report, "git.signature.valid")["status"], "PASS");
    assert_eq!(
        finding(&report, "git.signature.fingerprint")["status"],
        "FAIL"
    );
}

#[test]
fn reports_invalid_signature_as_cryptographic_failure() {
    let (temporary, policy, public_key, fingerprint) = setup();
    let repo = temporary.path().join("repo");
    invalidate_head(&temporary.path().join("gnupg"), &repo, temporary.path());
    write_policy(&policy, &repo, &fingerprint, &public_key);
    let report: Value =
        serde_json::from_slice(&run_persona(&repo, &policy, &gpg_binary().expect("GPG")).stdout)
            .expect("JSON report");
    assert_eq!(finding(&report, "git.signature.present")["status"], "PASS");
    assert_eq!(finding(&report, "git.signature.valid")["status"], "FAIL");
    assert_eq!(
        finding(&report, "git.signature.fingerprint")["status"],
        "UNKNOWN"
    );
}

#[test]
fn reports_unavailable_public_key_as_unknown() {
    let (temporary, policy, public_key, fingerprint) = setup();
    let repo = temporary.path().join("repo");
    fs::remove_file(public_key).expect("remove configured public key");
    write_policy(
        &policy,
        &repo,
        &fingerprint,
        &temporary.path().join("missing.asc"),
    );
    let report: Value =
        serde_json::from_slice(&run_persona(&repo, &policy, &gpg_binary().expect("GPG")).stdout)
            .expect("JSON report");
    assert_eq!(finding(&report, "git.signature.present")["status"], "PASS");
    assert_eq!(finding(&report, "git.signature.valid")["status"], "UNKNOWN");
    assert_eq!(
        finding(&report, "git.signature.fingerprint")["status"],
        "UNKNOWN"
    );
}

#[test]
fn push_audit_fails_when_an_earlier_outgoing_commit_is_unsigned() {
    let (temporary, policy, public_key, fingerprint) = setup();
    let repo = temporary.path().join("repo");
    let home = temporary.path().join("gnupg");
    let destination = temporary.path().join("remote.git");
    checked(git(
        &home,
        &repo,
        &["remote", "add", "origin", destination.to_str().unwrap()],
    ));
    let base = commit_oid(&home, &repo);
    checked(git(&home, &repo, &["config", "commit.gpgSign", "false"]));
    checked(git(
        &home,
        &repo,
        &[
            "-c",
            "user.name=Wrong",
            "-c",
            "user.email=wrong@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "unsigned",
        ],
    ));
    checked(git(&home, &repo, &["config", "commit.gpgSign", "true"]));
    signed_commit(&home, &repo);
    let head = commit_oid(&home, &repo);
    write_push_policy(&policy, &repo, &fingerprint, &public_key, &destination);
    let report = run_persona_push(
        &repo,
        &policy,
        &gpg_binary().expect("GPG"),
        &head,
        &base,
        &destination,
    );
    assert_eq!(
        finding(&report, "git.push.signature.present")["status"],
        "FAIL"
    );
    assert_eq!(
        finding(&report, "git.push.signature.valid")["status"],
        "FAIL"
    );
}

#[test]
fn push_audit_passes_when_every_outgoing_commit_is_signed_by_the_allowed_key() {
    let (temporary, policy, public_key, fingerprint) = setup();
    let repo = temporary.path().join("repo");
    let home = temporary.path().join("gnupg");
    let destination = temporary.path().join("remote.git");
    checked(git(
        &home,
        &repo,
        &["remote", "add", "origin", destination.to_str().unwrap()],
    ));
    let base = commit_oid(&home, &repo);
    signed_commit(&home, &repo);
    let head = commit_oid(&home, &repo);
    write_push_policy(&policy, &repo, &fingerprint, &public_key, &destination);
    let report = run_persona_push(
        &repo,
        &policy,
        &gpg_binary().expect("GPG"),
        &head,
        &base,
        &destination,
    );
    assert_eq!(
        finding(&report, "git.push.signature.present")["status"],
        "PASS"
    );
    assert_eq!(
        finding(&report, "git.push.signature.valid")["status"],
        "PASS"
    );
    assert_eq!(
        finding(&report, "git.push.signature.fingerprint")["status"],
        "PASS"
    );
}

#[test]
fn push_audit_reports_unknown_when_the_required_public_key_is_unavailable() {
    let (temporary, policy, public_key, fingerprint) = setup();
    let repo = temporary.path().join("repo");
    let home = temporary.path().join("gnupg");
    let destination = temporary.path().join("remote.git");
    checked(git(
        &home,
        &repo,
        &["remote", "add", "origin", destination.to_str().unwrap()],
    ));
    let base = commit_oid(&home, &repo);
    signed_commit(&home, &repo);
    let head = commit_oid(&home, &repo);
    fs::remove_file(&public_key).expect("remove configured public key");
    let missing = temporary.path().join("missing.asc");
    write_push_policy(&policy, &repo, &fingerprint, &missing, &destination);
    let report = run_persona_push(
        &repo,
        &policy,
        &gpg_binary().expect("GPG"),
        &head,
        &base,
        &destination,
    );
    assert_eq!(
        finding(&report, "git.push.signature.present")["status"],
        "PASS"
    );
    assert_eq!(
        finding(&report, "git.push.signature.valid")["status"],
        "UNKNOWN"
    );
    assert_eq!(
        finding(&report, "git.push.signature.fingerprint")["status"],
        "UNKNOWN"
    );
}
