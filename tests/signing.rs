use persona::git::{GitClient, safe_environment};
use persona::gpg::{GpgClient, GpgError};
use persona::ssh_signature::SshVerifier;
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

fn fixture_path() -> String {
    let mut directories = Vec::new();
    if let Ok(coreutils) = std::env::var("PERSONA_TEST_COREUTILS") {
        directories.push(coreutils);
    }
    if let Some(directory) = std::env::var_os("PERSONA_TEST_SSH_KEYGEN")
        .and_then(|path| PathBuf::from(path).parent().map(Path::to_path_buf))
    {
        directories.push(directory.to_string_lossy().into_owned());
    }
    directories.extend(["/usr/bin".to_owned(), "/bin".to_owned()]);
    directories.join(":")
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
        .env("PATH", fixture_path())
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
        .env("PATH", fixture_path())
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
    let mut command = Command::new(env!("CARGO_BIN_EXE_persona"));
    command
        .env_clear()
        .env("PERSONA_GIT", git_binary())
        .env("PERSONA_GPG", gpg)
        .env("PATH", fixture_path());
    if let Some(ssh_keygen) = executable("ssh-keygen", "PERSONA_TEST_SSH_KEYGEN") {
        command.env("PERSONA_SSH_KEYGEN", ssh_keygen);
    }
    command
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

    let cp = std::env::var_os("PERSONA_TEST_COREUTILS")
        .map(PathBuf::from)
        .map(|directory| directory.join("cp"))
        .unwrap_or_else(|| PathBuf::from("/bin/cp"));
    let script = format!(
        "#!/bin/sh\nif [ ! -e {marker} ]; then\n  : > {marker}\n  {cp} -f {replacement} {source}\nfi\nexec {real_gpg} \"$@\"\n",
        marker = shell_quote(marker),
        cp = shell_quote(&cp),
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
    let mut command = Command::new(env!("CARGO_BIN_EXE_persona"));
    command
        .env_clear()
        .env("PERSONA_GIT", git_binary())
        .env("PERSONA_GPG", gpg_path)
        .env("PATH", fixture_path());
    if let Some(ssh_keygen) = executable("ssh-keygen", "PERSONA_TEST_SSH_KEYGEN") {
        command.env("PERSONA_SSH_KEYGEN", ssh_keygen);
    }
    let mut child = command
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

#[cfg(unix)]
#[test]
fn annotated_tag_push_audit_requires_and_accepts_the_exact_valid_signature() {
    let (temporary, policy, public_key, fingerprint) = setup();
    let repo = temporary.path().join("repo");
    let home = temporary.path().join("gnupg");
    let destination = temporary.path().join("remote.git");
    checked(git(
        &home,
        temporary.path(),
        &["init", "--bare", destination.to_str().unwrap()],
    ));
    write_policy(&policy, &repo, &fingerprint, &public_key);
    let mut policy_text = fs::read_to_string(&policy).unwrap();
    policy_text.push_str(&format!("\n[scopes.git.push]\nremote = \"origin\"\ndestinations = [{:?}]\nallow_initial_push = true\nallow_fast_forward = true\nallow_annotated_tags = true\n", destination.to_string_lossy()));
    fs::write(&policy, policy_text).unwrap();
    checked(git(
        &home,
        &repo,
        &["remote", "add", "origin", destination.to_str().unwrap()],
    ));
    checked(git(
        &home,
        &repo,
        &[
            "-c",
            "gpg.format=openpgp",
            "-c",
            &format!("user.signingkey={fingerprint}"),
            "tag",
            "-s",
            "-m",
            "release",
            "v3",
        ],
    ));
    let tag_oid =
        String::from_utf8_lossy(&checked(git(&home, &repo, &["rev-parse", "refs/tags/v3"])).stdout)
            .trim()
            .to_owned();
    let tuple = format!("refs/tags/v3 {tag_oid} refs/tags/v3 {}\n", "0".repeat(40));
    let mut command = Command::new(env!("CARGO_BIN_EXE_persona"));
    command
        .env_clear()
        .env("HOME", &home)
        .env("GNUPGHOME", &home)
        .env("PATH", fixture_path())
        .env("PERSONA_GIT", git_binary())
        .env("PERSONA_GPG", gpg_binary().expect("GPG"))
        .args(["check", "--config"])
        .arg(&policy)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--operation", "push", "--remote", "origin", "--destination"])
        .arg(destination.to_string_lossy().as_ref())
        .args(["--format", "json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().expect("spawn tag audit");
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(tuple.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(finding(&report, "git.push.tag_signature")["status"], "PASS");
}

#[cfg(unix)]
#[test]
fn managed_amend_resets_identity_and_recreates_a_valid_signature() {
    let (temporary, policy, public_key, fingerprint) = setup();
    let repo = temporary.path().join("repo");
    let home = temporary.path().join("gnupg");
    write_policy(&policy, &repo, &fingerprint, &public_key);
    let mut command = Command::new(env!("CARGO_BIN_EXE_persona"));
    command
        .env_clear()
        .env("HOME", &home)
        .env("GNUPGHOME", &home)
        .env("PATH", fixture_path())
        .env("PERSONA_GIT", git_binary())
        .env("PERSONA_GPG", gpg_binary().expect("GPG"))
        .args(["run", "--config"])
        .arg(&policy)
        .args(["--cwd"])
        .arg(&repo)
        .args([
            "--",
            "git",
            "commit",
            "--amend",
            "--no-edit",
            "--allow-empty",
        ]);
    let amended = command.output().expect("run managed signed amend");
    assert_eq!(
        amended.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&amended.stderr)
    );

    let result = checked(git(
        &home,
        &repo,
        &["show", "-s", "--format=%G?|%an|%ae|%cn|%ce"],
    ));
    assert_eq!(
        String::from_utf8_lossy(&result.stdout).trim(),
        "G|Synthetic Signer|signer@example.invalid|Synthetic Signer|signer@example.invalid"
    );
    let git_client = GitClient::new(git_binary(), safe_environment());
    let head = git_client.resolve_commit_oid(&repo, "HEAD").unwrap();
    let keyring = GpgClient::new(gpg_binary().expect("GPG"))
        .isolated_keyring(&public_key)
        .unwrap();
    let verification = GpgClient::new(gpg_binary().expect("GPG"))
        .verify_commit_oid(&git_client, &repo, &head, keyring.path())
        .unwrap();
    assert!(verification.cryptographically_valid);
    assert_eq!(
        verification.primary_fingerprint.as_deref(),
        Some(fingerprint.as_str())
    );
}

#[cfg(unix)]
#[test]
fn managed_git_creates_only_signed_annotated_tags_with_policy_tagger_identity() {
    let (temporary, policy, public_key, fingerprint) = setup();
    let repo = temporary.path().join("repo");
    let home = temporary.path().join("gnupg");
    write_policy(&policy, &repo, &fingerprint, &public_key);
    let mut command = Command::new(env!("CARGO_BIN_EXE_persona"));
    command
        .env_clear()
        .env("HOME", &home)
        .env("GNUPGHOME", &home)
        .env("PATH", fixture_path())
        .env("PERSONA_GIT", git_binary())
        .env("PERSONA_GPG", gpg_binary().expect("GPG"))
        .args(["run", "--config"])
        .arg(&policy)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "tag", "-s", "-m", "managed release", "v2"]);
    let created = command.output().expect("run managed signed tag");
    assert_eq!(
        created.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let tagger = checked(git(
        &home,
        &repo,
        &[
            "for-each-ref",
            "--format=%(taggername)|%(taggeremail)",
            "refs/tags/v2",
        ],
    ));
    assert_eq!(
        String::from_utf8_lossy(&tagger.stdout).trim(),
        "Synthetic Signer|<signer@example.invalid>"
    );

    let git_client = GitClient::new(git_binary(), safe_environment());
    let (tag_oid, contents) = git_client.tag_object(&repo, "v2").unwrap();
    assert!(contents.contains("-----BEGIN PGP SIGNATURE-----"));
    let verifier = GpgClient::new(gpg_binary().expect("GPG"));
    let keyring = verifier.isolated_keyring(&public_key).unwrap();
    let verification = verifier
        .verify_tag_oid(&git_client, &repo, &tag_oid, keyring.path())
        .unwrap();
    assert!(verification.cryptographically_valid);
    assert_eq!(
        verification.primary_fingerprint.as_deref(),
        Some(fingerprint.as_str())
    );
}

#[cfg(unix)]
#[test]
fn verifies_openpgp_annotated_tag_with_forced_gpg_program() {
    let (temporary, _policy, public_key, fingerprint) = setup();
    let repo = temporary.path().join("repo");
    let home = temporary.path().join("gnupg");
    checked(git(&home, &repo, &["tag", "-s", "-m", "signed tag", "v1"]));
    let git_client = GitClient::new(git_binary(), safe_environment());
    let (tag_oid, contents) = git_client.tag_object(&repo, "v1").unwrap();
    assert!(contents.contains("-----BEGIN PGP SIGNATURE-----"));
    let gpg = GpgClient::new(gpg_binary().expect("GPG"));
    let keyring = gpg.isolated_keyring(&public_key).unwrap();

    let stub = temporary.path().join("tag-verifier-stub");
    let marker = temporary.path().join("tag-verifier-invoked");
    write_gpg_stub(&stub, &marker);
    checked(git(
        &home,
        &repo,
        &["config", "gpg.program", stub.to_str().unwrap()],
    ));
    checked(git(
        &home,
        &repo,
        &["config", "gpg.openpgp.program", stub.to_str().unwrap()],
    ));
    let verification = gpg
        .verify_tag_oid(&git_client, &repo, &tag_oid, keyring.path())
        .unwrap();
    assert!(verification.cryptographically_valid);
    assert_eq!(
        verification.primary_fingerprint.as_deref(),
        Some(fingerprint.as_str())
    );
    assert!(
        !marker.exists(),
        "repository gpg.program must not run during tag verification"
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

    success(
        git(
            &temporary.path().join("gnupg"),
            &repo,
            &["config", "gpg.openpgp.program", stub_path],
        ),
        "configure format-specific repository GPG stub",
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

#[cfg(unix)]
#[test]
fn openpgp_policy_never_executes_repository_selected_ssh_verifier() {
    use std::os::unix::fs::PermissionsExt;

    let (temporary, policy, public_key, fingerprint) = setup();
    let home = temporary.path().join("gnupg");
    let repo = temporary.path().join("repo");
    let ssh_key = temporary.path().join("ssh-signing-key");
    let ssh_pub = temporary.path().join("ssh-signing-key.pub");
    let ssh_keygen = executable("ssh-keygen", "PERSONA_TEST_SSH_KEYGEN")
        .expect("SSH keygen is required for this test");
    success(
        Command::new(ssh_keygen)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", fixture_path())
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&ssh_key)
            .output()
            .expect("generate disposable SSH signing key"),
        "ssh-keygen",
    );
    let public_text = fs::read_to_string(&ssh_pub).expect("read synthetic SSH public key");
    let allowed_signers = temporary.path().join("allowed_signers");
    fs::write(
        &allowed_signers,
        format!("signer@example.invalid {public_text}"),
    )
    .expect("write synthetic SSH allowed-signers file");
    for (key, value) in [
        ("gpg.format", "ssh"),
        ("commit.gpgSign", "true"),
        ("user.signingkey", ssh_key.to_str().expect("key path")),
        (
            "gpg.ssh.allowedSignersFile",
            allowed_signers.to_str().expect("allowed-signers path"),
        ),
    ] {
        success(
            git(&home, &repo, &["config", key, value]),
            "configure SSH signer",
        );
    }
    success(
        git(
            &home,
            &repo,
            &["commit", "--allow-empty", "-S", "-m", "SSH signed fixture"],
        ),
        "create SSH-signed fixture commit",
    );

    let marker = temporary.path().join("repository-ssh-verifier-invoked");
    let verifier = temporary.path().join("repository-ssh-verifier");
    let script = format!("#!/bin/sh\nprintf called > {}\nexit 1\n", marker.display());
    fs::write(&verifier, script).expect("write hostile verifier fixture");
    let mut permissions = fs::metadata(&verifier)
        .expect("stat hostile verifier")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&verifier, permissions).expect("make verifier executable");
    success(
        git(
            &home,
            &repo,
            &[
                "config",
                "gpg.ssh.program",
                verifier.to_str().expect("verifier path"),
            ],
        ),
        "configure repository-selected SSH verifier",
    );

    write_policy(&policy, &repo, &fingerprint, &public_key);
    let output = run_persona(&repo, &policy, &gpg_binary().expect("GPG"));
    let report: Value = serde_json::from_slice(&output.stdout).expect("JSON report");
    assert_eq!(finding(&report, "git.signing.config")["status"], "FAIL");
    assert!(!marker.exists(), "repository-selected SSH verifier ran");
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
fn ssh_signature_is_audited_against_the_configured_public_key() {
    let Some(ssh_keygen) = executable("ssh-keygen", "PERSONA_TEST_SSH_KEYGEN") else {
        eprintln!("SKIP: ssh-keygen is required for synthetic SSH signing fixture");
        return;
    };
    let temporary = tempdir().unwrap();
    let home = temporary.path().join("home");
    let repo = temporary.path().join("repo");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&repo).unwrap();
    checked(git(&home, &repo, &["init", "-q"]));
    checked(git(
        &home,
        &repo,
        &["config", "user.name", "Synthetic Signer"],
    ));
    checked(git(
        &home,
        &repo,
        &["config", "user.email", "signer@example.invalid"],
    ));
    let private_key = temporary.path().join("signing-key");
    let public_key = temporary.path().join("signing-key.pub");
    success(
        Command::new(&ssh_keygen)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&private_key)
            .output()
            .unwrap(),
        "synthetic ssh-keygen",
    );
    fs::write(repo.join("file"), "synthetic signed content\n").unwrap();
    checked(git(&home, &repo, &["add", "file"]));
    let private_key_text = private_key.to_string_lossy().into_owned();
    checked(git(
        &home,
        &repo,
        &[
            "-c",
            "gpg.format=ssh",
            "-c",
            &format!("user.signingkey={private_key_text}"),
            "-c",
            "commit.gpgsign=true",
            "commit",
            "-m",
            "signed",
        ],
    ));
    checked(git(&home, &repo, &["config", "gpg.format", "ssh"]));
    checked(git(
        &home,
        &repo,
        &["config", "user.signingkey", &private_key_text],
    ));
    checked(git(&home, &repo, &["config", "commit.gpgsign", "true"]));
    let fingerprint = String::from_utf8_lossy(
        &success(
            Command::new(&ssh_keygen)
                .env_clear()
                .env("HOME", &home)
                .env("PATH", "/usr/bin:/bin")
                .args(["-lf"])
                .arg(&public_key)
                .args(["-E", "sha256"])
                .output()
                .unwrap(),
            "ssh public-key fingerprint",
        )
        .stdout,
    )
    .split_whitespace()
    .find(|field| field.starts_with("SHA256:"))
    .unwrap()
    .to_owned();
    let policy = temporary.path().join("policy.toml");
    fs::write(&policy, format!(
        "version = 1\n[[scopes]]\nname = \"scope\"\npath = {:?}\n[scopes.git]\nauthor = {{ name = \"Synthetic Signer\", email = \"signer@example.invalid\" }}\ncommitter = {{ name = \"Synthetic Signer\", email = \"signer@example.invalid\" }}\n[scopes.git.signing]\nformat = \"ssh\"\nfingerprint = \"{fingerprint}\"\npublic_key = {:?}\n",
        repo.to_string_lossy(), public_key.to_string_lossy()
    )).unwrap();
    let report: Value =
        serde_json::from_slice(&run_persona(&repo, &policy, &gpg_binary().expect("GPG")).stdout)
            .unwrap();
    assert_eq!(finding(&report, "git.signing.config")["status"], "PASS");
    assert_eq!(finding(&report, "git.signature.present")["status"], "PASS");
    assert_eq!(
        finding(&report, "git.signature.valid")["status"],
        "PASS",
        "{report}"
    );
    assert_eq!(
        finding(&report, "git.signature.fingerprint")["status"],
        "PASS",
        "{report}"
    );
}

#[test]
fn ssh_commit_signature_uses_explicit_allowed_signer_and_ignores_repo_verifier() {
    let Some(ssh_keygen) = executable("ssh-keygen", "PERSONA_TEST_SSH_KEYGEN") else {
        eprintln!("SKIP: ssh-keygen is required for synthetic SSH signing fixture");
        return;
    };
    let temporary = tempdir().unwrap();
    let home = temporary.path().join("home");
    let repo = temporary.path().join("repo");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&repo).unwrap();
    checked(git(&home, &repo, &["init", "-q"]));
    checked(git(
        &home,
        &repo,
        &["config", "user.name", "Synthetic Signer"],
    ));
    checked(git(
        &home,
        &repo,
        &["config", "user.email", "signer@example.invalid"],
    ));
    let private_key = temporary.path().join("signing-key");
    let public_key = temporary.path().join("signing-key.pub");
    let generated = Command::new(&ssh_keygen)
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&private_key)
        .output()
        .unwrap();
    success(generated, "synthetic ssh-keygen");
    fs::write(repo.join("file"), "synthetic signed content\n").unwrap();
    checked(git(&home, &repo, &["add", "file"]));
    let private_key_text = private_key.to_string_lossy().into_owned();
    checked(git(
        &home,
        &repo,
        &[
            "-c",
            "gpg.format=ssh",
            "-c",
            &format!("user.signingkey={private_key_text}"),
            "-c",
            "commit.gpgsign=true",
            "commit",
            "-m",
            "signed",
        ],
    ));
    checked(git(
        &home,
        &repo,
        &[
            "-c",
            "gpg.format=ssh",
            "-c",
            &format!("user.signingkey={private_key_text}"),
            "tag",
            "-s",
            "-m",
            "signed tag",
            "v1",
        ],
    ));
    checked(git(&home, &repo, &["config", "gpg.format", "ssh"]));
    checked(git(
        &home,
        &repo,
        &["config", "user.signingkey", &private_key_text],
    ));
    checked(git(&home, &repo, &["config", "commit.gpgsign", "true"]));
    checked(git(&home, &repo, &["config", "tag.gpgsign", "true"]));

    let marker = temporary.path().join("hostile-verifier-ran");
    let hostile = temporary.path().join("hostile-verifier");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::write(
            &hostile,
            format!("#!/bin/sh\n: > '{}'\nexit 1\n", marker.display()),
        )
        .unwrap();
        fs::set_permissions(&hostile, fs::Permissions::from_mode(0o700)).unwrap();
    }
    checked(git(
        &home,
        &repo,
        &["config", "gpg.ssh.program", hostile.to_str().unwrap()],
    ));

    let git_client = GitClient::new(git_binary(), safe_environment());
    let verifier = SshVerifier::new(ssh_keygen.clone());
    let result = verifier
        .verify_commit(
            &git_client,
            &repo,
            "HEAD",
            &public_key,
            "signer@example.invalid",
        )
        .unwrap();
    assert!(result.cryptographically_valid);
    let (tag_oid, tag_contents) = git_client.tag_object(&repo, "v1").unwrap();
    assert!(tag_contents.contains("-----BEGIN SSH SIGNATURE-----"));
    let tag_result = verifier
        .verify_tag(
            &git_client,
            &repo,
            &tag_oid,
            &public_key,
            "signer@example.invalid",
        )
        .unwrap();
    assert!(
        tag_result.cryptographically_valid,
        "annotated SSH tag signature must verify"
    );
    assert!(
        !marker.exists(),
        "repository verifier helper must never run"
    );
    let wrong_private = temporary.path().join("wrong-key");
    let wrong_public = temporary.path().join("wrong-key.pub");
    success(
        Command::new(&ssh_keygen)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&wrong_private)
            .output()
            .unwrap(),
        "wrong synthetic ssh-keygen",
    );
    let wrong = verifier
        .verify_commit(
            &git_client,
            &repo,
            "HEAD",
            &wrong_public,
            "signer@example.invalid",
        )
        .unwrap();
    assert!(
        !wrong.cryptographically_valid,
        "a different allowed key must not authorize the signature"
    );
    assert!(
        !marker.exists(),
        "repository verifier helper must never run"
    );
    let output = Command::new(&ssh_keygen)
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .args(["-lf"])
        .arg(&public_key)
        .args(["-E", "sha256"])
        .output()
        .unwrap();
    let expected = String::from_utf8_lossy(&success(output, "ssh public-key fingerprint").stdout)
        .split_whitespace()
        .find(|field| field.starts_with("SHA256:"))
        .unwrap()
        .to_owned();
    assert_eq!(result.fingerprint.as_deref(), Some(expected.as_str()));

    let policy = temporary.path().join("ssh-tag-policy.toml");
    fs::write(&policy, format!(
        "version = 1\n[[scopes]]\nname = \"scope\"\npath = {:?}\n[scopes.git]\nauthor = {{ name = \"Synthetic Signer\", email = \"signer@example.invalid\" }}\ncommitter = {{ name = \"Synthetic Signer\", email = \"signer@example.invalid\" }}\n[scopes.git.signing]\nformat = \"ssh\"\nfingerprint = \"{expected}\"\npublic_key = {:?}\n",
        temporary.path().to_string_lossy(), public_key.to_string_lossy()
    )).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_persona"))
        .env_clear()
        .env("PERSONA_GIT", git_binary())
        .env("PERSONA_GPG", gpg_binary().unwrap())
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .env("PATH", fixture_path())
        .args(["check", "--config"])
        .arg(&policy)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--operation", "tag", "--tag", "v1", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decision["operation"], "git_tag_verification");
    for property in [
        "git.tag.signature.present",
        "git.tag.signature.valid",
        "git.tag.signature.fingerprint",
    ] {
        assert_eq!(finding(&decision, property)["status"], "PASS", "{decision}");
    }
    assert_eq!(
        finding(&decision, "git.tag.remote_verified")["status"],
        "UNKNOWN"
    );
    checked(git(
        &home,
        &repo,
        &["config", "user.signingkey", wrong_private.to_str().unwrap()],
    ));
    let mismatch = Command::new(env!("CARGO_BIN_EXE_persona"))
        .env_clear()
        .env("PERSONA_GIT", git_binary())
        .env("PERSONA_GPG", gpg_binary().unwrap())
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .env("PATH", fixture_path())
        .args(["check", "--config"])
        .arg(&policy)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--operation", "tag", "--tag", "v1", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(mismatch.status.code(), Some(1));
    let mismatch_decision: Value = serde_json::from_slice(&mismatch.stdout).unwrap();
    assert_eq!(
        finding(&mismatch_decision, "git.tag.signing.config")["status"],
        "FAIL"
    );
}

#[test]
fn push_audit_verifies_each_outgoing_ssh_commit() {
    let Some(ssh_keygen) = executable("ssh-keygen", "PERSONA_TEST_SSH_KEYGEN") else {
        eprintln!("SKIP: ssh-keygen is required for synthetic SSH signing fixture");
        return;
    };
    let temporary = tempdir().unwrap();
    let home = temporary.path().join("home");
    let repo = temporary.path().join("repo");
    let remote = temporary.path().join("remote.git");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&repo).unwrap();
    checked(git(&home, &repo, &["init", "-q"]));
    checked(git(
        &home,
        &repo,
        &["config", "user.name", "Synthetic Signer"],
    ));
    checked(git(
        &home,
        &repo,
        &["config", "user.email", "signer@example.invalid"],
    ));
    checked(git(
        &home,
        &repo,
        &["commit", "--allow-empty", "-m", "base"],
    ));
    let base = commit_oid(&home, &repo);
    checked(git(
        &home,
        &repo,
        &["init", "--bare", remote.to_str().unwrap()],
    ));
    checked(git(
        &home,
        &repo,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    ));
    let private_key = temporary.path().join("signing-key");
    let public_key = temporary.path().join("signing-key.pub");
    success(
        Command::new(&ssh_keygen)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&private_key)
            .output()
            .unwrap(),
        "synthetic ssh-keygen",
    );
    let private_key_text = private_key.to_string_lossy().into_owned();
    checked(git(&home, &repo, &["config", "gpg.format", "ssh"]));
    checked(git(
        &home,
        &repo,
        &["config", "user.signingkey", &private_key_text],
    ));
    checked(git(&home, &repo, &["config", "commit.gpgsign", "true"]));
    fs::write(repo.join("file"), "signed\n").unwrap();
    checked(git(&home, &repo, &["add", "file"]));
    checked(git(&home, &repo, &["commit", "-m", "signed"]));
    let head = commit_oid(&home, &repo);
    let fingerprint = String::from_utf8_lossy(
        &success(
            Command::new(&ssh_keygen)
                .env_clear()
                .env("HOME", &home)
                .env("PATH", "/usr/bin:/bin")
                .args(["-lf"])
                .arg(&public_key)
                .args(["-E", "sha256"])
                .output()
                .unwrap(),
            "ssh public-key fingerprint",
        )
        .stdout,
    )
    .split_whitespace()
    .find(|field| field.starts_with("SHA256:"))
    .unwrap()
    .to_owned();
    let policy = temporary.path().join("policy.toml");
    fs::write(&policy, format!(
        "version = 1\n[[scopes]]\nname = \"scope\"\npath = {:?}\n[scopes.git]\nauthor = {{ name = \"Synthetic Signer\", email = \"signer@example.invalid\" }}\ncommitter = {{ name = \"Synthetic Signer\", email = \"signer@example.invalid\" }}\n[scopes.git.signing]\nformat = \"ssh\"\nfingerprint = \"{fingerprint}\"\npublic_key = {:?}\n[scopes.git.push]\nremote = \"origin\"\ndestinations = [{:?}]\n",
        repo.to_string_lossy(), public_key.to_string_lossy(), remote.to_string_lossy()
    )).unwrap();
    let report = run_persona_push(
        &repo,
        &policy,
        &gpg_binary().expect("GPG"),
        &head,
        &base,
        &remote,
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

#[cfg(unix)]
#[test]
fn ssh_commit_signature_can_be_created_only_through_an_isolated_agent() {
    let Some(ssh_keygen) = executable("ssh-keygen", "PERSONA_TEST_SSH_KEYGEN") else {
        eprintln!("SKIP: ssh-keygen is required for synthetic SSH signing fixture");
        return;
    };
    let ssh_agent = executable("ssh-agent", "PERSONA_TEST_SSH_AGENT")
        .expect("ssh-agent is required for isolated signing-agent fixture");
    let ssh_add = executable("ssh-add", "PERSONA_TEST_SSH_ADD")
        .expect("ssh-add is required for isolated signing-agent fixture");
    let temporary = tempdir().unwrap();
    let home = temporary.path().join("home");
    let repo = temporary.path().join("repo");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&repo).unwrap();
    checked(git(&home, &repo, &["init", "-q"]));
    let private_key = temporary.path().join("agent-signing-key");
    let public_key = PathBuf::from(format!("{}.pub", private_key.display()));
    success(
        Command::new(&ssh_keygen)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", fixture_path())
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&private_key)
            .output()
            .unwrap(),
        "generate isolated SSH signing key",
    );
    let fingerprint = String::from_utf8_lossy(
        &success(
            Command::new(&ssh_keygen)
                .env_clear()
                .env("PATH", fixture_path())
                .arg("-lf")
                .arg(&public_key)
                .args(["-E", "sha256"])
                .output()
                .unwrap(),
            "fingerprint isolated SSH signing key",
        )
        .stdout,
    )
    .split_whitespace()
    .find(|field| field.starts_with("SHA256:"))
    .unwrap()
    .to_owned();
    let socket = temporary.path().join("ssh-agent.sock");
    let agent_start = success(
        Command::new(&ssh_agent)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", fixture_path())
            .args(["-a"])
            .arg(&socket)
            .arg("-s")
            .output()
            .unwrap(),
        "start isolated ssh-agent",
    );
    let agent_output = String::from_utf8_lossy(&agent_start.stdout);
    let pid = agent_output
        .lines()
        .find_map(|line| line.strip_prefix("SSH_AGENT_PID=")?.split(';').next())
        .unwrap()
        .to_owned();
    struct Agent {
        executable: PathBuf,
        socket: PathBuf,
        pid: String,
    }
    impl Drop for Agent {
        fn drop(&mut self) {
            let _ = Command::new(&self.executable)
                .env_clear()
                .env("SSH_AUTH_SOCK", &self.socket)
                .env("SSH_AGENT_PID", &self.pid)
                .args(["-k"])
                .output();
        }
    }
    let _agent = Agent {
        executable: ssh_agent,
        socket: socket.clone(),
        pid,
    };
    success(
        Command::new(&ssh_add)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", fixture_path())
            .env("SSH_AUTH_SOCK", &socket)
            .arg(&private_key)
            .output()
            .unwrap(),
        "load synthetic signing key into isolated agent",
    );
    fs::remove_file(&private_key).unwrap();
    fs::write(repo.join("file"), "agent-signed content\n").unwrap();
    checked(git(&home, &repo, &["add", "file"]));
    let command = Command::new(git_binary())
        .env_clear()
        .env("HOME", &home)
        .env("PATH", fixture_path())
        .env("SSH_AUTH_SOCK", &socket)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .current_dir(&repo)
        .args([
            "-c",
            "user.name=Synthetic Signer",
            "-c",
            "user.email=signer@example.invalid",
            "-c",
            "gpg.format=ssh",
            "-c",
            "commit.gpgsign=true",
        ])
        .arg("-c")
        .arg(format!("user.signingkey={}", public_key.display()))
        .args(["commit", "-m", "signed by agent"])
        .output()
        .unwrap();
    success(
        command,
        "create SSH-signed commit through agent with private file removed",
    );
    let policy = temporary.path().join("policy.toml");
    fs::write(
        &policy,
        format!(
            r#"version = 1
[[scopes]]
name = "scope"
path = {:?}
[scopes.git]
author = {{ name = "Synthetic Signer", email = "signer@example.invalid" }}
committer = {{ name = "Synthetic Signer", email = "signer@example.invalid" }}
[scopes.git.signing]
format = "ssh"
fingerprint = {fingerprint:?}
public_key = {:?}
"#,
            repo.to_string_lossy(),
            public_key.to_string_lossy()
        ),
    )
    .unwrap();
    let report: Value = serde_json::from_slice(
        &run_persona(
            &repo,
            &policy,
            &gpg_binary().expect("GPG is required for signing tests"),
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(
        finding(&report, "git.signature.valid")["status"],
        "PASS",
        "{report}"
    );
    assert_eq!(
        finding(&report, "git.signature.fingerprint")["status"],
        "PASS",
        "{report}"
    );
}
