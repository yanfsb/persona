use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

fn fixture_git(git: &Path, home: &Path) -> Command {
    let mut command = Command::new(git);
    command
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0");
    command
}

fn tracing_git(git: &Path, wrapper: &Path, fetch_calls: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::write(
        wrapper,
        format!(
            "#!/bin/sh\nfor argument in \"$@\"; do\n  if [ \"$argument\" = fetch ]; then\n    printf '%s\\n' \"$*\" >> '{}'\n    break\n  fi\ndone\nexec '{}' \"$@\"\n",
            fetch_calls.display(),
            git.display()
        ),
    )
    .unwrap();
    fs::set_permissions(wrapper, fs::Permissions::from_mode(0o700)).unwrap();
}

fn spawn_tls_client_hello_observer(
    listener: TcpListener,
    expected_hellos: usize,
    timeout: Duration,
) -> (Receiver<()>, Receiver<Vec<Vec<u8>>>) {
    let (ready_sender, ready_receiver) = mpsc::channel();
    let (complete_sender, complete_receiver) = mpsc::channel();
    thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + timeout;
        ready_sender.send(()).unwrap();
        let mut hellos = Vec::new();
        while hellos.len() < expected_hellos && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    stream.set_read_timeout(Some(remaining)).unwrap();
                    let mut bytes = [0; 8];
                    let count = stream.read(&mut bytes).unwrap_or(0);
                    if count > 0 && bytes[0] == 0x16 {
                        hellos.push(bytes[..count].to_vec());
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        let _ = complete_sender.send(hellos);
    });
    (ready_receiver, complete_receiver)
}

#[cfg(unix)]
#[test]
fn managed_fetch_routes_ssh_only_through_the_profile_transport() {
    use std::os::unix::fs::PermissionsExt;

    let git = std::path::PathBuf::from(
        std::env::var_os("PERSONA_TEST_GIT").expect("PERSONA_TEST_GIT must be set"),
    );
    let ssh_keygen = std::env::split_paths(&std::env::var_os("PATH").expect("PATH"))
        .map(|directory| directory.join("ssh-keygen"))
        .find(|path| path.is_file())
        .expect("ssh-keygen executable required");
    let temporary = tempdir().unwrap();
    let repo = temporary.path().join("repo");
    fs::create_dir(&repo).unwrap();
    let https_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let https_port = https_listener.local_addr().unwrap().port();
    let https_destination = format!("https://127.0.0.1:{https_port}/org/mixed.git");
    let key = temporary.path().join("client-key");
    let generated = Command::new(&ssh_keygen)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(generated.status.success());
    let public_key = Path::new(&format!("{}.pub", key.display())).to_path_buf();
    let fingerprint_output = Command::new(&ssh_keygen)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .arg("-lf")
        .arg(&public_key)
        .args(["-E", "sha256"])
        .output()
        .unwrap();
    assert!(fingerprint_output.status.success());
    let fingerprint = String::from_utf8_lossy(&fingerprint_output.stdout)
        .split_whitespace()
        .find(|field| field.starts_with("SHA256:"))
        .unwrap()
        .to_owned();
    let known_hosts = temporary.path().join("known_hosts");
    fs::write(
        &known_hosts,
        "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFixtureHostKey\n",
    )
    .unwrap();
    let marker = temporary.path().join("ssh-args");
    let fetch_calls = temporary.path().join("git-fetches");
    let tracing_git_path = temporary.path().join("git-fixture");
    tracing_git(&git, &tracing_git_path, &fetch_calls);
    let fake_ssh = temporary.path().join("ssh-fixture");
    fs::write(
        &fake_ssh,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\nexit 71\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_ssh, fs::Permissions::from_mode(0o700)).unwrap();

    let remote = "git@github.com:org/repo.git";
    let upstream = "git@github.com:org/upstream.git";
    let skipped = "git@github.com:org/skipped.git";
    let policy = persona::config::SshPolicy {
        host: "github.com".to_owned(),
        user: "git".to_owned(),
        port: 22,
        fingerprint: fingerprint.clone(),
        public_key: public_key.clone(),
        identity_file: Some(key.clone()),
        agent_socket: None,
        known_hosts_file: known_hosts.clone(),
    };
    let transport =
        persona::ssh_transport::ManagedSshTransport::new(fake_ssh.clone(), ssh_keygen.clone());
    assert!(
        transport
            .arguments(&policy, remote, "git-upload-pack 'org/repo.git'")
            .is_ok(),
        "fixture SSH transport policy must validate"
    );
    let init = fixture_git(&git, temporary.path())
        .args(["init", "--quiet"])
        .arg(&repo)
        .output()
        .unwrap();
    assert!(init.status.success());
    for (name, url) in [
        ("origin", remote),
        ("https", https_destination.as_str()),
        ("upstream", upstream),
        ("skipped", skipped),
    ] {
        let added = fixture_git(&git, temporary.path())
            .args(["-C"])
            .arg(&repo)
            .args(["remote", "add", name, url])
            .output()
            .unwrap();
        assert!(added.status.success());
    }
    let skipped_remote = fixture_git(&git, temporary.path())
        .args(["-C"])
        .arg(&repo)
        .args(["config", "remote.skipped.skipFetchAll", "true"])
        .output()
        .unwrap();
    assert!(skipped_remote.status.success());

    let scope_path = toml::Value::String(repo.to_string_lossy().into_owned());
    let remote_value = toml::Value::String(remote.to_owned());
    let public_key_value = toml::Value::String(public_key.to_string_lossy().into_owned());
    let identity_file_value = toml::Value::String(key.to_string_lossy().into_owned());
    let known_hosts_value = toml::Value::String(known_hosts.to_string_lossy().into_owned());
    let config = temporary.path().join("persona.toml");
    fs::write(
        &config,
        format!(
            r#"
version = 4

[profiles.fixture]
name = "Fixture"
email = "fixture@example.invalid"
scopes = [{scope_path}]

[profiles.fixture.git.remotes]
origin = {{ fetch = [{remote_value}], push = [{remote_value}] }}
https = {{ fetch = ["{https_destination}"] }}
upstream = {{ fetch = ["{upstream}"] }}
skipped = {{ fetch = ["{skipped}"] }}

[profiles.fixture.ssh]
host = "github.com"
user = "git"
port = 22
fingerprint = "{fingerprint}"
public_key = {public_key_value}
identity_file = {identity_file_value}
known_hosts_file = {known_hosts_value}
"#
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_persona"))
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &tracing_git_path)
        .env("PERSONA_SSH", &fake_ssh)
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .current_dir(&repo)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "fetch", "origin"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        marker.exists(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let ssh_args = fs::read_to_string(&marker).unwrap();
    assert!(ssh_args.contains("StrictHostKeyChecking=yes"));
    assert!(ssh_args.contains("ProxyCommand=none"));
    assert!(ssh_args.contains("git-upload-pack 'org/repo.git'"));

    fs::remove_file(&marker).unwrap();
    let _ = fs::remove_file(&fetch_calls);
    let (observer_ready, observer_complete) =
        spawn_tls_client_hello_observer(https_listener, 1, Duration::from_secs(6));
    observer_ready
        .recv_timeout(Duration::from_secs(1))
        .expect("mixed TLS observer must be ready before fetch-all starts");
    let all_fetch = Command::new(env!("CARGO_BIN_EXE_persona"))
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &tracing_git_path)
        .env("PERSONA_SSH", &fake_ssh)
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .current_dir(&repo)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "fetch", "--prune", "--all"])
        .output()
        .unwrap();
    assert!(
        !all_fetch.status.success(),
        "fake SSH exits before any transfer"
    );
    let all_ssh_args = fs::read_to_string(&marker).unwrap();
    assert!(all_ssh_args.contains("git-upload-pack 'org/repo.git'"));
    assert!(
        all_ssh_args.contains("git-upload-pack 'org/upstream.git'"),
        "fetch-all SSH calls were: {all_ssh_args}; stderr: {}",
        String::from_utf8_lossy(&all_fetch.stderr)
    );
    assert!(!all_ssh_args.contains("org/skipped.git"));
    let fetch_calls_output = fs::read_to_string(&fetch_calls).unwrap();
    let mut fetched_remotes = fetch_calls_output
        .lines()
        .filter_map(|call| call.split_whitespace().last())
        .collect::<Vec<_>>();
    fetched_remotes.sort_unstable();
    assert_eq!(fetched_remotes, ["https", "origin", "upstream"]);

    fs::remove_file(&marker).unwrap();
    let _ = fs::remove_file(&fetch_calls);
    let mut denied_config = fs::read_to_string(&config).unwrap();
    denied_config =
        denied_config.replace(&format!("upstream = {{ fetch = [\"{upstream}\"] }}\n"), "");
    fs::write(&config, denied_config).unwrap();
    let unauthorized = Command::new(env!("CARGO_BIN_EXE_persona"))
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &tracing_git_path)
        .env("PERSONA_SSH", &fake_ssh)
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .current_dir(&repo)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "fetch", "--all"])
        .output()
        .unwrap();
    assert!(!unauthorized.status.success());
    assert!(
        !marker.exists(),
        "all remotes must be authorized before transport"
    );
    assert!(
        !fetch_calls.exists(),
        "unauthorized mixed fetch must not launch any Git transport"
    );
    let observed_hellos = observer_complete
        .recv_timeout(Duration::from_secs(7))
        .expect("mixed TLS observer must complete within its bounded deadline");
    if std::env::var_os("PERSONA_TEST_SKIP_LOCAL_TLS").is_none() {
        assert_eq!(
            observed_hellos.len(),
            1,
            "mixed fetch should reach HTTPS once, while unauthorized preflight sends no second request"
        );
        assert!(
            observed_hellos[0].first() == Some(&0x16),
            "expected a TLS ClientHello record, got {observed_hellos:?}"
        );
    }

    let clone_target = repo.join("ssh-clone");
    let clone = Command::new(env!("CARGO_BIN_EXE_persona"))
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &tracing_git_path)
        .env("PERSONA_SSH", &fake_ssh)
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .current_dir(&repo)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "clone", remote])
        .arg(&clone_target)
        .output()
        .unwrap();
    assert!(
        !clone.status.success(),
        "the synthetic SSH fixture must stop before a real remote transfer"
    );
    assert!(
        marker.exists(),
        "SSH clone must reach the managed transport, stderr: {}",
        String::from_utf8_lossy(&clone.stderr)
    );
    let clone_ssh_args = fs::read_to_string(&marker).unwrap();
    assert!(clone_ssh_args.contains("StrictHostKeyChecking=yes"));
    assert!(clone_ssh_args.contains("git-upload-pack 'org/repo.git'"));
}

#[cfg(unix)]
#[test]
fn mixed_remote_fetch_all_preflight_rejects_before_any_transport() {
    let git = std::path::PathBuf::from(
        std::env::var_os("PERSONA_TEST_GIT").expect("PERSONA_TEST_GIT must be set"),
    );
    let temporary = tempdir().unwrap();
    let repo = temporary.path().join("repo");
    fs::create_dir(&repo).unwrap();
    let init = fixture_git(&git, temporary.path())
        .args(["init", "--quiet"])
        .arg(&repo)
        .output()
        .unwrap();
    assert!(init.status.success());
    for (name, url) in [
        ("00-denied", "https://127.0.0.1:9/org/denied.git"),
        ("zz-ssh", "git@github.com:org/repo.git"),
    ] {
        let added = fixture_git(&git, temporary.path())
            .args(["-C"])
            .arg(&repo)
            .args(["remote", "add", name, url])
            .output()
            .unwrap();
        assert!(added.status.success());
    }

    let config = temporary.path().join("persona.toml");
    let scope_path = toml::Value::String(repo.to_string_lossy().into_owned());
    fs::write(
        &config,
        format!(
            r#"
version = 4

[profiles.fixture]
name = "Fixture"
email = "fixture@example.invalid"
scopes = [{scope_path}]

[profiles.fixture.git.remotes]
zz-ssh = {{ fetch = ["git@github.com:org/repo.git"] }}
"#
        ),
    )
    .unwrap();

    let fetch_calls = temporary.path().join("git-fetches");
    let tracing_git_path = temporary.path().join("git-fixture");
    tracing_git(&git, &tracing_git_path, &fetch_calls);
    let output = Command::new(env!("CARGO_BIN_EXE_persona"))
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &tracing_git_path)
        .current_dir(&repo)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "fetch", "--all"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("00-denied"),
        "expected rejection of the unapproved mixed remote: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !fetch_calls.exists(),
        "unauthorized mixed preflight must not launch Git transport, even when local TLS is skipped"
    );
}

#[test]
fn mixed_tls_observer_waits_for_delayed_client_hello() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let client = thread::spawn(move || {
        let mut stream = TcpStream::connect(address).unwrap();
        thread::sleep(Duration::from_millis(100));
        stream.write_all(&[0x16]).unwrap();
    });
    let (ready, complete) = spawn_tls_client_hello_observer(listener, 1, Duration::from_secs(2));
    ready
        .recv_timeout(Duration::from_secs(1))
        .expect("delayed ClientHello observer must become ready");
    let hellos = complete
        .recv_timeout(Duration::from_secs(3))
        .expect("delayed ClientHello observer must complete within its deadline");
    client.join().unwrap();
    assert_eq!(hellos, [vec![0x16]]);
}

#[test]
fn managed_fetch_only_connects_to_an_exact_https_destination() {
    if let Some(reason) = std::env::var_os("PERSONA_TEST_SKIP_LOCAL_TLS") {
        eprintln!(
            "SKIP local TLS transport fixture: {}",
            reason.to_string_lossy()
        );
        return;
    }
    let git = std::env::var_os("PERSONA_TEST_GIT").expect("PERSONA_TEST_GIT must be set");
    let git = std::path::PathBuf::from(git);
    assert!(git.is_absolute());
    let temporary = tempdir().unwrap();
    let repo = temporary.path().join("repo");
    fs::create_dir(&repo).unwrap();

    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let destination = format!("https://127.0.0.1:{port}/org/repo.git");

    let init = fixture_git(&git, temporary.path())
        .args(["init", "--quiet"])
        .arg(&repo)
        .output()
        .unwrap();
    assert!(init.status.success());
    let remote = fixture_git(&git, temporary.path())
        .args(["-C"])
        .arg(&repo)
        .args(["remote", "add", "origin"])
        .arg(&destination)
        .output()
        .unwrap();
    assert!(remote.status.success());

    let quoted_root = toml::Value::String(repo.to_string_lossy().into_owned());
    let quoted_destination = toml::Value::String(destination.clone());
    let config = temporary.path().join("persona.toml");
    fs::write(
        &config,
        format!(
            "version = 4\n[profiles.fixture]\nauthor = {{ name = \"Fixture Author\", email = \"author@example.invalid\" }}\ncommitter = {{ name = \"Fixture Committer\", email = \"committer@example.invalid\" }}\nscopes = [{quoted_root}]\n[profiles.fixture.git]\nremote = \"origin\"\npush = [{quoted_destination}]\n"
        ),
    )
    .unwrap();

    let (observer_ready, observer_complete) =
        spawn_tls_client_hello_observer(listener, 2, Duration::from_secs(6));
    observer_ready
        .recv_timeout(Duration::from_secs(1))
        .expect("exact-destination TLS observer must be ready before fetch");
    let output = Command::new(env!("CARGO_BIN_EXE_persona"))
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .current_dir(&repo)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "fetch", "origin"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let clone = Command::new(env!("CARGO_BIN_EXE_persona"))
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .current_dir(&repo)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "clone"])
        .arg(&destination)
        .arg(repo.join("cloned-repository"))
        .output()
        .unwrap();
    assert!(
        !clone.status.success(),
        "the fixture server closes TLS before clone can complete"
    );
    let tls_hellos = observer_complete
        .recv_timeout(Duration::from_secs(7))
        .expect("exact-destination TLS observer must complete within its bounded deadline");
    assert_eq!(
        tls_hellos.len(),
        2,
        "fetch and clone should both connect locally"
    );
    assert!(
        tls_hellos.iter().all(|hello| hello.first() == Some(&0x16)),
        "expected TLS ClientHello records, got {tls_hellos:?}; clone stderr: {}",
        String::from_utf8_lossy(&clone.stderr)
    );

    let unapproved_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let unapproved_port = unapproved_listener.local_addr().unwrap().port();
    unapproved_listener.set_nonblocking(true).unwrap();
    let unapproved_server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match unapproved_listener.accept() {
                Ok(_) => return true,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return false,
            }
        }
    });
    let redirected = fixture_git(&git, temporary.path())
        .args(["-C"])
        .arg(&repo)
        .args(["remote", "set-url", "origin"])
        .arg(format!("https://127.0.0.1:{unapproved_port}/org/repo.git"))
        .output()
        .unwrap();
    assert!(redirected.status.success());
    let rejected = Command::new(env!("CARGO_BIN_EXE_persona"))
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .current_dir(&repo)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--", "git", "fetch", "origin"])
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(126));
    assert!(
        !unapproved_server.join().unwrap(),
        "unapproved destination was contacted"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn managed_https_push_succeeds_and_rejects_a_server_update_race() {
    use std::io::{BufRead, BufReader};
    use std::process::Child;

    if let Some(reason) = std::env::var_os("PERSONA_TEST_SKIP_LOCAL_HTTPS_PUSH") {
        let reason = reason.to_string_lossy();
        assert!(
            !reason.trim().is_empty(),
            "PERSONA_TEST_SKIP_LOCAL_HTTPS_PUSH must contain an explicit reason"
        );
        eprintln!("SKIP local HTTPS push fixture: {reason}");
        return;
    }
    assert!(
        std::env::var_os("PERSONA_TEST_LOCAL_HTTPS_TRUSTED").is_some(),
        "local HTTPS push fixture requires its synthetic CA in system trust; install tests/fixtures/https/test-ca.crt or set PERSONA_TEST_SKIP_LOCAL_HTTPS_PUSH with an explicit reason"
    );
    let git = std::path::PathBuf::from(
        std::env::var_os("PERSONA_TEST_GIT").expect("PERSONA_TEST_GIT must be set"),
    );
    let root = tempdir().unwrap();
    let run_git = |directory: &Path, arguments: &[&str]| {
        let mut command = fixture_git(&git, root.path());
        command.arg("-C").arg(directory).args(arguments);
        command.output().unwrap()
    };
    let bare = root.path().join("projects/org/repo.git");
    fs::create_dir_all(bare.parent().unwrap()).unwrap();
    let initialized = fixture_git(&git, root.path())
        .args(["init", "--bare", "--quiet", "-b", "main"])
        .arg(&bare)
        .output()
        .unwrap();
    assert!(initialized.status.success());
    let configure_receive = fixture_git(&git, root.path())
        .arg("--git-dir")
        .arg(&bare)
        .args(["config", "http.receivepack", "true"])
        .output()
        .unwrap();
    assert!(configure_receive.status.success());

    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/https");
    let race_file = root.path().join("race-request");
    let race_observed = root.path().join("race-observed");
    let server_script = fixtures.join("git_http_backend.py");
    let server = Command::new("python3")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_TEST_TLS_CERT", fixtures.join("server.crt"))
        .env("PERSONA_TEST_TLS_KEY", fixtures.join("server.key"))
        .arg(server_script)
        .arg(root.path().join("projects"))
        .arg(&race_file)
        .arg(&race_observed)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    struct Server(Child);
    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut _server = Server(server);
    let port = {
        let stdout = _server.0.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        line.trim().parse::<u16>().expect("fixture HTTPS port")
    };
    assert_ne!(port, 0);

    let worktree = root.path().join("worktree");
    let initialized = fixture_git(&git, root.path())
        .args(["init", "--quiet", "-b", "main"])
        .arg(&worktree)
        .output()
        .unwrap();
    assert!(initialized.status.success());
    let ssh_keygen = std::env::var_os("PERSONA_TEST_SSH_KEYGEN")
        .map(std::path::PathBuf::from)
        .expect("PERSONA_TEST_SSH_KEYGEN must be set for signed-tag transport coverage");
    let signing_key = root.path().join("publication-signing-key");
    let generated_key = Command::new(&ssh_keygen)
        .env_clear()
        .env("HOME", root.path())
        .env("PATH", "/usr/bin:/bin")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&signing_key)
        .output()
        .unwrap();
    assert!(
        generated_key.status.success(),
        "generate synthetic SSH signing key: {}",
        String::from_utf8_lossy(&generated_key.stderr)
    );
    let public_key = Path::new(&format!("{}.pub", signing_key.display())).to_path_buf();
    let fingerprint_output = Command::new(&ssh_keygen)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .arg("-lf")
        .arg(&public_key)
        .args(["-E", "sha256"])
        .output()
        .unwrap();
    assert!(fingerprint_output.status.success());
    let fingerprint = String::from_utf8_lossy(&fingerprint_output.stdout)
        .split_whitespace()
        .find(|field| field.starts_with("SHA256:"))
        .unwrap()
        .to_owned();
    for (key, value) in [("gpg.format", "ssh"), ("commit.gpgsign", "true")] {
        let configured = run_git(&worktree, &["config", key, value]);
        assert!(configured.status.success());
    }
    let signing_key_config = run_git(
        &worktree,
        &["config", "user.signingkey", signing_key.to_str().unwrap()],
    );
    assert!(signing_key_config.status.success());
    let base = fixture_git(&git, root.path())
        .arg("-C")
        .arg(&worktree)
        .env("GIT_AUTHOR_NAME", "Approved Upstream")
        .env("GIT_AUTHOR_EMAIL", "upstream@example.invalid")
        .args([
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
        ])
        .args(["commit", "--allow-empty", "-m", "pinned upstream base"])
        .output()
        .unwrap();
    assert!(
        base.status.success(),
        "{}",
        String::from_utf8_lossy(&base.stderr)
    );
    let base_oid = String::from_utf8_lossy(&run_git(&worktree, &["rev-parse", "HEAD"]).stdout)
        .trim()
        .to_owned();
    assert!(!base_oid.is_empty());
    let pin = run_git(
        &worktree,
        &["update-ref", "refs/remotes/origin/upstream", &base_oid],
    );
    assert!(pin.status.success());
    let tracking_pin = run_git(
        &worktree,
        &["update-ref", "refs/remotes/origin/main", &base_oid],
    );
    assert!(tracking_pin.status.success());
    let seed_remote = fixture_git(&git, root.path())
        .arg("--git-dir")
        .arg(&bare)
        .args(["fetch", "--quiet"])
        .arg(&worktree)
        .args(["refs/remotes/origin/main:refs/heads/main"])
        .output()
        .unwrap();
    assert!(
        seed_remote.status.success(),
        "seed exact upstream baseline on synthetic HTTPS remote: {}",
        String::from_utf8_lossy(&seed_remote.stderr)
    );
    let feature_branch = run_git(&worktree, &["checkout", "-b", "feature"]);
    assert!(feature_branch.status.success());
    let feature_commit = run_git(
        &worktree,
        &[
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "feature",
        ],
    );
    assert!(feature_commit.status.success());
    let back_to_main = run_git(&worktree, &["checkout", "main"]);
    assert!(back_to_main.status.success());
    let main_advance = run_git(
        &worktree,
        &[
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "main descendant of pinned upstream",
        ],
    );
    assert!(
        main_advance.status.success(),
        "create signed main descendant: {}",
        String::from_utf8_lossy(&main_advance.stderr)
    );

    let destination = format!("https://127.0.0.1:{port}/org/repo.git");
    let added = run_git(&worktree, &["remote", "add", "origin", &destination]);
    assert!(added.status.success());
    let configured = run_git(
        &worktree,
        &[
            "config",
            "remote.origin.fetch",
            "+refs/heads/*:refs/remotes/origin/*",
        ],
    );
    assert!(configured.status.success());

    let config = root.path().join("persona.toml");
    let q = |value: &str| toml::Value::String(value.to_owned()).to_string();
    fs::write(
        &config,
        format!(
            "version = 4\n[profiles.fixture]\nname = \"Synthetic\"\nemail = \"synthetic@example.invalid\"\nscopes = [{}]\n[profiles.fixture.signing]\nfingerprint = {fingerprint:?}\nformat = \"ssh\"\npublic_key = {public_key:?}\n[profiles.fixture.git]\nremote = \"origin\"\npush = [{}]\nallow_lightweight_tags = true\nallow_annotated_tags = true\nallow_branch_deletion = true\nallow_tag_deletion = true\nallow_force_with_lease = true\npreserve_authors = true\n[[profiles.fixture.git.baselines]]\ndestination = {}\ntracking_ref = \"refs/remotes/origin/upstream\"\noid = {base_oid:?}\n",
            q(&worktree.to_string_lossy()),
            q(&destination),
            q(&destination),
        ),
    )
    .unwrap();
    let persona = Path::new(env!("CARGO_BIN_EXE_persona"));
    let persona_command = |args: &[&str]| {
        let mut command = Command::new(persona);
        command
            .env_clear()
            .env("HOME", root.path())
            .env("PATH", "/usr/bin:/bin")
            .env("PERSONA_GIT", &git)
            .args(args)
            .arg("--config")
            .arg(&config)
            .args(["--cwd"])
            .arg(&worktree);
        command
    };
    let hook = persona_command(&["hooks", "install"]).output().unwrap();
    assert!(
        hook.status.success(),
        "{}",
        String::from_utf8_lossy(&hook.stderr)
    );
    let push = persona_command(&["run"])
        .args([
            "--",
            "git",
            "push",
            "--atomic",
            "origin",
            "refs/heads/main:refs/heads/main",
            "refs/heads/feature:refs/heads/feature",
        ])
        .output()
        .unwrap();
    assert!(
        push.status.success(),
        "stdout: {}; stderr: {}",
        String::from_utf8_lossy(&push.stdout),
        String::from_utf8_lossy(&push.stderr)
    );
    let pushed = fixture_git(&git, root.path())
        .arg("--git-dir")
        .arg(&bare)
        .args(["rev-parse", "refs/heads/main"])
        .output()
        .unwrap();
    assert!(pushed.status.success());
    let pushed_oid = String::from_utf8_lossy(&pushed.stdout).trim().to_owned();
    let pushed_feature = fixture_git(&git, root.path())
        .arg("--git-dir")
        .arg(&bare)
        .args(["rev-parse", "refs/heads/feature"])
        .output()
        .unwrap();
    assert!(pushed_feature.status.success());
    let refresh_after_initial = persona_command(&["run"])
        .args(["--", "git", "fetch", "origin"])
        .output()
        .unwrap();
    assert!(
        refresh_after_initial.status.success(),
        "managed HTTPS tracking refresh failed: {}",
        String::from_utf8_lossy(&refresh_after_initial.stderr)
    );
    let fast_forward_commit = run_git(
        &worktree,
        &[
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "fast-forward fixture",
        ],
    );
    assert!(
        fast_forward_commit.status.success(),
        "create HTTPS fast-forward commit: {}",
        String::from_utf8_lossy(&fast_forward_commit.stderr)
    );
    let fast_forward_push = persona_command(&["run"])
        .args([
            "--",
            "git",
            "push",
            "origin",
            "refs/heads/main:refs/heads/main",
        ])
        .output()
        .unwrap();
    assert!(
        fast_forward_push.status.success(),
        "managed HTTPS fast-forward failed: stdout {}; stderr {}",
        String::from_utf8_lossy(&fast_forward_push.stdout),
        String::from_utf8_lossy(&fast_forward_push.stderr)
    );

    let signed_tag = run_git(
        &worktree,
        &[
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "tag",
            "-s",
            "-m",
            "signed annotated publication",
            "signed-release",
            "refs/heads/main",
        ],
    );
    assert!(
        signed_tag.status.success(),
        "create SSH-signed annotated tag for HTTPS: {}",
        String::from_utf8_lossy(&signed_tag.stderr)
    );
    let signed_tag_push = persona_command(&["run"])
        .args([
            "--",
            "git",
            "push",
            "--force-with-lease=refs/tags/signed-release:0000000000000000000000000000000000000000",
            "origin",
            "refs/tags/signed-release:refs/tags/signed-release",
        ])
        .output()
        .unwrap();
    assert!(
        signed_tag_push.status.success(),
        "HTTPS signed annotated tag publication failed: stdout {}; stderr {}",
        String::from_utf8_lossy(&signed_tag_push.stdout),
        String::from_utf8_lossy(&signed_tag_push.stderr)
    );
    let tag = run_git(&worktree, &["tag", "release-fixture", "refs/heads/main"]);
    assert!(tag.status.success());
    let tag_push = persona_command(&["run"])
        .args([
            "--",
            "git",
            "push",
            "--force-with-lease=refs/tags/release-fixture:0000000000000000000000000000000000000000",
            "origin",
            "refs/tags/release-fixture:refs/tags/release-fixture",
        ])
        .output()
        .unwrap();
    assert!(
        tag_push.status.success(),
        "stdout: {}; stderr: {}",
        String::from_utf8_lossy(&tag_push.stdout),
        String::from_utf8_lossy(&tag_push.stderr)
    );
    let remote_tag = fixture_git(&git, root.path())
        .arg("--git-dir")
        .arg(&bare)
        .args(["rev-parse", "refs/tags/release-fixture"])
        .output()
        .unwrap();
    assert!(remote_tag.status.success());
    let local_tag = run_git(&worktree, &["rev-parse", "refs/tags/release-fixture"]);
    let mut remote_tag_oid = String::from_utf8_lossy(&remote_tag.stdout)
        .trim()
        .to_owned();
    assert_eq!(
        remote_tag_oid,
        String::from_utf8_lossy(&local_tag.stdout).trim()
    );
    let retarget_local_tag = run_git(
        &worktree,
        &["tag", "-f", "release-fixture", "refs/heads/feature"],
    );
    assert!(retarget_local_tag.status.success());
    let retargeted_tag = run_git(&worktree, &["rev-parse", "refs/tags/release-fixture"]);
    assert!(retargeted_tag.status.success());
    let retarget_push = persona_command(&["run"])
        .args([
            "--",
            "git",
            "push",
            &format!("--force-with-lease=refs/tags/release-fixture:{remote_tag_oid}"),
            "origin",
            "refs/tags/release-fixture:refs/tags/release-fixture",
        ])
        .output()
        .unwrap();
    assert!(
        retarget_push.status.success(),
        "exact-lease tag update failed: {}",
        String::from_utf8_lossy(&retarget_push.stderr)
    );
    let updated_remote_tag = fixture_git(&git, root.path())
        .arg("--git-dir")
        .arg(&bare)
        .args(["rev-parse", "refs/tags/release-fixture"])
        .output()
        .unwrap();
    assert!(updated_remote_tag.status.success());
    remote_tag_oid = String::from_utf8_lossy(&updated_remote_tag.stdout)
        .trim()
        .to_owned();
    assert_eq!(
        remote_tag_oid,
        String::from_utf8_lossy(&retargeted_tag.stdout).trim()
    );
    let delete_tag = persona_command(&["run"])
        .args([
            "--",
            "git",
            "push",
            &format!("--force-with-lease=refs/tags/release-fixture:{remote_tag_oid}"),
            "origin",
            ":refs/tags/release-fixture",
        ])
        .output()
        .unwrap();
    assert!(
        delete_tag.status.success(),
        "exact-lease tag deletion failed: {}",
        String::from_utf8_lossy(&delete_tag.stderr)
    );
    let absent_tag = fixture_git(&git, root.path())
        .arg("--git-dir")
        .arg(&bare)
        .args(["show-ref", "--verify", "refs/tags/release-fixture"])
        .output()
        .unwrap();
    assert!(
        !absent_tag.status.success(),
        "tag deletion should remove the exact remote ref"
    );

    let fetch = persona_command(&["run"])
        .args(["--", "git", "fetch", "origin"])
        .output()
        .unwrap();
    assert!(
        fetch.status.success(),
        "{}",
        String::from_utf8_lossy(&fetch.stderr)
    );
    let feature_remote_oid = run_git(&worktree, &["rev-parse", "refs/remotes/origin/feature"]);
    assert!(feature_remote_oid.status.success());
    let feature_remote_oid = String::from_utf8_lossy(&feature_remote_oid.stdout)
        .trim()
        .to_owned();
    let delete_branch = persona_command(&["run"])
        .args([
            "--",
            "git",
            "push",
            &format!("--force-with-lease=refs/heads/feature:{feature_remote_oid}"),
            "origin",
            ":refs/heads/feature",
        ])
        .output()
        .unwrap();
    assert!(
        delete_branch.status.success(),
        "exact-lease branch deletion failed: {}",
        String::from_utf8_lossy(&delete_branch.stderr)
    );
    let absent_branch = fixture_git(&git, root.path())
        .arg("--git-dir")
        .arg(&bare)
        .args(["show-ref", "--verify", "refs/heads/feature"])
        .output()
        .unwrap();
    assert!(
        !absent_branch.status.success(),
        "branch deletion should remove the exact remote ref"
    );
    let no_op = persona_command(&["run"])
        .args([
            "--",
            "git",
            "push",
            "origin",
            "refs/heads/main:refs/heads/main",
        ])
        .output()
        .unwrap();
    assert_eq!(no_op.status.code(), Some(126));
    assert!(String::from_utf8_lossy(&no_op.stderr).contains("unchanged or absent remote ref"));

    // Simulate stale/missing tracking data: native Git can report up-to-date
    // without invoking pre-push, so Persona must not report a policy-approved push.
    let removed_tracking = run_git(&worktree, &["update-ref", "-d", "refs/remotes/origin/main"]);
    assert!(removed_tracking.status.success());
    let skipped_hook = persona_command(&["run"])
        .args([
            "--",
            "git",
            "push",
            "origin",
            "refs/heads/main:refs/heads/main",
        ])
        .output()
        .unwrap();
    let skipped_hook_stderr = String::from_utf8_lossy(&skipped_hook.stderr);
    assert!(
        !skipped_hook.status.success(),
        "stale tracking data must not report a successful push without the authorization barrier: {}",
        skipped_hook_stderr
    );
    assert!(
        skipped_hook_stderr.contains("without consuming Persona's pre-push authorization barrier")
            || skipped_hook_stderr
                .contains("native ref/OID updates differ from primary authorization"),
        "unexpected stale no-op refusal: {skipped_hook_stderr}"
    );
    let refresh_tracking = persona_command(&["run"])
        .args(["--", "git", "fetch", "origin"])
        .output()
        .unwrap();
    assert!(refresh_tracking.status.success());

    let racing_worktree = root.path().join("racing-worktree");
    let clone = fixture_git(&git, root.path())
        .args(["clone", "--quiet", "--branch", "main"])
        .arg(&bare)
        .arg(&racing_worktree)
        .output()
        .unwrap();
    assert!(clone.status.success());
    let racing_commit = {
        let mut command = fixture_git(&git, root.path());
        command
            .arg("-C")
            .arg(&racing_worktree)
            .args([
                "-c",
                "user.name=Racer",
                "-c",
                "user.email=racer@example.invalid",
                "commit",
                "--allow-empty",
                "-m",
                "concurrent",
            ])
            .output()
            .unwrap()
    };
    assert!(
        racing_commit.status.success(),
        "{}",
        String::from_utf8_lossy(&racing_commit.stderr)
    );
    let racing_oid = run_git(&racing_worktree, &["rev-parse", "refs/heads/main"]);
    assert!(racing_oid.status.success());
    let racing_oid = String::from_utf8_lossy(&racing_oid.stdout)
        .trim()
        .to_owned();
    let transfer_racing_object = fixture_git(&git, root.path())
        .arg("--git-dir")
        .arg(&bare)
        .args(["fetch", "--quiet"])
        .arg(&racing_worktree)
        .arg("refs/heads/main")
        .output()
        .unwrap();
    assert!(
        transfer_racing_object.status.success(),
        "transfer race commit object without changing the remote ref: {}",
        String::from_utf8_lossy(&transfer_racing_object.stderr)
    );
    let local_advance = run_git(
        &worktree,
        &[
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "local advance",
        ],
    );
    assert!(
        local_advance.status.success(),
        "{}",
        String::from_utf8_lossy(&local_advance.stderr)
    );
    fs::write(&race_file, format!("refs/heads/main {racing_oid}\n")).unwrap();
    let raced_push = persona_command(&["run"])
        .args([
            "--",
            "git",
            "push",
            "origin",
            "refs/heads/main:refs/heads/main",
        ])
        .output()
        .unwrap();
    assert!(
        !raced_push.status.success(),
        "concurrent remote update must reject stale push; stdout: {}; stderr: {}; raced oid: {:?}",
        String::from_utf8_lossy(&raced_push.stdout),
        String::from_utf8_lossy(&raced_push.stderr),
        format!(
            "observed={:?}, request-log={:?}, race-request-exists={}",
            fs::read_to_string(&race_observed),
            fs::read_to_string(format!("{}.requests", race_observed.display())),
            race_file.exists()
        )
    );
    let rejection = format!(
        "{}{}",
        String::from_utf8_lossy(&raced_push.stdout),
        String::from_utf8_lossy(&raced_push.stderr)
    );
    assert!(
        rejection.contains("non-fast-forward")
            || rejection.contains("failed to update ref")
            || rejection.contains("stale info")
            || (rejection.contains("incorrect old value provided")
                && rejection.contains(&racing_oid))
            || (rejection.contains("cannot lock ref 'refs/heads/main'")
                && rejection.contains(&racing_oid)
                && rejection.contains(&pushed_oid)),
        "push failure must be attributable to the server's stale-ref rejection, not an unrelated local guard: {rejection}"
    );
    assert_eq!(
        fs::read_to_string(&race_observed).unwrap().trim(),
        racing_oid
    );
    let remote_after_race = fixture_git(&git, root.path())
        .arg("--git-dir")
        .arg(&bare)
        .args(["rev-parse", "refs/heads/main"])
        .output()
        .unwrap();
    assert!(remote_after_race.status.success());
    assert_eq!(
        String::from_utf8_lossy(&remote_after_race.stdout).trim(),
        racing_oid
    );
    assert_ne!(racing_oid, pushed_oid);

    if race_file.exists() {
        fs::remove_file(&race_file).unwrap();
    }
    let refresh_after_race = persona_command(&["run"])
        .args(["--", "git", "fetch", "origin"])
        .output()
        .unwrap();
    assert!(
        refresh_after_race.status.success(),
        "refresh after observed race failed: {}",
        String::from_utf8_lossy(&refresh_after_race.stderr)
    );
    let force_with_lease = persona_command(&["run"])
        .args([
            "--",
            "git",
            "push",
            &format!("--force-with-lease=refs/heads/main:{racing_oid}"),
            "origin",
            "refs/heads/main:refs/heads/main",
        ])
        .output()
        .unwrap();
    assert!(
        force_with_lease.status.success(),
        "exact-lease branch rewrite failed: stdout {}; stderr {}",
        String::from_utf8_lossy(&force_with_lease.stdout),
        String::from_utf8_lossy(&force_with_lease.stderr)
    );
    let after_leased_rewrite = fixture_git(&git, root.path())
        .arg("--git-dir")
        .arg(&bare)
        .args(["rev-parse", "refs/heads/main"])
        .output()
        .unwrap();
    assert!(after_leased_rewrite.status.success());
    let expected_local_head = run_git(&worktree, &["rev-parse", "HEAD"]);
    assert!(expected_local_head.status.success());
    assert_eq!(
        String::from_utf8_lossy(&after_leased_rewrite.stdout).trim(),
        String::from_utf8_lossy(&expected_local_head.stdout).trim()
    );

    // Configure upstream tracking on `main` so bare `git push --force-with-lease`
    // and `git push --force` work without manually specifying remote/refspec/OID.
    assert!(
        run_git(
            &worktree,
            &["branch", "--set-upstream-to=origin/main", "main"]
        )
        .status
        .success()
    );
    let amend_for_bare_lease = run_git(
        &worktree,
        &[
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "commit",
            "--amend",
            "--no-edit",
            "-m",
            "amended for bare force-with-lease",
        ],
    );
    assert!(
        amend_for_bare_lease.status.success(),
        "{}",
        String::from_utf8_lossy(&amend_for_bare_lease.stderr)
    );
    let bare_force_with_lease = persona_command(&["run"])
        .args(["--", "git", "push", "--force-with-lease"])
        .output()
        .unwrap();
    assert!(
        bare_force_with_lease.status.success(),
        "bare --force-with-lease branch rewrite should resolve cached tracking OID automatically: stdout {}; stderr {}",
        String::from_utf8_lossy(&bare_force_with_lease.stdout),
        String::from_utf8_lossy(&bare_force_with_lease.stderr)
    );
    let head_after_bare_lease =
        String::from_utf8_lossy(&run_git(&worktree, &["rev-parse", "HEAD"]).stdout)
            .trim()
            .to_owned();
    let remote_after_bare_lease = String::from_utf8_lossy(
        &fixture_git(&git, root.path())
            .arg("--git-dir")
            .arg(&bare)
            .args(["rev-parse", "refs/heads/main"])
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_owned();
    assert_eq!(remote_after_bare_lease, head_after_bare_lease);

    // `--force-with-lease=<ref>` (without `:oid`) also resolves the cached remote-tracking OID.
    let amend_for_ref_lease = run_git(
        &worktree,
        &[
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "commit",
            "--amend",
            "--no-edit",
            "-m",
            "amended for ref-only force-with-lease",
        ],
    );
    assert!(amend_for_ref_lease.status.success());
    let ref_only_lease = persona_command(&["run"])
        .args([
            "--",
            "git",
            "push",
            "--force-with-lease=main",
            "origin",
            "main",
        ])
        .output()
        .unwrap();
    assert!(
        ref_only_lease.status.success(),
        "ref-only --force-with-lease=main should succeed: stdout {}; stderr {}",
        String::from_utf8_lossy(&ref_only_lease.stdout),
        String::from_utf8_lossy(&ref_only_lease.stderr)
    );

    // Bare `--force-with-lease` must still fail closed when the remote moved ahead of
    // our cached tracking ref (race protection preserved).
    let racing_commit_two = fixture_git(&git, root.path())
        .arg("-C")
        .arg(&racing_worktree)
        .args([
            "-c",
            "user.name=Racer",
            "-c",
            "user.email=racer@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "concurrent two",
        ])
        .output()
        .unwrap();
    assert!(racing_commit_two.status.success());
    let racing_oid_two = String::from_utf8_lossy(
        &run_git(&racing_worktree, &["rev-parse", "refs/heads/main"]).stdout,
    )
    .trim()
    .to_owned();
    assert!(
        fixture_git(&git, root.path())
            .arg("--git-dir")
            .arg(&bare)
            .args(["fetch", "--quiet"])
            .arg(&racing_worktree)
            .arg("refs/heads/main")
            .output()
            .unwrap()
            .status
            .success()
    );
    let amend_for_raced_lease = run_git(
        &worktree,
        &[
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "commit",
            "--amend",
            "--no-edit",
            "-m",
            "amended against raced remote",
        ],
    );
    assert!(amend_for_raced_lease.status.success());
    fs::write(&race_file, format!("refs/heads/main {racing_oid_two}\n")).unwrap();
    let raced_bare_lease = persona_command(&["run"])
        .args(["--", "git", "push", "--force-with-lease"])
        .output()
        .unwrap();
    assert!(
        !raced_bare_lease.status.success(),
        "bare --force-with-lease must fail closed when the remote ref moved concurrently"
    );
    let remote_still_raced = String::from_utf8_lossy(
        &fixture_git(&git, root.path())
            .arg("--git-dir")
            .arg(&bare)
            .args(["rev-parse", "refs/heads/main"])
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_owned();
    assert_eq!(remote_still_raced, racing_oid_two);
    if race_file.exists() {
        fs::remove_file(&race_file).unwrap();
    }

    // Unleased `--force` is refused while `allow_force_push` is false (default opt-in).
    let blocked_force = persona_command(&["run"])
        .args(["--", "git", "push", "--force"])
        .output()
        .unwrap();
    assert!(!blocked_force.status.success());
    assert!(
        String::from_utf8_lossy(&blocked_force.stderr)
            .contains("unleased force push is disabled by the active profile's push policy"),
        "unexpected force rejection: {}",
        String::from_utf8_lossy(&blocked_force.stderr)
    );

    // Opting in via `allow_force_push = true` permits `git push --force` even when the
    // remote has an unfetched commit (`racing_oid_two`), while still auditing local commits.
    let base_config = fs::read_to_string(&config).unwrap();
    let force_enabled_config = base_config.replace(
        "allow_force_with_lease = true\n",
        "allow_force_with_lease = true\nallow_force_push = true\n",
    );
    fs::write(&config, &force_enabled_config).unwrap();
    let allowed_force = persona_command(&["run"])
        .args(["--", "git", "push", "--force"])
        .output()
        .unwrap();
    assert!(
        allowed_force.status.success(),
        "opt-in allow_force_push = true should allow git push --force: stdout {}; stderr {}",
        String::from_utf8_lossy(&allowed_force.stdout),
        String::from_utf8_lossy(&allowed_force.stderr)
    );
    let head_after_force =
        String::from_utf8_lossy(&run_git(&worktree, &["rev-parse", "HEAD"]).stdout)
            .trim()
            .to_owned();
    let remote_after_force = String::from_utf8_lossy(
        &fixture_git(&git, root.path())
            .arg("--git-dir")
            .arg(&bare)
            .args(["rev-parse", "refs/heads/main"])
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_owned();
    assert_eq!(remote_after_force, head_after_force);

    // Bare `--force-with-lease` must NOT bypass `allow_force_with_lease = false` even when
    // `allow_force_push = true`.
    let lease_disabled_config = force_enabled_config.replace(
        "allow_force_with_lease = true\n",
        "allow_force_with_lease = false\n",
    );
    fs::write(&config, &lease_disabled_config).unwrap();
    let amend_for_disabled_lease = run_git(
        &worktree,
        &[
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "commit",
            "--amend",
            "--no-edit",
            "-m",
            "amended with allow_force_with_lease disabled",
        ],
    );
    assert!(amend_for_disabled_lease.status.success());
    let blocked_bare_lease = persona_command(&["run"])
        .args(["--", "git", "push", "--force-with-lease"])
        .output()
        .unwrap();
    assert!(
        !blocked_bare_lease.status.success(),
        "bare --force-with-lease must stay blocked when allow_force_with_lease = false"
    );

    // `[profiles.<name>.git.commands]` denylist takes precedence even when `allow_force_push = true`.
    let force_denied_by_command_policy = format!(
        "{force_enabled_config}[profiles.fixture.git.commands]\nmode = \"denylist\"\ndeny = [\"push.force\"]\n"
    );
    fs::write(&config, &force_denied_by_command_policy).unwrap();
    let denied_force = persona_command(&["run"])
        .args(["--", "git", "push", "--force"])
        .output()
        .unwrap();
    assert!(
        !denied_force.status.success(),
        "command denylist must still block push.force when allow_force_push = true"
    );
    assert!(
        String::from_utf8_lossy(&denied_force.stderr).contains("push.force"),
        "unexpected denylist rejection: {}",
        String::from_utf8_lossy(&denied_force.stderr)
    );
}

#[cfg(unix)]
#[test]
fn managed_fetch_uses_additional_ssh_host_and_rejects_unconfigured_host() {
    use std::os::unix::fs::PermissionsExt;

    let git = std::path::PathBuf::from(
        std::env::var_os("PERSONA_TEST_GIT").expect("PERSONA_TEST_GIT must be set"),
    );
    let ssh_keygen = std::env::split_paths(&std::env::var_os("PATH").expect("PATH"))
        .map(|directory| directory.join("ssh-keygen"))
        .find(|path| path.is_file())
        .expect("ssh-keygen executable required");
    let temporary = tempdir().unwrap();
    let repo = temporary.path().join("repo");
    fs::create_dir(&repo).unwrap();

    let key = temporary.path().join("client-key");
    let generated = Command::new(&ssh_keygen)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(generated.status.success());
    let public_key = Path::new(&format!("{}.pub", key.display())).to_path_buf();
    let fingerprint_output = Command::new(&ssh_keygen)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .arg("-lf")
        .arg(&public_key)
        .args(["-E", "sha256"])
        .output()
        .unwrap();
    assert!(fingerprint_output.status.success());
    let fingerprint = String::from_utf8_lossy(&fingerprint_output.stdout)
        .split_whitespace()
        .find(|field| field.starts_with("SHA256:"))
        .unwrap()
        .to_owned();
    let known_hosts = temporary.path().join("known_hosts");
    fs::write(
        &known_hosts,
        "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFixtureHostKey\nforge.example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFixtureHostKey\n",
    )
    .unwrap();

    let ssh_marker = temporary.path().join("ssh-calls");
    let fake_ssh = temporary.path().join("ssh-fixture");
    fs::write(
        &fake_ssh,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\nexit 71\n",
            ssh_marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_ssh, fs::Permissions::from_mode(0o700)).unwrap();

    let forge = "git@forge.example.invalid:org/repo.git";
    let unconfigured = "git@unconfigured.example.invalid:org/repo.git";
    let initialized = fixture_git(&git, temporary.path())
        .args(["init", "--quiet"])
        .arg(&repo)
        .output()
        .unwrap();
    assert!(initialized.status.success());
    for (name, url) in [("origin", forge), ("third", unconfigured)] {
        let added = fixture_git(&git, temporary.path())
            .args(["-C"])
            .arg(&repo)
            .args(["remote", "add", name, url])
            .output()
            .unwrap();
        assert!(added.status.success());
    }

    let policy = temporary.path().join("persona.toml");
    let repo_path =
        toml::Value::String(repo.canonicalize().unwrap().to_string_lossy().into_owned());
    let public_key_value = toml::Value::String(public_key.to_string_lossy().into_owned());
    let key_value = toml::Value::String(key.to_string_lossy().into_owned());
    let known_hosts_value = toml::Value::String(known_hosts.to_string_lossy().into_owned());
    fs::write(
        &policy,
        format!(
            r#"version = 4

[profiles.fixture]
name = "Fixture"
email = "fixture@example.invalid"
scopes = [{repo_path}]

[profiles.fixture.git.remotes]
origin = {{ fetch = ["{forge}"] }}
third = {{ fetch = ["{unconfigured}"] }}

[profiles.fixture.github]
host = "github.com"
account_id = "4242"
account_selector = "synthetic-user"
token_fingerprint = "hmac-sha256:{fingerprint_hash}"

[profiles.fixture.ssh]
host = "github.com"
user = "git"
port = 22
fingerprint = "{fingerprint}"
public_key = {public_key_value}
identity_file = {key_value}
known_hosts_file = {known_hosts_value}

[[profiles.fixture.ssh.extra]]
host = "forge.example.invalid"
user = "git"
port = 22
fingerprint = "{fingerprint}"
public_key = {public_key_value}
identity_file = {key_value}
known_hosts_file = {known_hosts_value}
"#,
            fingerprint_hash = "0".repeat(64),
        ),
    )
    .unwrap();

    let run_fetch = |remote: &str| {
        Command::new(env!("CARGO_BIN_EXE_persona"))
            .env_clear()
            .env("HOME", temporary.path())
            .env("PATH", "/usr/bin:/bin")
            .env("PERSONA_GIT", &git)
            .env("PERSONA_SSH", &fake_ssh)
            .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
            .current_dir(&repo)
            .args(["run", "--config"])
            .arg(&policy)
            .args(["--cwd"])
            .arg(&repo)
            .args(["--", "git", "fetch", remote])
            .output()
            .unwrap()
    };

    let configured = run_fetch("origin");
    assert!(
        !configured.status.success(),
        "fixture SSH transport exits 71"
    );
    assert!(
        ssh_marker.exists(),
        "configured additional SSH host should reach the managed SSH adapter: {}",
        String::from_utf8_lossy(&configured.stderr)
    );
    let calls = fs::read_to_string(&ssh_marker).unwrap();
    assert!(
        calls.contains("forge.example.invalid"),
        "SSH calls: {calls}"
    );
    assert!(calls.contains("git-upload-pack 'org/repo.git'"));

    fs::remove_file(&ssh_marker).unwrap();
    let rejected = run_fetch("third");
    assert!(!rejected.status.success());
    assert!(
        !ssh_marker.exists(),
        "unconfigured SSH host must be rejected before transport: {}",
        String::from_utf8_lossy(&rejected.stderr)
    );
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("SSH destination differs from profile policy"),
        "unexpected rejection: {}",
        String::from_utf8_lossy(&rejected.stderr)
    );
}
