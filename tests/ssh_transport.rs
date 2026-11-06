use persona::config::SshPolicy;
use persona::ssh_transport::{ManagedSshTransport, SshTransportError};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;

fn optional_executable(name: &str, variable: &str) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(variable) {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    std::env::split_paths(&std::env::var_os("PATH").expect("PATH"))
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
}

fn executable(name: &str, variable: &str) -> PathBuf {
    optional_executable(name, variable).unwrap_or_else(|| panic!("{name} executable required"))
}

fn key_fingerprint(ssh_keygen: &Path, public_key: &Path) -> String {
    let output = Command::new(ssh_keygen)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args(["-lf"])
        .arg(public_key)
        .args(["-E", "sha256"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .find(|field| field.starts_with("SHA256:"))
        .unwrap()
        .to_owned()
}

fn fixture() -> (tempfile::TempDir, PathBuf, SshPolicy, PathBuf) {
    let temporary = tempdir().unwrap();
    let ssh_keygen = executable("ssh-keygen", "PERSONA_TEST_SSH_KEYGEN");
    let private_key = temporary.path().join("synthetic-key");
    let public_key = temporary.path().join("synthetic-key.pub");
    let output = Command::new(&ssh_keygen)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&private_key)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let known_hosts = temporary.path().join("known_hosts");
    fs::write(
        &known_hosts,
        "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFixtureKey\n",
    )
    .unwrap();
    let fingerprint = key_fingerprint(&ssh_keygen, &public_key);
    let policy = SshPolicy {
        host: "github.com".to_owned(),
        user: "git".to_owned(),
        port: 22,
        fingerprint,
        public_key,
        identity_file: Some(private_key),
        agent_socket: None,
        known_hosts_file: known_hosts,
    };
    (
        temporary,
        ssh_keygen,
        policy,
        executable("ssh", "PERSONA_TEST_SSH"),
    )
}

#[cfg(unix)]
#[test]
fn managed_ssh_uses_only_explicit_identity_hostkey_and_no_user_config_or_multiplexing() {
    use std::os::unix::fs::PermissionsExt;
    let (temporary, ssh_keygen, policy, _system_ssh) = fixture();
    let marker = temporary.path().join("ssh-invoked");
    let args_file = temporary.path().join("ssh-args");
    let fake_ssh = temporary.path().join("ssh-fixture");
    fs::write(&fake_ssh, format!(
        "#!/bin/sh\n: > '{}'\nprintf '%s\\n' \"$@\" > '{}'\nif [ -n \"${{SSH_AUTH_SOCK+x}}\" ]; then exit 73; fi\nexit 0\n",
        marker.display(), args_file.display()
    )).unwrap();
    fs::set_permissions(&fake_ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let transport = ManagedSshTransport::new(fake_ssh, ssh_keygen);
    let result = transport
        .run(
            &policy,
            "git@github.com:org/repo.git",
            "git-upload-pack 'org/repo.git'",
        )
        .unwrap();
    assert!(result.status.success());
    assert!(marker.exists());
    let args = fs::read_to_string(args_file).unwrap();
    for required in [
        "-F\nnone",
        "StrictHostKeyChecking=yes",
        "IdentitiesOnly=yes",
        "ProxyCommand=none",
        "ProxyJump=none",
        "ControlMaster=no",
        "ControlPath=none",
        "ForwardAgent=no",
        "UserKnownHostsFile=",
    ] {
        assert!(
            args.contains(required),
            "missing {required:?} in ssh args: {args}"
        );
    }
    assert!(!args.contains("-G\n"));
    assert!(!args.contains("ProxyCommand=") || args.contains("ProxyCommand=none"));
}

#[cfg(target_os = "linux")]
#[test]
fn managed_ssh_authenticates_to_a_local_sshd_with_only_the_pinned_key_and_host_key() {
    use std::io::ErrorKind;
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Child, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    struct Sshd(Child);
    impl Drop for Sshd {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }

    if let Some(reason) = std::env::var_os("PERSONA_TEST_SKIP_LOCAL_SSHD") {
        eprintln!(
            "SKIP local SSH server integration: {}",
            reason.to_string_lossy()
        );
        return;
    }
    let Some(sshd) = optional_executable("sshd", "PERSONA_TEST_SSHD") else {
        eprintln!("SKIP local SSH server integration: sshd is unavailable");
        return;
    };
    let (temporary, ssh_keygen, _fixture_policy, ssh) = fixture();
    let root = temporary.path();
    let port_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = port_listener.local_addr().unwrap().port();
    drop(port_listener);

    let client_key = root.join("client-key");
    let host_key = root.join("host-key");
    for key in [&client_key, &host_key] {
        let generated = Command::new(&ssh_keygen)
            .env_clear()
            .env("HOME", root)
            .env("PATH", "/usr/bin:/bin")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(key)
            .output()
            .unwrap();
        assert!(generated.status.success());
    }
    let client_public_key = PathBuf::from(format!("{}.pub", client_key.display()));
    let signing_fingerprint = key_fingerprint(&ssh_keygen, &client_public_key);
    let authorized_keys = root.join("authorized_keys");
    fs::copy(&client_public_key, &authorized_keys).unwrap();
    let agent_socket = root.join("ssh-agent.sock");
    let ssh_agent = optional_executable("ssh-agent", "PERSONA_TEST_SSH_AGENT")
        .expect("ssh-agent must be available for the isolated agent integration");
    let ssh_add = optional_executable("ssh-add", "PERSONA_TEST_SSH_ADD")
        .expect("ssh-add must be available for the isolated agent integration");
    let agent_start = Command::new(&ssh_agent)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .args(["-a"])
        .arg(&agent_socket)
        .arg("-s")
        .output()
        .unwrap();
    assert!(
        agent_start.status.success(),
        "ssh-agent failed to start: {}",
        String::from_utf8_lossy(&agent_start.stderr)
    );
    let agent_output = String::from_utf8(agent_start.stdout).unwrap();
    let agent_pid = agent_output
        .lines()
        .find_map(|line| line.strip_prefix("SSH_AGENT_PID=")?.split(';').next())
        .expect("ssh-agent emitted its pid")
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
        socket: agent_socket.clone(),
        pid: agent_pid,
    };
    let add_key = Command::new(&ssh_add)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .env("SSH_AUTH_SOCK", &agent_socket)
        .arg("-q")
        .arg(&client_key)
        .output()
        .unwrap();
    assert!(
        add_key.status.success(),
        "cannot load the synthetic SSH key into isolated ssh-agent: {}",
        String::from_utf8_lossy(&add_key.stderr)
    );
    let host_public = fs::read_to_string(format!("{}.pub", host_key.display())).unwrap();
    let host_fields = host_public.split_whitespace().collect::<Vec<_>>();
    assert!(host_fields.len() >= 2);
    let known_hosts = root.join("known_hosts");
    fs::write(
        &known_hosts,
        format!("[127.0.0.1]:{port} {} {}\n", host_fields[0], host_fields[1]),
    )
    .unwrap();
    let passwd = unsafe { libc::getpwuid(libc::geteuid()) };
    assert!(!passwd.is_null(), "test process has a passwd entry");
    let username = unsafe { std::ffi::CStr::from_ptr((*passwd).pw_name) }
        .to_string_lossy()
        .into_owned();
    let sshd_config = root.join("sshd_config");
    fs::write(
        &sshd_config,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nPubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nPermitRootLogin yes\nAllowUsers {username}\nAllowTcpForwarding no\nX11Forwarding no\nPermitTunnel no\nPrintMotd no\nLogLevel ERROR\n",
            host_key.display(),
            root.join("sshd.pid").display(),
            authorized_keys.display(),
        ),
    )
    .unwrap();
    let log = fs::File::create(root.join("sshd.log")).unwrap();
    let mut daemon = Sshd(
        Command::new(sshd)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args(["-D", "-e", "-f"])
            .arg(&sshd_config)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = daemon.0.try_wait().unwrap() {
            panic!("sshd exited before readiness: {status}");
        }
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => {
                drop(stream);
                break;
            }
            Err(error) if error.kind() == ErrorKind::ConnectionRefused => {
                assert!(Instant::now() < deadline, "sshd did not become ready");
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("cannot probe local sshd: {error}"),
        }
    }

    let git = executable("git", "PERSONA_TEST_GIT");
    let repository = root.join("repository.git");
    let worktree = root.join("worktree");
    for (directory, args) in [
        (&repository, vec!["init", "--bare", "--quiet"]),
        (&worktree, vec!["init", "--quiet", "-b", "main"]),
    ] {
        let init = Command::new(&git)
            .env_clear()
            .env("HOME", root)
            .env("PATH", "/usr/bin:/bin")
            .args(args)
            .arg(directory)
            .output()
            .unwrap();
        assert!(init.status.success());
    }
    let commit = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&worktree)
        .env("GIT_AUTHOR_NAME", "Approved Upstream")
        .env("GIT_AUTHOR_EMAIL", "upstream@example.invalid")
        .args([
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "-c",
            "gpg.format=ssh",
            "-c",
            "commit.gpgsign=true",
        ])
        .arg("-c")
        .arg(format!("user.signingkey={}", client_key.display()))
        .args(["commit", "--allow-empty", "-m", "synthetic"])
        .output()
        .unwrap();
    assert!(commit.status.success());
    let base_oid_output = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&worktree)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(base_oid_output.status.success());
    let base_oid = String::from_utf8_lossy(&base_oid_output.stdout)
        .trim()
        .to_owned();
    let pin = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&worktree)
        .args(["update-ref", "refs/remotes/origin/upstream", &base_oid])
        .output()
        .unwrap();
    assert!(pin.status.success());
    let tracking_pin = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&worktree)
        .args(["update-ref", "refs/remotes/origin/main", &base_oid])
        .output()
        .unwrap();
    assert!(tracking_pin.status.success());
    let seed_remote = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("--git-dir")
        .arg(&repository)
        .args(["fetch", "--quiet"])
        .arg(&worktree)
        .args(["refs/remotes/origin/main:refs/heads/main"])
        .output()
        .unwrap();
    assert!(
        seed_remote.status.success(),
        "seed exact upstream baseline on synthetic SSH remote: {}",
        String::from_utf8_lossy(&seed_remote.stderr)
    );
    let feature_branch = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&worktree)
        .args(["checkout", "-b", "feature"])
        .output()
        .unwrap();
    assert!(feature_branch.status.success());
    let feature_commit = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&worktree)
        .args([
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "-c",
            "gpg.format=ssh",
            "-c",
            "commit.gpgsign=true",
        ])
        .arg("-c")
        .arg(format!("user.signingkey={}", client_key.display()))
        .args(["commit", "--allow-empty", "-m", "feature"])
        .output()
        .unwrap();
    assert!(feature_commit.status.success());
    let checkout_main = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&worktree)
        .args(["checkout", "main"])
        .output()
        .unwrap();
    assert!(checkout_main.status.success());
    let main_advance = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&worktree)
        .args([
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "-c",
            "gpg.format=ssh",
            "-c",
            "commit.gpgsign=true",
        ])
        .arg("-c")
        .arg(format!("user.signingkey={}", client_key.display()))
        .args([
            "commit",
            "--allow-empty",
            "-m",
            "main descendant of pinned upstream",
        ])
        .output()
        .unwrap();
    assert!(
        main_advance.status.success(),
        "create signed main descendant: {}",
        String::from_utf8_lossy(&main_advance.stderr)
    );

    let public_key = client_public_key.clone();
    let fingerprint = signing_fingerprint.clone();
    let policy = SshPolicy {
        host: "127.0.0.1".to_owned(),
        user: username,
        port,
        fingerprint,
        public_key: public_key.clone(),
        identity_file: None,
        agent_socket: Some(agent_socket.clone()),
        known_hosts_file: known_hosts,
    };
    let repository_path = repository.to_str().unwrap();
    let destination = format!("ssh://{}@127.0.0.1:{port}{repository_path}", policy.user);
    let transport = ManagedSshTransport::new(ssh, ssh_keygen.clone());
    let command = transport
        .command(
            &policy,
            &destination,
            &format!("git-upload-pack '{repository_path}'"),
        )
        .unwrap();
    let mut ssh_arguments = command
        .get_args()
        .map(|argument| argument.to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert!(ssh_arguments.len() >= 2);
    ssh_arguments.truncate(ssh_arguments.len() - 2);
    let ssh_executable = command.get_program().to_str().unwrap();
    let quote = |value: &str| format!("'{}'", value.replace('\'', "'\\''"));
    let wrapper = root.join("persona-ssh-fixture");
    let ssh_marker = root.join("persona-ssh-invoked");
    let wrapper_text = format!(
        "#!/bin/sh\n: > '{}'\nexec {} {} \"$@\"\n",
        ssh_marker.display(),
        quote(ssh_executable),
        ssh_arguments
            .iter()
            .map(|arg| quote(arg))
            .collect::<Vec<_>>()
            .join(" ")
    );
    fs::write(&wrapper, wrapper_text).unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    let add_remote = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&worktree)
        .args(["remote", "add", "origin"])
        .arg(&destination)
        .output()
        .unwrap();
    assert!(add_remote.status.success());
    let config = root.join("persona.toml");
    fs::write(
        &config,
        format!(
            "version = 2\n[[profiles]]\nname = \\\"fixture\\\"\n[profiles.git]\nauthor = {{ name = \\\"Synthetic\\\", email = \\\"synthetic@example.invalid\\\" }}\ncommitter = {{ name = \\\"Synthetic\\\", email = \\\"synthetic@example.invalid\\\" }}\n[profiles.git.signing]\nfingerprint = {signing_fingerprint:?}\nformat = \"ssh\"\npublic_key = {public_key:?}\n[profiles.git.push]\nremote = \\\"origin\\\"\ndestinations = [{destination:?}]\nallow_lightweight_tags = true\nallow_annotated_tags = true\nallow_branch_deletion = true\nallow_tag_deletion = true\nallow_force_with_lease = true\npreserve_authors = true\n[[profiles.git.push.upstream_baselines]]\ndestination = {destination:?}\ntracking_ref = \"refs/remotes/origin/upstream\"\noid = {base_oid:?}\n[profiles.ssh]\nhost = \\\"127.0.0.1\\\"\nuser = {:?}\nport = {port}\nfingerprint = {:?}\npublic_key = {:?}\nagent_socket = {:?}\nknown_hosts_file = {:?}\n[[scopes]]\nname = \\\"fixture\\\"\npath = {:?}\nprofile = \\\"fixture\\\"\n",
            policy.user,
            policy.fingerprint,
            policy.public_key,
            policy.agent_socket.as_ref().unwrap(),
            policy.known_hosts_file,
            worktree,
        ),
    )
    .unwrap();
    let config_contents = fs::read_to_string(&config).unwrap().replace("\\\"", "\"");
    fs::write(&config, config_contents).unwrap();
    let persona = PathBuf::from(env!("CARGO_BIN_EXE_persona"));
    let blocked_without_hook = Command::new(&persona)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .env("PERSONA_SSH", &wrapper)
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&worktree)
        .args([
            "--",
            "git",
            "push",
            "origin",
            "refs/heads/main:refs/heads/main",
        ])
        .output()
        .unwrap();
    assert_eq!(blocked_without_hook.status.code(), Some(126));
    assert!(
        !ssh_marker.exists(),
        "missing second barrier must block before SSH"
    );

    let install_hook = Command::new(&persona)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .args(["hooks", "install", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&worktree)
        .output()
        .unwrap();
    assert!(
        install_hook.status.success(),
        "hook install failed: {}",
        String::from_utf8_lossy(&install_hook.stderr)
    );

    let push = Command::new(&persona)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .env("PERSONA_SSH", &wrapper)
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&worktree)
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
        "Persona managed SSH push failed; stdout: {}; stderr: {}; sshd log: {}",
        String::from_utf8_lossy(&push.stdout),
        String::from_utf8_lossy(&push.stderr),
        String::from_utf8_lossy(&fs::read(root.join("sshd.log")).unwrap())
    );
    assert!(
        ssh_marker.exists(),
        "managed adapter did not invoke the SSH fixture"
    );
    let remote_feature = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("--git-dir")
        .arg(&repository)
        .args(["rev-parse", "refs/heads/feature"])
        .output()
        .unwrap();
    assert!(remote_feature.status.success());

    let create_tag = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&worktree)
        .args(["tag", "release-fixture", "refs/heads/main"])
        .output()
        .unwrap();
    assert!(create_tag.status.success());
    let tag_push = Command::new(&persona)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .env("PERSONA_SSH", &wrapper)
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&worktree)
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
        "tag push failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&tag_push.stdout),
        String::from_utf8_lossy(&tag_push.stderr)
    );
    let remote_tag = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("--git-dir")
        .arg(&repository)
        .args(["rev-parse", "refs/tags/release-fixture"])
        .output()
        .unwrap();
    assert!(remote_tag.status.success());
    let mut remote_tag_oid = String::from_utf8_lossy(&remote_tag.stdout)
        .trim()
        .to_owned();
    let retarget_local_tag = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&worktree)
        .args(["tag", "-f", "release-fixture", "refs/heads/feature"])
        .output()
        .unwrap();
    assert!(retarget_local_tag.status.success());
    let retargeted_tag = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&worktree)
        .args(["rev-parse", "refs/tags/release-fixture"])
        .output()
        .unwrap();
    assert!(retargeted_tag.status.success());
    let update_tag = Command::new(&persona)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .env("PERSONA_SSH", &wrapper)
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&worktree)
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
        update_tag.status.success(),
        "exact-lease SSH tag update failed: {}",
        String::from_utf8_lossy(&update_tag.stderr)
    );
    let updated_remote_tag = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("--git-dir")
        .arg(&repository)
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
    let delete_tag = Command::new(&persona)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .env("PERSONA_SSH", &wrapper)
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&worktree)
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
        "exact-lease SSH tag deletion failed: {}",
        String::from_utf8_lossy(&delete_tag.stderr)
    );
    let absent_tag = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("--git-dir")
        .arg(&repository)
        .args(["show-ref", "--verify", "refs/tags/release-fixture"])
        .output()
        .unwrap();
    assert!(
        !absent_tag.status.success(),
        "SSH tag deletion should remove the remote ref"
    );

    let fetch = Command::new(&persona)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .env("PERSONA_SSH", &wrapper)
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&worktree)
        .args(["--", "git", "fetch", "origin"])
        .output()
        .unwrap();
    assert!(
        fetch.status.success(),
        "managed fetch for the fast-forward baseline failed: {}",
        String::from_utf8_lossy(&fetch.stderr)
    );
    let feature_remote_oid = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&worktree)
        .args(["rev-parse", "refs/remotes/origin/feature"])
        .output()
        .unwrap();
    assert!(feature_remote_oid.status.success());
    let feature_remote_oid = String::from_utf8_lossy(&feature_remote_oid.stdout)
        .trim()
        .to_owned();
    let delete_branch = Command::new(&persona)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .env("PERSONA_SSH", &wrapper)
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&worktree)
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
        "exact-lease SSH branch deletion failed: {}",
        String::from_utf8_lossy(&delete_branch.stderr)
    );
    let absent_branch = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("--git-dir")
        .arg(&repository)
        .args(["show-ref", "--verify", "refs/heads/feature"])
        .output()
        .unwrap();
    assert!(
        !absent_branch.status.success(),
        "SSH branch deletion should remove the remote ref"
    );

    let local_advance = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&worktree)
        .args([
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "-c",
            "gpg.format=ssh",
            "-c",
            "commit.gpgsign=true",
        ])
        .arg("-c")
        .arg(format!("user.signingkey={}", client_key.display()))
        .args(["commit", "--allow-empty", "-m", "local advance"])
        .output()
        .unwrap();
    assert!(
        local_advance.status.success(),
        "create local fast-forward fixture commit: {}",
        String::from_utf8_lossy(&local_advance.stderr)
    );
    let signed_tag = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&worktree)
        .args([
            "-c",
            "gpg.format=ssh",
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
        ])
        .arg("-c")
        .arg(format!("user.signingkey={}", client_key.display()))
        .args([
            "tag",
            "-s",
            "-m",
            "signed annotated publication",
            "signed-release",
            "refs/heads/main",
        ])
        .output()
        .unwrap();
    assert!(
        signed_tag.status.success(),
        "create SSH-signed annotated tag: {}",
        String::from_utf8_lossy(&signed_tag.stderr)
    );
    let signed_tag_push = Command::new(&persona)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .env("PERSONA_SSH", &wrapper)
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&worktree)
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
        "SSH signed annotated tag publication failed: stdout {}; stderr {}",
        String::from_utf8_lossy(&signed_tag_push.stdout),
        String::from_utf8_lossy(&signed_tag_push.stderr)
    );

    let fast_forward_push = Command::new(&persona)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .env("PERSONA_SSH", &wrapper)
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&worktree)
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
        "managed SSH fast-forward failed: stdout {}; stderr {}",
        String::from_utf8_lossy(&fast_forward_push.stdout),
        String::from_utf8_lossy(&fast_forward_push.stderr)
    );

    // Simulate another writer advancing the remote after Persona captured its
    // tracking-ref baseline but before native Git's pre-push hook receives tuples.
    let racing_worktree = root.join("racing-worktree");
    let racing_clone = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .args(["clone", "--quiet", "--branch", "main"])
        .arg(&repository)
        .arg(&racing_worktree)
        .output()
        .unwrap();
    assert!(
        racing_clone.status.success(),
        "create remote-race fixture clone: {}",
        String::from_utf8_lossy(&racing_clone.stderr)
    );
    let racing_commit = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&racing_worktree)
        .args([
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "concurrent remote advance",
        ])
        .output()
        .unwrap();
    assert!(
        racing_commit.status.success(),
        "create concurrent remote commit: {}",
        String::from_utf8_lossy(&racing_commit.stderr)
    );
    let racing_push = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&racing_worktree)
        .args(["push", "origin", "main"])
        .output()
        .unwrap();
    assert!(
        racing_push.status.success(),
        "advance only the synthetic local bare remote: {}",
        String::from_utf8_lossy(&racing_push.stderr)
    );
    let racing_oid = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&racing_worktree)
        .args(["rev-parse", "refs/heads/main"])
        .output()
        .unwrap();
    assert!(racing_oid.status.success());
    let racing_oid = String::from_utf8_lossy(&racing_oid.stdout)
        .trim()
        .to_owned();
    let remote_before_rejected_push = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&repository)
        .args(["rev-parse", "refs/heads/main"])
        .output()
        .unwrap();
    assert!(remote_before_rejected_push.status.success());
    let remote_before_rejected_push = String::from_utf8_lossy(&remote_before_rejected_push.stdout)
        .trim()
        .to_owned();

    let stale_plan_push = Command::new(&persona)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .env("PERSONA_SSH", &wrapper)
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&worktree)
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
        !stale_plan_push.status.success(),
        "a remote OID that changed after planning must be rejected by pre-push"
    );
    let remote_after_rejected_push = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&repository)
        .args(["rev-parse", "refs/heads/main"])
        .output()
        .unwrap();
    assert!(remote_after_rejected_push.status.success());
    assert_eq!(
        String::from_utf8_lossy(&remote_after_rejected_push.stdout).trim(),
        remote_before_rejected_push,
        "stale plan must not update the remote branch"
    );

    let refresh_after_race = Command::new(&persona)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .env("PERSONA_SSH", &wrapper)
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&worktree)
        .args(["--", "git", "fetch", "origin"])
        .output()
        .unwrap();
    assert!(
        refresh_after_race.status.success(),
        "refresh after SSH race failed: {}",
        String::from_utf8_lossy(&refresh_after_race.stderr)
    );
    let leased_rewrite = Command::new(&persona)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", &git)
        .env("PERSONA_SSH", &wrapper)
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&worktree)
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
        leased_rewrite.status.success(),
        "exact-lease SSH branch rewrite failed: stdout {}; stderr {}",
        String::from_utf8_lossy(&leased_rewrite.stdout),
        String::from_utf8_lossy(&leased_rewrite.stderr)
    );
    let final_remote = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("--git-dir")
        .arg(&repository)
        .args(["rev-parse", "refs/heads/main"])
        .output()
        .unwrap();
    assert!(final_remote.status.success());
    let local_head = Command::new(&git)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&worktree)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(local_head.status.success());
    assert_eq!(
        String::from_utf8_lossy(&final_remote.stdout).trim(),
        String::from_utf8_lossy(&local_head.stdout).trim()
    );
}

#[cfg(unix)]
#[test]
fn unsupported_host_or_remote_command_is_rejected_before_ssh_runs() {
    use std::os::unix::fs::PermissionsExt;
    let (temporary, ssh_keygen, policy, _system_ssh) = fixture();
    let marker = temporary.path().join("ssh-invoked");
    let fake_ssh = temporary.path().join("ssh-fixture");
    fs::write(
        &fake_ssh,
        format!("#!/bin/sh\n: > '{}'\nexit 0\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&fake_ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let transport = ManagedSshTransport::new(fake_ssh, ssh_keygen.clone());
    assert!(matches!(
        transport.run(
            &policy,
            "git@evil.example:org/repo.git",
            "git-upload-pack 'org/repo.git'"
        ),
        Err(SshTransportError::DestinationMismatch)
    ));
    assert!(matches!(
        transport.run(
            &policy,
            "git@github.com:org/repo.git",
            "sh -c 'touch /tmp/owned'"
        ),
        Err(SshTransportError::UnsupportedRemoteCommand)
    ));
    let wrong_identity = temporary.path().join("wrong-key");
    let generated = Command::new(&ssh_keygen)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&wrong_identity)
        .output()
        .unwrap();
    assert!(generated.status.success());
    let mut mismatched_policy = policy.clone();
    mismatched_policy.identity_file = Some(wrong_identity);
    assert!(matches!(
        transport.run(
            &mismatched_policy,
            "git@github.com:org/repo.git",
            "git-upload-pack 'org/repo.git'"
        ),
        Err(SshTransportError::PublicKeyMismatch)
    ));
    let expanded_path = temporary.path().join("known_hosts_%h");
    fs::write(&expanded_path, "synthetic\n").unwrap();
    let mut expanded_policy = policy.clone();
    expanded_policy.known_hosts_file = expanded_path;
    assert!(matches!(
        transport.run(
            &expanded_policy,
            "git@github.com:org/repo.git",
            "git-upload-pack 'org/repo.git'"
        ),
        Err(SshTransportError::UnsafePolicyPath(_))
    ));

    let expanded_identity = temporary.path().join("identity_%h");
    fs::copy(policy.identity_file.as_ref().unwrap(), &expanded_identity).unwrap();
    fs::copy(
        format!("{}.pub", policy.identity_file.as_ref().unwrap().display()),
        format!("{}.pub", expanded_identity.display()),
    )
    .unwrap();
    let mut expanded_identity_policy = policy.clone();
    expanded_identity_policy.identity_file = Some(expanded_identity);
    assert!(matches!(
        transport.arguments(
            &expanded_identity_policy,
            "git@github.com:org/repo.git",
            "git-upload-pack 'org/repo.git'"
        ),
        Err(SshTransportError::UnsafePolicyPath(_))
    ));

    #[cfg(unix)]
    {
        use std::os::unix::net::UnixListener;
        let expanded_public_key = temporary.path().join("public_%h.pub");
        fs::copy(&policy.public_key, &expanded_public_key).unwrap();
        let socket = temporary.path().join("agent.sock");
        let _agent = UnixListener::bind(&socket).unwrap();
        let mut expanded_public_policy = policy.clone();
        expanded_public_policy.identity_file = None;
        expanded_public_policy.agent_socket = Some(socket);
        expanded_public_policy.public_key = expanded_public_key;
        assert!(matches!(
            transport.arguments(
                &expanded_public_policy,
                "git@github.com:org/repo.git",
                "git-upload-pack 'org/repo.git'"
            ),
            Err(SshTransportError::UnsafePolicyPath(_))
        ));
    }
    assert!(
        !marker.exists(),
        "rejected SSH requests must not start an SSH process"
    );
}

#[test]
fn unknown_destination_syntax_fails_closed() {
    let (temporary, ssh_keygen, policy, ssh) = fixture();
    let transport = ManagedSshTransport::new(ssh, ssh_keygen);
    assert!(matches!(
        transport.arguments(
            &policy,
            "https://github.com/org/repo.git",
            "git-upload-pack 'org/repo.git'"
        ),
        Err(SshTransportError::UnsupportedDestination)
    ));
    assert!(temporary.path().exists());
}
