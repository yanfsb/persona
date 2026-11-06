use persona::git_https::required_git_http_overrides;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

fn executable(name: &str, variable: &str) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(variable) {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
}

fn git_command(git: &Path, home: &Path, arguments: &[String]) -> Command {
    let mut command = Command::new(git);
    command
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(http_args())
        .args(arguments);
    command
}

fn http_args() -> Vec<String> {
    let mut arguments = Vec::new();
    for (key, value) in required_git_http_overrides() {
        arguments.push("-c".to_owned());
        arguments.push(format!("{key}={value}"));
    }
    arguments
}

#[test]
fn managed_http_settings_do_not_follow_a_redirect_to_another_origin() {
    let Some(git) = executable("git", "PERSONA_TEST_GIT") else {
        panic!("Git executable required");
    };
    let temporary = tempdir().unwrap();
    let redirect = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let redirect_port = redirect.local_addr().unwrap().port();
    let target = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let target_port = target.local_addr().unwrap().port();
    target.set_nonblocking(true).unwrap();

    let redirect_server = thread::spawn(move || {
        let (mut stream, _) = redirect.accept().unwrap();
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request);
        write!(
            stream,
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{target_port}/redirected.git/info/refs?service=git-upload-pack\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
    });
    let target_server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_millis(750);
        loop {
            match target.accept() {
                Ok((mut stream, _)) => {
                    let mut request = [0_u8; 4096];
                    let _ = stream.read(&mut request);
                    return true;
                }
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

    let url = format!("http://127.0.0.1:{redirect_port}/org/repo.git");
    let output = git_command(&git, temporary.path(), &["ls-remote".to_owned(), url])
        .output()
        .unwrap();
    redirect_server.join().unwrap();
    assert!(
        !target_server.join().unwrap(),
        "Git followed a trust-changing redirect"
    );
    assert!(!output.status.success());
}

#[test]
fn managed_https_does_not_run_a_repository_credential_helper() {
    use std::os::unix::fs::PermissionsExt;

    let Some(git) = executable("git", "PERSONA_TEST_GIT") else {
        panic!("Git executable required");
    };
    let temporary = tempdir().unwrap();
    let repository = temporary.path().join("repository");
    let init = Command::new(&git)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .args(["init", "--quiet"])
        .arg(&repository)
        .output()
        .unwrap();
    assert!(init.status.success());

    let marker = temporary.path().join("credential-helper-ran");
    let helper = temporary.path().join("unsafe-helper");
    fs::write(
        &helper,
        format!("#!/bin/sh\n: > '{}'\nexit 0\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    let configured = Command::new(&git)
        .env_clear()
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .arg("-C")
        .arg(&repository)
        .args(["config", "credential.helper"])
        .arg(&helper)
        .output()
        .unwrap();
    assert!(configured.status.success());

    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request);
        stream
            .write_all(
                b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
    });
    let url = format!("http://127.0.0.1:{port}/org/repo.git");
    let output = git_command(
        &git,
        temporary.path(),
        &[
            "-C".to_owned(),
            repository.to_string_lossy().into_owned(),
            "ls-remote".to_owned(),
            url,
        ],
    )
    .output()
    .unwrap();
    server.join().unwrap();
    assert!(!output.status.success());
    assert!(
        !marker.exists(),
        "repository credential helper ran despite reset"
    );
}

#[test]
fn managed_https_keeps_certificate_verification_enabled_for_local_fixture() {
    let (Some(git), Some(openssl)) = (
        executable("git", "PERSONA_TEST_GIT"),
        executable("openssl", "PERSONA_TEST_OPENSSL"),
    ) else {
        eprintln!("skipping TLS fixture: Git or OpenSSL unavailable");
        return;
    };
    let temporary = tempdir().unwrap();
    let certificate = temporary.path().join("fixture-cert.pem");
    let private_key = temporary.path().join("fixture-key.pem");
    let generated = Command::new(&openssl)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-keyout",
        ])
        .arg(&private_key)
        .arg("-out")
        .arg(&certificate)
        .output()
        .unwrap();
    assert!(generated.status.success());
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let log = fs::File::create(temporary.path().join("tls-server.log")).unwrap();
    let mut server = Command::new(&openssl)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args(["s_server", "-quiet", "-www", "-accept"])
        .arg(port.to_string())
        .arg("-cert")
        .arg(&certificate)
        .arg("-key")
        .arg(&private_key)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = server.try_wait().unwrap() {
            panic!(
                "TLS fixture exited before readiness: {status}; {}",
                String::from_utf8_lossy(
                    &fs::read(temporary.path().join("tls-server.log")).unwrap()
                )
            );
        }
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) {
            drop(stream);
            break;
        }
        assert!(Instant::now() < deadline, "TLS fixture did not start");
        thread::sleep(Duration::from_millis(10));
    }

    let url = format!("https://127.0.0.1:{port}/org/repo.git");
    let output = git_command(&git, temporary.path(), &["ls-remote".to_owned(), url])
        .output()
        .unwrap();
    let _ = server.kill();
    let _ = server.wait();
    assert!(
        !output.status.success(),
        "untrusted local TLS certificate was accepted"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .to_ascii_lowercase()
            .contains("certificate"),
        "expected a certificate verification failure, got: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
