#![cfg(unix)]

use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

fn persona() -> &'static str {
    env!("CARGO_BIN_EXE_persona")
}

fn call(
    directory: &Path,
    home: &Path,
    xdg: &Path,
    state: &Path,
    gh: &Path,
    args: &[&str],
) -> Output {
    let git = PathBuf::from(std::env::var_os("PERSONA_TEST_GIT").expect("PERSONA_TEST_GIT"));
    call_with_git(directory, home, xdg, state, gh, &git, args)
}

fn call_with_git(
    directory: &Path,
    home: &Path,
    xdg: &Path,
    state: &Path,
    gh: &Path,
    git: &Path,
    args: &[&str],
) -> Output {
    Command::new(persona())
        .env_clear()
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", xdg)
        .env("XDG_STATE_HOME", state)
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", git)
        .env("PERSONA_GH", gh)
        .current_dir(directory)
        .args(args)
        .output()
        .unwrap()
}

fn write_private_config(path: &Path, scope: &Path) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        path,
        format!(
            "version=1\n[[scopes]]\nname=\"work\"\npath={:?}\n[scopes.git]\nauthor={{name=\"Test Author\",email=\"author@example.invalid\"}}\ncommitter={{name=\"Test Committer\",email=\"committer@example.invalid\"}}\n",
            scope.to_string_lossy()
        ),
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn managed_gh_binds_account_and_repository_before_native_delegation() {
    let temporary = tempdir().unwrap();
    let home = temporary.path().join("home");
    let xdg = temporary.path().join("xdg");
    let state = temporary.path().join("state");
    let scope = temporary.path().join("work");
    let gh_config = xdg.join("gh");
    fs::create_dir_all(&scope).unwrap();
    fs::create_dir_all(&gh_config).unwrap();
    fs::set_permissions(&gh_config, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        gh_config.join("hosts.yml"),
        "github.com:\n  user: synthetic-user\n",
    )
    .unwrap();
    let config = xdg.join("persona/config.toml");
    write_private_config(&config, &scope);

    let marker = temporary.path().join("gh-invocations");
    let native_git_calls = temporary.path().join("native-git-calls");
    let real_git = PathBuf::from(std::env::var_os("PERSONA_TEST_GIT").expect("PERSONA_TEST_GIT"));
    let fake_git = temporary.path().join("git-fixture");
    fs::write(
        &fake_git,
        format!(
            "#!/bin/sh\nfor arg in \"$@\"; do if [ \"$arg\" = \"clone\" ]; then printf '%s\\n' \"$*\" >> '{}'; exit 0; fi; done\nexec '{}' \"$@\"\n",
            native_git_calls.display(),
            real_git.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_git, fs::Permissions::from_mode(0o700)).unwrap();
    let gh = temporary.path().join("gh-fixture");
    fs::write(
        &gh,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nif [ \"$1 $2\" = \"auth token\" ]; then [ \"$5\" = \"--user\" ] && [ \"$6\" = \"synthetic-user\" ] || exit 63; printf 'synthetic-token\\n'; exit 0; fi\nif [ \"$1 $2\" = \"api user\" ]; then printf '4242\\n'; exit 0; fi\nif [ \"$1 $2\" = \"api repos/acme/persona/pulls/7\" ]; then [ \"$GH_TOKEN\" = \"synthetic-token\" ] || exit 73; printf '%s\\n' '[\"main\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]'; exit 0; fi\nif [ \"$1 $2\" = \"api repos/acme/persona/pulls/7/merge\" ]; then [ \"$GH_TOKEN\" = \"synthetic-token\" ] || exit 73; case \"$*\" in *\"--field merge_method=squash\"*\"--field sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"*) ;; *) exit 74;; esac; printf '%s\\n' '{{\"sha\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"merged\":true}}'; exit 0; fi\nif [ \"$1 $2\" = \"api repos/acme/persona/pulls/9/reviews\" ]; then [ \"$GH_TOKEN\" = \"synthetic-token\" ] || exit 73; case \"$*\" in *\"event=REQUEST_CHANGES\"*\"body=please fix\"*) ;; *) exit 75;; esac; printf '%s\\n' '{{\"id\":77}}'; exit 0; fi\nif [ \"$1 $2\" = \"repo view\" ]; then [ \"$GH_TOKEN\" = \"synthetic-token\" ] || exit 73; exit 0; fi\nif [ \"$1 $2\" = \"repo clone\" ]; then case \"$4\" in denied-target) exec git clone 'https://github.com/other/repo.git' \"$4\";; allowed-target|persistent-target) exec git clone 'https://github.com/acme/persona.git' \"$4\";; esac; fi\nif [ \"$1 $2\" = \"pr create\" ]; then exec git push origin refs/heads/main:refs/heads/main; fi\nexit 64\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&gh, fs::Permissions::from_mode(0o700)).unwrap();

    let enrolled = call(
        temporary.path(),
        &home,
        &xdg,
        &state,
        &gh,
        &[
            "auth",
            "enroll",
            "--profile",
            "work",
            "--user",
            "synthetic-user",
            "--confirm-online",
        ],
    );
    assert!(
        enrolled.status.success(),
        "{}",
        String::from_utf8_lossy(&enrolled.stderr)
    );
    let profile = call(
        temporary.path(),
        &home,
        &xdg,
        &state,
        &gh,
        &[
            "profile",
            "update",
            "work",
            "--author-name",
            "Test Author",
            "--author-email",
            "author@example.invalid",
            "--committer-name",
            "Test Committer",
            "--committer-email",
            "committer@example.invalid",
            "--github-repo",
            "Acme/Persona",
            "--allow-github-merge",
            "acme/persona|main|squash",
            "--push-remote",
            "origin",
            "--push-destination",
            "https://github.com/other/repo.git",
            "--push-destination",
            "https://github.com/acme/persona.git",
        ],
    );
    assert!(
        profile.status.success(),
        "{}",
        String::from_utf8_lossy(&profile.stderr)
    );
    assert!(
        fs::read_to_string(&config)
            .unwrap()
            .contains("acme/persona")
    );

    let merge = call(
        &scope,
        &home,
        &xdg,
        &state,
        &gh,
        &[
            "run",
            "--",
            "gh",
            "pr",
            "merge",
            "7",
            "--repo",
            "acme/persona",
            "--squash",
        ],
    );
    assert_eq!(
        merge.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&merge.stderr)
    );
    assert!(String::from_utf8_lossy(&merge.stdout).contains("not locally signed by Persona"));
    let merge_calls = fs::read_to_string(&marker).unwrap();
    assert!(merge_calls.contains("api repos/acme/persona/pulls/7/merge"));
    assert!(merge_calls.contains("--field merge_method=squash"));
    assert!(merge_calls.contains("--field sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    let review = call(
        &scope,
        &home,
        &xdg,
        &state,
        &gh,
        &[
            "run",
            "--",
            "gh",
            "pr",
            "review",
            "9",
            "--repo",
            "acme/persona",
            "--request-changes",
            "--body",
            "please fix",
        ],
    );
    assert_eq!(
        review.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&review.stderr)
    );
    assert!(String::from_utf8_lossy(&review.stdout).contains("Submitted RequestChanges review 77"));

    let denied_strategy = call(
        &scope,
        &home,
        &xdg,
        &state,
        &gh,
        &[
            "run",
            "--",
            "gh",
            "pr",
            "merge",
            "7",
            "--repo",
            "acme/persona",
            "--rebase",
        ],
    );
    assert_eq!(denied_strategy.status.code(), Some(126));
    assert!(
        String::from_utf8_lossy(&denied_strategy.stderr).contains("strategy is not authorized")
    );

    let view = call(
        &scope,
        &home,
        &xdg,
        &state,
        &gh,
        &["run", "--", "gh", "repository", "view", "acme/persona"],
    );
    assert_eq!(
        view.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&view.stderr)
    );
    let calls = fs::read_to_string(&marker).unwrap();
    assert!(calls.contains("auth token --hostname github.com"));
    assert!(calls.contains("repo view acme/persona"));
    assert!(!calls.contains("synthetic-token"));

    let nested_clone = call_with_git(
        &scope,
        &home,
        &xdg,
        &state,
        &gh,
        &fake_git,
        &[
            "run",
            "--",
            "gh",
            "repo",
            "clone",
            "acme/persona",
            "denied-target",
        ],
    );
    assert_eq!(nested_clone.status.code(), Some(126));
    assert!(
        !native_git_calls.exists(),
        "nested Git must reject the unallowlisted repository before native transport"
    );

    let allowed_clone = call_with_git(
        &scope,
        &home,
        &xdg,
        &state,
        &gh,
        &fake_git,
        &[
            "run",
            "--",
            "gh",
            "repo",
            "clone",
            "acme/persona",
            "allowed-target",
        ],
    );
    assert_eq!(
        allowed_clone.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&allowed_clone.stderr)
    );
    assert!(
        fs::read_to_string(&native_git_calls)
            .unwrap()
            .contains(" clone https://github.com/acme/persona.git allowed-target")
    );

    let implicit_push = call_with_git(
        &scope,
        &home,
        &xdg,
        &state,
        &gh,
        &fake_git,
        &[
            "run",
            "--",
            "gh",
            "pr",
            "create",
            "--title",
            "Synthetic fixture",
            "--head",
            "acme:main",
            "--repo",
            "acme/persona",
        ],
    );
    assert_eq!(implicit_push.status.code(), Some(126));
    assert!(
        String::from_utf8_lossy(&implicit_push.stderr).contains("Persona blocked Git"),
        "an implicit PR-create push must be denied by nested Git: {}",
        String::from_utf8_lossy(&implicit_push.stderr)
    );
    assert!(
        !fs::read_to_string(&native_git_calls)
            .unwrap()
            .contains("push origin"),
        "nested PR creation must never reach native Git after push authorization fails"
    );

    let shim_directory = temporary.path().join("persistent-bin");
    fs::create_dir(&shim_directory).unwrap();
    fs::set_permissions(&shim_directory, fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["git", "gh", "ssh", "git-credential-persona"] {
        std::os::unix::fs::symlink(persona(), shim_directory.join(name)).unwrap();
    }
    let native_first = temporary.path().join("native-first-bin");
    fs::create_dir(&native_first).unwrap();
    let bypass_marker = temporary.path().join("unmanaged-git-called");
    let unwrapped_git = native_first.join("git");
    fs::write(
        &unwrapped_git,
        format!(
            "#!/bin/sh\nprintf called > '{}'\nexit 0\n",
            bypass_marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&unwrapped_git, fs::Permissions::from_mode(0o700)).unwrap();
    let path = std::env::join_paths([
        native_first.as_path(),
        shim_directory.as_path(),
        Path::new("/usr/bin"),
        Path::new("/bin"),
    ])
    .unwrap();
    let managed_calls_before = fs::read_to_string(&native_git_calls)
        .unwrap()
        .lines()
        .count();
    let persistent_clone = Command::new(shim_directory.join("gh"))
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("PERSONA_CONFIG_PATH", &config)
        .env("PERSONA_SHIM_DIR", &shim_directory)
        .env("PERSONA_GH", &gh)
        .env("PERSONA_GIT", &fake_git)
        .env("PATH", path)
        .current_dir(&scope)
        .args(["repo", "clone", "acme/persona", "persistent-target"])
        .output()
        .unwrap();
    assert_eq!(
        persistent_clone.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&persistent_clone.stderr)
    );
    assert!(
        !bypass_marker.exists(),
        "nested gh Git must not resolve a native Git that precedes the Persona shim"
    );
    let managed_calls = fs::read_to_string(&native_git_calls).unwrap();
    assert_eq!(
        managed_calls.lines().count(),
        managed_calls_before + 1,
        "nested Git should enter the managed Git shim before native execution; calls={managed_calls:?}, gh={:?}",
        fs::read_to_string(&marker).unwrap()
    );

    let before = fs::read_to_string(&marker).unwrap().lines().count();
    let denied = call(
        &scope,
        &home,
        &xdg,
        &state,
        &gh,
        &[
            "run",
            "--",
            "gh",
            "issue",
            "close",
            "12",
            "--repo",
            "acme/persona",
        ],
    );
    assert_eq!(denied.status.code(), Some(126));
    assert_eq!(fs::read_to_string(&marker).unwrap().lines().count(), before);

    let wrong_repository = call(
        &scope,
        &home,
        &xdg,
        &state,
        &gh,
        &["run", "--", "gh", "repo", "view", "other/repo"],
    );
    assert_eq!(wrong_repository.status.code(), Some(126));
    assert_eq!(fs::read_to_string(&marker).unwrap().lines().count(), before);

    let unsigned_release = call(
        &scope,
        &home,
        &xdg,
        &state,
        &gh,
        &[
            "run",
            "--",
            "gh",
            "release",
            "create",
            "v1",
            "--repo",
            "acme/persona",
            "--verify-tag",
        ],
    );
    assert_eq!(unsigned_release.status.code(), Some(126));
    assert_eq!(fs::read_to_string(&marker).unwrap().lines().count(), before);

    let environment_override = Command::new(persona())
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("PATH", "/usr/bin:/bin")
        .env("PERSONA_GIT", std::env::var_os("PERSONA_TEST_GIT").unwrap())
        .env("PERSONA_GH", &gh)
        .env("GH_TOKEN", "synthetic-override")
        .current_dir(&scope)
        .args(["run", "--", "gh", "repo", "view", "acme/persona"])
        .output()
        .unwrap();
    assert_eq!(environment_override.status.code(), Some(126));
    assert_eq!(fs::read_to_string(&marker).unwrap().lines().count(), before);
}

#[test]
fn native_gh_routes_only_through_a_local_unix_socket_fixture() {
    let native_gh = PathBuf::from(
        std::env::var("PERSONA_TEST_NATIVE_GH")
            .expect("PERSONA_TEST_NATIVE_GH must point to the native gh fixture executable"),
    );
    assert!(
        native_gh.is_absolute() && native_gh.is_file(),
        "PERSONA_TEST_NATIVE_GH must name an absolute executable file"
    );

    let temporary = tempdir().unwrap();
    let home = temporary.path().join("home");
    let xdg = temporary.path().join("xdg");
    let state = temporary.path().join("state");
    let scope = temporary.path().join("work");
    let gh_config = xdg.join("gh");
    fs::create_dir_all(&scope).unwrap();
    fs::create_dir_all(&gh_config).unwrap();
    fs::set_permissions(&gh_config, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        gh_config.join("hosts.yml"),
        "github.com:\n  user: synthetic-user\n",
    )
    .unwrap();
    let socket = temporary.path().join("github-api.sock");
    fs::write(
        gh_config.join("config.yml"),
        format!("version: 1\nhttp_unix_socket: {}\n", socket.display()),
    )
    .unwrap();
    fs::set_permissions(
        gh_config.join("config.yml"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let config = xdg.join("persona/config.toml");
    write_private_config(&config, &scope);

    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut requests = Vec::new();
        while requests.len() < 2 && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut buffer = [0_u8; 4096];
                    loop {
                        let read = stream.read(&mut buffer).unwrap();
                        if read == 0 {
                            break;
                        }
                        request.extend_from_slice(&buffer[..read]);
                        if let Some(header_end) =
                            request.windows(4).position(|window| window == b"\r\n\r\n")
                        {
                            let header = String::from_utf8_lossy(&request[..header_end]);
                            let content_length = header
                                .lines()
                                .find_map(|line| {
                                    let (name, value) = line.split_once(':')?;
                                    name.eq_ignore_ascii_case("content-length")
                                        .then(|| value.trim().parse::<usize>().ok())
                                        .flatten()
                                })
                                .unwrap_or(0);
                            if request.len() >= header_end + 4 + content_length {
                                break;
                            }
                        }
                    }
                    let request_line = String::from_utf8_lossy(&request)
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .to_owned();
                    let payload = if request_line.contains("/user") {
                        b"{\"login\":\"synthetic-user\",\"id\":4242}\n".as_slice()
                    } else {
                        b"{\"id\":991,\"name\":\"persona\",\"full_name\":\"acme/persona\",\"private\":true}\n".as_slice()
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        payload.len()
                    );
                    stream.write_all(response.as_bytes()).unwrap();
                    stream.write_all(payload).unwrap();
                    requests.push((request_line, request));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("Unix socket fixture failed: {error}"),
            }
        }
        requests
    });

    let wrapper = temporary.path().join("gh-wrapper");
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nif [ \"$1 $2\" = \"auth token\" ]; then [ \"$5\" = \"--user\" ] && [ \"$6\" = \"synthetic-user\" ] || exit 63; printf 'synthetic-token\\n'; exit 0; fi\nexport GH_TOKEN=synthetic-token\nexport HTTP_PROXY=http://127.0.0.1:1 HTTPS_PROXY=http://127.0.0.1:1 ALL_PROXY=http://127.0.0.1:1\nexport http_proxy=$HTTP_PROXY https_proxy=$HTTPS_PROXY all_proxy=$ALL_PROXY NO_PROXY= no_proxy=\nexec '{}' \"$@\"\n",
            native_gh.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();

    let enrolled = call(
        &scope,
        &home,
        &xdg,
        &state,
        &wrapper,
        &[
            "auth",
            "enroll",
            "--profile",
            "work",
            "--user",
            "synthetic-user",
            "--confirm-online",
        ],
    );
    if !enrolled.status.success() {
        let requests = server.join().unwrap();
        assert!(
            !requests.is_empty(),
            "native gh did not reach the configured local Unix socket; stderr: {}",
            String::from_utf8_lossy(&enrolled.stderr)
        );
        panic!(
            "native gh reached the local fixture but enrollment failed: {}",
            String::from_utf8_lossy(&enrolled.stderr)
        );
    }
    assert_eq!(
        enrolled.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&enrolled.stderr)
    );
    let configured = call(
        &scope,
        &home,
        &xdg,
        &state,
        &wrapper,
        &[
            "profile",
            "update",
            "work",
            "--author-name",
            "Test Author",
            "--author-email",
            "author@example.invalid",
            "--committer-name",
            "Test Committer",
            "--committer-email",
            "committer@example.invalid",
            "--github-repo",
            "acme/persona",
        ],
    );
    assert_eq!(
        configured.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&configured.stderr)
    );
    // Some native gh releases rewrite their fixture host metadata while using
    // GH_TOKEN during enrollment; restore our synthetic local selector before
    // exercising the independently gated managed command.
    fs::write(
        gh_config.join("hosts.yml"),
        "github.com:\n  user: synthetic-user\n",
    )
    .unwrap();
    let output = call(
        &scope,
        &home,
        &xdg,
        &state,
        &wrapper,
        &[
            "run",
            "--",
            "gh",
            "api",
            "repos/acme/persona/issues",
            "--method",
            "POST",
            "--field",
            "title=synthetic issue",
        ],
    );
    let requests = server.join().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        requests.len(),
        2,
        "all native gh API traffic must use the fixture socket"
    );
    assert!(
        requests
            .iter()
            .any(|(line, _)| line.contains("GET /user HTTP/1.1"))
    );
    assert!(
        requests
            .iter()
            .any(|(line, _)| line.contains("POST /repos/acme/persona/issues HTTP/1.1"))
    );
    assert!(
        requests
            .iter()
            .all(|(_, request)| { String::from_utf8_lossy(request).contains("synthetic-token") })
    );
    let create_request = requests
        .iter()
        .find(|(line, _)| line.contains("POST /repos/acme/persona/issues HTTP/1.1"))
        .unwrap();
    assert!(String::from_utf8_lossy(&create_request.1).contains("synthetic issue"));
}

#[test]
fn pr_checkout_uses_managed_fetch_without_exposing_token_to_git_or_hooks() {
    let temporary = tempdir().unwrap();
    let home = temporary.path().join("home");
    let xdg = temporary.path().join("xdg");
    let state = temporary.path().join("state");
    let scope = temporary.path().join("work");
    let repo = scope.join("repo");
    let gh_config = xdg.join("gh");
    fs::create_dir_all(&repo).unwrap();
    fs::create_dir_all(&gh_config).unwrap();
    fs::set_permissions(&gh_config, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        gh_config.join("hosts.yml"),
        "github.com:\n  user: synthetic-user\n",
    )
    .unwrap();
    let real_git = PathBuf::from(std::env::var_os("PERSONA_TEST_GIT").expect("PERSONA_TEST_GIT"));
    let status = Command::new(&real_git)
        .current_dir(&repo)
        .args(["init", "-q", "-b", "main"])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(
        Command::new(&real_git)
            .current_dir(&repo)
            .args([
                "-c",
                "user.name=Test Author",
                "-c",
                "user.email=author@example.invalid",
                "commit",
                "--allow-empty",
                "-m",
                "fixture"
            ])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(&real_git)
            .current_dir(&repo)
            .args([
                "remote",
                "add",
                "origin",
                "https://github.com/acme/persona.git"
            ])
            .status()
            .unwrap()
            .success()
    );
    let oid = String::from_utf8(
        Command::new(&real_git)
            .current_dir(&repo)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    let config = xdg.join("persona/config.toml");
    write_private_config(&config, &scope);
    let gh = temporary.path().join("gh-fixture");
    let api_calls = temporary.path().join("api-calls");
    fs::write(&gh, format!("#!/bin/sh\nif [ \"$1 $2\" = \"auth token\" ]; then [ \"$5\" = \"--user\" ] && [ \"$6\" = \"synthetic-user\" ] || exit 63; printf 'synthetic-token\\n'; exit 0; fi\nif [ \"$1 $2\" = \"api user\" ]; then printf '4242\\n'; exit 0; fi\ncase \"$2\" in repos/acme/persona/pulls/15|repos/acme/persona/pulls/16) printf '%s\\n' \"$*\" >> '{}'; printf '%s\\n' '[\"{oid}\",\"feature\"]'; exit 0;; esac\nexit 64\n", api_calls.display())).unwrap();
    fs::set_permissions(&gh, fs::Permissions::from_mode(0o700)).unwrap();
    let enrolled = call(
        &scope,
        &home,
        &xdg,
        &state,
        &gh,
        &[
            "auth",
            "enroll",
            "--profile",
            "work",
            "--user",
            "synthetic-user",
            "--confirm-online",
        ],
    );
    assert!(
        enrolled.status.success(),
        "{}",
        String::from_utf8_lossy(&enrolled.stderr)
    );
    let updated = call(
        &scope,
        &home,
        &xdg,
        &state,
        &gh,
        &[
            "profile",
            "update",
            "work",
            "--author-name",
            "Test Author",
            "--author-email",
            "author@example.invalid",
            "--committer-name",
            "Test Committer",
            "--committer-email",
            "committer@example.invalid",
            "--github-repo",
            "acme/persona",
            "--remote-policy",
            "origin|https://github.com/acme/persona.git|https://github.com/acme/persona.git",
        ],
    );
    assert!(
        updated.status.success(),
        "{}",
        String::from_utf8_lossy(&updated.stderr)
    );

    let fetch_marker = temporary.path().join("fetch-env");
    let fake_git = temporary.path().join("git-fixture");
    fs::write(&fake_git, format!("#!/bin/sh\nfor arg in \"$@\"; do if [ \"$arg\" = fetch ]; then if [ -n \"${{GH_TOKEN+x}}\" ]; then printf 'present\\n' > '{}'; else printf 'absent\\n' > '{}'; fi; printf '{oid}\\t\\trefs/pull/15/head\\n' > '{}/.git/FETCH_HEAD'; for arg in \"$@\"; do case \"$arg\" in refs/pull/16/head) printf '{oid}\\t\\trefs/pull/16/head\\n' > '{}/.git/FETCH_HEAD';; esac; done; exit 0; fi; done\nexec '{}' \"$@\"\n", fetch_marker.display(), fetch_marker.display(), repo.display(), repo.display(), real_git.display())).unwrap();
    fs::set_permissions(&fake_git, fs::Permissions::from_mode(0o700)).unwrap();
    let checked_out = call_with_git(
        &repo,
        &home,
        &xdg,
        &state,
        &gh,
        &fake_git,
        &[
            "run",
            "--",
            "gh",
            "pr",
            "checkout",
            "15",
            "--repo",
            "acme/persona",
        ],
    );
    assert_eq!(
        checked_out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&checked_out.stderr)
    );
    assert_eq!(fs::read_to_string(&fetch_marker).unwrap(), "absent\n");
    let branch = Command::new(&real_git)
        .current_dir(&repo)
        .args(["rev-parse", "refs/heads/pr-15"])
        .output()
        .unwrap();
    assert!(branch.status.success());
    assert_eq!(String::from_utf8_lossy(&branch.stdout).trim(), oid);

    let hook_marker = temporary.path().join("hook-token");
    let hook = repo.join(".git/hooks/post-checkout");
    fs::write(
        &hook,
        format!(
            "#!/bin/sh\nif [ -n \"${{GH_TOKEN+x}}\" ]; then printf 'present' > '{}'; fi\n",
            hook_marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();
    let blocked = call_with_git(
        &repo,
        &home,
        &xdg,
        &state,
        &gh,
        &fake_git,
        &[
            "run",
            "--",
            "gh",
            "pr",
            "checkout",
            "16",
            "--repo",
            "acme/persona",
            "--branch",
            "pr-16",
        ],
    );
    assert_eq!(blocked.status.code(), Some(126));
    assert!(
        !hook_marker.exists(),
        "repository-controlled post-checkout hook must not execute"
    );
}

#[test]
fn audited_signed_tag_release_uses_local_credentials_and_validates_response() {
    let temporary = tempdir().unwrap();
    let home = temporary.path().join("home");
    let xdg = temporary.path().join("xdg");
    let state = temporary.path().join("state");
    let gh_config = xdg.join("gh");
    fs::create_dir_all(&gh_config).unwrap();
    fs::set_permissions(&gh_config, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        gh_config.join("hosts.yml"),
        "github.com:\n  user: synthetic-user\n",
    )
    .unwrap();
    let repo = temporary.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    let git = PathBuf::from(std::env::var_os("PERSONA_TEST_GIT").expect("PERSONA_TEST_GIT"));
    let ssh_keygen = PathBuf::from(
        std::env::var_os("PERSONA_TEST_SSH_KEYGEN").expect("PERSONA_TEST_SSH_KEYGEN"),
    );
    // Nix checks use an intentionally minimal PATH, so expose only the
    // resolved fixture ssh-keygen directory to Git's SSH-signature helper.
    let test_path = ssh_keygen.parent().expect("ssh-keygen directory");
    let signing_key = temporary.path().join("release-signing-key");
    let generated = Command::new(&ssh_keygen)
        .env_clear()
        .env("HOME", &home)
        .env("PATH", test_path)
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&signing_key)
        .output()
        .unwrap();
    assert!(generated.status.success());
    let public_key = PathBuf::from(format!("{}.pub", signing_key.display()));
    let fingerprint_output = Command::new(&ssh_keygen)
        .env_clear()
        .env("PATH", test_path)
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
    let git_run = |args: &[&str]| {
        Command::new(&git)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", test_path)
            .arg("-C")
            .arg(&repo)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(
        Command::new(&git)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", test_path)
            .args(["init", "-q", "-b", "main"])
            .arg(&repo)
            .status()
            .unwrap()
            .success()
    );
    for (key, value) in [
        ("user.name", "Release Author"),
        ("user.email", "release@example.invalid"),
        ("gpg.format", "ssh"),
        ("user.signingkey", signing_key.to_str().unwrap()),
        ("commit.gpgsign", "true"),
        ("tag.gpgsign", "true"),
    ] {
        assert!(git_run(&["config", key, value]).status.success());
    }
    assert!(
        git_run(&["remote", "add", "origin", "https://github.com/org/repo.git"])
            .status
            .success()
    );
    assert!(
        git_run(&["commit", "--allow-empty", "-m", "release fixture"])
            .status
            .success()
    );
    assert!(
        git_run(&[
            "-c",
            "user.name=Release Author",
            "-c",
            "user.email=release@example.invalid",
            "tag",
            "-s",
            "-m",
            "signed release",
            "v1"
        ])
        .status
        .success()
    );
    for tag in ["v-missing", "v-wrong", "v-partial", "v-bad", "v-race"] {
        assert!(
            git_run(&[
                "-c",
                "user.name=Release Author",
                "-c",
                "user.email=release@example.invalid",
                "tag",
                "-s",
                "-m",
                "signed release",
                tag,
            ])
            .status
            .success()
        );
    }
    let tag_oid = String::from_utf8_lossy(&git_run(&["rev-parse", "refs/tags/v1"]).stdout)
        .trim()
        .to_owned();
    let additional_tag_oids = ["v-missing", "v-wrong", "v-partial", "v-bad", "v-race"].map(|tag| {
        String::from_utf8_lossy(&git_run(&["rev-parse", &format!("refs/tags/{tag}")]).stdout)
            .trim()
            .to_owned()
    });
    let marker = temporary.path().join("gh-api-calls");
    let curl_marker = temporary.path().join("curl-upload-calls");
    let asset_source = repo.join("fixture.bin");
    let uploaded_body = temporary.path().join("uploaded-body");
    let plus_asset_source = repo.join("release+notes.bin");
    let plus_uploaded_body = temporary.path().join("plus-uploaded-body");
    let wrong_account_mode = temporary.path().join("wrong-account-mode");
    let race_seen = temporary.path().join("race-tag-seen");
    let changed_tag_oid = "f".repeat(40);
    let fixture_digest = format!("sha256:{:x}", Sha256::digest(b"snapshot bytes"));
    fs::write(&asset_source, b"snapshot bytes").unwrap();
    let gh = temporary.path().join("gh-fixture");
    let script = format!(
        r#"#!/bin/sh
printf '%s\n' "$*" >> '{marker}'
if [ "$1 $2" = "auth token" ]; then [ "$5" = "--user" ] && [ "$6" = "synthetic-user" ] || exit 63; if [ -f '{wrong_account_mode}' ]; then printf 'different-account-token\n'; else printf 'synthetic-release-token\n'; fi; exit 0; fi
if [ "$1" = "api" ]; then [ "$GH_TOKEN" = "synthetic-release-token" ] || exit 73; fi
if [ "$1 $2" = "api user" ]; then printf '4242\n'; exit 0; fi
case "$2" in
  repos/org/repo/git/ref/tags/v1) printf '%s\n' '["{tag_oid}","tag"]'; exit 0;;
  repos/org/repo/git/ref/tags/v-missing) printf '%s\n' '["{missing_tag_oid}","tag"]'; exit 0;;
  repos/org/repo/git/ref/tags/v-wrong) printf '%s\n' '["{wrong_tag_oid}","tag"]'; exit 0;;
  repos/org/repo/git/ref/tags/v-partial) printf '%s\n' '["{partial_tag_oid}","tag"]'; exit 0;;
  repos/org/repo/git/ref/tags/v-bad) printf '%s\n' '["{bad_tag_oid}","tag"]'; exit 0;;
  repos/org/repo/git/ref/tags/v-race) if [ -f '{race_seen}' ]; then printf '%s\n' '["{changed_tag_oid}","tag"]'; else : > '{race_seen}'; printf '%s\n' '["{race_tag_oid}","tag"]'; fi; exit 0;;
  repos/org/repo/releases) printf '%s\n' '{{"id":123,"tag_name":"v1"}}'; exit 0;;
  repos/org/repo/releases/tags/v1) printf 'mutated after snapshot' > '{asset_source}'; if [ -f '{uploaded_body}' ]; then printf '%s\n' '{{"id":123,"tag_name":"v1","assets":[{{"name":"fixture.bin"}}]}}'; else printf '%s\n' '{{"id":123,"tag_name":"v1","assets":[]}}'; fi; exit 0;;
  repos/org/repo/releases/tags/v-missing) exit 1;;
  repos/org/repo/releases/tags/v-wrong) printf '%s\n' '{{"id":123,"tag_name":"wrong-tag","assets":[]}}'; exit 0;;
  repos/org/repo/releases/tags/v-race) printf '%s\n' '{{"id":123,"tag_name":"v-race","assets":[]}}'; exit 0;;
  repos/org/repo/releases/tags/v-bad) printf '%s\n' '{{"id":123,"tag_name":"v-bad","assets":[]}}'; exit 0;;
  repos/org/repo/releases/tags/v-partial) printf '%s\n' '{{"id":123,"tag_name":"v-partial","assets":[]}}'; exit 0;;
esac
exit 64
"#,
        marker = marker.display(),
        tag_oid = tag_oid,
        missing_tag_oid = additional_tag_oids[0],
        wrong_tag_oid = additional_tag_oids[1],
        partial_tag_oid = additional_tag_oids[2],
        bad_tag_oid = additional_tag_oids[3],
        race_tag_oid = additional_tag_oids[4],
        changed_tag_oid = changed_tag_oid,
        asset_source = asset_source.display(),
        uploaded_body = uploaded_body.display(),
        wrong_account_mode = wrong_account_mode.display(),
        race_seen = race_seen.display(),
    );
    fs::write(&gh, script).unwrap();
    fs::set_permissions(&gh, fs::Permissions::from_mode(0o700)).unwrap();
    let curl = temporary.path().join("curl-fixture");
    let curl_script = format!(
        r#"#!/bin/sh
printf '%s\n' "$*" >> '{curl_marker}'
[ -z "$GH_TOKEN" ] || exit 71
[ "$PERSONA_UPLOAD_TOKEN" = "synthetic-release-token" ] || exit 72
[ "$1" = "--disable" ] || exit 73
joined="$*"
case "$joined" in *"--location --max-redirs 0 --proto =https --proto-redir =https"*) ;; *) exit 74;; esac
case "$joined" in *"--variable %PERSONA_UPLOAD_TOKEN --expand-header Authorization: Bearer {{{{PERSONA_UPLOAD_TOKEN}}}}"*) ;; *) exit 75;; esac
case "$joined" in *synthetic-release-token*) exit 76;; esac
url=
for argument in "$@"; do url="$argument"; done
case "$url" in
  *name=fixture.bin)
    cat > '{uploaded_body}'
    [ "$(cat '{uploaded_body}')" = "snapshot bytes" ] || exit 76
    printf 'HTTP/2.0 201 Created\r\nContent-Type: application/json\r\n\r\n%s\n' '{{"id":456,"name":"fixture.bin","size":14,"state":"uploaded","digest":"{fixture_digest}"}}'
    exit 0;;
  *name=release%2Bnotes.bin)
    cat > '{plus_uploaded_body}'
    [ "$(cat '{plus_uploaded_body}')" = "plus snapshot" ] || exit 77
    printf 'HTTP/2.0 201 Created\r\nContent-Type: application/json\r\n\r\n%s\n' '{{"id":460,"name":"release+notes.bin","size":13,"state":"uploaded","digest":null}}'
    exit 0;;
  *name=race.bin)
    cat >/dev/null
    printf 'HTTP/2.0 201 Created\r\n\r\n%s\n' '{{"id":457,"name":"race.bin","size":4,"state":"uploaded","digest":null}}'
    exit 0;;
  *name=first.bin)
    cat > '{first_body}'
    printf 'HTTP/2.0 201 Created\r\n\r\n%s\n' '{{"id":458,"name":"first.bin","size":5,"state":"uploaded","digest":null}}'
    exit 0;;
  *name=fail.bin)
    cat >/dev/null
    printf 'HTTP/2.0 502 Bad Gateway\r\n\r\n%s\n' '{{"message":"upload may have started"}}'
    exit 0;;
  *name=bad.bin)
    cat >/dev/null
    printf 'HTTP/2.0 201 Created\r\n\r\n%s\n' '{{"id":459,"name":"bad.bin","size":999,"state":"uploaded","digest":null}}'
    exit 0;;
esac
exit 64
"#,
        curl_marker = curl_marker.display(),
        uploaded_body = uploaded_body.display(),
        plus_uploaded_body = plus_uploaded_body.display(),
        first_body = temporary.path().join("first-body").display(),
        fixture_digest = fixture_digest,
    );
    fs::write(&curl, curl_script).unwrap();
    fs::set_permissions(&curl, fs::Permissions::from_mode(0o700)).unwrap();
    let config = xdg.join("persona/config.toml");
    write_private_config(&config, &repo);
    let enrollment = Command::new(persona())
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("PERSONA_GIT", &git)
        .env("PERSONA_GH", &gh)
        .env("GH_CONFIG_DIR", &gh_config)
        .env("PATH", test_path)
        .args([
            "auth",
            "enroll",
            "--profile",
            "work",
            "--host",
            "github.com",
            "--user",
            "synthetic-user",
            "--confirm-online",
        ])
        .output()
        .unwrap();
    assert!(
        enrollment.status.success(),
        "{}",
        String::from_utf8_lossy(&enrollment.stderr)
    );
    let update = Command::new(persona())
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("PERSONA_GIT", &git)
        .env("PERSONA_GH", &gh)
        .env("GH_CONFIG_DIR", &gh_config)
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .env("PATH", test_path)
        .args([
            "profile",
            "update",
            "work",
            "--author-name",
            "Release Author",
            "--author-email",
            "release@example.invalid",
            "--committer-name",
            "Release Author",
            "--committer-email",
            "release@example.invalid",
            "--github-repo",
            "org/repo",
            "--push-remote",
            "origin",
            "--push-destination",
            "https://github.com/org/repo.git",
            "--remote-policy",
            "origin|-|https://github.com/org/repo.git",
            "--signing-fingerprint",
            &fingerprint,
            "--signing-format",
            "ssh",
            "--public-key",
        ])
        .arg(&public_key)
        .args(["--allow-annotated-tags", "true"])
        .output()
        .unwrap();
    assert!(
        update.status.success(),
        "{}",
        String::from_utf8_lossy(&update.stderr)
    );
    let tag_check = Command::new(persona())
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("PERSONA_GIT", &git)
        .env("PERSONA_GPG", std::env::var_os("PERSONA_TEST_GPG").unwrap())
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .env("PATH", test_path)
        .current_dir(&repo)
        .args(["check", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args(["--operation", "tag", "--tag", "v1", "--format", "json"])
        .output()
        .unwrap();
    assert!(
        tag_check.status.success(),
        "tag audit: {} {}",
        String::from_utf8_lossy(&tag_check.stdout),
        String::from_utf8_lossy(&tag_check.stderr)
    );
    let release = Command::new(persona())
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", &state)
        .env("PERSONA_GIT", &git)
        .env(
            "PERSONA_GPG",
            std::env::var_os("PERSONA_TEST_GPG").expect("PERSONA_TEST_GPG"),
        )
        .env("PERSONA_SSH_KEYGEN", &ssh_keygen)
        .env("PERSONA_GH", &gh)
        .env("PATH", test_path)
        .current_dir(&repo)
        .args(["run", "--config"])
        .arg(&config)
        .args(["--cwd"])
        .arg(&repo)
        .args([
            "--",
            "gh",
            "release",
            "create",
            "v1",
            "--repo",
            "org/repo",
            "--title",
            "Fixture release",
            "--notes",
            "signed tag only",
        ])
        .output()
        .unwrap();
    assert_eq!(
        release.status.code(),
        Some(0),
        "stdout: {}; stderr: {}",
        String::from_utf8_lossy(&release.stdout),
        String::from_utf8_lossy(&release.stderr)
    );
    assert!(
        String::from_utf8_lossy(&release.stdout).contains("existing locally audited signed tag")
    );
    let calls = fs::read_to_string(&marker).unwrap();
    assert_eq!(
        calls.matches("repos/org/repo/git/ref/tags/v1").count(),
        2,
        "pre/post remote tag verification calls: {calls}"
    );
    assert!(calls.contains("repos/org/repo/releases --method POST"));
    assert!(calls.contains("tag_name=v1"));
    assert!(calls.contains(&format!(
        "target_commitish={}",
        String::from_utf8_lossy(&git_run(&["rev-parse", "refs/tags/v1^{}"]).stdout).trim()
    )));

    let shim_directory = temporary.path().join("installed-shims");
    fs::create_dir(&shim_directory).unwrap();
    fs::set_permissions(&shim_directory, fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["git", "gh", "ssh", "git-credential-persona"] {
        std::os::unix::fs::symlink(persona(), shim_directory.join(name)).unwrap();
    }
    let call_installed = |arguments: &[&str]| {
        Command::new(shim_directory.join("gh"))
            .env_clear()
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &xdg)
            .env("XDG_STATE_HOME", &state)
            .env("PATH", test_path)
            .env("PERSONA_CONFIG_PATH", &config)
            .env("PERSONA_SHIM_DIR", &shim_directory)
            .env("PERSONA_GH", &gh)
            .env("PERSONA_CURL", &curl)
            .env("PERSONA_GIT", &git)
            .current_dir(&repo)
            .args(arguments)
            .output()
            .unwrap()
    };
    let upload = call_installed(&[
        "release",
        "upload",
        "v1",
        "fixture.bin",
        "--repo",
        "org/repo",
    ]);
    assert_eq!(
        upload.status.code(),
        Some(0),
        "stdout: {}; stderr: {}; curl fixture log: {}",
        String::from_utf8_lossy(&upload.stdout),
        String::from_utf8_lossy(&upload.stderr),
        fs::read_to_string(&curl_marker).unwrap_or_else(|error| format!("<unavailable: {error}>"))
    );
    assert!(String::from_utf8_lossy(&upload.stdout).contains("Uploaded fixture.bin (id 456)"));
    assert_eq!(fs::read(&uploaded_body).unwrap(), b"snapshot bytes");
    assert_eq!(fs::read(&asset_source).unwrap(), b"mutated after snapshot");
    let upload_calls = fs::read_to_string(&marker).unwrap();
    assert!(upload_calls.contains("repos/org/repo/releases/tags/v1"));
    assert!(!upload_calls.contains("synthetic-release-token"));
    let curl_calls = fs::read_to_string(&curl_marker).unwrap();
    assert!(curl_calls.contains(
        "https://uploads.github.com/repos/org/repo/releases/123/assets?name=fixture.bin"
    ));
    assert!(curl_calls.contains("--location --max-redirs 0 --proto =https --proto-redir =https"));
    assert!(!curl_calls.contains("synthetic-release-token"));

    fs::write(&plus_asset_source, b"plus snapshot").unwrap();
    let plus_upload = call_installed(&[
        "release",
        "upload",
        "v1",
        "release+notes.bin",
        "--repo",
        "org/repo",
    ]);
    assert_eq!(
        plus_upload.status.code(),
        Some(0),
        "stdout: {}; stderr: {}",
        String::from_utf8_lossy(&plus_upload.stdout),
        String::from_utf8_lossy(&plus_upload.stderr)
    );
    assert!(
        String::from_utf8_lossy(&plus_upload.stdout)
            .contains("Uploaded release+notes.bin (id 460)")
    );
    assert_eq!(fs::read(&plus_uploaded_body).unwrap(), b"plus snapshot");
    let curl_calls = fs::read_to_string(&curl_marker).unwrap();
    assert!(curl_calls.contains("name=release%2Bnotes.bin"));
    assert!(!curl_calls.contains("Authorization: Bearer synthetic-release-token"));

    let upload_calls = fs::read_to_string(&marker).unwrap();
    let calls_before_denial = upload_calls.lines().count();
    let curl_calls_before_denial = fs::read_to_string(&curl_marker).unwrap().lines().count();
    let outside = temporary.path().join("outside.bin");
    fs::write(&outside, b"outside").unwrap();
    let escape = call_installed(&[
        "release",
        "upload",
        "v1",
        "../outside.bin",
        "--repo",
        "org/repo",
    ]);
    assert_eq!(escape.status.code(), Some(126));
    assert!(String::from_utf8_lossy(&escape.stderr).contains("escapes"));
    let after_denial = fs::read_to_string(&marker).unwrap();
    assert_eq!(
        after_denial.lines().count(),
        calls_before_denial,
        "invalid local paths must not retrieve credentials or invoke the GitHub fixture"
    );
    assert_eq!(
        fs::read_to_string(&curl_marker).unwrap().lines().count(),
        curl_calls_before_denial,
        "invalid local paths must not invoke the upload transport"
    );

    let conflict = call_installed(&[
        "release",
        "upload",
        "v1",
        "fixture.bin",
        "--repo",
        "org/repo",
    ]);
    assert_eq!(conflict.status.code(), Some(126));
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("already exists"));
    let final_calls = fs::read_to_string(&marker).unwrap();
    assert!(!final_calls.contains("synthetic-release-token"));

    let api_call_count = |calls: &str| {
        calls
            .lines()
            .filter(|line| line.starts_with("api "))
            .count()
    };
    let before_policy_denials = final_calls.clone();
    let wrong_repository = call_installed(&[
        "release",
        "upload",
        "v1",
        "fixture.bin",
        "--repo",
        "other/repo",
    ]);
    assert_eq!(wrong_repository.status.code(), Some(126));
    let calls = fs::read_to_string(&marker).unwrap();
    assert_eq!(calls.lines().count(), before_policy_denials.lines().count());

    assert!(
        git_run(&[
            "-c",
            "tag.gpgsign=false",
            "tag",
            "-a",
            "-m",
            "unsigned fixture",
            "v-unsigned"
        ])
        .status
        .success()
    );
    fs::write(repo.join("unsigned.bin"), b"unsigned").unwrap();
    let unsigned_tag = call_installed(&[
        "release",
        "upload",
        "v-unsigned",
        "unsigned.bin",
        "--repo",
        "org/repo",
    ]);
    assert_eq!(unsigned_tag.status.code(), Some(126));
    assert!(String::from_utf8_lossy(&unsigned_tag.stderr).contains("signature and scope audit"));
    let calls = fs::read_to_string(&marker).unwrap();
    assert_eq!(calls.lines().count(), before_policy_denials.lines().count());
    let missing_tag = call_installed(&[
        "release",
        "upload",
        "v-not-local",
        "unsigned.bin",
        "--repo",
        "org/repo",
    ]);
    assert_eq!(missing_tag.status.code(), Some(126));
    assert_eq!(
        fs::read_to_string(&marker).unwrap().lines().count(),
        before_policy_denials.lines().count()
    );

    let original_config = fs::read(&config).unwrap();
    let config_text = String::from_utf8(original_config.clone()).unwrap();
    assert!(config_text.contains("https://github.com/org/repo.git"));
    fs::write(
        &config,
        config_text.replace(
            "https://github.com/org/repo.git",
            "https://github.com/other/repo.git",
        ),
    )
    .unwrap();
    let wrong_destination = call_installed(&[
        "release",
        "upload",
        "v1",
        "fixture.bin",
        "--repo",
        "org/repo",
    ]);
    assert_eq!(wrong_destination.status.code(), Some(126));
    let calls = fs::read_to_string(&marker).unwrap();
    assert_eq!(calls.lines().count(), before_policy_denials.lines().count());
    fs::write(&config, original_config).unwrap();

    fs::write(&wrong_account_mode, b"wrong selected account").unwrap();
    let api_calls_before_account_mismatch = api_call_count(&fs::read_to_string(&marker).unwrap());
    let wrong_account = call_installed(&[
        "release",
        "upload",
        "v1",
        "fixture.bin",
        "--repo",
        "org/repo",
    ]);
    assert_eq!(wrong_account.status.code(), Some(126));
    assert!(String::from_utf8_lossy(&wrong_account.stderr).contains("does not match"));
    assert_eq!(
        api_call_count(&fs::read_to_string(&marker).unwrap()),
        api_calls_before_account_mismatch,
        "an account mismatch must not invoke GitHub API endpoints"
    );
    fs::remove_file(&wrong_account_mode).unwrap();

    fs::write(repo.join("missing.bin"), b"missing release").unwrap();
    let missing_release = call_installed(&[
        "release",
        "upload",
        "v-missing",
        "missing.bin",
        "--repo",
        "org/repo",
    ]);
    assert_eq!(missing_release.status.code(), Some(126));
    assert!(String::from_utf8_lossy(&missing_release.stderr).contains("existing GitHub release"));
    fs::write(repo.join("wrong.bin"), b"wrong release tag").unwrap();
    let wrong_release = call_installed(&[
        "release",
        "upload",
        "v-wrong",
        "wrong.bin",
        "--repo",
        "org/repo",
    ]);
    assert_eq!(wrong_release.status.code(), Some(126));
    assert!(String::from_utf8_lossy(&wrong_release.stderr).contains("existing GitHub release"));

    fs::write(repo.join("bad.bin"), b"bad").unwrap();
    let malformed_response = call_installed(&[
        "release", "upload", "v-bad", "bad.bin", "--repo", "org/repo",
    ]);
    assert_eq!(malformed_response.status.code(), Some(126));
    assert!(
        String::from_utf8_lossy(&malformed_response.stderr).contains("uncertain asset: bad.bin")
    );

    fs::write(repo.join("first.bin"), b"first").unwrap();
    fs::write(repo.join("fail.bin"), b"fail").unwrap();
    let partial_failure = call_installed(&[
        "release",
        "upload",
        "v-partial",
        "first.bin",
        "fail.bin",
        "--repo",
        "org/repo",
    ]);
    assert_eq!(partial_failure.status.code(), Some(126));
    let partial_error = String::from_utf8_lossy(&partial_failure.stderr);
    assert!(partial_error.contains("confirmed uploaded assets: first.bin (id 458)"));
    assert!(partial_error.contains("uncertain asset: fail.bin"));
    assert!(!partial_error.contains("synthetic-release-token"));

    fs::write(repo.join("race.bin"), b"race").unwrap();
    let concurrent_tag_move = call_installed(&[
        "release", "upload", "v-race", "race.bin", "--repo", "org/repo",
    ]);
    assert_eq!(concurrent_tag_move.status.code(), Some(126));
    let race_error = String::from_utf8_lossy(&concurrent_tag_move.stderr);
    assert!(race_error.contains("changed concurrently"));
    assert!(race_error.contains("confirmed uploaded assets: race.bin (id 457)"));
}
