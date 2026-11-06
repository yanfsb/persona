#![cfg(unix)]

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
    let tag_oid = String::from_utf8_lossy(&git_run(&["rev-parse", "refs/tags/v1"]).stdout)
        .trim()
        .to_owned();
    let marker = temporary.path().join("gh-api-calls");
    let gh = temporary.path().join("gh-fixture");
    let script = format!(
        r#"#!/bin/sh
printf '%s\n' "$*" >> '{marker}'
if [ "$1 $2" = "auth token" ]; then [ "$5" = "--user" ] && [ "$6" = "synthetic-user" ] || exit 63; printf 'synthetic-release-token\n'; exit 0; fi
if [ "$1" = "api" ]; then [ "$GH_TOKEN" = "synthetic-release-token" ] || exit 73; fi
if [ "$1 $2" = "api user" ]; then printf '4242\n'; exit 0; fi
case "$2" in
  repos/org/repo/git/ref/tags/v1) printf '%s\n' '["{tag_oid}","tag"]'; exit 0;;
  repos/org/repo/releases) printf '%s\n' '{{"id":123,"tag_name":"v1"}}'; exit 0;;
esac
exit 64
"#,
        marker = marker.display(),
        tag_oid = tag_oid,
    );
    fs::write(&gh, script).unwrap();
    fs::set_permissions(&gh, fs::Permissions::from_mode(0o700)).unwrap();
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
    assert!(!calls.contains("synthetic-release-token"));
}
