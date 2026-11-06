use persona::runner::{RunError, RunLimits, RunRequest, SubprocessRunner, argument};
use std::ffi::OsString;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

fn request<'a>(args: &'a [OsString], cwd: &'a Path) -> RunRequest<'a> {
    static ENVIRONMENT: OnceLock<Vec<(OsString, OsString)>> = OnceLock::new();
    let environment = ENVIRONMENT.get_or_init(|| {
        let coreutils = std::env::var_os("PERSONA_TEST_COREUTILS")
            .unwrap_or_else(|| OsString::from("/usr/bin"));
        let mut path = coreutils;
        path.push(":/bin:/usr/bin");
        vec![(OsString::from("PATH"), path)]
    });
    RunRequest {
        executable: Path::new("/bin/sh"),
        args,
        cwd,
        environment,
        stdin: None,
    }
}

#[test]
fn sends_bounded_input_to_a_child_without_shell_interpolation() {
    let args = [];
    let input = b"synthetic stdin fixture";
    let cat = std::env::var_os("PERSONA_TEST_CAT").unwrap_or_else(|| OsString::from("/bin/cat"));
    let mut request = request(&args, Path::new("/"));
    request.executable = Path::new(&cat);
    request.stdin = Some(input);
    let output = SubprocessRunner::default()
        .run(request)
        .expect("run cat fixture");
    assert!(output.status.success());
    assert_eq!(output.stdout, input);
}

#[test]
fn captures_output_without_shell_interpolation_in_the_runner() {
    let args = [argument("-c"), argument("printf '%s' literal")];
    let output = SubprocessRunner::default()
        .run(request(&args, Path::new("/")))
        .expect("run fixture");

    assert!(output.status.success());
    assert_eq!(output.stdout, b"literal");
}

#[test]
fn terminates_commands_that_exceed_the_deadline() {
    let args = [argument("-c"), argument("sleep 2")];
    let runner = SubprocessRunner::new(RunLimits {
        timeout: Duration::from_millis(30),
        poll_interval: Duration::from_millis(1),
        ..RunLimits::default()
    });

    assert!(matches!(
        runner.run(request(&args, Path::new("/"))),
        Err(RunError::Timeout)
    ));
}

#[cfg(unix)]
#[test]
fn cleans_up_descendants_that_keep_pipes_open_after_the_shell_exits() {
    use std::fs;
    use tempfile::tempdir;

    let temporary = tempdir().expect("create fixture directory");
    let pid_path = temporary.path().join("child.pid");
    let script = format!(
        "sleep 30 & child=$!; printf '%s' \"$child\" > {}; exit 0",
        pid_path.display()
    );
    let args = [argument("-c"), argument(script)];
    let started = Instant::now();
    let output = SubprocessRunner::default()
        .run(request(&args, temporary.path()))
        .expect("shell should exit successfully");

    assert!(output.status.success());
    assert!(started.elapsed() < Duration::from_secs(2));

    let pid: libc::pid_t = fs::read_to_string(&pid_path)
        .expect("shell should record the descendant PID")
        .parse()
        .expect("descendant PID should be numeric");
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        // A killed process may remain as a zombie briefly while its parent
        // reaps it; ESRCH is the stable indication that it is gone.
        let result = unsafe { libc::kill(pid, 0) };
        if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            break;
        }
        assert!(Instant::now() < deadline, "descendant process was leaked");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn terminates_commands_that_exceed_output_caps() {
    let args = [argument("-c"), argument("printf '1234567890'")];
    let runner = SubprocessRunner::new(RunLimits {
        max_stdout_bytes: 4,
        ..RunLimits::default()
    });

    assert!(matches!(
        runner.run(request(&args, Path::new("/"))),
        Err(RunError::OutputLimit { stream: "stdout" })
    ));
}
