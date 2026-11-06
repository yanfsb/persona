use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub struct RunLimits {
    pub timeout: Duration,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
    pub poll_interval: Duration,
}

impl Default for RunLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
            poll_interval: Duration::from_millis(5),
        }
    }
}

#[derive(Debug)]
pub struct RunRequest<'a> {
    pub executable: &'a Path,
    pub args: &'a [OsString],
    pub cwd: &'a Path,
    pub environment: &'a [(OsString, OsString)],
    pub stdin: Option<&'a [u8]>,
}

#[derive(Debug)]
pub struct RunOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RunError {
    RelativeExecutable(PathBuf),
    Spawn(String),
    Timeout,
    OutputLimit { stream: &'static str },
    Wait(String),
    Termination(String),
    StdinWrite(String),
}

#[derive(Debug, Clone)]
pub struct SubprocessRunner {
    limits: RunLimits,
}

impl SubprocessRunner {
    pub fn new(limits: RunLimits) -> Self {
        Self { limits }
    }

    pub fn run(&self, request: RunRequest<'_>) -> Result<RunOutput, RunError> {
        if request.executable.is_relative() {
            return Err(RunError::RelativeExecutable(
                request.executable.to_path_buf(),
            ));
        }

        let mut command = Command::new(request.executable);
        command
            .args(request.args)
            .current_dir(request.cwd)
            .env_clear()
            .stdin(if request.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in request.environment {
            command.env(name, value);
        }
        configure_process_group(&mut command);

        let mut child = command
            .spawn()
            .map_err(|error| RunError::Spawn(error.to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| RunError::Spawn("stdout pipe unavailable".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| RunError::Spawn("stderr pipe unavailable".to_owned()))?;

        let stdin_thread = request.stdin.map(|input| {
            let mut stdin = child
                .stdin
                .take()
                .expect("piped stdin exists when input is configured");
            let input = input.to_vec();
            thread::spawn(move || stdin.write_all(&input))
        });

        let stdout_overflow = Arc::new(AtomicBool::new(false));
        let stderr_overflow = Arc::new(AtomicBool::new(false));
        let stdout_thread = read_capped(
            stdout,
            self.limits.max_stdout_bytes,
            Arc::clone(&stdout_overflow),
        );
        let stderr_thread = read_capped(
            stderr,
            self.limits.max_stderr_bytes,
            Arc::clone(&stderr_overflow),
        );

        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if stdout_overflow.load(Ordering::Acquire) {
                        let _ = terminate(&mut child);
                        join_readers(stdout_thread, stderr_thread);
                        let _ = join_stdin_writer(stdin_thread);
                        return Err(RunError::OutputLimit { stream: "stdout" });
                    }
                    if stderr_overflow.load(Ordering::Acquire) {
                        let _ = terminate(&mut child);
                        join_readers(stdout_thread, stderr_thread);
                        let _ = join_stdin_writer(stdin_thread);
                        return Err(RunError::OutputLimit { stream: "stderr" });
                    }
                    if started.elapsed() >= self.limits.timeout {
                        let _ = terminate(&mut child);
                        join_readers(stdout_thread, stderr_thread);
                        let _ = join_stdin_writer(stdin_thread);
                        return Err(RunError::Timeout);
                    }
                    thread::sleep(self.limits.poll_interval);
                }
                Err(error) => {
                    let _ = terminate(&mut child);
                    join_readers(stdout_thread, stderr_thread);
                    let _ = join_stdin_writer(stdin_thread);
                    return Err(RunError::Wait(error.to_string()));
                }
            }
        };

        // A command can exit while a descendant still owns one of the pipes.
        // Always tear down the isolated process group before joining readers.
        let termination_error = terminate(&mut child).err();
        let (stdout, stderr) = join_readers(stdout_thread, stderr_thread);
        let stdin_error = join_stdin_writer(stdin_thread);
        if let Some(error) = termination_error {
            return Err(error);
        }
        if stdout_overflow.load(Ordering::Acquire) {
            return Err(RunError::OutputLimit { stream: "stdout" });
        }
        if stderr_overflow.load(Ordering::Acquire) {
            return Err(RunError::OutputLimit { stream: "stderr" });
        }
        if status.success() {
            if let Some(error) = stdin_error {
                return Err(RunError::StdinWrite(error));
            }
        }
        Ok(RunOutput {
            status,
            stdout,
            stderr,
        })
    }
}

impl Default for SubprocessRunner {
    fn default() -> Self {
        Self::new(RunLimits::default())
    }
}

fn read_capped<R: Read + Send + 'static>(
    mut reader: R,
    limit: usize,
    overflow: Arc<AtomicBool>,
) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut output = Vec::with_capacity(limit.min(4096));
        let mut buffer = [0_u8; 4096];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    if output.len().saturating_add(count) > limit {
                        overflow.store(true, Ordering::Release);
                        break;
                    }
                    output.extend_from_slice(&buffer[..count]);
                }
                Err(_) => break,
            }
        }
        output
    })
}

fn join_stdin_writer(writer: Option<thread::JoinHandle<std::io::Result<()>>>) -> Option<String> {
    let writer = writer?;
    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    while !writer.is_finished() {
        if Instant::now() >= deadline {
            drop(writer);
            return Some("stdin writer cleanup exceeded its deadline".to_owned());
        }
        thread::sleep(Duration::from_millis(1));
    }
    match writer.join() {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error.to_string()),
        Err(_) => Some("stdin writer thread panicked".to_owned()),
    }
}

fn join_readers(
    stdout: thread::JoinHandle<Vec<u8>>,
    stderr: thread::JoinHandle<Vec<u8>>,
) -> (Vec<u8>, Vec<u8>) {
    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    (
        join_reader_until(stdout, deadline),
        join_reader_until(stderr, deadline),
    )
}

fn join_reader_until(reader: thread::JoinHandle<Vec<u8>>, deadline: Instant) -> Vec<u8> {
    while !reader.is_finished() {
        if Instant::now() >= deadline {
            // The process group cleanup normally closes the pipe. If an
            // unusual platform failure prevents that, do not block the
            // caller forever on a reader thread.
            drop(reader);
            return Vec::new();
        }
        thread::sleep(Duration::from_millis(1));
    }
    reader.join().unwrap_or_default()
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    // SAFETY: setpgid only changes the child process created by this Command;
    // no Rust memory or inherited application state is accessed by the hook.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

fn terminate(child: &mut Child) -> Result<(), RunError> {
    #[cfg(unix)]
    terminate_process_group(child)?;

    #[cfg(not(unix))]
    terminate_direct_child(child)?;

    Ok(())
}

#[cfg(unix)]
fn terminate_process_group(child: &mut Child) -> Result<(), RunError> {
    let pid = libc::pid_t::try_from(child.id())
        .map_err(|_| RunError::Termination("child PID is out of range".to_owned()))?;

    // The child placed itself in a new process group before exec. Killing the
    // negative PID therefore also closes pipes held by shell descendants.
    // SAFETY: pid identifies the process group created for this child.
    let result = unsafe { libc::kill(-pid, libc::SIGKILL) };
    if result == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(RunError::Termination(error.to_string()));
        }
    }
    wait_for_child(child)
}

#[cfg(not(unix))]
fn terminate_direct_child(child: &mut Child) -> Result<(), RunError> {
    match child.try_wait() {
        Ok(Some(_)) => Ok(()),
        Ok(None) => {
            child
                .kill()
                .map_err(|error| RunError::Termination(error.to_string()))?;
            wait_for_child(child)
        }
        Err(error) => Err(RunError::Wait(error.to_string())),
    }
}

fn wait_for_child(child: &mut Child) -> Result<(), RunError> {
    child
        .wait()
        .map(|_| ())
        .map_err(|error| RunError::Termination(error.to_string()))
}

pub fn argument(value: impl AsRef<OsStr>) -> OsString {
    value.as_ref().to_os_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn stdin_writer_join_is_bounded_when_the_writer_is_stuck() {
        let (release, wait) = mpsc::channel::<()>();
        let writer = thread::spawn(move || {
            let _ = wait.recv();
            Ok(())
        });
        let started = Instant::now();
        let result = join_stdin_writer(Some(writer));
        assert!(result.is_some());
        assert!(started.elapsed() < CLEANUP_TIMEOUT + Duration::from_millis(250));
        release.send(()).unwrap();
    }
}
