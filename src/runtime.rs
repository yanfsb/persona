use crate::config::Config;
use crate::git::GitClient;
use crate::storage::PersonaPaths;
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const EXIT_ERROR: u8 = 2;

static INVOKED_SHIM_DIRECTORY: OnceLock<PathBuf> = OnceLock::new();

pub fn record_invoked_shim_directory(argv0: &OsStr) {
    if std::env::var_os("PERSONA_SHIM_DIR").is_none() {
        if let Some(directory) = infer_shim_directory(argv0) {
            let _ = INVOKED_SHIM_DIRECTORY.set(directory);
        }
    }
}

pub fn persona_dispatcher_executable() -> Result<PathBuf, String> {
    let path = match std::env::var_os("PERSONA_INSTALL_EXECUTABLE") {
        Some(path) => PathBuf::from(path),
        None => {
            std::env::current_exe().map_err(|_| "cannot resolve Persona executable".to_owned())?
        }
    };
    if !path.is_absolute() || !path.is_file() {
        return Err("Persona dispatcher executable is not an absolute existing file".to_owned());
    }
    std::fs::canonicalize(path).map_err(|_| "cannot canonicalize Persona dispatcher".to_owned())
}

fn infer_shim_directory(argv0: &OsStr) -> Option<PathBuf> {
    let current = persona_dispatcher_executable().ok()?;
    let invoked = PathBuf::from(argv0);
    let candidates = if invoked.components().count() > 1 || invoked.is_absolute() {
        vec![invoked]
    } else {
        std::env::split_paths(&std::env::var_os("PATH")?)
            .map(|directory| directory.join(&invoked))
            .collect()
    };
    candidates.into_iter().find_map(|candidate| {
        (std::fs::canonicalize(&candidate).ok()? == current)
            .then(|| std::fs::canonicalize(candidate.parent()?).ok())
            .flatten()
    })
}

pub fn validate_managed_shim_directory() -> Result<PathBuf, String> {
    let path = std::env::var_os("PERSONA_SHIM_DIR")
        .map(PathBuf::from)
        .or_else(|| INVOKED_SHIM_DIRECTORY.get().cloned())
        .filter(|path| path.is_absolute())
        .ok_or_else(|| "managed Persona shim directory is unavailable".to_owned())?;
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|_| "managed Persona shim directory is missing".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("managed Persona shim directory is not a real directory".to_owned());
    }
    #[cfg(unix)]
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
        return Err(
            "managed Persona shim directory has unsafe ownership or permissions".to_owned(),
        );
    }
    let directory = std::fs::canonicalize(&path)
        .map_err(|_| "managed Persona shim directory cannot be canonicalized".to_owned())?;
    let executable = persona_dispatcher_executable()?;
    for name in ["git", "gh", "ssh", "git-credential-persona"] {
        let shim = directory.join(name);
        let metadata = std::fs::symlink_metadata(&shim)
            .map_err(|_| format!("managed Persona shim is missing: {name}"))?;
        if !metadata.file_type().is_symlink()
            || std::fs::canonicalize(&shim).ok().as_ref() != Some(&executable)
        {
            return Err(format!("managed Persona shim target is unexpected: {name}"));
        }
    }
    Ok(directory)
}

pub fn build_managed_path(shim_directory: &Path) -> Result<OsString, String> {
    let mut entries = vec![shim_directory.to_path_buf()];
    if let Some(path) = std::env::var_os("PATH") {
        for entry in std::env::split_paths(&path) {
            if entry != shim_directory {
                entries.push(entry);
            }
        }
    } else {
        entries.push(PathBuf::from("/usr/bin"));
        entries.push(PathBuf::from("/bin"));
    }
    std::env::join_paths(entries).map_err(|error| format!("cannot construct managed PATH: {error}"))
}

pub fn isolated_git_environment(isolated_home: &Path) -> Vec<(OsString, OsString)> {
    vec![
        (OsString::from("HOME"), isolated_home.as_os_str().to_owned()),
        (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
        (
            OsString::from("GIT_CONFIG_SYSTEM"),
            OsString::from("/dev/null"),
        ),
        (
            OsString::from("GIT_CONFIG_GLOBAL"),
            OsString::from("/dev/null"),
        ),
        (OsString::from("GIT_TERMINAL_PROMPT"), OsString::from("0")),
    ]
}

pub fn hook_git_client() -> Result<(tempfile::TempDir, GitClient), String> {
    let executable = git_executable();
    if !executable.is_absolute() || !executable.is_file() {
        return Err("native Git executable is unavailable".to_owned());
    }
    let home = tempfile::tempdir().map_err(|_| "cannot create isolated Git HOME".to_owned())?;
    let environment = isolated_git_environment(home.path());
    Ok((home, GitClient::new(executable, environment)))
}

pub fn resolve_config_path(explicit: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if let Some(path) = std::env::var_os("PERSONA_CONFIG_PATH") {
        let path = PathBuf::from(path);
        if path.as_os_str().is_empty() {
            return Err("PERSONA_CONFIG_PATH cannot be empty".to_owned());
        }
        return Ok(path);
    }
    let paths = PersonaPaths::discover()
        .map_err(|error| format!("cannot resolve Persona paths: {error}"))?;
    paths
        .validate_private_config()
        .map_err(|error| format!("unsafe private configuration: {error}"))?;
    if !paths.config_file.is_file() {
        return Err(format!(
            "no Persona configuration at {}; run `persona setup` or pass --config",
            paths.config_file.display()
        ));
    }
    Ok(paths.config_file)
}

pub fn load_config(explicit: Option<&Path>) -> Result<Config, String> {
    let path = resolve_config_path(explicit)?;
    Config::load(&path).map_err(|error| error.to_string())
}

pub fn physical_scope_root(path: &Path) -> Result<PathBuf, String> {
    let canonical =
        std::fs::canonicalize(path).map_err(|_| "scope directory must exist".to_owned())?;
    if !canonical.is_dir() {
        return Err("scope path must be a directory".to_owned());
    }
    let git = GitClient::new(git_executable(), crate::git::safe_environment());
    Ok(git.checkout_root(&canonical).unwrap_or(canonical))
}

pub fn absolute_path(path: &Path, base: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

pub fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes =
        std::fs::read(path).map_err(|_| "cannot read policy for push handoff".to_owned())?;
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    Ok(output)
}

pub fn status_exit_code(status: std::process::ExitStatus) -> u8 {
    if let Some(code) = status.code() {
        code.clamp(0, u8::MAX as i32) as u8
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            status.signal().map_or(EXIT_ERROR, |signal| {
                (128 + signal).min(u8::MAX as i32) as u8
            })
        }
        #[cfg(not(unix))]
        {
            EXIT_ERROR
        }
    }
}

pub fn wait_child_ignoring_sigint(
    command: &mut std::process::Command,
) -> std::io::Result<std::process::ExitStatus> {
    let mut child = command.spawn()?;
    #[cfg(unix)]
    let previous_sigint = unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) };
    #[cfg(unix)]
    let previous_sigquit = unsafe { libc::signal(libc::SIGQUIT, libc::SIG_IGN) };
    let result = child.wait();
    #[cfg(unix)]
    unsafe {
        if previous_sigint != libc::SIG_ERR {
            libc::signal(libc::SIGINT, previous_sigint);
        }
        if previous_sigquit != libc::SIG_ERR {
            libc::signal(libc::SIGQUIT, previous_sigquit);
        }
    }
    result
}

pub fn git_executable() -> PathBuf {
    if let Some(path) = std::env::var_os("PERSONA_GIT") {
        return PathBuf::from(path);
    }
    find_executable("git").unwrap_or_else(|| PathBuf::from("/usr/bin/git"))
}

pub fn gh_executable() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PERSONA_GH") {
        let path = PathBuf::from(path);
        return path
            .is_absolute()
            .then_some(path)
            .filter(|path| path.is_file());
    }
    find_executable("gh")
}

pub fn ssh_executable() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PERSONA_SSH") {
        let path = PathBuf::from(path);
        return path
            .is_absolute()
            .then_some(path)
            .filter(|path| path.is_file());
    }
    find_executable("ssh")
}

pub fn ssh_keygen_executable() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PERSONA_SSH_KEYGEN") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    find_executable("ssh-keygen")
}

pub fn gpg_executable() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PERSONA_GPG") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    find_executable("gpg")
}

fn find_executable(name: &str) -> Option<PathBuf> {
    let current = std::env::current_exe()
        .ok()
        .and_then(|path| std::fs::canonicalize(path).ok());
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join(name))
        .find(|path| {
            path.is_file()
                && std::fs::canonicalize(path)
                    .ok()
                    .is_some_and(|canonical| Some(canonical) != current)
        })
}
