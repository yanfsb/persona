use std::env;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tempfile::{Builder, NamedTempFile};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonaPaths {
    pub config_file: PathBuf,
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
}

/// Advisory process lock for a complete private-config read/modify/write.
pub struct ConfigUpdateLock {
    _file: File,
}

#[derive(Debug)]
pub enum StorageError {
    MissingHome,
    RelativeXdgPath(PathBuf),
    UnsafeDirectory(PathBuf),
    UnsafeFile(PathBuf),
    OutsideBackupDirectory(PathBuf),
    Io { path: PathBuf, source: io::Error },
}

impl PersonaPaths {
    pub fn discover() -> Result<Self, StorageError> {
        let home = env::var_os("HOME").map(PathBuf::from);
        let config_home = env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
        let state_home = env::var_os("XDG_STATE_HOME").map(PathBuf::from);
        Self::from_environment(
            home.as_deref(),
            config_home.as_deref(),
            state_home.as_deref(),
        )
    }

    pub fn from_environment(
        home: Option<&Path>,
        config_home: Option<&Path>,
        state_home: Option<&Path>,
    ) -> Result<Self, StorageError> {
        let home = home.ok_or(StorageError::MissingHome)?;
        if !home.is_absolute() {
            return Err(StorageError::RelativeXdgPath(home.to_path_buf()));
        }
        let config_home = absolute_or_default(config_home, home.join(".config"))?;
        let state_home = absolute_or_default(state_home, home.join(".local/state"))?;
        let config_dir = config_home.join("persona");
        let state_dir = state_home.join("persona");
        Ok(Self {
            config_file: config_dir.join("config.toml"),
            config_dir,
            state_dir,
        })
    }

    pub fn ensure_private_directories(&self) -> Result<(), StorageError> {
        ensure_private_dir(&self.config_dir)?;
        ensure_private_dir(&self.state_dir)?;
        ensure_private_dir(&self.backup_dir())
    }

    pub fn validate_private_state(&self) -> Result<(), StorageError> {
        let metadata = fs::symlink_metadata(&self.state_dir)
            .map_err(|source| io_error(&self.state_dir, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(StorageError::UnsafeDirectory(self.state_dir.clone()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                return Err(StorageError::UnsafeDirectory(self.state_dir.clone()));
            }
        }
        Ok(())
    }

    /// Serialize config mutations across Persona processes. Keep the returned
    /// guard alive from before loading the config until after writing it.
    pub fn lock_config_update(&self) -> Result<ConfigUpdateLock, StorageError> {
        self.ensure_private_directories()?;
        self.validate_private_state()?;
        let path = self.state_dir.join("config-update.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options
            .open(&path)
            .map_err(|source| io_error(&path, source))?;
        let metadata = file.metadata().map_err(|source| io_error(&path, source))?;
        if !metadata.is_file() {
            return Err(StorageError::UnsafeFile(path));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
                || metadata.nlink() != 1
            {
                return Err(StorageError::UnsafeFile(path));
            }
            use std::os::fd::AsRawFd;
            #[cfg(feature = "test-support")]
            let mut acquired =
                if let Some(marker) = env::var_os("PERSONA_TEST_CONFIG_LOCK_CONTENDED") {
                    // Test-only signal: emit it only after the kernel confirms that
                    // another process currently owns the exclusive lock.
                    // SAFETY: `file` remains open for the lifetime of the guard.
                    let result =
                        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
                    if result == 0 {
                        true
                    } else {
                        let error = io::Error::last_os_error();
                        if error.kind() != io::ErrorKind::WouldBlock {
                            return Err(io_error(&path, error));
                        }
                        let marker = PathBuf::from(marker);
                        OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&marker)
                            .map_err(|source| io_error(&marker, source))?;
                        false
                    }
                } else {
                    false
                };
            #[cfg(not(feature = "test-support"))]
            let mut acquired = false;
            while !acquired {
                // SAFETY: `file` remains open for the lifetime of the returned guard.
                let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
                if result == 0 {
                    acquired = true;
                    continue;
                }
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(io_error(&path, error));
                }
            }
        }
        #[cfg(not(unix))]
        return Err(io_error(
            &path,
            io::Error::new(io::ErrorKind::Unsupported, "config locking requires Unix"),
        ));
        Ok(ConfigUpdateLock { _file: file })
    }

    pub fn validate_private_config(&self) -> Result<(), StorageError> {
        let directory = match fs::symlink_metadata(&self.config_dir) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(source) => return Err(io_error(&self.config_dir, source)),
        };
        if directory.file_type().is_symlink() || !directory.is_dir() {
            return Err(StorageError::UnsafeDirectory(self.config_dir.clone()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if directory.uid() != unsafe { libc::geteuid() } || directory.mode() & 0o077 != 0 {
                return Err(StorageError::UnsafeDirectory(self.config_dir.clone()));
            }
        }
        let metadata = match fs::symlink_metadata(&self.config_file) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(source) => return Err(io_error(&self.config_file, source)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(StorageError::UnsafeFile(self.config_file.clone()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
                || metadata.nlink() != 1
            {
                return Err(StorageError::UnsafeFile(self.config_file.clone()));
            }
        }
        Ok(())
    }

    /// Create the initial configuration without replacing a concurrent or
    /// pre-existing file.
    pub fn create_config(&self, contents: &[u8]) -> Result<(), StorageError> {
        self.ensure_private_directories()?;
        self.validate_private_config()?;
        match fs::symlink_metadata(&self.config_file) {
            Ok(_) => return Err(StorageError::UnsafeFile(self.config_file.clone())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error(&self.config_file, source)),
        }
        let mut temporary = NamedTempFile::new_in(&self.config_dir)
            .map_err(|source| io_error(&self.config_dir, source))?;
        set_private_file(temporary.as_file())?;
        temporary
            .write_all(contents)
            .map_err(|source| io_error(temporary.path(), source))?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|source| io_error(temporary.path(), source))?;
        temporary
            .persist_noclobber(&self.config_file)
            .map_err(|error| io_error(&self.config_file, error.error))?;
        File::open(&self.config_dir)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_error(&self.config_dir, source))?;
        Ok(())
    }

    /// Atomically replace the private configuration. If one existed, preserve
    /// its bytes in the private state backup directory and return that path.
    pub fn write_config(&self, contents: &[u8]) -> Result<Option<PathBuf>, StorageError> {
        self.ensure_private_directories()?;
        self.validate_private_config()?;
        let backup = if self.config_file.exists() {
            Some(self.backup_current_config()?)
        } else {
            None
        };
        atomic_write(&self.config_file, contents)?;
        Ok(backup)
    }

    /// Restore only a backup created under this Persona state directory.
    /// The current configuration is itself backed up before replacement.
    pub fn rollback(&self, backup: &Path) -> Result<Option<PathBuf>, StorageError> {
        self.ensure_private_directories()?;
        let backup_root = fs::canonicalize(self.backup_dir())
            .map_err(|source| io_error(self.backup_dir(), source))?;
        let backup_path = fs::canonicalize(backup).map_err(|source| io_error(backup, source))?;
        if backup_path.parent() != Some(backup_root.as_path()) {
            return Err(StorageError::OutsideBackupDirectory(backup.to_path_buf()));
        }
        let metadata =
            fs::symlink_metadata(&backup_path).map_err(|source| io_error(&backup_path, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(StorageError::UnsafeFile(backup_path));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
                || metadata.nlink() != 1
            {
                return Err(StorageError::UnsafeFile(backup_path));
            }
        }
        let contents = fs::read(&backup_path).map_err(|source| io_error(&backup_path, source))?;
        self.write_config(&contents)
    }

    pub fn backup_dir(&self) -> PathBuf {
        self.state_dir.join("backups")
    }

    fn backup_current_config(&self) -> Result<PathBuf, StorageError> {
        let contents =
            fs::read(&self.config_file).map_err(|source| io_error(&self.config_file, source))?;
        let mut backup = Builder::new()
            .prefix("persona-config-")
            .suffix(".toml")
            .tempfile_in(self.backup_dir())
            .map_err(|source| io_error(self.backup_dir(), source))?;
        set_private_file(backup.as_file())?;
        backup
            .write_all(&contents)
            .map_err(|source| io_error(backup.path(), source))?;
        backup
            .as_file()
            .sync_all()
            .map_err(|source| io_error(backup.path(), source))?;
        let (_, path) = backup
            .keep()
            .map_err(|error| io_error(error.file.path(), error.error))?;
        Ok(path)
    }
}

fn absolute_or_default(path: Option<&Path>, default: PathBuf) -> Result<PathBuf, StorageError> {
    let path = path.unwrap_or(&default);
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Err(StorageError::RelativeXdgPath(path.to_path_buf()))
    }
}

fn ensure_private_dir(path: &Path) -> Result<(), StorageError> {
    fs::create_dir_all(path).map_err(|source| io_error(path, source))?;
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StorageError::UnsafeDirectory(path.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(StorageError::UnsafeDirectory(path.to_path_buf()));
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|source| io_error(path, source))?;
    }
    Ok(())
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), StorageError> {
    let parent = path
        .parent()
        .ok_or_else(|| StorageError::UnsafeFile(path.to_path_buf()))?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(StorageError::UnsafeFile(path.to_path_buf()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(io_error(path, source)),
    }
    let mut temporary = NamedTempFile::new_in(parent).map_err(|source| io_error(parent, source))?;
    set_private_file(temporary.as_file())?;
    temporary
        .write_all(contents)
        .map_err(|source| io_error(temporary.path(), source))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| io_error(temporary.path(), source))?;
    temporary
        .persist(path)
        .map_err(|error| io_error(path, error.error))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(parent, source))?;
    Ok(())
}

fn set_private_file(file: &File) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| io_error(Path::new("<open file>"), source))?;
    }
    Ok(())
}

fn io_error(path: impl AsRef<OsStr>, source: io::Error) -> StorageError {
    StorageError::Io {
        path: PathBuf::from(path.as_ref()),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::{PersonaPaths, StorageError};
    use std::fs::{self, File};
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn resolves_xdg_paths_and_home_fallback() {
        let home = Path::new("/home/example");
        let paths = PersonaPaths::from_environment(
            Some(home),
            Some(Path::new("/config")),
            Some(Path::new("/state")),
        )
        .expect("absolute XDG paths");
        assert_eq!(paths.config_file, Path::new("/config/persona/config.toml"));
        assert_eq!(paths.state_dir, Path::new("/state/persona"));

        let fallback = PersonaPaths::from_environment(Some(home), None, None).unwrap();
        assert_eq!(
            fallback.config_file,
            Path::new("/home/example/.config/persona/config.toml")
        );
        assert_eq!(
            fallback.state_dir,
            Path::new("/home/example/.local/state/persona")
        );
    }

    #[test]
    fn rejects_relative_xdg_roots() {
        assert!(matches!(
            PersonaPaths::from_environment(None, None, None),
            Err(StorageError::MissingHome)
        ));
        assert!(matches!(
            PersonaPaths::from_environment(
                Some(Path::new("/home/example")),
                Some(Path::new("relative")),
                None,
            ),
            Err(StorageError::RelativeXdgPath(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn config_update_lock_excludes_other_open_file_descriptions() {
        use std::os::fd::AsRawFd;
        let temporary = tempdir().unwrap();
        let paths = PersonaPaths::from_environment(Some(temporary.path()), None, None).unwrap();
        let first = paths.lock_config_update().unwrap();
        let lock_path = paths.state_dir.join("config-update.lock");
        let second = File::open(lock_path).unwrap();
        // SAFETY: both descriptors remain open during the nonblocking lock attempt.
        assert_ne!(
            unsafe { libc::flock(second.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        drop(first);
        // SAFETY: `second` remains open and the first advisory lock was released.
        assert_eq!(
            unsafe { libc::flock(second.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn serialized_config_updates_read_the_latest_contents() {
        use std::sync::mpsc;
        use std::thread;

        let temporary = tempdir().unwrap();
        let paths = PersonaPaths::from_environment(Some(temporary.path()), None, None).unwrap();
        paths.write_config(b"base").unwrap();
        let first_lock = paths.lock_config_update().unwrap();
        let first_snapshot = fs::read(&paths.config_file).unwrap();

        let (started_tx, started_rx) = mpsc::channel();
        let second_paths = paths.clone();
        let second = thread::spawn(move || {
            started_tx.send(()).unwrap();
            let _lock = second_paths.lock_config_update().unwrap();
            let mut contents = fs::read(&second_paths.config_file).unwrap();
            contents.extend_from_slice(b"-second");
            second_paths.write_config(&contents).unwrap();
        });
        started_rx.recv().unwrap();

        let mut first_contents = first_snapshot;
        first_contents.extend_from_slice(b"-first");
        paths.write_config(&first_contents).unwrap();
        drop(first_lock);
        second.join().unwrap();

        assert_eq!(fs::read(&paths.config_file).unwrap(), b"base-first-second");
    }

    #[cfg(unix)]
    #[test]
    fn writes_owner_only_config_and_rolls_back_from_private_backup() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempdir().unwrap();
        let paths = PersonaPaths::from_environment(Some(temporary.path()), None, None).unwrap();
        assert_eq!(paths.write_config(b"first").unwrap(), None);
        let backup = paths.write_config(b"second").unwrap().unwrap();
        assert_eq!(fs::read(&paths.config_file).unwrap(), b"second");
        assert_eq!(
            fs::metadata(&paths.config_file)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&paths.config_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        paths.rollback(&backup).unwrap();
        assert_eq!(fs::read(&paths.config_file).unwrap(), b"first");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlinked_private_state_directory() {
        use std::os::unix::fs::symlink;
        let temporary = tempdir().unwrap();
        let paths = PersonaPaths::from_environment(Some(temporary.path()), None, None).unwrap();
        fs::create_dir_all(paths.state_dir.parent().unwrap()).unwrap();
        let outside = temporary.path().join("outside-state");
        fs::create_dir(&outside).unwrap();
        symlink(outside, &paths.state_dir).unwrap();
        assert!(matches!(
            paths.validate_private_state(),
            Err(StorageError::UnsafeDirectory(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_replace_a_symlinked_config() {
        use std::os::unix::fs::symlink;
        let temporary = tempdir().unwrap();
        let paths = PersonaPaths::from_environment(Some(temporary.path()), None, None).unwrap();
        paths.ensure_private_directories().unwrap();
        let target = temporary.path().join("target");
        fs::write(&target, b"untouched").unwrap();
        symlink(&target, &paths.config_file).unwrap();
        assert!(matches!(
            paths.write_config(b"replacement"),
            Err(StorageError::UnsafeFile(_))
        ));
        assert_eq!(fs::read(target).unwrap(), b"untouched");
    }
}
