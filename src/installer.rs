use crate as persona;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tempfile::NamedTempFile;

const VERSION: u32 = 1;
const SHIMS: [&str; 4] = ["git", "gh", "ssh", "git-credential-persona"];

/// Read-only installation state for diagnostics; never reads credential material.
pub fn coverage_state() -> &'static str {
    let Ok(paths) = paths() else {
        return "unknown";
    };
    match read_manifest(&manifest_path(&paths.state_dir)) {
        Ok(None) => "absent",
        Ok(Some(manifest)) if verify_manifest_links(&manifest).is_ok() => {
            let on_path = std::env::var_os("PATH").is_some_and(|path| {
                std::env::split_paths(&path).any(|entry| {
                    fs::canonicalize(entry).is_ok_and(|entry| entry == manifest.bin_directory)
                })
            });
            if !on_path {
                return "installed-not-on-path";
            }
            if shims_resolve_first(&manifest.bin_directory) {
                "active"
            } else {
                "shadowed"
            }
        }
        Ok(Some(_)) => "incomplete",
        Err(_) => "unknown",
    }
}

fn shims_resolve_first(bin_directory: &Path) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    shims_resolve_first_in(bin_directory, &path)
}

fn shims_resolve_first_in(bin_directory: &Path, path: &std::ffi::OsStr) -> bool {
    let entries = std::env::split_paths(path).collect::<Vec<_>>();
    SHIMS.iter().all(|name| {
        let expected = bin_directory.join(name);
        let Some(first) = entries
            .iter()
            .map(|directory| directory.join(name))
            .find(|candidate| is_executable_file(candidate))
        else {
            return false;
        };
        fs::canonicalize(first).ok() == fs::canonicalize(expected).ok()
    })
}

fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| {
        metadata.is_file() && {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o111 != 0
        }
    })
}

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Manifest {
    version: u32,
    bin_directory: PathBuf,
    executable: PathBuf,
    links: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Backup {
    version: u32,
    previous: Option<Manifest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Transaction {
    version: u32,
    before: Option<Manifest>,
    desired: Option<Manifest>,
}

fn paths() -> Result<persona::storage::PersonaPaths, String> {
    persona::storage::PersonaPaths::discover()
        .map_err(|error| format!("cannot resolve private installation state: {error:?}"))
}

fn manifest_path(state: &Path) -> PathBuf {
    state.join("install.toml")
}

fn transaction_path(state: &Path) -> PathBuf {
    state.join("install.transaction")
}

pub fn preview_install(bin: &Path, executable: &Path) -> Result<String, String> {
    let paths = paths()?;
    ensure_no_transaction(&paths.state_dir)?;
    let desired = new_manifest(bin, executable)?;
    match read_manifest(&manifest_path(&paths.state_dir))? {
        Some(current) => {
            verify_manifest_links(&current)?;
            if current.bin_directory != desired.bin_directory {
                return Err(
                    "an installation already owns another shim directory; remove it first".into(),
                );
            }
            Ok(format!(
                "refresh {} owned shims in {}",
                SHIMS.len(),
                desired.bin_directory.display()
            ))
        }
        None => {
            verify_paths_absent(&desired)?;
            Ok(format!(
                "install {} owned shims in {}",
                SHIMS.len(),
                desired.bin_directory.display()
            ))
        }
    }
}

pub fn apply_install(bin: &Path, executable: &Path) -> Result<Option<PathBuf>, String> {
    let paths = paths()?;
    ensure_state(&paths)?;
    let _lock = Lock::acquire(&paths.state_dir)?;
    recover(&paths.state_dir)?;
    let manifest_file = manifest_path(&paths.state_dir);
    let before = read_manifest(&manifest_file)?;
    let desired = new_manifest(bin, executable)?;
    match &before {
        Some(old) if old.bin_directory != desired.bin_directory => {
            return Err(
                "an installation already owns another shim directory; remove it first".into(),
            );
        }
        Some(old) => verify_manifest_links(old)?,
        None => verify_paths_absent(&desired)?,
    }
    if before.as_ref() == Some(&desired) {
        return Ok(None);
    }
    let backup = write_backup(&paths.state_dir, before.clone())?;
    finish_transition(&paths.state_dir, before.as_ref(), Some(&desired)).map_err(|error| {
        format!(
            "installation failed; recovery point {}: {error}",
            backup.display()
        )
    })?;
    Ok(Some(backup))
}

pub fn preview_refresh() -> Result<String, String> {
    let paths = paths()?;
    ensure_no_transaction(&paths.state_dir)?;
    let old = read_manifest(&manifest_path(&paths.state_dir))?
        .ok_or_else(|| "Persona has no recorded shim installation".to_owned())?;
    verify_manifest_links(&old)?;
    let executable = current_executable()?;
    Ok(format!(
        "refresh {} owned shims in {} to {}",
        SHIMS.len(),
        old.bin_directory.display(),
        executable.display()
    ))
}

pub fn refresh() -> Result<Option<PathBuf>, String> {
    let paths = paths()?;
    ensure_state(&paths)?;
    let _lock = Lock::acquire(&paths.state_dir)?;
    recover(&paths.state_dir)?;
    let file = manifest_path(&paths.state_dir);
    let before = read_manifest(&file)?
        .ok_or_else(|| "Persona has no recorded shim installation".to_owned())?;
    verify_manifest_links(&before)?;
    let mut desired = before.clone();
    desired.executable = current_executable()?;
    if desired == before {
        return Ok(None);
    }
    let backup = write_backup(&paths.state_dir, Some(before.clone()))?;
    finish_transition(&paths.state_dir, Some(&before), Some(&desired)).map_err(|error| {
        format!(
            "refresh failed; recovery point {}: {error}",
            backup.display()
        )
    })?;
    Ok(Some(backup))
}

pub fn preview_remove() -> Result<String, String> {
    let paths = paths()?;
    ensure_no_transaction(&paths.state_dir)?;
    let Some(manifest) = read_manifest(&manifest_path(&paths.state_dir))? else {
        return Ok("no Persona shim installation is recorded".into());
    };
    verify_manifest_links(&manifest)?;
    Ok(format!(
        "remove {} owned shims from {}",
        SHIMS.len(),
        manifest.bin_directory.display()
    ))
}

pub fn remove() -> Result<Option<PathBuf>, String> {
    let paths = paths()?;
    ensure_state(&paths)?;
    let _lock = Lock::acquire(&paths.state_dir)?;
    recover(&paths.state_dir)?;
    let file = manifest_path(&paths.state_dir);
    let Some(before) = read_manifest(&file)? else {
        return Ok(None);
    };
    verify_manifest_links(&before)?;
    let backup = write_backup(&paths.state_dir, Some(before.clone()))?;
    finish_transition(&paths.state_dir, Some(&before), None).map_err(|error| {
        format!(
            "removal failed; recovery point {}: {error}",
            backup.display()
        )
    })?;
    Ok(Some(backup))
}

pub fn preview_rollback(backup_path: &Path) -> Result<String, String> {
    let paths = paths()?;
    ensure_no_transaction(&paths.state_dir)?;
    let backup = read_backup(&paths.state_dir, backup_path)?;
    let current = read_manifest(&manifest_path(&paths.state_dir))?;
    validate_transition(current.as_ref(), backup.previous.as_ref())?;
    match backup.previous {
        Some(manifest) => Ok(format!(
            "restore {} owned shims in {}",
            manifest.links.len(),
            manifest.bin_directory.display()
        )),
        None => Ok("remove the current Persona shim installation".into()),
    }
}

pub fn rollback(backup_path: &Path) -> Result<PathBuf, String> {
    let paths = paths()?;
    ensure_state(&paths)?;
    let _lock = Lock::acquire(&paths.state_dir)?;
    recover(&paths.state_dir)?;
    let backup = read_backup(&paths.state_dir, backup_path)?;
    let file = manifest_path(&paths.state_dir);
    let current = read_manifest(&file)?;
    validate_transition(current.as_ref(), backup.previous.as_ref())?;
    let safety = write_backup(&paths.state_dir, current.clone())?;
    finish_transition(&paths.state_dir, current.as_ref(), backup.previous.as_ref()).map_err(
        |error| {
            format!(
                "rollback failed; recovery point {}: {error}",
                safety.display()
            )
        },
    )?;
    Ok(safety)
}

fn new_manifest(bin: &Path, executable: &Path) -> Result<Manifest, String> {
    Ok(Manifest {
        version: VERSION,
        bin_directory: validate_bin_directory(bin)?,
        executable: validate_executable(executable)?,
        links: SHIMS.iter().map(|name| (*name).to_owned()).collect(),
    })
}

fn finish_transition(
    state: &Path,
    before: Option<&Manifest>,
    desired: Option<&Manifest>,
) -> Result<(), String> {
    validate_transition(before, desired)?;
    let transaction = Transaction {
        version: VERSION,
        before: before.cloned(),
        desired: desired.cloned(),
    };
    write_transaction(state, &transaction)?;
    transition(before, desired, &manifest_path(state))?;
    remove_file_sync(&transaction_path(state))
}

fn transition(
    before: Option<&Manifest>,
    desired: Option<&Manifest>,
    file: &Path,
) -> Result<(), String> {
    let paths = transition_paths(before, desired);
    let mut changed: Vec<(PathBuf, Option<PathBuf>)> = Vec::new();
    for path in paths {
        let old = target_for(before, &path);
        let new = target_for(desired, &path);
        if old == new {
            continue;
        }
        if !path_has_target(&path, old.as_deref()) {
            let rollback = restore_links(&changed);
            return Err(rollback.err().map_or_else(
                || format!("install path changed during operation: {}", path.display()),
                |failure| {
                    format!(
                        "install path changed during operation: {}; restore incomplete: {failure}",
                        path.display()
                    )
                },
            ));
        }
        let result = set_link(&path, new.as_deref());
        if let Err(error) = result {
            if path_has_target(&path, new.as_deref()) {
                changed.push((path.clone(), old));
            }
            let restore = restore_links(&changed);
            return Err(restore.err().map_or(error.clone(), |failure| {
                format!("{error}; restore incomplete: {failure}")
            }));
        }
        changed.push((path, old));
    }
    let write = match desired {
        Some(manifest) => write_manifest(file, manifest),
        None => remove_file_sync(file),
    };
    if let Err(error) = write {
        let links = restore_links(&changed);
        let state = match before {
            Some(manifest) => write_manifest(file, manifest),
            None => remove_file_sync(file),
        };
        if let Err(failure) = links {
            return Err(format!("{error}; shim restore incomplete: {failure}"));
        }
        if let Err(failure) = state {
            return Err(format!("{error}; manifest restore incomplete: {failure}"));
        }
        return Err(error);
    }
    Ok(())
}

fn validate_transition(
    before: Option<&Manifest>,
    desired: Option<&Manifest>,
) -> Result<(), String> {
    if let Some(manifest) = before {
        validate_manifest(manifest)?;
        verify_manifest_links(manifest)?;
    }
    if let Some(manifest) = desired {
        validate_manifest(manifest)?;
        for path in transition_paths(before, desired) {
            if target_for(before, &path).is_none()
                && target_for(desired, &path).is_some()
                && fs::symlink_metadata(&path).is_ok()
            {
                return Err(format!(
                    "refusing to overwrite unowned install path {}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

fn recover(state: &Path) -> Result<(), String> {
    let Some(transaction) = read_transaction(state)? else {
        return Ok(());
    };
    let file = manifest_path(state);
    let current = read_manifest(&file)?;
    if current == transaction.desired {
        validate_paths_match(transaction.desired.as_ref(), transaction.before.as_ref())?;
        return remove_file_sync(&transaction_path(state));
    }
    if current != transaction.before {
        return Err("interrupted installation state matches neither transaction side".into());
    }
    let paths = transition_paths(transaction.before.as_ref(), transaction.desired.as_ref());
    for path in &paths {
        let old = target_for(transaction.before.as_ref(), path);
        let new = target_for(transaction.desired.as_ref(), path);
        if !path_has_target(path, old.as_deref()) && !path_has_target(path, new.as_deref()) {
            return Err(format!(
                "interrupted install path was externally changed: {}",
                path.display()
            ));
        }
    }
    for path in paths {
        let old = target_for(transaction.before.as_ref(), &path);
        let new = target_for(transaction.desired.as_ref(), &path);
        if old != new && !path_has_target(&path, old.as_deref()) {
            set_link(&path, old.as_deref())?;
        }
    }
    match transaction.before.as_ref() {
        Some(manifest) => write_manifest(&file, manifest)?,
        None => remove_file_sync(&file)?,
    }
    remove_file_sync(&transaction_path(state))
}

fn ensure_no_transaction(state: &Path) -> Result<(), String> {
    if read_transaction(state)?.is_some() {
        Err("an interrupted installation transaction requires an explicit apply/refresh/remove/rollback action to recover".into())
    } else {
        Ok(())
    }
}

fn validate_paths_match(first: Option<&Manifest>, second: Option<&Manifest>) -> Result<(), String> {
    for path in transition_paths(first, second) {
        if !path_has_target(&path, target_for(first, &path).as_deref()) {
            return Err(format!(
                "committed install transaction has an unexpected path: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn write_transaction(state: &Path, transaction: &Transaction) -> Result<(), String> {
    if transaction.version != VERSION {
        return Err("install transaction version is unsupported".into());
    }
    if let Some(manifest) = &transaction.before {
        validate_manifest(manifest)?;
    }
    if let Some(manifest) = &transaction.desired {
        validate_manifest(manifest)?;
    }
    let bytes =
        toml::to_string(transaction).map_err(|_| "cannot encode install transaction".to_owned())?;
    atomic_write(&transaction_path(state), bytes.as_bytes())
}

fn read_transaction(state: &Path) -> Result<Option<Transaction>, String> {
    let Some(contents) = read_private_file(&transaction_path(state))? else {
        return Ok(None);
    };
    let transaction: Transaction =
        toml::from_str(&contents).map_err(|_| "install transaction is malformed".to_owned())?;
    if transaction.version != VERSION {
        return Err("install transaction version is unsupported".into());
    }
    if let Some(manifest) = &transaction.before {
        validate_manifest(manifest)?;
    }
    if let Some(manifest) = &transaction.desired {
        validate_manifest(manifest)?;
    }
    Ok(Some(transaction))
}

fn transition_paths(before: Option<&Manifest>, desired: Option<&Manifest>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for manifest in [before, desired].into_iter().flatten() {
        paths.extend(
            manifest
                .links
                .iter()
                .map(|name| manifest.bin_directory.join(name)),
        );
    }
    paths.sort();
    paths.dedup();
    paths
}

fn target_for(manifest: Option<&Manifest>, path: &Path) -> Option<PathBuf> {
    manifest.and_then(|manifest| {
        manifest
            .links
            .iter()
            .any(|name| manifest.bin_directory.join(name) == path)
            .then(|| manifest.executable.clone())
    })
}

fn path_has_target(path: &Path, expected: Option<&Path>) -> bool {
    match (expected, fs::symlink_metadata(path)) {
        (Some(expected), Ok(metadata)) if metadata.file_type().is_symlink() => {
            fs::read_link(path).is_ok_and(|actual| actual == expected)
        }
        (None, Err(error)) if error.kind() == io::ErrorKind::NotFound => true,
        _ => false,
    }
}

fn verify_manifest_links(manifest: &Manifest) -> Result<(), String> {
    validate_manifest(manifest)?;
    for name in &manifest.links {
        let path = manifest.bin_directory.join(name);
        let metadata = fs::symlink_metadata(&path).map_err(|error| io_error(&path, error))?;
        if !metadata.file_type().is_symlink()
            || fs::read_link(&path).map_err(|error| io_error(&path, error))? != manifest.executable
        {
            return Err(format!(
                "owned shim was externally changed: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn verify_paths_absent(manifest: &Manifest) -> Result<(), String> {
    for name in &manifest.links {
        let path = manifest.bin_directory.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(format!(
                    "refusing to overwrite unowned install path {}",
                    path.display()
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(&path, error)),
        }
    }
    Ok(())
}

fn validate_manifest(manifest: &Manifest) -> Result<(), String> {
    if manifest.version != VERSION
        || manifest
            .links
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != SHIMS
    {
        return Err("installation manifest version or shim list is invalid".into());
    }
    if validate_bin_directory(&manifest.bin_directory)? != manifest.bin_directory {
        return Err("installation manifest bin path is not canonical".into());
    }
    validate_recorded_executable(&manifest.executable)
}

fn validate_bin_directory(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("shim directory must be an absolute existing directory".into());
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("shim directory must be a real directory, not a symlink".into());
    }
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o700 != 0o700
    {
        return Err(
            "shim directory must be user-owned, owner-accessible and not group/world writable"
                .into(),
        );
    }
    fs::canonicalize(path).map_err(|error| io_error(path, error))
}

fn validate_executable(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("Persona executable path must be absolute".into());
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    if !metadata.is_file() {
        return Err("Persona executable must be a regular file".into());
    }
    fs::canonicalize(path).map_err(|error| io_error(path, error))
}

fn validate_recorded_executable(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err("installation manifest executable path is not canonical".into());
    }
    if path.exists() && fs::canonicalize(path).map_err(|error| io_error(path, error))? != path {
        return Err("installation manifest executable path is not canonical".into());
    }
    Ok(())
}

fn current_executable() -> Result<PathBuf, String> {
    let path = match std::env::var_os("PERSONA_INSTALL_EXECUTABLE") {
        Some(path) => PathBuf::from(path),
        None => std::env::current_exe()
            .map_err(|error| format!("cannot resolve Persona executable: {error}"))?,
    };
    validate_executable(&path)
}

fn read_manifest(path: &Path) -> Result<Option<Manifest>, String> {
    let Some(contents) = read_private_file(path)? else {
        return Ok(None);
    };
    let manifest: Manifest =
        toml::from_str(&contents).map_err(|_| "installation manifest is malformed".to_owned())?;
    validate_manifest(&manifest)?;
    Ok(Some(manifest))
}

fn write_manifest(path: &Path, manifest: &Manifest) -> Result<(), String> {
    let bytes =
        toml::to_string(manifest).map_err(|_| "cannot encode installation manifest".to_owned())?;
    atomic_write(path, bytes.as_bytes())
}

fn read_backup(state: &Path, path: &Path) -> Result<Backup, String> {
    if !path.is_absolute() {
        return Err("rollback backup path must be absolute".into());
    }
    let directory = state.join("install-backups");
    validate_private_directory(&directory)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("rollback backup must be a regular file".into());
    }
    let directory = fs::canonicalize(directory).map_err(|error| io_error(state, error))?;
    let path = fs::canonicalize(path).map_err(|error| io_error(path, error))?;
    if path.parent() != Some(directory.as_path()) {
        return Err("rollback backup is outside Persona's private install backup directory".into());
    }
    let contents =
        read_private_file(&path)?.ok_or_else(|| "rollback backup is missing".to_owned())?;
    let backup: Backup =
        toml::from_str(&contents).map_err(|_| "rollback backup is malformed".to_owned())?;
    if backup.version != VERSION {
        return Err("rollback backup version is unsupported".into());
    }
    if let Some(manifest) = &backup.previous {
        validate_manifest(manifest)?;
    }
    Ok(backup)
}

fn write_backup(state: &Path, previous: Option<Manifest>) -> Result<PathBuf, String> {
    let directory = state.join("install-backups");
    create_private_directory(&directory)?;
    let value = Backup {
        version: VERSION,
        previous,
    };
    let bytes = toml::to_string(&value).map_err(|_| "cannot encode install backup".to_owned())?;
    let mut file =
        NamedTempFile::new_in(&directory).map_err(|error| io_error(&directory, error))?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| io_error(file.path(), error))?;
    file.write_all(bytes.as_bytes())
        .map_err(|error| io_error(file.path(), error))?;
    file.as_file()
        .sync_all()
        .map_err(|error| io_error(file.path(), error))?;
    let (_, path) = file
        .keep()
        .map_err(|error| io_error(error.file.path(), error.error))?;
    sync_directory(&directory)?;
    Ok(path)
}

fn read_private_file(path: &Path) -> Result<Option<String>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(path, error)),
    };
    let parent = path
        .parent()
        .ok_or_else(|| "private state file has no parent".to_owned())?;
    validate_private_directory(parent)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(format!(
            "private installer state has unsafe type, owner or permissions: {}",
            path.display()
        ));
    }
    fs::read_to_string(path)
        .map(Some)
        .map_err(|error| io_error(path, error))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "private state file has no parent".to_owned())?;
    validate_private_directory(parent)?;
    let mut temp = NamedTempFile::new_in(parent).map_err(|error| io_error(parent, error))?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| io_error(temp.path(), error))?;
    temp.write_all(bytes)
        .map_err(|error| io_error(temp.path(), error))?;
    temp.as_file()
        .sync_all()
        .map_err(|error| io_error(temp.path(), error))?;
    temp.persist(path)
        .map_err(|error| io_error(path, error.error))?;
    sync_directory(parent)
}

fn remove_file_sync(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => sync_directory(
            path.parent()
                .ok_or_else(|| "state file has no parent".to_owned())?,
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(path, error)),
    }
}

fn set_link(path: &Path, target: Option<&Path>) -> Result<(), String> {
    match target {
        Some(target) => {
            let parent = path
                .parent()
                .ok_or_else(|| "shim path has no parent".to_owned())?;
            let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let temp = parent.join(format!(".persona-shim-{}-{id}", std::process::id()));
            symlink(target, &temp).map_err(|error| io_error(&temp, error))?;
            if let Err(error) = fs::rename(&temp, path) {
                let _ = fs::remove_file(&temp);
                return Err(io_error(path, error));
            }
            sync_directory(parent)
        }
        None => remove_file_sync(path),
    }
}

fn restore_links(changed: &[(PathBuf, Option<PathBuf>)]) -> Result<(), String> {
    let mut first = None;
    for (path, target) in changed.iter().rev() {
        if let Err(error) = set_link(path, target.as_deref()) {
            first.get_or_insert(error);
        }
    }
    first.map_or(Ok(()), Err)
}

fn ensure_state(paths: &persona::storage::PersonaPaths) -> Result<(), String> {
    paths
        .ensure_private_directories()
        .map_err(|error| format!("cannot prepare private install state: {error:?}"))?;
    validate_private_directory(&paths.state_dir)
}

fn create_private_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
            return Err(format!(
                "private installer directory is unsafe: {}",
                path.display()
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|error| io_error(path, error))?
        }
        Err(error) => return Err(io_error(path, error)),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| io_error(path, error))?;
    validate_private_directory(path)
}

fn validate_private_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(format!(
            "private installer directory is unsafe: {}",
            path.display()
        ));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| io_error(path, error))
}

fn io_error(path: &Path, error: io::Error) -> String {
    format!("{}: {error}", path.display())
}

struct Lock {
    _file: File,
}
impl Lock {
    fn acquire(state: &Path) -> Result<Self, String> {
        let path = state.join("install.lock");
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW);
        let file = options
            .open(&path)
            .map_err(|error| io_error(&path, error))?;
        let metadata = file.metadata().map_err(|error| io_error(&path, error))?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err("installation lock file has unsafe type, owner or permissions".into());
        }
        let result = unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&file),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        };
        if result != 0 {
            return Err("another Persona installation operation is active".into());
        }
        Ok(Self { _file: file })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fixture_manifest(bin: &Path, executable: &Path) -> Manifest {
        Manifest {
            version: VERSION,
            bin_directory: fs::canonicalize(bin).unwrap(),
            executable: fs::canonicalize(executable).unwrap(),
            links: SHIMS.iter().map(|name| (*name).to_owned()).collect(),
        }
    }

    fn install_links(manifest: &Manifest) {
        for name in &manifest.links {
            symlink(&manifest.executable, manifest.bin_directory.join(name)).unwrap();
        }
    }

    #[test]
    fn shim_coverage_ignores_non_executable_path_candidates() {
        let temp = tempdir().unwrap();
        let bin = temp.path().join("persona-bin");
        let shadow = temp.path().join("shadow");
        fs::create_dir(&bin).unwrap();
        fs::create_dir(&shadow).unwrap();
        let executable = temp.path().join("persona");
        fs::write(&executable, "persona").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        for name in SHIMS {
            symlink(&executable, bin.join(name)).unwrap();
            fs::write(shadow.join(name), "other executable").unwrap();
        }
        let path = std::env::join_paths([&shadow, &bin]).unwrap();

        assert!(shims_resolve_first_in(&bin, &path));
    }

    #[test]
    fn shim_coverage_rejects_an_earlier_executable_path_candidate() {
        let temp = tempdir().unwrap();
        let bin = temp.path().join("persona-bin");
        let shadow = temp.path().join("shadow");
        fs::create_dir(&bin).unwrap();
        fs::create_dir(&shadow).unwrap();
        let executable = temp.path().join("persona");
        fs::write(&executable, "persona").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        for name in SHIMS {
            symlink(&executable, bin.join(name)).unwrap();
            fs::write(shadow.join(name), "other executable").unwrap();
            fs::set_permissions(shadow.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = std::env::join_paths([&shadow, &bin]).unwrap();

        assert!(!shims_resolve_first_in(&bin, &path));
    }

    #[test]
    fn interrupted_initial_install_is_recovered_without_touching_other_files() {
        let temp = tempdir().unwrap();
        let state = temp.path().join("state");
        let bin = temp.path().join("bin");
        fs::create_dir(&state).unwrap();
        fs::create_dir(&bin).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let executable = temp.path().join("persona");
        fs::write(&executable, b"synthetic").unwrap();
        let desired = fixture_manifest(&bin, &executable);
        symlink(&desired.executable, bin.join("git")).unwrap();
        symlink(&desired.executable, bin.join("gh")).unwrap();
        write_transaction(
            &state,
            &Transaction {
                version: VERSION,
                before: None,
                desired: Some(desired),
            },
        )
        .unwrap();
        recover(&state).unwrap();
        assert!(fs::symlink_metadata(bin.join("git")).is_err());
        assert!(fs::symlink_metadata(bin.join("gh")).is_err());
        assert!(!transaction_path(&state).exists());
    }

    #[test]
    fn interrupted_refresh_restores_previous_owned_targets() {
        let temp = tempdir().unwrap();
        let state = temp.path().join("state");
        let bin = temp.path().join("bin");
        fs::create_dir(&state).unwrap();
        fs::create_dir(&bin).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let old = temp.path().join("old");
        let new = temp.path().join("new");
        fs::write(&old, b"old").unwrap();
        fs::write(&new, b"new").unwrap();
        let before = fixture_manifest(&bin, &old);
        let desired = fixture_manifest(&bin, &new);
        install_links(&before);
        for name in ["git", "gh"] {
            fs::remove_file(bin.join(name)).unwrap();
            symlink(&desired.executable, bin.join(name)).unwrap();
        }
        write_manifest(&manifest_path(&state), &before).unwrap();
        write_transaction(
            &state,
            &Transaction {
                version: VERSION,
                before: Some(before.clone()),
                desired: Some(desired),
            },
        )
        .unwrap();
        recover(&state).unwrap();
        verify_manifest_links(&before).unwrap();
        assert_eq!(read_manifest(&manifest_path(&state)).unwrap(), Some(before));
    }

    #[test]
    fn interrupted_recovery_refuses_external_shim_edits() {
        let temp = tempdir().unwrap();
        let state = temp.path().join("state");
        let bin = temp.path().join("bin");
        fs::create_dir(&state).unwrap();
        fs::create_dir(&bin).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let old = temp.path().join("old");
        let new = temp.path().join("new");
        let external = temp.path().join("external");
        fs::write(&old, b"old").unwrap();
        fs::write(&new, b"new").unwrap();
        fs::write(&external, b"external").unwrap();
        let before = fixture_manifest(&bin, &old);
        let desired = fixture_manifest(&bin, &new);
        install_links(&before);
        fs::remove_file(bin.join("git")).unwrap();
        symlink(&desired.executable, bin.join("git")).unwrap();
        fs::remove_file(bin.join("gh")).unwrap();
        symlink(&external, bin.join("gh")).unwrap();
        write_manifest(&manifest_path(&state), &before).unwrap();
        write_transaction(
            &state,
            &Transaction {
                version: VERSION,
                before: Some(before),
                desired: Some(desired),
            },
        )
        .unwrap();
        assert!(recover(&state).is_err());
        assert_eq!(fs::read_link(bin.join("gh")).unwrap(), external);
        assert!(transaction_path(&state).exists());
    }
}
