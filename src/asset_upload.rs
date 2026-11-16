use std::collections::BTreeSet;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

pub const MAX_ASSET_FILES: usize = 8;
pub const MAX_ASSET_FILE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_ASSET_TOTAL_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetSnapshot {
    pub name: String,
    pub bytes: Vec<u8>,
}

pub fn valid_asset_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

pub fn snapshot_files(
    worktree_root: &Path,
    caller_directory: &Path,
    paths: &[PathBuf],
) -> Result<Vec<AssetSnapshot>, String> {
    snapshot_files_with_open_hook(worktree_root, caller_directory, paths, |_| {})
}

fn snapshot_files_with_open_hook(
    worktree_root: &Path,
    caller_directory: &Path,
    paths: &[PathBuf],
    mut before_open: impl FnMut(&Path),
) -> Result<Vec<AssetSnapshot>, String> {
    if paths.is_empty() || paths.len() > MAX_ASSET_FILES {
        return Err(format!(
            "release uploads accept between 1 and {MAX_ASSET_FILES} files"
        ));
    }
    let root = worktree_root
        .canonicalize()
        .map_err(|_| "cannot resolve the physical managed worktree".to_owned())?;
    let caller = caller_directory
        .canonicalize()
        .map_err(|_| "cannot resolve the physical release upload directory".to_owned())?;
    let caller_relative = caller.strip_prefix(&root).map_err(|_| {
        "release upload directory is outside its physical managed worktree".to_owned()
    })?;

    let root_directory = open_directory(&root)
        .map_err(|_| "cannot open the physical managed worktree safely".to_owned())?;
    let caller_components = normalized_relative_components(caller_relative)?;
    let opened_caller = open_directory_components(&root_directory, &caller_components)
        .map_err(|_| "release upload directory changed while it was being opened".to_owned())?;
    if std::env::current_dir()
        .ok()
        .and_then(|path| path.canonicalize().ok())
        .as_deref()
        == Some(caller.as_path())
    {
        let process_directory = open_directory(Path::new("."))
            .map_err(|_| "cannot verify the current release upload directory".to_owned())?;
        if !same_directory(&opened_caller, &process_directory) {
            return Err("release upload directory changed while it was being opened".to_owned());
        }
    }

    let mut names = BTreeSet::new();
    let mut total_bytes = 0_usize;
    let mut snapshots = Vec::with_capacity(paths.len());
    for path in paths {
        let path_text = path
            .to_str()
            .ok_or_else(|| "release asset paths must be valid UTF-8".to_owned())?;
        if path_text == "-" || path_text.contains(['#', '*', '?', '[', ']']) || path_text.is_empty()
        {
            return Err("release asset paths cannot use stdin, glob, or label syntax".to_owned());
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| valid_asset_name(name))
            .ok_or_else(|| "release asset basename is unsafe".to_owned())?
            .to_owned();
        if !names.insert(name.to_ascii_lowercase()) {
            return Err("release asset basenames must be unique".to_owned());
        }

        let selected_path = if path.is_absolute() {
            path.clone()
        } else {
            caller.join(path)
        };
        let relative_path = selected_path
            .strip_prefix(&root)
            .map_err(|_| "release asset file escapes its physical managed worktree".to_owned())?;
        let components = normalized_relative_components(relative_path)?;
        let (file_name, parent_components) = components
            .split_last()
            .ok_or_else(|| "release asset basename is unsafe".to_owned())?;
        let parent_directory = open_directory_components(&root_directory, parent_components)
            .map_err(|_| "release asset file escapes its physical managed worktree".to_owned())?;
        before_open(&selected_path);
        let file = open_regular_file(&parent_directory, file_name).map_err(|_| {
            "release asset must be a regular file inside its physical managed worktree".to_owned()
        })?;
        let metadata = file
            .metadata()
            .map_err(|_| "cannot inspect release asset file".to_owned())?;
        if !metadata.is_file() {
            return Err("release assets must be regular files".to_owned());
        }
        let remaining_bytes = MAX_ASSET_TOTAL_BYTES - total_bytes;
        let file_limit = MAX_ASSET_FILE_BYTES.min(remaining_bytes);
        if metadata.len() > file_limit as u64 {
            return Err(if remaining_bytes < MAX_ASSET_FILE_BYTES {
                "release assets exceed the 128 MiB aggregate limit".to_owned()
            } else {
                format!("release asset {name} exceeds the 64 MiB per-file limit")
            });
        }
        let mut bytes = Vec::with_capacity((metadata.len() as usize).min(file_limit));
        file.take(file_limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read release asset file".to_owned())?;
        if bytes.len() > file_limit {
            return Err(if remaining_bytes < MAX_ASSET_FILE_BYTES {
                "release assets exceed the 128 MiB aggregate limit".to_owned()
            } else {
                format!("release asset {name} exceeds the 64 MiB per-file limit")
            });
        }
        total_bytes += bytes.len();
        snapshots.push(AssetSnapshot { name, bytes });
    }
    Ok(snapshots)
}

fn normalized_relative_components(path: &Path) -> Result<Vec<OsString>, String> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => components.push(name.to_os_string()),
            Component::CurDir => {}
            Component::ParentDir => {
                if components.pop().is_none() {
                    return Err(
                        "release asset file escapes its physical managed worktree".to_owned()
                    );
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err("release asset file escapes its physical managed worktree".to_owned());
            }
        }
    }
    Ok(components)
}

fn open_directory(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn open_directory_components(root: &File, components: &[OsString]) -> std::io::Result<File> {
    let mut directory = root.try_clone()?;
    for component in components {
        directory = open_at(
            &directory,
            component,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )?;
    }
    Ok(directory)
}

fn open_regular_file(directory: &File, name: &OsStr) -> std::io::Result<File> {
    open_at(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
    )
}

fn open_at(directory: &File, name: &OsStr, flags: i32) -> std::io::Result<File> {
    let name = CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path component contains a NUL byte",
        )
    })?;
    let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn same_directory(left: &File, right: &File) -> bool {
    match (left.metadata(), right.metadata()) {
        (Ok(left), Ok(right)) => left.dev() == right.dev() && left.ino() == right.ino(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn aggregate_asset_size_is_bounded_before_any_upload() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repo");
        fs::create_dir_all(&root).unwrap();
        for name in ["first.bin", "second.bin"] {
            File::create(root.join(name))
                .unwrap()
                .set_len(MAX_ASSET_FILE_BYTES as u64)
                .unwrap();
        }
        fs::write(root.join("third.bin"), b"x").unwrap();
        assert!(
            snapshot_files(
                &root,
                &root,
                &[
                    PathBuf::from("first.bin"),
                    PathBuf::from("second.bin"),
                    PathBuf::from("third.bin"),
                ]
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlink_swap_between_path_check_and_open() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repo");
        fs::create_dir_all(&root).unwrap();
        let asset = root.join("release.bin");
        fs::write(&asset, b"inside snapshot").unwrap();
        let outside = temporary.path().join("outside.bin");
        fs::write(&outside, b"outside secret").unwrap();

        let result = snapshot_files_with_open_hook(
            &root,
            &root,
            &[PathBuf::from("release.bin")],
            |checked_path| {
                fs::rename(checked_path, root.join("original.bin")).unwrap();
                std::os::unix::fs::symlink(&outside, checked_path).unwrap();
            },
        );
        assert!(
            result.is_err(),
            "must reject a swapped symlink, not snapshot outside bytes"
        );
    }

    #[test]
    fn snapshots_only_bounded_regular_files_inside_physical_worktree() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repo");
        let caller = root.join("subdir");
        fs::create_dir_all(&caller).unwrap();
        fs::write(caller.join("release.bin"), b"snapshot").unwrap();
        let snapshots = snapshot_files(&root, &caller, &[PathBuf::from("release.bin")]).unwrap();
        assert_eq!(snapshots[0].name, "release.bin");
        assert_eq!(snapshots[0].bytes, b"snapshot");
        fs::write(caller.join("release.bin"), b"changed").unwrap();
        assert_eq!(snapshots[0].bytes, b"snapshot");

        let outside = temporary.path().join("outside.bin");
        fs::write(&outside, b"outside").unwrap();
        assert!(snapshot_files(&root, &caller, std::slice::from_ref(&outside)).is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, caller.join("escape.bin")).unwrap();
            assert!(snapshot_files(&root, &caller, &[PathBuf::from("escape.bin")]).is_err());
        }
        assert!(snapshot_files(&root, &caller, &[PathBuf::from(".")]).is_err());
        assert!(snapshot_files(&root, &caller, &[PathBuf::from("release.bin#label")]).is_err());
        assert!(snapshot_files(&root, &caller, &[PathBuf::from("*.bin")]).is_err());
        assert!(snapshot_files(&root, &caller, &[PathBuf::from("-")]).is_err());
        assert!(snapshot_files(&root, &caller, &[]).is_err());
        assert!(
            snapshot_files(
                &root,
                &caller,
                &[PathBuf::from("release.bin"), PathBuf::from("./release.bin")]
            )
            .is_err()
        );
        let oversized = caller.join("oversized.bin");
        File::create(&oversized)
            .unwrap()
            .set_len((MAX_ASSET_FILE_BYTES + 1) as u64)
            .unwrap();
        assert!(snapshot_files(&root, &caller, &[PathBuf::from("oversized.bin")]).is_err());
        assert!(
            snapshot_files(
                &root,
                &caller,
                &vec![PathBuf::from("release.bin"); MAX_ASSET_FILES + 1]
            )
            .is_err()
        );
    }
}
