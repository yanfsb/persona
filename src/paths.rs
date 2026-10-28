use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum PathError {
    RelativePath(PathBuf),
    NotDirectory(PathBuf),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

pub fn canonical_directory(path: &Path) -> Result<PathBuf, PathError> {
    if path.is_relative() {
        return Err(PathError::RelativePath(path.to_path_buf()));
    }

    // remove symlinks like '.' and '..'
    let canonical = std::fs::canonicalize(path).map_err(|source| PathError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    let metadata = std::fs::metadata(&canonical).map_err(|source| PathError::Io {
        path: canonical.clone(),
        source,
    })?;
    if !metadata.is_dir() {
        return Err(PathError::NotDirectory(canonical));
    }

    Ok(canonical)
}
