use crate::paths::{PathError, canonical_directory};
use crate::{ResolveError, Scope, resolve};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum ContextError {
    Path(PathError),
    Policy(ResolveError),
}

pub fn resolve_context(directory: &Path, scopes: &[Scope]) -> Result<Option<Scope>, ContextError> {
    resolve_context_at(
        &canonical_directory(directory).map_err(ContextError::Path)?,
        scopes,
    )
}

/// Resolve an operation against an existing destination directory or a new
/// single-component destination whose parent already exists.
pub fn resolve_operation_context(
    caller_directory: &Path,
    target_directory: Option<&Path>,
    scopes: &[Scope],
) -> Result<Option<Scope>, ContextError> {
    match target_directory {
        Some(target) => resolve_target_context(target, scopes),
        None => resolve_context(caller_directory, scopes),
    }
}

pub fn resolve_target_context(
    target: &Path,
    scopes: &[Scope],
) -> Result<Option<Scope>, ContextError> {
    let physical_target = match canonical_directory(target) {
        Ok(directory) => directory,
        Err(PathError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            resolve_missing_target(target).map_err(ContextError::Path)?
        }
        Err(error) => return Err(ContextError::Path(error)),
    };
    resolve_context_at(&physical_target, scopes)
}

fn resolve_missing_target(target: &Path) -> Result<PathBuf, PathError> {
    let absolute = if target.is_absolute() {
        target.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| PathError::Io {
                path: target.to_path_buf(),
                source,
            })?
            .join(target)
    };
    let mut suffix = Vec::new();
    let mut ancestor = absolute.as_path();
    loop {
        match canonical_directory(ancestor) {
            Ok(canonical) => {
                let mut resolved = canonical;
                for component in suffix.iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(PathError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                if fs::symlink_metadata(ancestor)
                    .is_ok_and(|metadata| metadata.file_type().is_symlink())
                {
                    return Err(PathError::Io {
                        path: ancestor.to_path_buf(),
                        source: std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "target path contains a dangling symbolic link",
                        ),
                    });
                }
                let name = ancestor
                    .file_name()
                    .ok_or_else(|| PathError::RelativePath(absolute.clone()))?;
                suffix.push(name.to_os_string());
                ancestor = ancestor
                    .parent()
                    .ok_or_else(|| PathError::RelativePath(absolute.clone()))?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn resolve_context_at(
    physical_directory: &Path,
    scopes: &[Scope],
) -> Result<Option<Scope>, ContextError> {
    let mut physical_scopes = Vec::with_capacity(scopes.len());

    for scope in scopes {
        let physical_root = canonical_directory(&scope.root).map_err(ContextError::Path)?;

        physical_scopes.push(Scope {
            name: scope.name.clone(),
            root: physical_root,
        })
    }

    resolve(physical_directory, &physical_scopes).map_err(ContextError::Policy)
}
