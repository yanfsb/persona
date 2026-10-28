pub mod config;
pub mod context;
pub mod git;
pub mod gpg;
pub mod paths;
pub mod report;
pub mod runner;

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub name: String,
    pub root: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResolveError {
    RelativePath(PathBuf),
    DuplicateRoot(PathBuf),
}

pub fn resolve(directory: &Path, scopes: &[Scope]) -> Result<Option<Scope>, ResolveError> {
    validate_inputs(directory, scopes)?;

    let mut selected_scope = None;
    let mut greatest_depth = 0;

    for scope in scopes {
        if !directory.starts_with(&scope.root) {
            continue;
        }

        let depth = scope.root.components().count();

        if depth > greatest_depth {
            selected_scope = Some(scope);
            greatest_depth = depth;
        }
    }

    match selected_scope {
        Some(scope) => Ok(Some(scope.clone())),
        None => Ok(None),
    }
}

fn validate_inputs(directory: &Path, scopes: &[Scope]) -> Result<(), ResolveError> {
    if directory.is_relative() {
        return Err(ResolveError::RelativePath(directory.to_path_buf()));
    }

    let mut seen_roots = std::collections::HashSet::new();

    for scope in scopes {
        if scope.root.is_relative() {
            return Err(ResolveError::RelativePath(scope.root.clone()));
        }

        if !seen_roots.insert(scope.root.clone()) {
            return Err(ResolveError::DuplicateRoot(scope.root.clone()));
        }
    }

    Ok(())
}
