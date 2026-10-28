use crate::paths::{PathError, canonical_directory};
use crate::{ResolveError, Scope, resolve};
use std::path::Path;

#[derive(Debug)]
pub enum ContextError {
    Path(PathError),
    Policy(ResolveError),
}

pub fn resolve_context(directory: &Path, scopes: &[Scope]) -> Result<Option<Scope>, ContextError> {
    let physical_directory = canonical_directory(directory).map_err(ContextError::Path)?;

    let mut physical_scopes = Vec::with_capacity(scopes.len());

    for scope in scopes {
        let physical_root = canonical_directory(&scope.root).map_err(ContextError::Path)?;

        physical_scopes.push(Scope {
            name: scope.name.clone(),
            root: physical_root,
        })
    }

    resolve(&physical_directory, &physical_scopes).map_err(ContextError::Policy)
}
