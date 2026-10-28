#![cfg(unix)]

use persona::context::{ContextError, resolve_context};
use persona::paths::PathError;
use persona::{ResolveError, Scope};
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::symlink;
use std::path::Path;
use tempfile::tempdir;

fn scope(name: &str, root: &Path) -> Scope {
    Scope {
        name: name.to_owned(),
        root: root.to_path_buf(),
    }
}

#[test]
fn canonicalizes_query_and_scopes_before_selecting() {
    let temporary = tempdir().expect("create temporary directory");
    let broad = temporary.path().join("work");
    let nested = broad.join("private");
    let project = nested.join("project");
    let scope_alias = temporary.path().join("scope_alias");
    let query_alias = temporary.path().join("query_alias");

    fs::create_dir_all(&project).expect("create project");
    symlink(&nested, &scope_alias).expect("create scope_alias");
    symlink(&project, &query_alias).expect("create query_alias alias");

    let scopes = [scope("work", &broad), scope("private", &scope_alias)];

    let selected = resolve_context(&query_alias, &scopes)
        .expect("valid context")
        .expect("matching scope");

    assert_eq!(selected.name, "private");
    assert_eq!(
        selected.root,
        fs::canonicalize(&nested).expect("canonicalize expected root")
    )
}

#[test]
fn does_not_inherit_scope_through_a_symlink_to_an_external_project() {
    let temporary = tempdir().expect("create temporary directory");

    let managed = temporary.path().join("managed");
    let external = temporary.path().join("external");
    let alias = managed.join("linked-project");

    fs::create_dir(&managed).expect("create managed directory");
    fs::create_dir(&external).expect("create external directory");
    symlink(&external, &alias).expect("create project alias");

    let scopes = [scope("managed", &managed)];

    let selected = resolve_context(&alias, &scopes).expect("valid context");

    assert!(selected.is_none());
}

#[test]
fn rejects_duplicate_physical_roots_even_ehen_the_query_is_unmanaged() {
    let temporary = tempdir().expect("create temporary directory");

    let root = temporary.path().join("work");
    let alias = temporary.path().join("work-alias");
    let outside = temporary.path().join("outside");

    fs::create_dir(&root).expect("create root directory");
    fs::create_dir(&outside).expect("create outside directory");
    symlink(&root, &alias).expect("create scope alias");

    let scopes = [scope("original", &root), scope("alis", &alias)];
    let result = resolve_context(&outside, &scopes);

    assert!(matches!(
        result,
        Err(ContextError::Policy(ResolveError::DuplicateRoot(_)))
    ));
}

#[test]
fn rejects_a_missing_scope_even_when_another_scope_matches() {
    let temporary = tempdir().expect("create temporary directory");

    let managed = temporary.path().join("managed");
    let project = managed.join("project");
    let missing = temporary.path().join("missing");

    fs::create_dir_all(&project).expect("create project");

    let scopes = [scope("managed", &managed), scope("missing", &missing)];

    let result = resolve_context(&project, &scopes);

    assert!(matches!(
        result,
        Err(ContextError::Path(PathError::Io { source, .. }))
            if source.kind() == ErrorKind::NotFound
    ));
}
