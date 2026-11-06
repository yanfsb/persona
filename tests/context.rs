#![cfg(unix)]

use persona::context::{
    ContextError, resolve_context, resolve_operation_context, resolve_target_context,
};
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
fn new_clone_target_uses_its_most_specific_scope_not_the_callers_scope() {
    let temporary = tempdir().expect("create temporary directory");
    let parent = temporary.path().join("work");
    let nested = parent.join("personal");
    fs::create_dir_all(&nested).expect("create nested scope parent");
    let target = nested.join("new-clone");
    let scopes = [scope("work", &parent), scope("personal", &nested)];

    let selected = resolve_target_context(&target, &scopes)
        .expect("resolve future clone target")
        .expect("clone target is managed");
    assert_eq!(selected.name, "personal");
    assert_eq!(selected.root, fs::canonicalize(&nested).unwrap());
}

#[test]
fn new_nested_clone_target_resolves_from_nearest_physical_ancestor() {
    let temporary = tempdir().expect("create temporary directory");
    let managed = temporary.path().join("managed");
    fs::create_dir_all(&managed).expect("create managed scope");
    let alias = temporary.path().join("managed-alias");
    symlink(&managed, &alias).expect("create scope alias");
    let target = alias.join("group").join("repository");
    let scopes = [scope("managed", &managed)];

    let selected = resolve_target_context(&target, &scopes)
        .expect("resolve nested target")
        .expect("target is managed");

    assert_eq!(selected.name, "managed");
    assert_eq!(selected.root, fs::canonicalize(&managed).unwrap());
}

#[test]
fn target_operation_selects_target_scope_without_requiring_managed_caller_context() {
    let temporary = tempdir().expect("create temporary directory");
    let managed = temporary.path().join("managed");
    let unmanaged = temporary.path().join("unmanaged");
    fs::create_dir_all(&managed).expect("create managed scope");
    fs::create_dir_all(&unmanaged).expect("create unmanaged caller");
    let target = managed.join("new-clone");
    let scopes = [scope("managed", &managed)];

    let selected = resolve_operation_context(&unmanaged, Some(&target), &scopes)
        .expect("resolve target operation")
        .expect("target is managed");
    assert_eq!(selected.name, "managed");
}

#[test]
fn dangling_symlink_in_future_target_path_is_rejected() {
    let temporary = tempdir().expect("create temporary directory");
    let managed = temporary.path().join("managed");
    fs::create_dir_all(&managed).expect("create managed scope");
    let dangling = temporary.path().join("dangling");
    symlink(temporary.path().join("missing-target"), &dangling).expect("create dangling link");
    let scopes = [scope("managed", &managed)];

    assert!(resolve_target_context(&dangling.join("clone"), &scopes).is_err());
}

#[test]
fn new_clone_target_outside_managed_scopes_stays_unmanaged() {
    let temporary = tempdir().expect("create temporary directory");
    let managed = temporary.path().join("managed");
    let outside = temporary.path().join("outside");
    fs::create_dir_all(&managed).expect("create managed scope");
    fs::create_dir_all(&outside).expect("create unmanaged parent");
    let scopes = [scope("managed", &managed)];

    assert!(
        resolve_target_context(&outside.join("clone"), &scopes)
            .expect("resolve future target")
            .is_none()
    );
}

#[test]
fn nested_v2_scope_replaces_parent_profile_without_inheritance() {
    let temporary = tempdir().expect("create temporary directory");
    let parent = temporary.path().join("work");
    let nested = parent.join("personal");
    fs::create_dir_all(&nested).expect("create nested scope");
    let config_text = format!(
        "version = 2\n\
         [[profiles]]\nname = \"work\"\n[profiles.git]\nauthor = {{ name = \"Work\", email = \"work@example.invalid\" }}\ncommitter = {{ name = \"Work\", email = \"work@example.invalid\" }}\n\
         [[profiles]]\nname = \"personal\"\n[profiles.git]\nauthor = {{ name = \"Personal\", email = \"personal@example.invalid\" }}\ncommitter = {{ name = \"Personal\", email = \"personal@example.invalid\" }}\n\
         [[scopes]]\nname = \"work-root\"\npath = {:?}\nprofile = \"work\"\n\
         [[scopes]]\nname = \"personal-root\"\npath = {:?}\nprofile = \"personal\"\n",
        parent, nested
    );
    let config = persona::config::Config::parse(&config_text).expect("v2 nested config");
    let selected = resolve_context(&nested, &config.scopes())
        .expect("resolve nested scope")
        .expect("nested scope selected");
    assert_eq!(selected.name, "personal-root");
    assert_eq!(
        config
            .policies()
            .iter()
            .find(|policy| policy.name == selected.name)
            .unwrap()
            .git
            .author
            .name,
        "Personal"
    );
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
