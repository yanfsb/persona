use persona::{ResolveError, Scope, resolve};
use std::path::{Path, PathBuf};

fn scope(name: &str, root: &str) -> Scope {
    Scope {
        name: name.to_owned(),
        root: PathBuf::from(root),
    }
}

#[test]
fn chooses_the_most_specific_scope_regardless_of_order() {
    let broad = scope("work", "/work");
    let nested = scope("private", "/work/private");

    let orders = [vec![broad.clone(), nested.clone()], vec![nested, broad]];

    for scopes in orders {
        let selected = resolve(Path::new("/work/private/repo"), &scopes)
            .expect("policy should be valid")
            .expect("directory should have a scope");

        assert_eq!(selected.name, "private");
    }
}

#[test]
fn mathces_the_scope_root_itself() {
    let scopes = [scope("work", "/work")];

    let selected = resolve(Path::new("/work"), &scopes)
        .expect("policy should be valid")
        .expect("scope root should match");

    assert_eq!(selected.name, "work");
}

#[test]
fn supports_the_filesystem_root_as_a_scope() {
    let scopes = [scope("fallback", "/")];

    let selected = resolve(Path::new("/work/repo"), &scopes)
        .expect("policy should be valid")
        .expect("scope root should match");

    assert_eq!(selected.name, "fallback");
}

#[test]
fn does_not_confuse_textual_prefixes_with_ancestors() {
    let scopes = [scope("project", "/work/proj")];

    let selected = resolve(Path::new("/work/project"), &scopes).expect("policy should be valid");

    assert!(selected.is_none());
}

#[test]
fn returns_unmanaged_outside_configured_scopes() {
    let scopes = [scope("work", "/work")];

    let selected = resolve(Path::new("/personal/repo"), &scopes).expect("policy should be valid");

    assert!(selected.is_none());
}

#[test]
fn rejects_relative_query_paths() {
    let result = resolve(Path::new("work/repo"), &[]);

    assert_eq!(
        result,
        Err(ResolveError::RelativePath(PathBuf::from("work/repo")))
    );
}

#[test]
fn rejects_relative_scope_roots_even_when_they_do_not_match() {
    let scopes = [scope("invalid", "other")];

    let result = resolve(Path::new("/work/repo"), &scopes);

    assert_eq!(
        result,
        Err(ResolveError::RelativePath(PathBuf::from("other")))
    );
}

#[test]
fn rejects_duplicate_roots_regardless_of_matching_or_order() {
    let first = scope("first", "/work");
    let duplicate = scope("duplicate", "/work");
    let nested = scope("nested", "/work/private");

    let orders = [
        vec![first.clone(), duplicate.clone(), nested.clone()],
        vec![nested, first, duplicate],
    ];

    for scopes in orders {
        for directory in ["/work/private/repo", "/elsewhere"] {
            let result = resolve(Path::new(directory), &scopes);

            assert_eq!(
                result,
                Err(ResolveError::DuplicateRoot(PathBuf::from("/work")))
            );
        }
    }
}
