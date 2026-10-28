use persona::paths::{PathError, canonical_directory};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use tempfile::tempdir;

#[test]
fn returns_the_canonical_path_of_an_existing_directory() {
    let temporary = tempdir().expect("create temporary directory");
    let directory = temporary.path().join("project");

    fs::create_dir(&directory).expect("create project directory");

    let actual = canonical_directory(&directory).expect("canonical_directory should succeed");

    let expected = fs::canonicalize(&directory).expect("canonicalize expected path");

    assert_eq!(actual, expected);
    assert!(actual.is_absolute());
}

#[cfg(unix)]
#[test]
fn resolves_a_symlink_to_its_physical_directory() {
    let temporary = tempdir().expect("create temporary directory");
    let physical = temporary.path().join("physical");
    let alias = temporary.path().join("alias");

    fs::create_dir(&physical).expect("create physical diretory");

    std::os::unix::fs::symlink(&physical, &alias).expect("create symlink");

    let actual = canonical_directory(&alias).expect("canonical_directory should succeed");

    let expected = fs::canonicalize(&physical).expect("canonicalize expected path");

    assert_eq!(actual, expected);
}

#[test]
fn rejects_a_missing_directory() {
    let temporary = tempdir().expect("create temporary directory");
    let missing = temporary.path().join("missing");

    let result = canonical_directory(&missing);

    //diverge do agent
    assert!(
        matches!(result, Err(PathError::Io { path, source }) if path == missing && source.kind() == ErrorKind::NotFound)
    );
}

#[test]
fn rejects_a_file_used_as_a_directory() {
    let temporary = tempdir().expect("create temporary directory");
    let file = temporary.path().join("document.txt");

    fs::write(&file, "fixture").expect("create file fixture");

    let result = canonical_directory(&file);

    assert!(matches!(result, Err(PathError::NotDirectory(_))));
}

#[test]
fn rejects_relative_paths_before_accessing_the_filesystem() {
    let result = canonical_directory(Path::new("relative/project"));

    assert!(matches!(result, Err(PathError::RelativePath(_))))
}
