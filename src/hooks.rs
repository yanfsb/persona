use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookManifest {
    version: u32,
    config_path: PathBuf,
    hook_path: PathBuf,
    persona_executable: PathBuf,
    original_sha256: Option<String>,
    original_mode: Option<u32>,
    original_executable: bool,
}

#[derive(Debug, Clone)]
pub struct HookPaths {
    pub root: PathBuf,
    pub hook: PathBuf,
    pub state: PathBuf,
    pub manifest: PathBuf,
    pub backup: PathBuf,
}

pub fn resolve_paths(git: &crate::git::GitClient, directory: &Path) -> Result<HookPaths, String> {
    if git
        .has_custom_hooks_path(directory)
        .map_err(|error| format!("cannot inspect Git hook configuration: {error:?}"))?
    {
        return Err(
            "custom core.hooksPath is configured; refusing to replace or chain it implicitly"
                .to_owned(),
        );
    }
    let hook = git
        .git_path(directory, "hooks/pre-push")
        .map_err(|error| format!("cannot resolve Git pre-push hook path: {error:?}"))?;
    let hooks_dir = hook
        .parent()
        .ok_or_else(|| "Git pre-push hook has no parent directory".to_owned())?;
    let root = hooks_dir
        .parent()
        .ok_or_else(|| "Git hooks directory has no metadata parent".to_owned())?
        .to_path_buf();
    Ok(HookPaths {
        root: root.clone(),
        hook,
        state: root.join("persona-hooks"),
        manifest: root.join("persona-hooks").join("pre-push.json"),
        backup: root.join("persona-hooks").join("pre-push.original"),
    })
}

pub fn install(
    paths: &HookPaths,
    config_path: &Path,
    persona_executable: &Path,
    preview: bool,
) -> Result<String, String> {
    let config_path = fs::canonicalize(config_path)
        .map_err(|_| "Persona config file must exist and resolve physically".to_owned())?;
    let persona_executable = fs::canonicalize(persona_executable)
        .map_err(|_| "Persona executable must exist and resolve physically".to_owned())?;
    if !config_path.is_file() || !persona_executable.is_file() {
        return Err("config or Persona executable is not a regular file".to_owned());
    }
    validate_directories(paths, preview)?;

    if paths.manifest.exists() {
        let mut manifest = read_manifest(&paths.manifest)?;
        verify_installed_hook(paths, &manifest)?;
        if preview {
            return Ok(format!(
                "would refresh Persona pre-push hook policy to {}",
                config_path.display()
            ));
        }
        let previous_executable = manifest.persona_executable.clone();
        replace_owned_symlink(&paths.hook, &previous_executable, &persona_executable)?;
        manifest.config_path = config_path;
        manifest.persona_executable = persona_executable;
        if let Err(error) = write_manifest_atomic(&paths.manifest, &manifest) {
            let rollback = replace_owned_symlink(
                &paths.hook,
                &manifest.persona_executable,
                &previous_executable,
            );
            return Err(match rollback {
                Ok(()) => error,
                Err(rollback_error) => format!("{error}; hook rollback failed: {rollback_error}"),
            });
        }
        return Ok("refreshed the owned Persona pre-push hook".to_owned());
    }

    let hook_metadata = match fs::symlink_metadata(&paths.hook) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() > 1024 * 1024
            {
                return Err(
                    "existing pre-push hook is not a bounded regular file; refusing to replace it"
                        .to_owned(),
                );
            }
            Some(metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err("cannot inspect existing pre-push hook".to_owned()),
    };
    if paths.backup.exists() {
        return Err(
            "unowned Persona hook backup already exists; refusing to overwrite it".to_owned(),
        );
    }
    if preview {
        return Ok(if hook_metadata.is_some() {
            "would preserve the existing pre-push hook and install the Persona guard".to_owned()
        } else {
            "would install the Persona pre-push guard".to_owned()
        });
    }

    let original_mode = hook_metadata.as_ref().map(file_mode);
    if original_mode.is_some_and(|mode| mode & 0o7000 != 0) {
        return Err(
            "existing pre-push hook has special permission bits; refusing to preserve it"
                .to_owned(),
        );
    }
    let source_sha256 = hook_metadata
        .as_ref()
        .map(|_| sha256_file(&paths.hook))
        .transpose()?;
    fs::create_dir_all(&paths.state)
        .map_err(|_| "cannot create Persona hook state directory".to_owned())?;
    if let Err(error) = set_private_directory(&paths.state) {
        let _ = fs::remove_dir(&paths.state);
        return Err(error);
    }
    let preserve_result = (|| -> Result<(), String> {
        if hook_metadata.is_some() {
            fs::copy(&paths.hook, &paths.backup)
                .map_err(|_| "cannot preserve existing pre-push hook".to_owned())?;
            set_private_hook_permissions(&paths.backup, original_mode.unwrap_or(0o600))?;
            if Some(sha256_file(&paths.backup)?) != source_sha256 {
                return Err("existing pre-push hook changed while being preserved".to_owned());
            }
        }
        Ok(())
    })();
    if let Err(error) = preserve_result {
        let _ = fs::remove_file(&paths.backup);
        let _ = fs::remove_dir(&paths.state);
        return Err(error);
    }
    let original_sha256 = source_sha256;
    let original_executable = original_mode.is_some_and(|mode| mode & 0o111 != 0);
    let manifest = HookManifest {
        version: MANIFEST_VERSION,
        config_path,
        hook_path: paths.hook.clone(),
        persona_executable: persona_executable.clone(),
        original_sha256: original_sha256.clone(),
        original_mode,
        original_executable,
    };
    if let Err(error) = write_manifest_atomic(&paths.manifest, &manifest) {
        let _ = fs::remove_file(&paths.backup);
        let _ = fs::remove_dir(&paths.state);
        return Err(error);
    }
    if let Err(error) = install_symlink(
        &paths.hook,
        &persona_executable,
        original_sha256.as_deref(),
        original_mode,
    ) {
        let _ = fs::remove_file(&paths.manifest);
        if hook_metadata.is_some() {
            let _ = fs::remove_file(&paths.backup);
        }
        let _ = fs::remove_dir(&paths.state);
        return Err(error);
    }
    Ok("installed the Persona pre-push guard and preserved the previous hook".to_owned())
}

pub fn uninstall(paths: &HookPaths, preview: bool) -> Result<String, String> {
    let manifest = match read_manifest(&paths.manifest) {
        Ok(manifest) => manifest,
        Err(_error) if !paths.manifest.exists() => {
            return Ok("no owned Persona pre-push hook is installed".to_owned());
        }
        Err(error) => return Err(error),
    };
    verify_installed_hook(paths, &manifest)?;
    if let Some(expected_hash) = &manifest.original_sha256 {
        if !is_regular_nonsymlink(&paths.backup) || sha256_file(&paths.backup)? != *expected_hash {
            return Err("preserved pre-push hook backup changed; refusing rollback".to_owned());
        }
    } else if paths.backup.exists() {
        return Err("unexpected pre-push backup exists; refusing rollback".to_owned());
    }
    if preview {
        return Ok(
            "would remove Persona's pre-push guard and restore the previous hook".to_owned(),
        );
    }
    verify_installed_hook(paths, &manifest)?;
    if let Some(expected_hash) = &manifest.original_sha256 {
        if !is_regular_nonsymlink(&paths.backup) || sha256_file(&paths.backup)? != *expected_hash {
            return Err("preserved pre-push hook backup changed; refusing rollback".to_owned());
        }
    }
    if manifest.original_sha256.is_some() {
        if let Some(mode) = manifest.original_mode {
            set_file_mode(&paths.backup, mode)?;
        }
        fs::rename(&paths.backup, &paths.hook)
            .map_err(|_| "cannot atomically restore the preserved pre-push hook".to_owned())?;
    } else {
        fs::remove_file(&paths.hook)
            .map_err(|_| "cannot remove the owned Persona pre-push hook".to_owned())?;
    }
    fs::remove_file(&paths.manifest)
        .map_err(|_| "cannot remove Persona hook manifest".to_owned())?;
    let _ = fs::remove_dir(&paths.state);
    Ok("removed the Persona pre-push guard and restored owned hook state".to_owned())
}

pub fn load_manifest(paths: &HookPaths) -> Result<HookManifest, String> {
    let manifest = read_manifest(&paths.manifest)?;
    if let Some(expected_hash) = &manifest.original_sha256 {
        if !is_regular_nonsymlink(&paths.backup) || sha256_file(&paths.backup)? != *expected_hash {
            return Err("preserved pre-push hook backup changed; refusing to run it".to_owned());
        }
    }
    Ok(manifest)
}

impl HookManifest {
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn original_hook<'a>(&self, paths: &'a HookPaths) -> Option<&'a Path> {
        self.original_executable.then_some(paths.backup.as_path())
    }

    pub fn persona_executable(&self) -> &Path {
        &self.persona_executable
    }
}

fn validate_directories(paths: &HookPaths, preview: bool) -> Result<(), String> {
    let root = fs::canonicalize(&paths.root)
        .map_err(|_| "Git metadata directory must exist".to_owned())?;
    if root != paths.root {
        return Err("Git metadata path is not canonical".to_owned());
    }
    let hooks_dir = paths
        .hook
        .parent()
        .ok_or_else(|| "Git hooks directory is unavailable".to_owned())?;
    if let Ok(metadata) = fs::symlink_metadata(hooks_dir) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("Git hooks path is not a real directory".to_owned());
        }
        let canonical = fs::canonicalize(hooks_dir)
            .map_err(|_| "cannot canonicalize Git hooks directory".to_owned())?;
        if canonical != hooks_dir {
            return Err("Git hooks path is not canonical".to_owned());
        }
    } else if !preview {
        fs::create_dir_all(hooks_dir)
            .map_err(|_| "cannot create Git hooks directory".to_owned())?;
    }
    if paths.state.exists() {
        let metadata = fs::symlink_metadata(&paths.state)
            .map_err(|_| "cannot inspect Persona hook state".to_owned())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("Persona hook state is not a real directory".to_owned());
        }
    }
    Ok(())
}

fn read_manifest(path: &Path) -> Result<HookManifest, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "Persona hook manifest is missing or unreadable".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 64 * 1024 {
        return Err("Persona hook manifest is not a regular file".to_owned());
    }
    let bytes = fs::read(path).map_err(|_| "cannot read Persona hook manifest".to_owned())?;
    let manifest: HookManifest = serde_json::from_slice(&bytes)
        .map_err(|_| "Persona hook manifest is invalid".to_owned())?;
    if manifest.version != MANIFEST_VERSION {
        return Err("Persona hook manifest version is unsupported".to_owned());
    }
    Ok(manifest)
}

pub fn verify_installed_hook(paths: &HookPaths, manifest: &HookManifest) -> Result<(), String> {
    if manifest.hook_path != paths.hook {
        return Err("Persona hook manifest points to a different repository".to_owned());
    }
    let link = fs::read_link(&paths.hook)
        .map_err(|_| "installed pre-push hook changed or is missing".to_owned())?;
    if link != manifest.persona_executable {
        return Err("installed pre-push hook was externally modified".to_owned());
    }
    Ok(())
}

fn write_manifest_atomic(path: &Path, manifest: &HookManifest) -> Result<(), String> {
    let directory = path
        .parent()
        .ok_or_else(|| "Persona manifest has no parent directory".to_owned())?;
    let mut temporary = tempfile::NamedTempFile::new_in(directory)
        .map_err(|_| "cannot create temporary hook manifest".to_owned())?;
    let contents = serde_json::to_vec(manifest)
        .map_err(|_| "cannot encode Persona hook manifest".to_owned())?;
    temporary
        .write_all(&contents)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| "cannot write Persona hook manifest".to_owned())?;
    temporary
        .persist(path)
        .map_err(|_| "cannot atomically install Persona hook manifest".to_owned())?;
    Ok(())
}

fn replace_owned_symlink(hook: &Path, expected: &Path, replacement: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        if !fs::read_link(hook).is_ok_and(|target| target == expected) {
            return Err("installed pre-push hook changed; refusing refresh".to_owned());
        }
        let temporary = hook.with_extension(format!("persona-refresh-{}", std::process::id()));
        if temporary.exists() || fs::symlink_metadata(&temporary).is_ok() {
            return Err("temporary Persona hook path already exists".to_owned());
        }
        symlink(replacement, &temporary)
            .map_err(|_| "cannot create refreshed Persona hook symlink".to_owned())?;
        if !fs::read_link(hook).is_ok_and(|target| target == expected) {
            let _ = fs::remove_file(&temporary);
            return Err("installed pre-push hook changed during refresh".to_owned());
        }
        fs::rename(&temporary, hook).map_err(|_| {
            let _ = fs::remove_file(&temporary);
            "cannot activate refreshed Persona pre-push hook".to_owned()
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (hook, expected, replacement);
        Err("managed hook refresh is supported only on Unix platforms".to_owned())
    }
}

fn install_symlink(
    hook: &Path,
    executable: &Path,
    expected_sha256: Option<&str>,
    expected_mode: Option<u32>,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let temporary = hook.with_extension(format!("persona-{}", std::process::id()));
        if temporary.exists() {
            return Err("temporary Persona hook path already exists".to_owned());
        }
        symlink(executable, &temporary)
            .map_err(|_| "cannot create Persona hook symlink".to_owned())?;
        let unchanged = match expected_sha256 {
            Some(expected) => {
                is_regular_nonsymlink(hook)
                    && sha256_file(hook).is_ok_and(|actual| actual == expected)
                    && fs::symlink_metadata(hook)
                        .is_ok_and(|metadata| Some(file_mode(&metadata)) == expected_mode)
            }
            None => fs::symlink_metadata(hook)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        };
        if !unchanged {
            let _ = fs::remove_file(&temporary);
            return Err(
                "pre-push hook changed during installation; refusing replacement".to_owned(),
            );
        }
        fs::rename(&temporary, hook).map_err(|_| {
            let _ = fs::remove_file(&temporary);
            "cannot activate Persona pre-push hook".to_owned()
        })?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (hook, executable);
        Err("managed hook installation is supported only on Unix platforms".to_owned())
    }
}

fn file_mode(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        0
    }
}

fn set_private_hook_permissions(path: &Path, original_mode: u32) -> Result<(), String> {
    let private_mode = if original_mode & 0o111 != 0 {
        0o700
    } else {
        0o600
    };
    set_file_mode(path, private_mode)
}

fn set_file_mode(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|_| "cannot set preserved pre-push hook permissions".to_owned())?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

fn set_private_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| "cannot restrict Persona hook state permissions".to_owned())?;
    }
    Ok(())
}

fn is_regular_nonsymlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| !metadata.file_type().is_symlink() && metadata.is_file())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|_| "cannot hash preserved pre-push hook".to_owned())?;
    let hash = Sha256::digest(bytes);
    let digits = b"0123456789abcdef";
    let mut encoded = String::with_capacity(hash.len() * 2);
    for byte in hash {
        encoded.push(char::from(digits[(byte >> 4) as usize]));
        encoded.push(char::from(digits[(byte & 0x0f) as usize]));
    }
    Ok(encoded)
}
