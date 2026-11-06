use crate::credential::{sign_private_state_payload, verify_private_state_payload};
use crate::storage::PersonaPaths;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

const VERSION: u32 = 1;
const MAX_HANDOFF_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushHandoff {
    pub config_path: PathBuf,
    pub config_sha256: String,
    pub hook_manifest_path: PathBuf,
    pub hook_manifest_sha256: String,
    pub checkout_root: PathBuf,
    pub profile: String,
    pub remote: String,
    pub destination: String,
    pub tuples: Vec<HandoffTuple>,
    pub github_binding: Option<HandoffGithubBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffTuple {
    pub local_ref: String,
    pub local_oid: String,
    pub remote_ref: String,
    pub remote_oid: String,
    pub expected_lease_oid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffGithubBinding {
    pub host: String,
    pub account_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    version: u32,
    payload: String,
    mac: String,
}

pub fn write(paths: &PersonaPaths, handoff: &PushHandoff) -> Result<NamedTempFile, String> {
    paths
        .ensure_private_directories()
        .map_err(|error| format!("cannot initialize private push handoff storage: {error:?}"))?;
    let payload = serde_json::to_vec(handoff)
        .map_err(|_| "cannot encode immutable push handoff".to_owned())?;
    if payload.len() as u64 > MAX_HANDOFF_BYTES {
        return Err("immutable push handoff exceeds the size limit".to_owned());
    }
    let mac = sign_private_state_payload(paths, &payload)
        .map_err(|_| "cannot authenticate immutable push handoff".to_owned())?;
    let payload =
        String::from_utf8(payload).map_err(|_| "push handoff encoding was not UTF-8".to_owned())?;
    let envelope = serde_json::to_vec(&Envelope {
        version: VERSION,
        payload,
        mac,
    })
    .map_err(|_| "cannot encode authenticated push handoff".to_owned())?;
    let mut file = NamedTempFile::new_in(&paths.state_dir)
        .map_err(|_| "cannot create private push handoff file".to_owned())?;
    file.write_all(&envelope)
        .and_then(|()| file.as_file().sync_all())
        .map_err(|_| "cannot persist authenticated push handoff".to_owned())?;
    Ok(file)
}

pub fn read(paths: &PersonaPaths, path: &Path) -> Result<PushHandoff, String> {
    paths
        .validate_private_state()
        .map_err(|_| "push handoff state directory is not private".to_owned())?;
    if path.parent() != Some(paths.state_dir.as_path()) {
        return Err("push handoff is outside private Persona state".to_owned());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .map_err(|_| "push handoff file is unavailable or unsafe".to_owned())?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect private push handoff".to_owned())?;
    if !metadata.is_file() || metadata.len() > MAX_HANDOFF_BYTES {
        return Err("push handoff file type or size is invalid".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err("push handoff file permissions are unsafe".to_owned());
        }
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_HANDOFF_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read private push handoff".to_owned())?;
    if bytes.len() as u64 > MAX_HANDOFF_BYTES {
        return Err("push handoff exceeds the size limit".to_owned());
    }
    let envelope: Envelope = serde_json::from_slice(&bytes)
        .map_err(|_| "push handoff envelope is malformed".to_owned())?;
    if envelope.version != VERSION {
        return Err("push handoff version is unsupported".to_owned());
    }
    if !verify_private_state_payload(paths, envelope.payload.as_bytes(), &envelope.mac)
        .map_err(|_| "cannot verify push handoff authentication".to_owned())?
    {
        return Err("push handoff authentication failed".to_owned());
    }
    serde_json::from_str(&envelope.payload)
        .map_err(|_| "push handoff payload is malformed".to_owned())
}

#[cfg(test)]
mod tests {
    use super::{HandoffTuple, PushHandoff, read, write};
    use crate::storage::PersonaPaths;
    use std::fs;
    use tempfile::tempdir;

    fn paths(root: &std::path::Path) -> PersonaPaths {
        PersonaPaths::from_environment(
            Some(root),
            Some(&root.join("config-home")),
            Some(&root.join("state-home")),
        )
        .unwrap()
    }

    fn handoff() -> PushHandoff {
        PushHandoff {
            config_path: "/tmp/persona.toml".into(),
            config_sha256: "a".repeat(64),
            hook_manifest_path: "/tmp/pre-push.json".into(),
            hook_manifest_sha256: "b".repeat(64),
            checkout_root: "/tmp/repository".into(),
            profile: "work".into(),
            remote: "origin".into(),
            destination: "https://github.com/example/repo.git".into(),
            tuples: vec![HandoffTuple {
                local_ref: "refs/heads/main".into(),
                local_oid: "1".repeat(40),
                remote_ref: "refs/heads/main".into(),
                remote_oid: "0".repeat(40),
                expected_lease_oid: None,
            }],
            github_binding: None,
        }
    }

    #[test]
    fn authenticated_handoff_round_trips_and_rejects_tampering() {
        let temporary = tempdir().unwrap();
        let paths = paths(temporary.path());
        let file = write(&paths, &handoff()).unwrap();
        assert_eq!(read(&paths, file.path()).unwrap(), handoff());

        fs::write(file.path(), b"{}").unwrap();
        assert!(read(&paths, file.path()).is_err());
    }

    #[test]
    fn handoff_cannot_be_read_outside_private_state() {
        let temporary = tempdir().unwrap();
        let paths = paths(temporary.path());
        let file = write(&paths, &handoff()).unwrap();
        let elsewhere = temporary.path().join("elsewhere.json");
        fs::copy(file.path(), &elsewhere).unwrap();
        assert!(read(&paths, &elsewhere).is_err());
        let traversal = paths.state_dir.join("../..").join("elsewhere.json");
        assert!(read(&paths, &traversal).is_err());

        let symlink = paths.state_dir.join("handoff-link");
        std::os::unix::fs::symlink(file.path(), &symlink).unwrap();
        assert!(read(&paths, &symlink).is_err());
    }
}
