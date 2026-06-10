//! Owner-only payload staging and request state management.

use std::env;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::Serialize;
use uuid::Uuid;

use crate::binary::BinaryInspection;
use crate::error::{Error, Result};
use crate::wine;

use super::model::PayloadPathMode;

/// Selects the payload file that should appear in the helper request
///
/// # Errors
///
/// Returns an error when staged-copy mode cannot copy or re-inspect the payload
pub fn prepare_payload_for_request(
    payload: &BinaryInspection,
    run_directory: &Path,
    payload_path_mode: PayloadPathMode,
) -> Result<BinaryInspection> {
    match payload_path_mode {
        PayloadPathMode::StagedCopy => stage_payload(payload, run_directory),
        PayloadPathMode::OriginalPath => Ok(payload.clone()),
    }
}

/// Copies one inspected payload into owner-only request state
fn stage_payload(payload: &BinaryInspection, run_directory: &Path) -> Result<BinaryInspection> {
    let file_name = payload.path.file_name().ok_or_else(|| {
        Error::InvalidInput(format!(
            "payload path has no file name: {}",
            payload.path.display()
        ))
    })?;
    let payload_directory = run_directory.join("payload");
    fs::create_dir(&payload_directory).map_err(|error| Error::io(&payload_directory, error))?;
    fs::set_permissions(&payload_directory, fs::Permissions::from_mode(0o700))
        .map_err(|error| Error::io(&payload_directory, error))?;
    validate_owner_directory(&payload_directory)?;
    let staged_path = payload_directory.join(file_name);
    let mut source = File::open(&payload.path).map_err(|error| Error::io(&payload.path, error))?;
    let source_before = source
        .metadata()
        .map_err(|error| Error::io(&payload.path, error))?;
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged_path)
        .map_err(|error| Error::io(&staged_path, error))?;
    let mut buffer = [0_u8; 16 * 1024];
    let mut copied = 0_u64;
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|error| Error::io(&payload.path, error))?;
        if count == 0 {
            break;
        }
        copied =
            copied
                .checked_add(u64::try_from(count).map_err(|_| {
                    Error::InvalidInput("payload read count does not fit u64".into())
                })?)
                .ok_or_else(|| Error::InvalidInput("payload size overflowed u64".into()))?;
        if copied > payload.size_bytes {
            return Err(Error::InvalidInput(
                "payload grew while it was being staged".into(),
            ));
        }
        destination
            .write_all(&buffer[..count])
            .map_err(|error| Error::io(&staged_path, error))?;
    }
    if copied != payload.size_bytes {
        return Err(Error::InvalidInput(format!(
            "payload changed while staging: expected {} bytes, copied {copied}",
            payload.size_bytes
        )));
    }
    let source_after = source
        .metadata()
        .map_err(|error| Error::io(&payload.path, error))?;
    if !same_file_snapshot(&source_before, &source_after) {
        return Err(Error::InvalidInput(
            "payload metadata changed while staging".into(),
        ));
    }
    destination
        .sync_all()
        .map_err(|error| Error::io(&staged_path, error))?;
    let staged = crate::binary::inspect(&staged_path)?;
    if staged.format != payload.format || staged.architecture != payload.architecture {
        return Err(Error::InvalidInput(
            "staged payload headers differ from the inspected source".into(),
        ));
    }
    Ok(staged)
}

/// Compares stable Linux file identity and change indicators around one copy.
fn same_file_snapshot(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

/// Creates one owner-only run directory.
/// Creates a request directory visible through the selected prefix mappings.
///
/// # Errors
///
/// Returns an error for invalid request identifiers, filesystem failures, or
/// prefixes with neither a mapped state directory nor a configured C: drive.
pub fn create_request_directory(prefix: &Path, request_id: &str) -> Result<PathBuf> {
    Uuid::parse_str(request_id)
        .map_err(|error| Error::InvalidInput(format!("invalid request UUID: {error}")))?;
    let primary_root = state_directory();
    let primary = create_owner_directory(&primary_root, request_id)?;
    if wine::unix_path_to_windows(prefix, &primary).is_ok() {
        return Ok(primary);
    }
    let _ = fs::remove_dir(&primary);

    // A configured C: mapping is a prefix-local fallback when no drive exposes
    // the Linux state directory
    let c_root = wine::drive_mappings(prefix)?
        .into_iter()
        .find_map(|(drive, root)| (drive == 'c').then_some(root))
        .ok_or_else(|| {
            Error::InvalidInput(
                "neither the state directory nor a configured C: drive is available to Wine".into(),
            )
        })?;
    create_owner_directory(&c_root.join(".proton-informer"), request_id)
}

/// Creates owner-only root, runs, and request directory levels.
fn create_owner_directory(root: &Path, request_id: &str) -> Result<PathBuf> {
    let runs = root.join("runs");
    let directory = runs.join(request_id);
    for path in [root, runs.as_path(), directory.as_path()] {
        create_private_directory(path)?;
        validate_owner_directory_shape(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|source| Error::io(path, source))?;
        validate_owner_directory(path)?;
    }
    Ok(directory)
}

/// Creates one missing directory tree with owner-only modes from creation.
fn create_private_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => return Ok(()),
        Ok(_) => {
            return Err(Error::Rejected(format!(
                "state path is not a real directory: {}",
                path.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(Error::io(path, error)),
    }

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        create_private_directory(parent)?;
    }

    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(Error::io(path, error)),
    }
}

/// Verifies a created state directory without following symlinks.
fn validate_owner_directory(path: &Path) -> Result<()> {
    let metadata = validate_owner_directory_shape(path)?;
    if metadata.mode() & 0o777 != 0o700 {
        return Err(Error::Rejected(format!(
            "state path is not mode 0700: {}",
            path.display()
        )));
    }
    Ok(())
}

/// Verifies directory type and owner before any permission changes.
fn validate_owner_directory_shape(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).map_err(|source| Error::io(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::Rejected(format!(
            "state path is not a real directory: {}",
            path.display()
        )));
    }
    if metadata.uid() != current_uid()? {
        return Err(Error::Rejected(format!(
            "state path is not owned by the current user: {}",
            path.display()
        )));
    }
    Ok(metadata)
}

/// Writes one owner-only JSON file without following a pre-existing file.
pub(super) fn write_private_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(Error::from)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| Error::io(path, source))?;
    file.write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|source| Error::io(path, source))
}

/// Returns the state root without assuming one user's home path.
pub fn state_directory() -> PathBuf {
    env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .unwrap_or_else(env::temp_dir)
        .join("proton-informer")
}

/// Reads the effective process UID from procfs without adding an FFI boundary.
fn current_uid() -> Result<u32> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|source| Error::io("/proc/self/status", source))?;
    let line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or_else(|| Error::Rejected("procfs did not report process UIDs".into()))?;
    line.split_ascii_whitespace()
        .nth(2)
        .ok_or_else(|| Error::Rejected("procfs effective UID is missing".into()))?
        .parse::<u32>()
        .map_err(|_| Error::Rejected("procfs effective UID is invalid".into()))
}
