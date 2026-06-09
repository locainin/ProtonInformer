//! Safe inspection and cleanup of controller-managed run state.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result};

/// One validated run directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunState {
    /// Seconds elapsed since the directory modification time.
    pub age_seconds: u64,
    /// Request UUID represented by the directory.
    pub request_id: String,
    /// Managed run directory path.
    pub path: PathBuf,
}

/// Run-state listing with retained validation warnings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunStateReport {
    /// State root inspected by this operation.
    pub root: PathBuf,
    /// Valid owner-controlled run directories.
    pub runs: Vec<RunState>,
    /// Entries skipped because they were not safe managed state.
    pub warnings: Vec<String>,
}

/// Cleanup result for one managed state root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupReport {
    /// Number of run directories removed.
    pub removed: usize,
    /// State root inspected by this operation.
    pub root: PathBuf,
    /// Entries skipped because they were not safe managed state.
    pub warnings: Vec<String>,
}

/// Lists run state from the configured XDG or HOME state directory.
///
/// # Errors
///
/// Returns an error when the managed root cannot be inspected safely.
pub fn list() -> Result<RunStateReport> {
    list_in(&crate::helper_runtime::state_directory())
}

/// Lists run state under one explicit root.
///
/// This boundary supports deterministic tests and administrative callers.
///
/// # Errors
///
/// Returns an error when the root or runs directory cannot be inspected.
pub fn list_in(root: &Path) -> Result<RunStateReport> {
    let runs_root = root.join("runs");
    if !runs_root.exists() {
        return Ok(RunStateReport {
            root: root.to_path_buf(),
            runs: Vec::new(),
            warnings: Vec::new(),
        });
    }
    validate_root(&runs_root)?;
    let current_uid = current_uid()?;
    let now = SystemTime::now();
    let mut runs = Vec::new();
    let mut warnings = Vec::new();
    for entry in fs::read_dir(&runs_root).map_err(|source| Error::io(&runs_root, source))? {
        let entry = entry.map_err(|source| Error::io(&runs_root, source))?;
        match inspect_entry(&entry.path(), current_uid, now) {
            Ok(run) => runs.push(run),
            Err(error) => warnings.push(error.to_string()),
        }
    }
    runs.sort_unstable_by(|left, right| left.request_id.cmp(&right.request_id));
    Ok(RunStateReport {
        root: root.to_path_buf(),
        runs,
        warnings,
    })
}

/// Removes safe managed runs older than an optional threshold.
///
/// # Errors
///
/// Returns an error when listing or deleting a validated run fails.
pub fn cleanup(older_than: Option<Duration>) -> Result<CleanupReport> {
    cleanup_in(&crate::helper_runtime::state_directory(), older_than)
}

/// Removes safe managed runs under one explicit root.
///
/// # Errors
///
/// Returns an error when listing or deleting a validated run fails.
pub fn cleanup_in(root: &Path, older_than: Option<Duration>) -> Result<CleanupReport> {
    let report = list_in(root)?;
    let current_uid = current_uid()?;
    let mut removed = 0_usize;
    let mut warnings = report.warnings;
    for run in report.runs {
        if older_than.is_some_and(|threshold| run.age_seconds < threshold.as_secs()) {
            continue;
        }
        match inspect_entry(&run.path, current_uid, SystemTime::now()) {
            Ok(current) if current.request_id == run.request_id => {
                fs::remove_dir_all(&run.path).map_err(|source| Error::io(&run.path, source))?;
                removed = removed.saturating_add(1);
            }
            Ok(_) => warnings.push(format!(
                "run identity changed before cleanup: {}",
                run.path.display()
            )),
            Err(error) => warnings.push(error.to_string()),
        }
    }
    Ok(CleanupReport {
        removed,
        root: root.to_path_buf(),
        warnings,
    })
}

/// Parses compact cleanup ages such as `30m`, `12h`, or `7d`.
///
/// # Errors
///
/// Returns an error for missing, zero, overflowing, or unknown units.
pub fn parse_age(value: &str) -> Result<Duration> {
    let value = value.trim();
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .ok_or_else(|| Error::InvalidInput("age requires a unit: s, m, h, or d".into()))?;
    let (amount, unit) = value.split_at(split);
    let amount = amount
        .parse::<u64>()
        .map_err(|_| Error::InvalidInput("age must start with a positive integer".into()))?;
    if amount == 0 {
        return Err(Error::InvalidInput("age must be greater than zero".into()));
    }
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => return Err(Error::InvalidInput("age unit must be s, m, h, or d".into())),
    };
    let seconds = amount
        .checked_mul(multiplier)
        .ok_or_else(|| Error::InvalidInput("age exceeds the supported range".into()))?;
    Ok(Duration::from_secs(seconds))
}

/// Validates the owner-only managed runs root.
fn validate_root(runs_root: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(runs_root).map_err(|source| Error::io(runs_root, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::Rejected(format!(
            "run-state root is not a real directory: {}",
            runs_root.display()
        )));
    }
    if metadata.uid() != current_uid()? || metadata.mode() & 0o077 != 0 {
        return Err(Error::Rejected(format!(
            "run-state root is not owner-only: {}",
            runs_root.display()
        )));
    }
    Ok(())
}

/// Validates one direct UUID directory without following symlinks.
fn inspect_entry(path: &Path, current_uid: u32, now: SystemTime) -> Result<RunState> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::Rejected(format!("run name is not UTF-8: {}", path.display())))?;
    Uuid::parse_str(name)
        .map_err(|_| Error::Rejected(format!("run name is not a UUID: {}", path.display())))?;
    let metadata = fs::symlink_metadata(path).map_err(|source| Error::io(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::Rejected(format!(
            "run entry is not a real directory: {}",
            path.display()
        )));
    }
    if metadata.uid() != current_uid || metadata.mode() & 0o077 != 0 {
        return Err(Error::Rejected(format!(
            "run entry is not owner-only: {}",
            path.display()
        )));
    }
    let modified = metadata
        .modified()
        .map_err(|source| Error::io(path, source))?;
    let age_seconds = now
        .duration_since(modified)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    Ok(RunState {
        age_seconds,
        request_id: name.to_owned(),
        path: path.to_path_buf(),
    })
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
