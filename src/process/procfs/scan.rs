//! Volatile /proc process scanning and discovery diagnostics

use std::fs;
use std::path::{Path, PathBuf};

use super::super::model::{
    ClassificationConfidence, EnvironmentStatus, ProcessEvidenceFailure, ProcessInfo,
    ProcessInspectionFailure, ProcessListReport, ProcessUids, TargetKind,
};
use super::reader::{LinuxProcessIdentity, read_process_identity, read_uids};
use super::{inspect_for_scan, inspect_with_identity};
use crate::error::Error;

/// Lists processes while sharing invariant snapshot data and owner filtering
pub(super) fn list_report_internal(owned_only: bool) -> ProcessListReport {
    let current_uids = match read_uids(0, Path::new("/proc/self/status")) {
        Ok(uids) => uids,
        Err(error) => {
            return ProcessListReport {
                processes: Vec::new(),
                rejections: vec![inspection_failure(None, &error)],
            };
        }
    };
    let entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(source) => {
            return ProcessListReport {
                processes: Vec::new(),
                rejections: vec![inspection_failure(None, &Error::io("/proc", source))],
            };
        }
    };

    let mut processes = Vec::new();
    let mut rejections = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(source) => {
                rejections.push(inspection_failure(None, &Error::io("/proc", source)));
                continue;
            }
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };

        let process_dir = entry.path();
        let identity = match read_process_identity(pid, &process_dir) {
            Ok(identity) => identity,
            // A process disappearing during a scan is expected
            Err(Error::ProcessUnavailable(_)) => continue,
            Err(error) => {
                rejections.push(inspection_failure(Some(pid), &error));
                continue;
            }
        };
        if owned_only && identity.uids.filesystem != current_uids.filesystem {
            // Foreign processes are expected exclusions from an owned scan
            continue;
        }

        let inspected = if owned_only {
            inspect_for_scan(pid, &current_uids, identity)
        } else {
            inspect_with_identity(pid, &current_uids, identity)
        };
        match inspected {
            Ok(process) => processes.push(process),
            // A process disappearing during a scan is expected
            Err(Error::ProcessUnavailable(_)) => {}
            Err(error) => rejections.push(inspection_failure(Some(pid), &error)),
        }
    }
    processes.sort_by_key(|process| process.pid);
    ProcessListReport {
        processes,
        rejections,
    }
}

/// Builds a cheap native row after non-Wine evidence is ruled out
pub(super) const fn native_process(
    pid: u32,
    name: String,
    executable: Option<PathBuf>,
    identity: LinuxProcessIdentity,
    current_uids: &ProcessUids,
    evidence_failures: Vec<ProcessEvidenceFailure>,
) -> ProcessInfo {
    ProcessInfo {
        classification_confidence: ClassificationConfidence::High,
        command: Vec::new(),
        compatdata_dir: None,
        environment_status: EnvironmentStatus::NotInspected,
        evidence_failures,
        executable,
        guest_architecture: None,
        guest_executable: None,
        name,
        owned_by_current_user: Some(identity.uids.filesystem == current_uids.filesystem),
        pid,
        start_time_ticks: identity.start_time_ticks,
        proton_dist: None,
        steam_app_id: None,
        steam_client_path: None,
        target_kind: TargetKind::NativeLinux,
        uids: Some(identity.uids),
        wine_prefix: None,
    }
}

/// Detects likely Wine or guest processes before reading larger procfs fields
pub(super) fn has_cheap_wine_indicator(name: &str, executable: Option<&Path>) -> bool {
    let is_candidate_name = |value: &str| {
        let value = value.to_ascii_lowercase();
        Path::new(&value)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
            || matches!(
                value.as_str(),
                "wine" | "wine64" | "wine-preloader" | "wine64-preloader" | "wineserver" | "proton"
            )
    };
    is_candidate_name(name)
        || executable
            .and_then(Path::file_name)
            .and_then(|value| value.to_str())
            .is_some_and(is_candidate_name)
}

/// Converts one retained inspection error into structured scan diagnostics
fn inspection_failure(pid: Option<u32>, error: &Error) -> ProcessInspectionFailure {
    ProcessInspectionFailure {
        pid,
        kind: error.kind().into(),
        message: error.to_string(),
    }
}
