//! Process inspection orchestration

use std::fs;
use std::path::{Path, PathBuf};

use super::model::{
    ProcessEvidenceFailure, ProcessInfo, ProcessListReport, ProcessUids, TargetKind,
};
use super::{evidence, proton};
use crate::error::{Error, Result};

mod reader;
mod scan;

use reader::LinuxProcessIdentity;

struct BasicProcessEvidence {
    process_dir: PathBuf,
    name: String,
    executable: Option<PathBuf>,
    failures: Vec<ProcessEvidenceFailure>,
}

/// Inspects one process without retaining its full environment
///
/// # Errors
///
/// Returns an error when the process does not exist or required `/proc` fields
/// cannot be read
pub fn inspect(pid: u32) -> Result<ProcessInfo> {
    let current_uids = reader::read_uids(0, Path::new("/proc/self/status"))?;
    let process_dir = PathBuf::from(format!("/proc/{pid}"));
    let identity = reader::read_process_identity(pid, &process_dir)?;
    inspect_with_identity(pid, &current_uids, identity)
}

/// Inspects one process with the complete evidence model
fn inspect_with_identity(
    pid: u32,
    current_uids: &ProcessUids,
    identity: LinuxProcessIdentity,
) -> Result<ProcessInfo> {
    let basic = read_basic_process_evidence(pid)?;
    inspect_full_process(
        pid,
        &basic.process_dir,
        basic.name,
        basic.executable,
        current_uids,
        identity,
        basic.failures,
    )
}

/// Inspects one process using the cheap gate reserved for broad scans
fn inspect_for_scan(
    pid: u32,
    current_uids: &ProcessUids,
    identity: LinuxProcessIdentity,
) -> Result<ProcessInfo> {
    let basic = read_basic_process_evidence(pid)?;
    if !scan::has_cheap_wine_indicator(&basic.name, basic.executable.as_deref()) {
        reader::verify_process_identity(pid, identity.start_time_ticks)?;
        return Ok(scan::native_process(
            pid,
            basic.name,
            basic.executable,
            identity,
            current_uids,
            basic.failures,
        ));
    }

    inspect_full_process(
        pid,
        &basic.process_dir,
        basic.name,
        basic.executable,
        current_uids,
        identity,
        basic.failures,
    )
}

/// Reads the identity evidence shared by authoritative and scan paths
fn read_basic_process_evidence(pid: u32) -> Result<BasicProcessEvidence> {
    let process_dir = PathBuf::from(format!("/proc/{pid}"));
    if !process_dir.is_dir() {
        return Err(Error::ProcessUnavailable(pid));
    }

    let mut evidence_failures = Vec::new();
    let name_path = process_dir.join("comm");
    let name = fs::read_to_string(&name_path)
        .map_err(|source| reader::process_file_error(pid, &name_path, source))?
        .trim()
        .to_owned();
    let executable =
        reader::read_optional_evidence(pid, &process_dir.join("exe"), &mut evidence_failures)?;

    Ok(BasicProcessEvidence {
        process_dir,
        name,
        executable,
        failures: evidence_failures,
    })
}

/// Reads the complete process evidence after identity fields are available
fn inspect_full_process(
    pid: u32,
    process_dir: &Path,
    name: String,
    executable: Option<PathBuf>,
    current_uids: &ProcessUids,
    identity: LinuxProcessIdentity,
    mut evidence_failures: Vec<ProcessEvidenceFailure>,
) -> Result<ProcessInfo> {
    let raw_command = reader::read_command_line(pid, &process_dir.join("cmdline"))?;
    let command = raw_command
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let (environment, environment_status) =
        reader::read_selected_environment(pid, &process_dir.join("environ"))?;
    let command_compatdata_paths = evidence::command_compatdata_paths(&raw_command)?;
    let proton_identity = proton::resolve_proton_identity(&environment, &command_compatdata_paths)?;
    let proton::ProtonIdentity {
        compatdata_dir,
        app_id: steam_app_id,
        proton_dist,
        steam_client_path,
        wine_prefix,
    } = proton_identity;

    let working_directory =
        reader::read_optional_evidence(pid, &process_dir.join("cwd"), &mut evidence_failures)?;

    let process_evidence = evidence::collect(
        &name,
        executable.as_deref(),
        &raw_command,
        &environment,
        !command_compatdata_paths.is_empty(),
    );
    let (target_kind, classification_confidence) = evidence::classify(&process_evidence);

    // Native discovery does not inspect host ELF files because no native
    // injection backend consumes that architecture
    let guest_result = if target_kind == TargetKind::WineProtonWindows {
        Some(evidence::find_guest_executable(
            &raw_command,
            wine_prefix.as_deref(),
            working_directory.as_deref(),
        ))
    } else {
        None
    };

    // The process must still be the process whose identity was captured before
    // any command, environment, or guest-path resolution work
    reader::verify_process_identity(pid, identity.start_time_ticks)?;

    let (guest_executable, guest_architecture) = match guest_result {
        Some(result) => result?.map_or((None, None), |(candidate, architecture)| {
            (Some(candidate), Some(architecture))
        }),
        None => (None, None),
    };

    Ok(ProcessInfo {
        classification_confidence,
        command,
        compatdata_dir,
        environment_status,
        evidence_failures,
        executable,
        guest_architecture,
        guest_executable,
        name,
        owned_by_current_user: Some(identity.uids.filesystem == current_uids.filesystem),
        pid,
        start_time_ticks: identity.start_time_ticks,
        proton_dist,
        steam_app_id,
        steam_client_path,
        target_kind,
        uids: Some(identity.uids),
        wine_prefix,
    })
}

/// Lists every process and retains non-transient inspection failures
#[must_use]
pub fn list_report() -> ProcessListReport {
    scan::list_report_internal(false)
}

/// Lists only current-user processes for target selection and Steam polling
#[must_use]
pub fn list_owned_report() -> ProcessListReport {
    scan::list_report_internal(true)
}

/// Preserves the original process-list API for callers that need only rows
#[must_use]
pub fn list() -> Vec<ProcessInfo> {
    list_report().processes
}

/// Revalidates a process identity immediately before a mutating operation
///
/// # Errors
///
/// Returns an error when the PID disappeared, was reused, ownership changed,
/// or its stat record could not be parsed
pub fn revalidate_identity(
    pid: u32,
    expected_start_time_ticks: u64,
    expected_filesystem_uid: u32,
) -> Result<()> {
    reader::revalidate_identity(pid, expected_start_time_ticks, expected_filesystem_uid)
}
