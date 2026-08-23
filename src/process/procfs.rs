//! Bounded `/proc` readers and process assembly

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Read};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use super::evidence;
use super::model::{
    EnvironmentStatus, ProcessEvidenceFailure, ProcessInfo, ProcessInspectionFailure,
    ProcessListReport, ProcessUids, TargetKind,
};
use crate::error::{Error, Result};

/// Maximum aggregate command-line or environment bytes read from one process
const MAX_PROC_FIELD_SIZE: u64 = 4 * 1024 * 1024;

/// Selected runtime values do not need megabytes of storage
const MAX_ENVIRONMENT_ENTRY_SIZE: u64 = 1024 * 1024;

/// Environment keys that identify Wine or Proton without retaining secrets
const SELECTED_ENVIRONMENT_KEYS: &[&str] = &[
    "WINEPREFIX",
    "STEAM_COMPAT_DATA_PATH",
    "STEAM_COMPAT_CLIENT_INSTALL_PATH",
    "STEAM_COMPAT_TOOL_PATHS",
    "STEAM_COMPAT_APP_ID",
    "SteamAppId",
    "SteamGameId",
    "PROTONPATH",
];

/// Identity fields read before choosing a full or scan-optimized inspection
struct BasicProcessEvidence {
    process_dir: PathBuf,
    name: String,
    executable: Option<PathBuf>,
    failures: Vec<ProcessEvidenceFailure>,
}

/// Stable Linux identity captured from `/proc/<pid>` before evidence reads
#[derive(Debug, Clone, Copy)]
struct LinuxProcessIdentity {
    start_time_ticks: u64,
    uids: ProcessUids,
}

/// One consistent Steam identity assembled from all available sources
struct ProtonIdentity {
    compatdata_dir: Option<PathBuf>,
    app_id: Option<u32>,
    proton_dist: Option<PathBuf>,
    steam_client_path: Option<PathBuf>,
    wine_prefix: Option<PathBuf>,
}

/// Inspects one process without retaining its full environment
///
/// # Errors
///
/// Returns an error when the process does not exist or required `/proc` fields
/// cannot be read
pub fn inspect(pid: u32) -> Result<ProcessInfo> {
    let current_uids = read_uids(0, Path::new("/proc/self/status"))?;
    let process_dir = PathBuf::from(format!("/proc/{pid}"));
    let identity = read_process_identity(pid, &process_dir)?;
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
    if !has_cheap_wine_indicator(&basic.name, basic.executable.as_deref()) {
        verify_process_identity(pid, identity.start_time_ticks)?;
        return Ok(native_process(
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
        .map_err(|source| process_file_error(pid, &name_path, source))?
        .trim()
        .to_owned();
    let executable = read_optional_evidence(pid, &process_dir.join("exe"), &mut evidence_failures)?;

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
    let raw_command = read_command_line(pid, &process_dir.join("cmdline"))?;
    let command = raw_command
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let (environment, environment_status) =
        read_selected_environment(pid, &process_dir.join("environ"))?;
    let command_compatdata_paths = evidence::command_compatdata_paths(&raw_command)?;
    let proton_identity = resolve_proton_identity(&environment, &command_compatdata_paths)?;
    let ProtonIdentity {
        compatdata_dir,
        app_id: steam_app_id,
        proton_dist,
        steam_client_path,
        wine_prefix,
    } = proton_identity;

    let working_directory =
        read_optional_evidence(pid, &process_dir.join("cwd"), &mut evidence_failures)?;

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
    verify_process_identity(pid, identity.start_time_ticks)?;

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
    list_report_internal(false)
}

/// Lists only current-user processes for target selection and Steam polling
#[must_use]
pub fn list_owned_report() -> ProcessListReport {
    list_report_internal(true)
}

/// Lists processes while sharing invariant snapshot data and owner filtering
fn list_report_internal(owned_only: bool) -> ProcessListReport {
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
const fn native_process(
    pid: u32,
    name: String,
    executable: Option<PathBuf>,
    identity: LinuxProcessIdentity,
    current_uids: &ProcessUids,
    evidence_failures: Vec<ProcessEvidenceFailure>,
) -> ProcessInfo {
    ProcessInfo {
        classification_confidence: super::model::ClassificationConfidence::High,
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

/// Preserves the original process-list API for callers that need only rows
#[must_use]
pub fn list() -> Vec<ProcessInfo> {
    list_report().processes
}

/// Reads a NUL-separated command line with a memory ceiling
fn read_command_line(pid: u32, path: &Path) -> Result<Vec<OsString>> {
    let bytes = read_capped(pid, path)?;
    Ok(bytes
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .map(|argument| OsString::from_vec(argument.to_vec()))
        .collect())
}

/// Reads selected environment values while discarding unrelated secrets
fn read_selected_environment(
    pid: u32,
    path: &Path,
) -> Result<(BTreeMap<String, String>, EnvironmentStatus)> {
    let mut selected = BTreeMap::new();
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == ErrorKind::PermissionDenied => {
            return Ok((BTreeMap::new(), EnvironmentStatus::PermissionDenied));
        }
        Err(source) => return Err(process_file_error(pid, path, source)),
    };
    let mut buffer = [0_u8; 16 * 1024];
    let mut entry = Vec::new();
    let mut total_read = 0_u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| process_file_error(pid, path, source))?;
        if count == 0 {
            break;
        }
        total_read = total_read
            .checked_add(u64::try_from(count).map_err(|_| {
                Error::InvalidInput(format!(
                    "process environment read size does not fit in 64 bits: {}",
                    path.display()
                ))
            })?)
            .ok_or_else(|| {
                Error::InvalidInput(format!(
                    "process environment read size overflowed: {}",
                    path.display()
                ))
            })?;
        if total_read > MAX_PROC_FIELD_SIZE {
            return Err(Error::InvalidInput(format!(
                "process environment exceeds the aggregate {MAX_PROC_FIELD_SIZE}-byte limit: {}",
                path.display()
            )));
        }
        for byte in &buffer[..count] {
            if *byte == 0 {
                retain_environment_entry(&entry, path, &mut selected)?;
                entry.clear();
            } else {
                if u64::try_from(entry.len()).unwrap_or(u64::MAX) >= MAX_ENVIRONMENT_ENTRY_SIZE {
                    return Err(Error::InvalidInput(format!(
                        "process environment entry exceeds {MAX_ENVIRONMENT_ENTRY_SIZE} bytes: {}",
                        path.display()
                    )));
                }
                entry.push(*byte);
            }
        }
    }
    retain_environment_entry(&entry, path, &mut selected)?;

    Ok((selected, EnvironmentStatus::Read))
}

/// Retains one selected environment entry without storing unrelated values
fn retain_environment_entry(
    entry: &[u8],
    path: &Path,
    selected: &mut BTreeMap<String, String>,
) -> Result<()> {
    if entry.is_empty() {
        return Ok(());
    }
    let Some(separator) = entry.iter().position(|byte| *byte == b'=') else {
        return Ok(());
    };
    let key = &entry[..separator];
    let Some(selected_key) = SELECTED_ENVIRONMENT_KEYS
        .iter()
        .copied()
        .find(|candidate| candidate.as_bytes() == key)
    else {
        // Unrelated environment values are discarded before text decoding
        return Ok(());
    };
    if selected.contains_key(selected_key) {
        return Err(Error::InvalidProcessEnvironment {
            path: path.to_path_buf(),
            reason: format!("selected key {selected_key} appears more than once"),
        });
    }

    let value = std::str::from_utf8(&entry[separator + 1..]).map_err(|error| {
        Error::InvalidProcessEnvironment {
            path: path.to_path_buf(),
            reason: format!(
                "selected key {selected_key} has invalid UTF-8 at byte {}",
                error.valid_up_to()
            ),
        }
    })?;
    selected.insert(selected_key.to_owned(), value.to_owned());
    Ok(())
}

/// Reads the Linux identity fields that distinguish one PID incarnation
fn read_process_identity(pid: u32, process_dir: &Path) -> Result<LinuxProcessIdentity> {
    let start_time_ticks = read_start_time(pid, &process_dir.join("stat"))?;
    let uids = read_uids(pid, &process_dir.join("status"))?;
    Ok(LinuxProcessIdentity {
        start_time_ticks,
        uids,
    })
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
    let process_dir = PathBuf::from(format!("/proc/{pid}"));
    let actual_start_time_ticks = read_start_time(pid, &process_dir.join("stat"))?;
    if actual_start_time_ticks != expected_start_time_ticks {
        return Err(Error::ProcessIdentityChanged {
            pid,
            expected_start_time_ticks,
            actual_start_time_ticks,
        });
    }

    let actual_filesystem_uid = read_uids(pid, &process_dir.join("status"))?.filesystem;
    let current_filesystem_uid = read_uids(0, Path::new("/proc/self/status"))?.filesystem;
    let final_start_time_ticks = read_start_time(pid, &process_dir.join("stat"))?;
    if final_start_time_ticks != expected_start_time_ticks {
        return Err(Error::ProcessIdentityChanged {
            pid,
            expected_start_time_ticks,
            actual_start_time_ticks: final_start_time_ticks,
        });
    }
    if actual_filesystem_uid != expected_filesystem_uid
        || actual_filesystem_uid != current_filesystem_uid
    {
        return Err(Error::ProcessOwnershipChanged {
            pid,
            expected_filesystem_uid,
            actual_filesystem_uid,
            current_filesystem_uid,
        });
    }
    Ok(())
}

/// Reads `/proc/<pid>/stat` field 22 without splitting the parenthesized name
fn read_start_time(pid: u32, path: &Path) -> Result<u64> {
    let stat = fs::read_to_string(path).map_err(|source| process_file_error(pid, path, source))?;
    parse_start_time(&stat, path)
}

/// Parses field 22 from a Linux stat record
fn parse_start_time(stat: &str, path: &Path) -> Result<u64> {
    let opening_parenthesis = stat.find('(').ok_or_else(|| {
        Error::InvalidInput(format!(
            "procfs stat is missing the process-name delimiter: {}",
            path.display()
        ))
    })?;

    // The comm field may contain spaces or closing parentheses. Try closing
    // delimiters from the right and accept only a valid state plus numeric
    // fields through field 22
    for (relative_offset, _) in stat[opening_parenthesis..].match_indices(')').rev() {
        let closing_parenthesis = opening_parenthesis + relative_offset;
        let mut fields = stat[closing_parenthesis + 1..].split_whitespace();
        let Some(state) = fields.next() else {
            continue;
        };
        if state.len() != 1
            || !state
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
        {
            continue;
        }

        let mut start_time = None;
        let mut valid_fields = true;
        for index in 0..19 {
            let Some(field) = fields.next() else {
                valid_fields = false;
                break;
            };
            if index == 18 {
                start_time = field.parse::<u64>().ok();
            } else if field.parse::<i128>().is_err() {
                valid_fields = false;
                break;
            }
        }
        if valid_fields && let Some(start_time) = start_time {
            return Ok(start_time);
        }
    }

    Err(Error::InvalidInput(format!(
        "procfs stat has no valid start time field: {}",
        path.display()
    )))
}

/// Confirms that the PID still names the same Linux process incarnation
fn verify_process_identity(pid: u32, expected_start_time_ticks: u64) -> Result<()> {
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let actual_start_time_ticks = read_start_time(pid, &path)?;
    if actual_start_time_ticks != expected_start_time_ticks {
        return Err(Error::ProcessIdentityChanged {
            pid,
            expected_start_time_ticks,
            actual_start_time_ticks,
        });
    }
    Ok(())
}

/// Reads all four Linux UIDs from a status file
fn read_uids(pid: u32, path: &Path) -> Result<ProcessUids> {
    let status = fs::read_to_string(path).map_err(|source| {
        if source.kind() == ErrorKind::NotFound && pid != 0 {
            Error::ProcessUnavailable(pid)
        } else {
            Error::io(path, source)
        }
    })?;
    let uid_line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or_else(|| {
            Error::InvalidInput(format!(
                "procfs status is missing Uid fields: {}",
                path.display()
            ))
        })?;
    let mut values = uid_line.split_whitespace().skip(1).map(str::parse::<u32>);

    Ok(ProcessUids {
        real: parse_uid(&mut values, path)?,
        effective: parse_uid(&mut values, path)?,
        saved: parse_uid(&mut values, path)?,
        filesystem: parse_uid(&mut values, path)?,
    })
}

/// Reads one pseudo-file without allowing unbounded allocation
fn read_capped(pid: u32, path: &Path) -> Result<Vec<u8>> {
    let file = fs::File::open(path).map_err(|source| process_file_error(pid, path, source))?;
    let mut bytes = Vec::new();
    file.take(MAX_PROC_FIELD_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| Error::io(path, source))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_PROC_FIELD_SIZE {
        return Err(Error::InvalidInput(format!(
            "process field exceeds {MAX_PROC_FIELD_SIZE} bytes: {}",
            path.display()
        )));
    }
    Ok(bytes)
}

/// Reads optional procfs links without hiding permission failures
fn read_optional_link(pid: u32, path: &Path) -> Result<Option<PathBuf>> {
    match fs::read_link(path) {
        Ok(path) => Ok(Some(path)),
        Err(source) => Err(process_file_error(pid, path, source)),
    }
}

/// Keeps optional evidence failures beside a surviving process row
fn read_optional_evidence(
    pid: u32,
    path: &Path,
    failures: &mut Vec<ProcessEvidenceFailure>,
) -> Result<Option<PathBuf>> {
    match read_optional_link(pid, path) {
        Ok(path) => Ok(path),
        Err(Error::ProcessUnavailable(_)) => Err(Error::ProcessUnavailable(pid)),
        Err(error) => {
            failures.push(evidence_failure(&error));
            Ok(None)
        }
    }
}

/// Converts one retained optional-read error into the public evidence model
fn evidence_failure(error: &Error) -> ProcessEvidenceFailure {
    ProcessEvidenceFailure {
        kind: error.kind().into(),
        message: error.to_string(),
    }
}

/// Detects likely Wine or guest processes before reading larger procfs fields
fn has_cheap_wine_indicator(name: &str, executable: Option<&Path>) -> bool {
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

/// Converts one procfs race into the transient process error category
fn process_file_error(pid: u32, path: &Path, source: std::io::Error) -> Error {
    if source.kind() == ErrorKind::NotFound {
        Error::ProcessUnavailable(pid)
    } else {
        Error::io(path, source)
    }
}

/// Parses one UID while retaining malformed procfs data as an error
fn parse_uid(
    values: &mut impl Iterator<Item = std::result::Result<u32, std::num::ParseIntError>>,
    path: &Path,
) -> Result<u32> {
    values
        .next()
        .ok_or_else(|| {
            Error::InvalidInput(format!(
                "procfs status has too few Uid fields: {}",
                path.display()
            ))
        })?
        .map_err(|_| {
            Error::InvalidInput(format!(
                "procfs status has an invalid UID: {}",
                path.display()
            ))
        })
}

/// Converts one retained inspection error into structured scan diagnostics
fn inspection_failure(pid: Option<u32>, error: &Error) -> ProcessInspectionFailure {
    ProcessInspectionFailure {
        pid,
        kind: error.kind().into(),
        message: error.to_string(),
    }
}

/// Resolves all Steam/Proton identity sources without precedence-based guesses
fn resolve_proton_identity(
    environment: &BTreeMap<String, String>,
    command_compatdata_paths: &[PathBuf],
) -> Result<ProtonIdentity> {
    let (compatdata_dir, app_id) =
        resolve_steam_identity_sources(environment, command_compatdata_paths)?;
    let (wine_prefix, proton_dist, steam_client_path) =
        resolve_runtime_identity(environment, compatdata_dir.as_deref())?;

    Ok(ProtonIdentity {
        compatdata_dir,
        app_id,
        proton_dist,
        steam_client_path,
        wine_prefix,
    })
}

/// Reconciles compatdata paths and Steam application identifiers
fn resolve_steam_identity_sources(
    environment: &BTreeMap<String, String>,
    command_compatdata_paths: &[PathBuf],
) -> Result<(Option<PathBuf>, Option<u32>)> {
    let environment_path = environment.get("STEAM_COMPAT_DATA_PATH").map(PathBuf::from);
    if let Some(path) = environment_path.as_deref() {
        require_absolute_runtime_path("STEAM_COMPAT_DATA_PATH", path)?;
    }
    let mut path_candidates = Vec::new();
    if let Some(path) = environment_path {
        path_candidates.push(("STEAM_COMPAT_DATA_PATH".to_owned(), path));
    }
    path_candidates.extend(
        command_compatdata_paths
            .iter()
            .cloned()
            .map(|path| ("command line".to_owned(), path)),
    );

    let mut unique_paths: Vec<(String, PathBuf)> = Vec::new();
    for (source, path) in path_candidates {
        if unique_paths
            .iter()
            .any(|(_, existing)| equivalent_identity_path(existing, &path))
        {
            continue;
        }
        unique_paths.push((source, path));
    }
    if unique_paths.len() > 1 {
        return Err(Error::SteamIdentityConflict {
            details: format!(
                "compatdata paths disagree: {}",
                format_identity_paths(&unique_paths)
            ),
        });
    }

    let app_id_candidates = steam_app_id_candidates(environment, &unique_paths)?;
    let app_id = reconcile_app_ids(&app_id_candidates)?;
    let compatdata_dir = unique_paths.first().map(|(_, path)| path.clone());
    Ok((compatdata_dir, app_id))
}

/// Validates one prefix and all runtime paths used by Proton invocation
fn resolve_runtime_identity(
    environment: &BTreeMap<String, String>,
    compatdata_dir: Option<&Path>,
) -> Result<(Option<PathBuf>, Option<PathBuf>, Option<PathBuf>)> {
    let environment_prefix = environment.get("WINEPREFIX").map(PathBuf::from);
    if let Some(path) = environment_prefix.as_deref() {
        require_absolute_runtime_path("WINEPREFIX", path)?;
    }
    let compatdata_prefix = compatdata_dir.as_ref().map(|path| path.join("pfx"));
    let wine_prefix = match (environment_prefix, compatdata_prefix) {
        (Some(environment_prefix), Some(compatdata_prefix)) => {
            if !equivalent_identity_path(&environment_prefix, &compatdata_prefix) {
                return Err(Error::SteamIdentityConflict {
                    details: format!(
                        "WINEPREFIX={} does not match STEAM_COMPAT_DATA_PATH/pfx={}",
                        environment_prefix.display(),
                        compatdata_prefix.display()
                    ),
                });
            }
            Some(environment_prefix)
        }
        (Some(environment_prefix), None) => Some(environment_prefix),
        (None, Some(compatdata_prefix)) => Some(compatdata_prefix),
        (None, None) => None,
    }
    .map(|path| require_runtime_directory("Wine prefix", path))
    .transpose()?;

    let proton_dist = resolve_proton_dist(environment)?;
    let steam_client_path = environment
        .get("STEAM_COMPAT_CLIENT_INSTALL_PATH")
        .map(PathBuf::from);
    if let Some(path) = steam_client_path.as_deref() {
        require_absolute_runtime_path("STEAM_COMPAT_CLIENT_INSTALL_PATH", path)?;
    }

    Ok((wine_prefix, proton_dist, steam_client_path))
}

/// Resolves the explicit Proton path or the first documented tool path
fn resolve_proton_dist(environment: &BTreeMap<String, String>) -> Result<Option<PathBuf>> {
    if let Some(value) = environment.get("PROTONPATH") {
        let path = PathBuf::from(value);
        require_absolute_runtime_path("PROTONPATH", &path)?;
        return Ok(Some(path));
    }

    let mut first_tool_path = None;
    if let Some(value) = environment.get("STEAM_COMPAT_TOOL_PATHS") {
        for tool_path in value.split(':').filter(|path| !path.is_empty()) {
            let path = PathBuf::from(tool_path);
            require_absolute_runtime_path("STEAM_COMPAT_TOOL_PATHS", &path)?;
            if first_tool_path.is_none() {
                first_tool_path = Some(path);
            }
        }
    }
    Ok(first_tool_path)
}

/// Collects every AppID-bearing environment and path source
fn steam_app_id_candidates(
    environment: &BTreeMap<String, String>,
    paths: &[(String, PathBuf)],
) -> Result<Vec<(String, u32)>> {
    let mut candidates = Vec::new();
    for key in ["STEAM_COMPAT_APP_ID", "SteamAppId", "SteamGameId"] {
        if let Some(value) = environment.get(key) {
            let app_id = value
                .parse::<u32>()
                .map_err(|_| Error::SteamIdentityConflict {
                    details: format!("{key} is not a valid numeric AppID: {value:?}"),
                })?;
            candidates.push((key.to_owned(), app_id));
        }
    }
    for (source, path) in paths {
        let app_id =
            steam_app_id_from_compatdata_dir(path).ok_or_else(|| Error::SteamIdentityConflict {
                details: format!(
                    "{source} does not end in a numeric compatdata AppID: {}",
                    path.display()
                ),
            })?;
        candidates.push((format!("{source} path"), app_id));
    }
    Ok(candidates)
}

/// Requires every available `AppID` source to identify the same game
fn reconcile_app_ids(candidates: &[(String, u32)]) -> Result<Option<u32>> {
    let Some(first_app_id) = candidates.first().map(|(_, app_id)| *app_id) else {
        return Ok(None);
    };
    if candidates.iter().all(|(_, app_id)| *app_id == first_app_id) {
        return Ok(Some(first_app_id));
    }

    Err(Error::SteamIdentityConflict {
        details: format!(
            "AppID candidates disagree: {}",
            candidates
                .iter()
                .map(|(source, app_id)| format!("{source}={app_id}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    })
}

/// Rejects runtime paths that cannot identify a Linux filesystem location
fn require_absolute_runtime_path(name: &str, path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(Error::SteamIdentityConflict {
            details: format!("{name} must be absolute: {}", path.display()),
        });
    }
    Ok(())
}

/// Requires an identity-bearing runtime path to exist and be a directory
fn require_runtime_directory(name: &str, path: PathBuf) -> Result<PathBuf> {
    let metadata = fs::metadata(&path).map_err(|source| Error::io(&path, source))?;
    if !metadata.is_dir() {
        return Err(Error::SteamIdentityConflict {
            details: format!("{name} is not a directory: {}", path.display()),
        });
    }
    Ok(path)
}

/// Treats identical or already-canonicalized paths as one identity value
fn equivalent_identity_path(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }

    left.canonicalize()
        .ok()
        .zip(right.canonicalize().ok())
        .is_some_and(|(left, right)| left == right)
}

/// Formats path sources without hiding which identity disagreed
fn format_identity_paths(paths: &[(String, PathBuf)]) -> String {
    paths
        .iter()
        .map(|(source, path)| format!("{source}={}", path.display()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Extracts an application identifier from a compatdata directory
fn steam_app_id_from_compatdata_dir(path: &Path) -> Option<u32> {
    path.file_name()?.to_str()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{parse_start_time, read_uids};
    use crate::Error;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn stat_start_time_accepts_lowercase_tracing_stop_and_complex_comm() {
        let mut fields = vec!["1"; 19];
        fields[18] = "123456";
        let stat = format!("123 (worker) name) t {}", fields.join(" "));

        let start_time = parse_start_time(&stat, Path::new("/proc/123/stat"))
            .expect("valid tracing-stop stat record");

        assert_eq!(start_time, 123_456);
    }

    #[test]
    fn stat_start_time_handles_a_process_name_without_a_later_closing_parenthesis() {
        let mut fields = vec!["1"; 19];
        fields[18] = "654321";
        let stat = format!("987654 (worker) t {}", fields.join(" "));

        let start_time = parse_start_time(&stat, Path::new("/proc/987654/stat"))
            .expect("valid stat record with one closing delimiter");

        assert_eq!(start_time, 654_321);
    }

    #[test]
    fn stat_start_time_rejects_a_multi_character_process_state() {
        let stat = format!("123 (worker) tt {}", ["1"; 19].join(" "));

        let error = parse_start_time(&stat, Path::new("/proc/123/stat"))
            .expect_err("a multi-character process state is malformed");

        assert!(matches!(error, Error::InvalidInput(_)));
    }

    #[test]
    fn missing_nonzero_pid_status_is_a_transient_process_error() {
        let directory = tempdir().expect("temporary directory");
        let error = read_uids(123, &directory.path().join("missing-status"))
            .expect_err("missing process status");

        assert!(matches!(error, Error::ProcessUnavailable(123)));
    }

    #[test]
    fn missing_pid_zero_status_keeps_the_filesystem_error() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("missing-status");
        let error = read_uids(0, &path).expect_err("missing PID zero status");

        assert!(matches!(error, Error::Io { .. }));
    }
}
