//! Process inspection orchestration

use std::fs;
use std::path::{Path, PathBuf};

use std::collections::BTreeMap;

use super::evidence;
use super::model::{
    ProcessEvidenceFailure, ProcessInfo, ProcessListReport, ProcessUids, TargetKind,
};
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
    let proton_identity = resolve_proton_identity(&environment, &command_compatdata_paths)?;
    let ProtonIdentity {
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
