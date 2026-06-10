//! Bounded `/proc` readers and process assembly

use std::collections::BTreeMap;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use super::evidence;
use super::model::{EnvironmentStatus, ProcessInfo, ProcessUids, TargetKind};
use crate::binary;
use crate::error::{Error, Result};
use crate::types::Architecture;

/// Maximum command-line or environment bytes retained from one process
const MAX_PROC_FIELD_SIZE: u64 = 4 * 1024 * 1024;

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

/// Inspects one process without retaining its full environment
///
/// # Errors
///
/// Returns an error when the process does not exist or required `/proc` fields
/// cannot be read
pub fn inspect(pid: u32) -> Result<ProcessInfo> {
    let process_dir = PathBuf::from(format!("/proc/{pid}"));
    if !process_dir.is_dir() {
        return Err(Error::ProcessUnavailable(pid));
    }

    let name_path = process_dir.join("comm");
    let name = fs::read_to_string(&name_path)
        .map_err(|source| Error::io(&name_path, source))?
        .trim()
        .to_owned();
    let executable = fs::read_link(process_dir.join("exe")).ok();
    let working_directory = fs::read_link(process_dir.join("cwd")).ok();
    let command = read_command_line(&process_dir.join("cmdline"))?;
    let uids = read_uids(&process_dir.join("status"));
    let current_uids = read_uids(Path::new("/proc/self/status"));
    let (environment, environment_status) = read_selected_environment(&process_dir.join("environ"));

    let compatdata_dir = environment
        .get("STEAM_COMPAT_DATA_PATH")
        .map(PathBuf::from)
        .or_else(|| {
            command
                .iter()
                .find_map(|value| evidence::host_compatdata_path(value))
        });
    let wine_prefix = wine_prefix_from_environment(&environment).or_else(|| {
        compatdata_dir
            .as_ref()
            .map(|path| path.join("pfx"))
            .filter(|path| path.is_dir())
    });
    let proton_dist = environment.get("PROTONPATH").map(PathBuf::from);
    let proton_dist = proton_dist.or_else(|| {
        environment
            .get("STEAM_COMPAT_TOOL_PATHS")
            .and_then(|paths| paths.split(':').find(|path| !path.is_empty()))
            .map(PathBuf::from)
    });
    let steam_client_path = environment
        .get("STEAM_COMPAT_CLIENT_INSTALL_PATH")
        .map(PathBuf::from);
    let steam_app_id = steam_app_id_from_environment(&environment)
        .or_else(|| {
            command
                .iter()
                .find_map(|value| evidence::steam_app_id_from_path(value))
        })
        .or_else(|| {
            compatdata_dir
                .as_deref()
                .and_then(steam_app_id_from_compatdata_dir)
        });

    let process_evidence = evidence::collect(&name, executable.as_deref(), &command, &environment);
    let (target_kind, classification_confidence) = evidence::classify(&process_evidence);

    // Host architecture is valid only for native planning
    let host_architecture = executable
        .as_deref()
        .and_then(|path| binary::inspect(path).ok())
        .map_or(Architecture::Unknown, |inspection| inspection.architecture);

    // Guest architecture comes only from a readable PE executable
    let guest_executable = (target_kind == TargetKind::WineProtonWindows)
        .then(|| {
            evidence::find_guest_executable(
                &command,
                wine_prefix.as_deref(),
                working_directory.as_deref(),
            )
        })
        .flatten();
    let guest_architecture = guest_executable
        .as_ref()
        .and_then(|candidate| binary::inspect(&candidate.path).ok())
        .map(|inspection| inspection.architecture);

    Ok(ProcessInfo {
        classification_confidence,
        command,
        compatdata_dir,
        environment_status,
        executable,
        guest_architecture,
        guest_executable,
        host_architecture,
        name,
        owned_by_current_user: uids
            .zip(current_uids)
            .map(|(owner, current)| owner.filesystem == current.filesystem),
        pid,
        proton_dist,
        steam_app_id,
        steam_client_path,
        target_kind,
        uids,
        wine_prefix,
    })
}

/// Lists every process whose required `/proc` fields are readable
#[must_use]
pub fn list() -> Vec<ProcessInfo> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };

    // Exits and permission failures are normal during a live process scan
    let mut processes: Vec<_> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter_map(|pid| inspect(pid).ok())
        .collect();
    processes.sort_by_key(|process| process.pid);
    processes
}

/// Reads a NUL-separated command line with a memory ceiling
fn read_command_line(path: &Path) -> Result<Vec<String>> {
    let bytes = read_capped(path)?;
    Ok(bytes
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .map(|argument| String::from_utf8_lossy(argument).into_owned())
        .collect())
}

/// Reads selected environment values while discarding unrelated secrets
fn read_selected_environment(path: &Path) -> (BTreeMap<String, String>, EnvironmentStatus) {
    let bytes = match read_capped(path) {
        Ok(bytes) => bytes,
        Err(Error::Io { source, .. }) if source.kind() == ErrorKind::PermissionDenied => {
            return (BTreeMap::new(), EnvironmentStatus::PermissionDenied);
        }
        Err(_) => return (BTreeMap::new(), EnvironmentStatus::Missing),
    };

    let mut selected = BTreeMap::new();

    for entry in bytes
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let text = String::from_utf8_lossy(entry);
        let Some((key, value)) = text.split_once('=') else {
            continue;
        };
        if SELECTED_ENVIRONMENT_KEYS.contains(&key) {
            selected.insert(key.to_owned(), value.to_owned());
        }
    }

    (selected, EnvironmentStatus::Read)
}

/// Reads all four Linux UIDs from a status file
fn read_uids(path: &Path) -> Option<ProcessUids> {
    let status = fs::read_to_string(path).ok()?;
    let mut values = status
        .lines()
        .find(|line| line.starts_with("Uid:"))?
        .split_whitespace()
        .skip(1)
        .map(str::parse::<u32>);

    Some(ProcessUids {
        real: values.next()?.ok()?,
        effective: values.next()?.ok()?,
        saved: values.next()?.ok()?,
        filesystem: values.next()?.ok()?,
    })
}

/// Reads one pseudo-file without allowing unbounded allocation
fn read_capped(path: &Path) -> Result<Vec<u8>> {
    let file = fs::File::open(path).map_err(|source| Error::io(path, source))?;
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

/// Derives an existing prefix from selected environment values
fn wine_prefix_from_environment(environment: &BTreeMap<String, String>) -> Option<PathBuf> {
    environment
        .get("WINEPREFIX")
        .map(PathBuf::from)
        .or_else(|| {
            environment
                .get("STEAM_COMPAT_DATA_PATH")
                .map(PathBuf::from)
                .map(|path| path.join("pfx"))
        })
        .filter(|path| path.is_dir())
}

/// Extracts an application identifier from known environment keys
fn steam_app_id_from_environment(environment: &BTreeMap<String, String>) -> Option<u32> {
    ["STEAM_COMPAT_APP_ID", "SteamAppId", "SteamGameId"]
        .into_iter()
        .find_map(|key| environment.get(key)?.parse().ok())
}

/// Extracts an application identifier from a compatdata directory
fn steam_app_id_from_compatdata_dir(path: &Path) -> Option<u32> {
    path.file_name()?.to_str()?.parse().ok()
}
