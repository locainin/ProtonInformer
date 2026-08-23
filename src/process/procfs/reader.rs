//! Linux /proc mechanics and process-incarnation checks

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Read};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use super::super::model::{EnvironmentStatus, ProcessEvidenceFailure, ProcessUids};
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

/// Stable Linux identity captured from `/proc/<pid>` before evidence reads
#[derive(Debug, Clone, Copy)]
pub(super) struct LinuxProcessIdentity {
    pub(super) start_time_ticks: u64,
    pub(super) uids: ProcessUids,
}

/// Reads a NUL-separated command line with a memory ceiling
pub(super) fn read_command_line(pid: u32, path: &Path) -> Result<Vec<OsString>> {
    let bytes = read_capped(pid, path)?;
    Ok(bytes
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .map(|argument| OsString::from_vec(argument.to_vec()))
        .collect())
}

/// Reads selected environment values while discarding unrelated secrets
pub(super) fn read_selected_environment(
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
pub(super) fn read_process_identity(pid: u32, process_dir: &Path) -> Result<LinuxProcessIdentity> {
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
pub(super) fn revalidate_identity(
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
pub(super) fn verify_process_identity(pid: u32, expected_start_time_ticks: u64) -> Result<()> {
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
pub(super) fn read_uids(pid: u32, path: &Path) -> Result<ProcessUids> {
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
pub(super) fn read_optional_evidence(
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

/// Converts one procfs race into the transient process error category
pub(super) fn process_file_error(pid: u32, path: &Path, source: std::io::Error) -> Error {
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
