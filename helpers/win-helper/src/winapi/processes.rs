//! Windows process enumeration, path lookup, and architecture detection.

use std::mem::{size_of, zeroed};

use proton_informer_helper_protocol::{ProtocolArchitecture, WindowsProcessInfo};
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, FILETIME, GetLastError};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::SystemInformation::{
    IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_UNKNOWN,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, GetProcessTimes, IsWow64Process2, OpenProcess,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

use super::common::{OwnedHandle, wide_string};
use super::modules::create_snapshot;
use crate::error::HelperFailure;

/// Returns the current Windows process identifier.
pub fn current_process_id() -> u32 {
    // SAFETY: GetCurrentProcessId has no arguments or preconditions
    unsafe { GetCurrentProcessId() }
}

/// Enumerates visible Windows processes with best-effort path and architecture.
pub fn processes() -> Result<Vec<WindowsProcessInfo>, HelperFailure> {
    let snapshot = create_snapshot(TH32CS_SNAPPROCESS, 0, "process snapshot")?;
    // SAFETY: zeroed is the documented initialization for PROCESSENTRY32W
    // and dwSize is set before the structure is passed to Windows
    let mut entry: PROCESSENTRY32W = unsafe { zeroed() };
    entry.dwSize = u32::try_from(size_of::<PROCESSENTRY32W>())
        .map_err(|_| HelperFailure::Validation("PROCESSENTRY32W is too large".into()))?;

    // SAFETY: snapshot is valid and entry points to initialized writable memory
    if unsafe { Process32FirstW(snapshot.raw(), &raw mut entry) } == 0 {
        let code = unsafe { GetLastError() };
        if code == ERROR_NO_MORE_FILES {
            return Ok(Vec::new());
        }
        return Err(HelperFailure::Windows {
            code,
            operation: "Process32FirstW",
        });
    }

    let mut processes = Vec::new();
    loop {
        let pid = entry.th32ProcessID;
        let details = process_details(pid);
        processes.push(WindowsProcessInfo {
            architecture: details
                .as_ref()
                .map_or(ProtocolArchitecture::Unknown, |details| {
                    details.architecture
                }),
            creation_time_100ns: details
                .as_ref()
                .and_then(|details| details.creation_time_100ns),
            executable_windows_path: details.and_then(|details| details.path),
            process_name: wide_string(&entry.szExeFile),
            windows_pid: pid,
        });

        // SAFETY: snapshot and entry remain valid for the enumeration lifetime
        if unsafe { Process32NextW(snapshot.raw(), &raw mut entry) } == 0 {
            let code = unsafe { GetLastError() };
            if code == ERROR_NO_MORE_FILES {
                break;
            }
            return Err(HelperFailure::Windows {
                code,
                operation: "Process32NextW",
            });
        }
    }
    processes.sort_by_key(|process| process.windows_pid);
    Ok(processes)
}

/// Best-effort identity fields collected through one process handle.
struct ProcessDetails {
    architecture: ProtocolArchitecture,
    creation_time_100ns: Option<u64>,
    path: Option<String>,
}

/// Opens one process once and collects all available identity evidence.
fn process_details(windows_pid: u32) -> Option<ProcessDetails> {
    let process = open_query_process(windows_pid).ok()?;
    Some(ProcessDetails {
        architecture: process_architecture(&process),
        creation_time_100ns: process_creation_time(&process),
        path: process_path(&process),
    })
}

/// Returns a process executable path when query access is available.
fn process_path(process: &OwnedHandle) -> Option<String> {
    let mut buffer = vec![0_u16; 32_768];
    let mut length = u32::try_from(buffer.len()).ok()?;
    // SAFETY: buffer is writable for length UTF-16 code units and process is valid
    if unsafe { QueryFullProcessImageNameW(process.raw(), 0, buffer.as_mut_ptr(), &raw mut length) }
        == 0
    {
        return None;
    }
    let length = usize::try_from(length).ok()?;
    Some(String::from_utf16_lossy(buffer.get(..length)?))
}

/// Returns a process architecture when query access is available.
fn process_architecture(process: &OwnedHandle) -> ProtocolArchitecture {
    let mut process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    let mut native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    // SAFETY: both output pointers are valid and process has query access
    if unsafe {
        IsWow64Process2(
            process.raw(),
            &raw mut process_machine,
            &raw mut native_machine,
        )
    } == 0
    {
        return ProtocolArchitecture::Unknown;
    }
    machine_architecture(if process_machine == IMAGE_FILE_MACHINE_UNKNOWN {
        native_machine
    } else {
        process_machine
    })
}

/// Returns the immutable process creation timestamp used to reject PID reuse.
fn process_creation_time(process: &OwnedHandle) -> Option<u64> {
    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
    // SAFETY: process is valid and every FILETIME output is writable
    if unsafe {
        GetProcessTimes(
            process.raw(),
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    } == 0
    {
        return None;
    }
    Some((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

/// Opens one process for non-mutating identity queries.
fn open_query_process(windows_pid: u32) -> Result<OwnedHandle, HelperFailure> {
    // SAFETY: PID and access flags are plain values with no pointer preconditions
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, windows_pid) };
    OwnedHandle::new(handle, "OpenProcess query")
}

/// Maps a Windows machine type into the shared architecture enum.
const fn machine_architecture(machine: u16) -> ProtocolArchitecture {
    match machine {
        IMAGE_FILE_MACHINE_AMD64 => ProtocolArchitecture::X86_64,
        IMAGE_FILE_MACHINE_I386 => ProtocolArchitecture::X86,
        _ => ProtocolArchitecture::Unknown,
    }
}
