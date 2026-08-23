//! Windows process enumeration, path lookup, and architecture detection

use std::mem::{size_of, zeroed};

use proton_informer_helper_protocol::{
    ProcessQueryRejection, ProtocolArchitecture, WindowsProcessInfo,
};
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

/// Returns the current Windows process identifier
pub fn current_process_id() -> u32 {
    // SAFETY: GetCurrentProcessId has no arguments or preconditions
    unsafe { GetCurrentProcessId() }
}

/// Queries one exact Windows process without enumerating unrelated processes
pub fn process(windows_pid: u32) -> Result<WindowsProcessInfo, HelperFailure> {
    let handle = open_query_process(windows_pid)?;
    let executable_windows_path = process_path(&handle)?;
    let process_name = process_name_from_path(&executable_windows_path)?;
    let architecture = process_architecture(&handle)?;
    let creation_time_100ns = process_creation_time(&handle)?;

    Ok(WindowsProcessInfo {
        architecture,
        creation_time_100ns: Some(creation_time_100ns),
        executable_windows_path: Some(executable_windows_path),
        process_name,
        windows_pid,
    })
}

/// Enumerates visible Windows processes while retaining identity read failures
pub fn processes() -> Result<(Vec<WindowsProcessInfo>, Vec<ProcessQueryRejection>), HelperFailure> {
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
            return Ok((Vec::new(), Vec::new()));
        }
        return Err(HelperFailure::Windows {
            code,
            operation: "Process32FirstW",
        });
    }

    let mut processes = Vec::new();
    let mut rejections = Vec::new();
    loop {
        let pid = entry.th32ProcessID;
        let process_name = match wide_string(&entry.szExeFile) {
            Ok(name) => name,
            Err(error) => {
                // An unrepresentable unrelated row must not stop the snapshot
                rejections.push(process_rejection(
                    pid,
                    "<unrepresentable process name>",
                    error,
                ));
                if !advance_process_snapshot(&snapshot, &mut entry)? {
                    break;
                }
                continue;
            }
        };
        let (details, failures) = process_details(pid);
        rejections.extend(
            failures
                .into_iter()
                .map(|failure| process_rejection(pid, &process_name, failure)),
        );
        processes.push(WindowsProcessInfo {
            architecture: details.architecture,
            creation_time_100ns: details.creation_time_100ns,
            executable_windows_path: details.path,
            process_name,
            windows_pid: pid,
        });

        if !advance_process_snapshot(&snapshot, &mut entry)? {
            break;
        }
    }
    processes.sort_by_key(|process| process.windows_pid);
    Ok((processes, rejections))
}

/// Advances a process snapshot without hiding enumeration failures
fn advance_process_snapshot(
    snapshot: &OwnedHandle,
    entry: &mut PROCESSENTRY32W,
) -> Result<bool, HelperFailure> {
    // SAFETY: snapshot and entry remain valid for the enumeration lifetime
    if unsafe { Process32NextW(snapshot.raw(), &raw mut *entry) } == 0 {
        let code = unsafe { GetLastError() };
        if code == ERROR_NO_MORE_FILES {
            return Ok(false);
        }
        return Err(HelperFailure::Windows {
            code,
            operation: "Process32NextW",
        });
    }
    Ok(true)
}

/// Identity fields collected through one process handle
struct ProcessDetails {
    architecture: ProtocolArchitecture,
    creation_time_100ns: Option<u64>,
    path: Option<String>,
}

/// Opens one process once and retains every identity read failure
fn process_details(windows_pid: u32) -> (ProcessDetails, Vec<HelperFailure>) {
    let process = match open_query_process(windows_pid) {
        Ok(process) => process,
        Err(error) => return (ProcessDetails::default(), vec![error]),
    };
    let mut failures = Vec::new();
    let architecture = match process_architecture(&process) {
        Ok(architecture) => architecture,
        Err(error) => {
            failures.push(error);
            ProtocolArchitecture::Unknown
        }
    };
    let creation_time_100ns = match process_creation_time(&process) {
        Ok(creation_time) => Some(creation_time),
        Err(error) => {
            failures.push(error);
            None
        }
    };
    let path = match process_path(&process) {
        Ok(path) => Some(path),
        Err(error) => {
            failures.push(error);
            None
        }
    };
    (
        ProcessDetails {
            architecture,
            creation_time_100ns,
            path,
        },
        failures,
    )
}

/// Returns a process executable path when query access is available
fn process_path(process: &OwnedHandle) -> Result<String, HelperFailure> {
    let mut buffer = vec![0_u16; 32_768];
    let mut length = u32::try_from(buffer.len())
        .map_err(|_| HelperFailure::Validation("process path buffer is too large".into()))?;
    // SAFETY: buffer is writable for length UTF-16 code units and process is valid
    if unsafe { QueryFullProcessImageNameW(process.raw(), 0, buffer.as_mut_ptr(), &raw mut length) }
        == 0
    {
        return Err(HelperFailure::Windows {
            code: unsafe { GetLastError() },
            operation: "QueryFullProcessImageNameW",
        });
    }
    let length = usize::try_from(length)
        .map_err(|_| HelperFailure::Validation("process path length is too large".into()))?;
    let path = buffer
        .get(..length)
        .ok_or_else(|| HelperFailure::Validation("process path length is invalid".into()))?;
    String::from_utf16(path).map_err(|_| {
        HelperFailure::Validation("Windows process image path is not valid Unicode".into())
    })
}

/// Extracts the basename used by the process snapshot from a full image path
fn process_name_from_path(path: &str) -> Result<String, HelperFailure> {
    let name = path
        .rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| HelperFailure::Validation("process image path has no basename".into()))?;
    Ok(name.to_owned())
}

/// Returns a process architecture when query access is available
fn process_architecture(process: &OwnedHandle) -> Result<ProtocolArchitecture, HelperFailure> {
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
        return Err(HelperFailure::Windows {
            code: unsafe { GetLastError() },
            operation: "IsWow64Process2",
        });
    }
    Ok(machine_architecture(
        if process_machine == IMAGE_FILE_MACHINE_UNKNOWN {
            native_machine
        } else {
            process_machine
        },
    ))
}

/// Returns the immutable process creation timestamp used to reject PID reuse
pub(super) fn process_creation_time(process: &OwnedHandle) -> Result<u64, HelperFailure> {
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
        return Err(HelperFailure::Windows {
            code: unsafe { GetLastError() },
            operation: "GetProcessTimes",
        });
    }
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

/// Converts one retained helper failure into the shared query model
fn process_rejection(
    windows_pid: u32,
    process_name: &str,
    failure: HelperFailure,
) -> ProcessQueryRejection {
    let error = failure.to_protocol_error();
    ProcessQueryRejection {
        kind: error.kind,
        message: error.message,
        windows_error: error.windows_error,
        windows_pid,
        process_name: process_name.into(),
    }
}

impl Default for ProcessDetails {
    fn default() -> Self {
        Self {
            architecture: ProtocolArchitecture::Unknown,
            creation_time_100ns: None,
            path: None,
        }
    }
}

/// Opens one process for non-mutating identity queries
fn open_query_process(windows_pid: u32) -> Result<OwnedHandle, HelperFailure> {
    // SAFETY: PID and access flags are plain values with no pointer preconditions
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, windows_pid) };
    OwnedHandle::new(handle, "OpenProcess query")
}

/// Maps a Windows machine type into the shared architecture enum
const fn machine_architecture(machine: u16) -> ProtocolArchitecture {
    match machine {
        IMAGE_FILE_MACHINE_AMD64 => ProtocolArchitecture::X86_64,
        IMAGE_FILE_MACHINE_I386 => ProtocolArchitecture::X86,
        _ => ProtocolArchitecture::Unknown,
    }
}
