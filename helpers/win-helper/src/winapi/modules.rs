//! Windows module snapshots and validated address-range discovery.

use std::mem::{size_of, zeroed};

use proton_informer_helper_protocol::WindowsModuleInfo;
use windows_sys::Win32::Foundation::{
    ERROR_BAD_LENGTH, ERROR_NO_MORE_FILES, GetLastError, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
};

use super::common::{OwnedHandle, last_error, wide_string};
use crate::error::HelperFailure;

/// Module address range in one process.
pub(super) struct ModuleAddress {
    pub(super) base: usize,
    pub(super) name: String,
    pub(super) size: usize,
}

/// Enumerates modules for one Windows process.
pub fn modules(windows_pid: u32) -> Result<Vec<WindowsModuleInfo>, HelperFailure> {
    let snapshot = create_module_snapshot(windows_pid)?;
    // SAFETY: zeroed is the documented initialization for MODULEENTRY32W
    // and dwSize is set before the structure is passed to Windows
    let mut entry: MODULEENTRY32W = unsafe { zeroed() };
    entry.dwSize = u32::try_from(size_of::<MODULEENTRY32W>())
        .map_err(|_| HelperFailure::Validation("MODULEENTRY32W is too large".into()))?;

    // SAFETY: snapshot is valid and entry points to initialized writable memory
    if unsafe { Module32FirstW(snapshot.raw(), &raw mut entry) } == 0 {
        let code = unsafe { GetLastError() };
        if code == ERROR_NO_MORE_FILES {
            return Ok(Vec::new());
        }
        return Err(HelperFailure::Windows {
            code,
            operation: "Module32FirstW",
        });
    }

    let mut modules = Vec::new();
    loop {
        modules.push(WindowsModuleInfo {
            module_name: wide_string(&entry.szModule),
            windows_path: wide_string(&entry.szExePath),
        });

        // SAFETY: snapshot and entry remain valid for the enumeration lifetime
        if unsafe { Module32NextW(snapshot.raw(), &raw mut entry) } == 0 {
            let code = unsafe { GetLastError() };
            if code == ERROR_NO_MORE_FILES {
                break;
            }
            return Err(HelperFailure::Windows {
                code,
                operation: "Module32NextW",
            });
        }
    }
    modules.sort_by(|left, right| {
        left.windows_path
            .to_ascii_lowercase()
            .cmp(&right.windows_path.to_ascii_lowercase())
    });
    Ok(modules)
}

/// Creates a module snapshot and retries transient `ERROR_BAD_LENGTH` failures.
///
/// Each helper is built for the same architecture as its target, so
/// `TH32CS_SNAPMODULE` selects the correct module view without asking Wine for
/// the opposite-bitness list through `TH32CS_SNAPMODULE32`.
pub(super) fn create_module_snapshot(windows_pid: u32) -> Result<OwnedHandle, HelperFailure> {
    let mut last_code = ERROR_BAD_LENGTH;
    for _ in 0..8 {
        // SAFETY: flags and PID are plain values with no pointer preconditions
        let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, windows_pid) };
        if handle != INVALID_HANDLE_VALUE {
            return OwnedHandle::new(handle, "module snapshot");
        }
        // SAFETY: GetLastError has no preconditions and is read immediately
        last_code = unsafe { GetLastError() };
        if last_code != ERROR_BAD_LENGTH {
            break;
        }
        std::thread::yield_now();
    }
    Err(HelperFailure::Windows {
        code: last_code,
        operation: "CreateToolhelp32Snapshot modules",
    })
}

/// Creates one non-module snapshot.
pub(super) fn create_snapshot(
    flags: u32,
    windows_pid: u32,
    operation: &'static str,
) -> Result<OwnedHandle, HelperFailure> {
    // SAFETY: flags and PID are plain values with no pointer preconditions
    let handle = unsafe { CreateToolhelp32Snapshot(flags, windows_pid) };
    OwnedHandle::new(handle, operation)
}

/// Enumerates module names and address ranges for address validation.
pub(super) fn module_addresses(windows_pid: u32) -> Result<Vec<ModuleAddress>, HelperFailure> {
    let snapshot = create_module_snapshot(windows_pid)?;
    // SAFETY: zeroed is the documented initialization for MODULEENTRY32W
    // and dwSize is set before the structure is passed to Windows
    let mut entry: MODULEENTRY32W = unsafe { zeroed() };
    entry.dwSize = u32::try_from(size_of::<MODULEENTRY32W>())
        .map_err(|_| HelperFailure::Validation("MODULEENTRY32W is too large".into()))?;
    // SAFETY: snapshot is valid and entry points to initialized writable memory
    if unsafe { Module32FirstW(snapshot.raw(), &raw mut entry) } == 0 {
        return Err(last_error("Module32FirstW remote base"));
    }
    let mut modules = Vec::new();
    loop {
        modules.push(ModuleAddress {
            base: entry.modBaseAddr as usize,
            name: wide_string(&entry.szModule),
            size: usize::try_from(entry.modBaseSize)
                .map_err(|_| HelperFailure::LoadFailed("module size does not fit usize".into()))?,
        });
        // SAFETY: snapshot and entry remain valid for the enumeration lifetime
        if unsafe { Module32NextW(snapshot.raw(), &raw mut entry) } == 0 {
            let code = unsafe { GetLastError() };
            if code == ERROR_NO_MORE_FILES {
                break;
            }
            return Err(HelperFailure::Windows {
                code,
                operation: "Module32NextW remote base",
            });
        }
    }
    Ok(modules)
}
