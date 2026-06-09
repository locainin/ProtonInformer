//! Remote memory, loader-address validation, and thread execution

use std::ffi::{CString, c_void};
use std::mem::{size_of, transmute};
use std::ptr;

use windows_sys::Win32::Foundation::{
    ERROR_INVALID_PARAMETER, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, LPTHREAD_START_ROUTINE, OpenProcess,
    PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE, WaitForSingleObject,
};

use super::common::{OwnedHandle, last_error, last_error_code, null_terminated_wide};
use super::modules::{ModuleAddress, module_addresses};
use super::processes::process_creation_time;
use crate::error::HelperFailure;

/// Remote allocation released after the loader thread no longer uses it
struct RemoteAllocation {
    address: *mut c_void,
    process: HANDLE,
    release_on_drop: bool,
}

/// Remote loader state retained until the target thread completes
struct RemoteLoader {
    load_library: usize,
    path: RemoteAllocation,
}

/// Result from the standard remote `LoadLibraryW` thread
pub struct LoadLibraryThreadResult {
    /// Full pointer-sized value returned by `LoadLibraryW`
    pub load_library_return: u64,
    /// Target-side error when a diagnostic loader records one
    pub windows_error: u32,
    /// Windows thread exit codes are always 32-bit, even for 64-bit modules
    pub exit_code_low32: u32,
}

impl RemoteAllocation {
    /// Allocates writable memory in one opened target process
    fn new(process: HANDLE, bytes: usize) -> Result<Self, HelperFailure> {
        // SAFETY: process is valid and the requested region has no source pointer
        let address = unsafe {
            VirtualAllocEx(
                process,
                ptr::null(),
                bytes,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if address.is_null() {
            return Err(last_error("VirtualAllocEx"));
        }
        Ok(Self {
            address,
            process,
            release_on_drop: true,
        })
    }

    /// Retains timed-out memory because the remote thread may still read it
    fn retain(mut self) {
        self.release_on_drop = false;
    }
}

impl Drop for RemoteAllocation {
    fn drop(&mut self) {
        if self.release_on_drop {
            // SAFETY: address belongs to process and MEM_RELEASE requires size zero
            unsafe {
                VirtualFreeEx(self.process, self.address, 0, MEM_RELEASE);
            }
        }
    }
}

impl RemoteLoader {
    /// Writes the DLL path and resolves the target-local `LoadLibraryW` address
    fn new(process: HANDLE, windows_pid: u32, wide_path: &[u16]) -> Result<Self, HelperFailure> {
        let byte_count = wide_path
            .len()
            .checked_mul(size_of::<u16>())
            .ok_or_else(|| HelperFailure::Validation("payload path is too long".into()))?;
        let path = RemoteAllocation::new(process, byte_count)?;
        write_remote(
            process,
            path.address,
            wide_path.as_ptr().cast(),
            byte_count,
            "WriteProcessMemory path",
        )?;

        let load_library = remote_function_address(windows_pid, "LoadLibraryW")?;

        Ok(Self { load_library, path })
    }

    /// Starts a standard remote `LoadLibraryW` thread and reads its exit code
    fn execute(
        self,
        process: HANDLE,
        timeout_ms: u64,
    ) -> Result<LoadLibraryThreadResult, HelperFailure> {
        // SAFETY: the validated remote address is passed opaquely to Windows
        let thread_start = unsafe { remote_thread_start(self.load_library)? };
        // SAFETY: process, start routine, and remote allocations remain valid
        let thread = unsafe {
            CreateRemoteThread(
                process,
                ptr::null(),
                0,
                thread_start,
                self.path.address,
                0,
                ptr::null_mut(),
            )
        };
        let thread = OwnedHandle::new(thread, "CreateRemoteThread")?;
        let timeout = u32::try_from(timeout_ms)
            .map_err(|_| HelperFailure::Validation("timeout does not fit u32".into()))?;
        // SAFETY: thread is a valid synchronization handle
        match unsafe { WaitForSingleObject(thread.raw(), timeout) } {
            WAIT_OBJECT_0 => completed_result(&thread),
            WAIT_TIMEOUT => {
                // The thread may still read the remote DLL path
                self.path.retain();
                Err(HelperFailure::LoadTimeout {
                    timeout_ms,
                    remote_allocation_retained: true,
                })
            }
            WAIT_FAILED => {
                let code = last_error_code();
                // A failed wait does not prove that the remote thread stopped
                self.path.retain();
                Err(HelperFailure::Windows {
                    code,
                    operation: "WaitForSingleObject; remote allocations retained",
                })
            }
            status => {
                // Unknown wait states also leave thread completion uncertain
                self.path.retain();
                Err(HelperFailure::LoadFailed(format!(
                    "WaitForSingleObject returned unexpected status {status}; remote allocations \
                     retained"
                )))
            }
        }
    }
}

/// Reads one finished `LoadLibraryW` thread result
fn completed_result(thread: &OwnedHandle) -> Result<LoadLibraryThreadResult, HelperFailure> {
    let mut exit_code_low32 = 0_u32;
    // SAFETY: thread has completed and exit_code is writable
    if unsafe { GetExitCodeThread(thread.raw(), &raw mut exit_code_low32) } == 0 {
        return Err(last_error("GetExitCodeThread"));
    }
    Ok(LoadLibraryThreadResult {
        load_library_return: u64::from(exit_code_low32),
        // Standard `CreateRemoteThread(LoadLibraryW)` cannot safely read target-local `GetLastError`
        windows_error: 0,
        exit_code_low32,
    })
}

/// Loads one DLL by running `LoadLibraryW` in the selected Windows process
pub fn load_library(
    windows_pid: u32,
    windows_path: &str,
    timeout_ms: u64,
    expected_creation_time_100ns: u64,
) -> Result<LoadLibraryThreadResult, HelperFailure> {
    let wide_path = null_terminated_wide(windows_path)?;
    let process = open_load_process(windows_pid, expected_creation_time_100ns)?;
    RemoteLoader::new(process.raw(), windows_pid, &wide_path)?.execute(process.raw(), timeout_ms)
}

/// Opens one process with only the rights required for `LoadLibraryW`
fn open_load_process(
    windows_pid: u32,
    expected_creation_time_100ns: u64,
) -> Result<OwnedHandle, HelperFailure> {
    let access = PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE;
    // SAFETY: PID and access flags are plain values with no pointer preconditions
    let handle = unsafe { OpenProcess(access, 0, windows_pid) };
    if handle.is_null() {
        let code = last_error_code();
        if code == ERROR_INVALID_PARAMETER {
            return Err(HelperFailure::TargetNotFound(format!(
                "Windows process {windows_pid} disappeared before loading"
            )));
        }
        return Err(HelperFailure::Windows {
            code,
            operation: "OpenProcess load",
        });
    }
    let process = OwnedHandle::new(handle, "OpenProcess load")?;
    let actual_creation_time_100ns = process_creation_time(&process).ok_or_else(|| {
        HelperFailure::TargetIdentityChanged(format!(
            "Windows process {windows_pid} creation time could not be verified"
        ))
    })?;
    if actual_creation_time_100ns != expected_creation_time_100ns {
        return Err(HelperFailure::TargetIdentityChanged(format!(
            "Windows process {windows_pid} was replaced before loading"
        )));
    }
    Ok(process)
}

/// Finds the process-local `LoadLibraryW` function address
fn remote_function_address(
    windows_pid: u32,
    function_name: &'static str,
) -> Result<usize, HelperFailure> {
    let kernel32 = null_terminated_wide("kernel32.dll")?;
    // SAFETY: kernel32 is loaded in every ordinary Windows process
    let module = unsafe { GetModuleHandleW(kernel32.as_ptr()) };
    if module.is_null() {
        return Err(last_error("GetModuleHandleW kernel32"));
    }
    let symbol = CString::new(function_name)
        .map_err(|_| HelperFailure::Validation("invalid loader symbol".into()))?;
    // SAFETY: module is valid and symbol is NUL terminated
    let local_function = unsafe { GetProcAddress(module, symbol.as_ptr().cast()) }
        .ok_or_else(|| last_error("GetProcAddress loader function"))?;
    let local_address = local_function as *const () as usize;
    // PID zero is the documented current-process selector for module
    // snapshots and avoids Wine treating the helper as a foreign process
    let local_module = module_containing(0, local_address)?;
    let function_offset = local_address
        .checked_sub(local_module.base)
        .ok_or_else(|| HelperFailure::LoadFailed("function address precedes module base".into()))?;
    if function_offset >= local_module.size {
        return Err(HelperFailure::LoadFailed(format!(
            "{function_name} offset {function_offset:#x} is outside local module {}",
            local_module.name,
        )));
    }
    let remote_module = remote_module(windows_pid, &local_module.name)?;
    if function_offset >= remote_module.size {
        return Err(HelperFailure::LoadFailed(format!(
            "{function_name} offset {function_offset:#x} is outside remote module {}",
            remote_module.name,
        )));
    }
    remote_module
        .base
        .checked_add(function_offset)
        .ok_or_else(|| HelperFailure::LoadFailed("remote loader function address overflow".into()))
}

/// Writes an exact byte range into the selected process
fn write_remote(
    process: HANDLE,
    destination: *mut c_void,
    source: *const c_void,
    bytes: usize,
    operation: &'static str,
) -> Result<(), HelperFailure> {
    let mut bytes_written = 0_usize;
    // SAFETY: source and destination are valid for the requested byte count
    if unsafe { WriteProcessMemory(process, destination, source, bytes, &raw mut bytes_written) }
        == 0
    {
        return Err(last_error(operation));
    }
    if bytes_written != bytes {
        return Err(HelperFailure::LoadFailed(format!(
            "{operation} wrote {bytes_written} of {bytes} bytes"
        )));
    }
    Ok(())
}

/// Finds the module containing one address in the helper process
fn module_containing(windows_pid: u32, address: usize) -> Result<ModuleAddress, HelperFailure> {
    let modules = module_addresses(windows_pid)?;
    modules
        .into_iter()
        .find(|module| {
            module
                .base
                .checked_add(module.size)
                .is_some_and(|end| address >= module.base && address < end)
        })
        .ok_or_else(|| {
            HelperFailure::LoadFailed(format!(
                "no local module contains function address {address:#x}"
            ))
        })
}

/// Finds one named module and its address bounds in the target process
fn remote_module(windows_pid: u32, expected_name: &str) -> Result<ModuleAddress, HelperFailure> {
    module_addresses(windows_pid)?
        .into_iter()
        .find(|module| module.name.eq_ignore_ascii_case(expected_name))
        .ok_or_else(|| {
            HelperFailure::LoadFailed(format!(
                "{expected_name} was not found in the target process"
            ))
        })
}

/// Converts a validated remote address into an opaque thread entry pointer
unsafe fn remote_thread_start(address: usize) -> Result<LPTHREAD_START_ROUTINE, HelperFailure> {
    if address == 0 {
        return Err(HelperFailure::LoadFailed(
            "remote thread start address is null".into(),
        ));
    }
    // SAFETY: the function pointer is never called in this process. Windows
    // interprets the address in the target process for CreateRemoteThread
    Ok(unsafe { transmute::<usize, LPTHREAD_START_ROUTINE>(address) })
}
