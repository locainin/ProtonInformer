//! Remote memory, loader-address validation, and thread execution.

use std::ffi::{CString, c_void};
use std::mem::{size_of, transmute};
use std::ptr;

use windows_sys::Win32::Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, LPTHREAD_START_ROUTINE, OpenProcess,
    PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
    WaitForSingleObject,
};

use super::common::{OwnedHandle, last_error, null_terminated_wide};
use super::modules::{ModuleAddress, module_addresses};
use crate::error::HelperFailure;

/// Remote allocation released after the loader thread no longer uses it.
struct RemoteAllocation {
    address: *mut c_void,
    process: HANDLE,
    release_on_drop: bool,
}

/// Diagnostic result from the remote loader thread.
pub struct LoadLibraryThreadResult {
    /// Windows thread exit codes are always 32-bit, even for 64-bit modules.
    pub exit_code_low32: u32,
}

impl RemoteAllocation {
    /// Allocates writable memory in one opened target process.
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

    /// Retains timed-out memory because the remote thread may still read it.
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

/// Loads one DLL by running `LoadLibraryW` in the selected Windows process.
pub fn load_library(
    windows_pid: u32,
    windows_path: &str,
    timeout_ms: u64,
) -> Result<LoadLibraryThreadResult, HelperFailure> {
    let wide_path = null_terminated_wide(windows_path)?;
    let process = open_load_process(windows_pid)?;
    let byte_count = wide_path
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or_else(|| HelperFailure::Validation("payload path is too long".into()))?;
    let allocation = RemoteAllocation::new(process.raw(), byte_count)?;
    let mut bytes_written = 0_usize;
    // SAFETY: both buffers are valid for byte_count and allocation is writable
    if unsafe {
        WriteProcessMemory(
            process.raw(),
            allocation.address,
            wide_path.as_ptr().cast(),
            byte_count,
            &raw mut bytes_written,
        )
    } == 0
    {
        return Err(last_error("WriteProcessMemory"));
    }
    if bytes_written != byte_count {
        return Err(HelperFailure::LoadFailed(format!(
            "WriteProcessMemory wrote {bytes_written} of {byte_count} bytes"
        )));
    }

    let load_library = load_library_address(windows_pid)?;
    // SAFETY: the validated remote address is passed opaquely to Windows and
    // is never called in the helper process
    let thread_start = unsafe { remote_thread_start(load_library)? };
    // SAFETY: process, start routine, and remote path allocation remain valid
    let thread = unsafe {
        CreateRemoteThread(
            process.raw(),
            ptr::null(),
            0,
            thread_start,
            allocation.address,
            0,
            ptr::null_mut(),
        )
    };
    let thread = OwnedHandle::new(thread, "CreateRemoteThread")?;
    let timeout = u32::try_from(timeout_ms)
        .map_err(|_| HelperFailure::Validation("timeout does not fit u32".into()))?;
    // SAFETY: thread is a valid synchronization handle
    match unsafe { WaitForSingleObject(thread.raw(), timeout) } {
        WAIT_OBJECT_0 => {
            let mut exit_code_low32 = 0_u32;
            // SAFETY: thread has completed and exit_code is writable
            if unsafe { GetExitCodeThread(thread.raw(), &raw mut exit_code_low32) } == 0 {
                return Err(last_error("GetExitCodeThread"));
            }
            Ok(LoadLibraryThreadResult { exit_code_low32 })
        }
        WAIT_TIMEOUT => {
            allocation.retain();
            Err(HelperFailure::LoadTimeout {
                timeout_ms,
                remote_allocation_retained: true,
            })
        }
        WAIT_FAILED => Err(last_error("WaitForSingleObject")),
        status => Err(HelperFailure::LoadFailed(format!(
            "WaitForSingleObject returned unexpected status {status}"
        ))),
    }
}

/// Opens one process with only the rights required for `LoadLibraryW`.
fn open_load_process(windows_pid: u32) -> Result<OwnedHandle, HelperFailure> {
    let access =
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
    // SAFETY: PID and access flags are plain values with no pointer preconditions
    let handle = unsafe { OpenProcess(access, 0, windows_pid) };
    OwnedHandle::new(handle, "OpenProcess load")
}

/// Finds the process-local `LoadLibraryW` function address.
fn load_library_address(windows_pid: u32) -> Result<usize, HelperFailure> {
    let kernel32 = null_terminated_wide("kernel32.dll")?;
    // SAFETY: kernel32 is loaded in every ordinary Windows process
    let module = unsafe { GetModuleHandleW(kernel32.as_ptr()) };
    if module.is_null() {
        return Err(last_error("GetModuleHandleW kernel32"));
    }
    let symbol = CString::new("LoadLibraryW")
        .map_err(|_| HelperFailure::Validation("invalid loader symbol".into()))?;
    // SAFETY: module is valid and symbol is NUL terminated
    let local_function = unsafe { GetProcAddress(module, symbol.as_ptr().cast()) }
        .ok_or_else(|| last_error("GetProcAddress LoadLibraryW"))?;
    let local_address = local_function as *const () as usize;
    // PID zero is the documented current-process selector for module
    // snapshots and avoids Wine treating the helper as a foreign process
    let local_module = module_containing(0, local_address)?;
    let function_offset = local_address
        .checked_sub(local_module.base)
        .ok_or_else(|| HelperFailure::LoadFailed("function address precedes module base".into()))?;
    if function_offset >= local_module.size {
        return Err(HelperFailure::LoadFailed(format!(
            "LoadLibraryW offset {function_offset:#x} is outside local module {}",
            local_module.name
        )));
    }
    let remote_module = remote_module(windows_pid, &local_module.name)?;
    if function_offset >= remote_module.size {
        return Err(HelperFailure::LoadFailed(format!(
            "LoadLibraryW offset {function_offset:#x} is outside remote module {}",
            remote_module.name
        )));
    }
    remote_module
        .base
        .checked_add(function_offset)
        .ok_or_else(|| HelperFailure::LoadFailed("remote LoadLibraryW address overflow".into()))
}

/// Finds the module containing one address in the helper process.
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

/// Finds one named module and its address bounds in the target process.
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

/// Converts a validated remote address into an opaque thread entry pointer.
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
