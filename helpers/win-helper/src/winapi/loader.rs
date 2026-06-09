//! Remote memory, loader-address validation, and thread execution.

use std::ffi::{CString, c_void};
use std::mem::{size_of, transmute};
use std::ptr;

use windows_sys::Win32::Foundation::{
    ERROR_INVALID_PARAMETER, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    FlushInstructionCache, ReadProcessMemory, WriteProcessMemory,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualAllocEx,
    VirtualFreeEx, VirtualProtectEx,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, LPTHREAD_START_ROUTINE, OpenProcess,
    PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE, WaitForSingleObject,
};

use super::common::{OwnedHandle, last_error, last_error_code, null_terminated_wide};
use super::modules::{ModuleAddress, module_addresses};
use crate::error::HelperFailure;

/// Remote allocation released after the loader thread no longer uses it.
struct RemoteAllocation {
    address: *mut c_void,
    process: HANDLE,
    release_on_drop: bool,
}

/// Remote loader state retained until the target thread completes.
struct RemoteLoader {
    code: RemoteAllocation,
    context: RemoteAllocation,
    context_bytes: Vec<u8>,
    path: RemoteAllocation,
}

/// Diagnostic result from the remote loader thread.
pub struct LoadLibraryThreadResult {
    /// Full pointer-sized value returned by `LoadLibraryW`.
    pub load_library_return: u64,
    /// Target-side error captured immediately after `LoadLibraryW`.
    pub windows_error: u32,
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

impl RemoteLoader {
    /// Writes the path, result context, and executable routine into the target.
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
        let get_last_error = remote_function_address(windows_pid, "GetLastError")?;
        let context_bytes = remote_context(load_library, get_last_error, path.address as usize)?;
        let context = RemoteAllocation::new(process, context_bytes.len())?;
        write_remote(
            process,
            context.address,
            context_bytes.as_ptr().cast(),
            context_bytes.len(),
            "WriteProcessMemory context",
        )?;
        let code_bytes = remote_loader_code();
        let code = RemoteAllocation::new(process, code_bytes.len())?;
        write_remote(
            process,
            code.address,
            code_bytes.as_ptr().cast(),
            code_bytes.len(),
            "WriteProcessMemory loader code",
        )?;
        make_executable(process, &code, code_bytes.len())?;

        Ok(Self {
            code,
            context,
            context_bytes,
            path,
        })
    }

    /// Starts the remote routine and reads its completed result block.
    fn execute(
        mut self,
        process: HANDLE,
        timeout_ms: u64,
    ) -> Result<LoadLibraryThreadResult, HelperFailure> {
        // SAFETY: the validated remote address is passed opaquely to Windows
        let thread_start = unsafe { remote_thread_start(self.code.address as usize)? };
        // SAFETY: process, start routine, and remote allocations remain valid
        let thread = unsafe {
            CreateRemoteThread(
                process,
                ptr::null(),
                0,
                thread_start,
                self.context.address,
                0,
                ptr::null_mut(),
            )
        };
        let thread = OwnedHandle::new(thread, "CreateRemoteThread")?;
        let timeout = u32::try_from(timeout_ms)
            .map_err(|_| HelperFailure::Validation("timeout does not fit u32".into()))?;
        // SAFETY: thread is a valid synchronization handle
        match unsafe { WaitForSingleObject(thread.raw(), timeout) } {
            WAIT_OBJECT_0 => self.completed_result(process, &thread),
            WAIT_TIMEOUT => {
                // The thread may still read every remote allocation
                self.retain_all();
                Err(HelperFailure::LoadTimeout {
                    timeout_ms,
                    remote_allocation_retained: true,
                })
            }
            WAIT_FAILED => {
                let code = last_error_code();
                // A failed wait does not prove that the remote thread stopped
                self.retain_all();
                Err(HelperFailure::Windows {
                    code,
                    operation: "WaitForSingleObject; remote allocations retained",
                })
            }
            status => {
                // Unknown wait states also leave thread completion uncertain
                self.retain_all();
                Err(HelperFailure::LoadFailed(format!(
                    "WaitForSingleObject returned unexpected status {status}; remote allocations \
                     retained"
                )))
            }
        }
    }

    /// Keeps every allocation alive when remote thread completion is unknown.
    fn retain_all(self) {
        self.path.retain();
        self.context.retain();
        self.code.retain();
    }

    /// Reads one finished thread and the result block it wrote.
    fn completed_result(
        &mut self,
        process: HANDLE,
        thread: &OwnedHandle,
    ) -> Result<LoadLibraryThreadResult, HelperFailure> {
        let mut exit_code_low32 = 0_u32;
        // SAFETY: thread has completed and exit_code is writable
        if unsafe { GetExitCodeThread(thread.raw(), &raw mut exit_code_low32) } == 0 {
            return Err(last_error("GetExitCodeThread"));
        }
        read_remote(
            process,
            self.context.address,
            self.context_bytes.as_mut_ptr().cast(),
            self.context_bytes.len(),
            "ReadProcessMemory context",
        )?;
        let (load_library_return, windows_error) = decode_remote_context(&self.context_bytes)?;
        Ok(LoadLibraryThreadResult {
            load_library_return,
            windows_error,
            exit_code_low32,
        })
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
    RemoteLoader::new(process.raw(), windows_pid, &wide_path)?.execute(process.raw(), timeout_ms)
}

/// Marks initialized remote code executable and flushes its instruction cache.
fn make_executable(
    process: HANDLE,
    allocation: &RemoteAllocation,
    bytes: usize,
) -> Result<(), HelperFailure> {
    let mut old_protection = 0_u32;
    // SAFETY: allocation is valid and fully initialized
    if unsafe {
        VirtualProtectEx(
            process,
            allocation.address,
            bytes,
            PAGE_EXECUTE_READ,
            &raw mut old_protection,
        )
    } == 0
    {
        return Err(last_error("VirtualProtectEx loader code"));
    }
    // SAFETY: the target code range was just written and made executable
    if unsafe { FlushInstructionCache(process, allocation.address.cast_const(), bytes) } == 0 {
        return Err(last_error("FlushInstructionCache loader code"));
    }
    Ok(())
}

/// Opens one process with only the rights required for `LoadLibraryW`.
fn open_load_process(windows_pid: u32) -> Result<OwnedHandle, HelperFailure> {
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
    OwnedHandle::new(handle, "OpenProcess load")
}

/// Finds the process-local `LoadLibraryW` function address.
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

/// Writes an exact byte range into the selected process.
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

/// Reads an exact byte range from the selected process.
fn read_remote(
    process: HANDLE,
    source: *const c_void,
    destination: *mut c_void,
    bytes: usize,
    operation: &'static str,
) -> Result<(), HelperFailure> {
    let mut bytes_read = 0_usize;
    // SAFETY: source and destination are valid for the requested byte count
    if unsafe { ReadProcessMemory(process, source, destination, bytes, &raw mut bytes_read) } == 0 {
        return Err(last_error(operation));
    }
    if bytes_read != bytes {
        return Err(HelperFailure::LoadFailed(format!(
            "{operation} read {bytes_read} of {bytes} bytes"
        )));
    }
    Ok(())
}

/// Encodes the architecture-specific remote loader result block.
fn remote_context(
    load_library: usize,
    get_last_error: usize,
    path: usize,
) -> Result<Vec<u8>, HelperFailure> {
    #[cfg(target_arch = "x86_64")]
    {
        let mut bytes = Vec::with_capacity(40);
        bytes.extend_from_slice(
            &u64::try_from(load_library)
                .map_err(|_| HelperFailure::LoadFailed("LoadLibraryW address overflow".into()))?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(
            &u64::try_from(get_last_error)
                .map_err(|_| HelperFailure::LoadFailed("GetLastError address overflow".into()))?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(
            &u64::try_from(path)
                .map_err(|_| HelperFailure::LoadFailed("payload path address overflow".into()))?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        Ok(bytes)
    }
    #[cfg(target_arch = "x86")]
    {
        let mut bytes = Vec::with_capacity(20);
        bytes.extend_from_slice(
            &u32::try_from(load_library)
                .map_err(|_| HelperFailure::LoadFailed("LoadLibraryW address overflow".into()))?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(get_last_error)
                .map_err(|_| HelperFailure::LoadFailed("GetLastError address overflow".into()))?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(path)
                .map_err(|_| HelperFailure::LoadFailed("payload path address overflow".into()))?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        Ok(bytes)
    }
}

/// Decodes the result fields written by the remote loader routine.
fn decode_remote_context(context: &[u8]) -> Result<(u64, u32), HelperFailure> {
    #[cfg(target_arch = "x86_64")]
    {
        let module = u64::from_le_bytes(
            context[24..32]
                .try_into()
                .map_err(|_| HelperFailure::LoadFailed("remote result is truncated".into()))?,
        );
        let error = u32::from_le_bytes(
            context[32..36]
                .try_into()
                .map_err(|_| HelperFailure::LoadFailed("remote error is truncated".into()))?,
        );
        Ok((module, error))
    }
    #[cfg(target_arch = "x86")]
    {
        let module = u32::from_le_bytes(
            context[12..16]
                .try_into()
                .map_err(|_| HelperFailure::LoadFailed("remote result is truncated".into()))?,
        );
        let error = u32::from_le_bytes(
            context[16..20]
                .try_into()
                .map_err(|_| HelperFailure::LoadFailed("remote error is truncated".into()))?,
        );
        Ok((u64::from(module), error))
    }
}

/// Returns the minimal remote routine for the helper architecture.
const fn remote_loader_code() -> &'static [u8] {
    #[cfg(target_arch = "x86_64")]
    {
        &[
            0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x89, 0xcb, 0x48, 0x8b, 0x4b, 0x10, 0xff, 0x13,
            0x48, 0x89, 0x43, 0x18, 0xff, 0x53, 0x08, 0x89, 0x43, 0x20, 0x31, 0xc0, 0x48, 0x83,
            0xc4, 0x20, 0x5b, 0xc3,
        ]
    }
    #[cfg(target_arch = "x86")]
    {
        &[
            0x53, 0x8b, 0x5c, 0x24, 0x08, 0xff, 0x73, 0x08, 0xff, 0x13, 0x89, 0x43, 0x0c, 0xff,
            0x53, 0x04, 0x89, 0x43, 0x10, 0x31, 0xc0, 0x5b, 0xc2, 0x04, 0x00,
        ]
    }
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
