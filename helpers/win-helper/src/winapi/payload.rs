//! Payload path validation, canonicalization, and mutation locking.

use std::ptr;

use windows_sys::Win32::Foundation::{GENERIC_READ, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_NAME_NORMALIZED, FILE_SHARE_READ,
    GetFinalPathNameByHandleW, OPEN_EXISTING, VOLUME_NAME_DOS,
};

use super::common::{OwnedHandle, last_error, last_error_code, null_terminated_wide};
use crate::error::HelperFailure;

/// Read-locked payload and the normalized Windows path represented by its handle.
pub struct LockedPayload {
    /// Handle remains open to deny write and delete sharing through the load.
    _handle: OwnedHandle,
    canonical_path: String,
}

impl LockedPayload {
    /// Returns the normalized DOS path used for validation and loading.
    pub fn canonical_path(&self) -> &str {
        &self.canonical_path
    }
}

/// Opens and canonicalizes one payload while denying write and delete sharing.
pub fn lock_payload(windows_path: &str) -> Result<LockedPayload, HelperFailure> {
    if !is_absolute_windows_path(windows_path) {
        return Err(HelperFailure::InvalidWindowsPath(format!(
            "payload path is not drive-absolute or UNC: {windows_path}"
        )));
    }
    let wide_path = null_terminated_wide(windows_path)?;
    // SAFETY: path is NUL terminated and all optional pointers are null
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        let code = last_error_code();
        return Err(HelperFailure::PayloadUnavailable {
            code,
            message: format!(
                "payload path is not visible or readable inside the selected Wine prefix: \
                 {windows_path} (Windows error {code})"
            ),
        });
    }
    let handle = OwnedHandle::new(handle, "CreateFileW payload lock")?;
    let canonical_path = final_path_name(handle.raw())?;
    Ok(LockedPayload {
        _handle: handle,
        canonical_path,
    })
}

/// Returns the normalized DOS path represented by one open file handle.
fn final_path_name(handle: HANDLE) -> Result<String, HelperFailure> {
    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    // SAFETY: null output requests the required buffer length
    let required = unsafe { GetFinalPathNameByHandleW(handle, ptr::null_mut(), 0, flags) };
    if required == 0 {
        return Err(last_error("GetFinalPathNameByHandleW size"));
    }
    let capacity = usize::try_from(required)
        .map_err(|_| HelperFailure::InvalidWindowsPath("canonical path is too long".into()))?
        .checked_add(1)
        .ok_or_else(|| HelperFailure::InvalidWindowsPath("canonical path overflow".into()))?;
    let mut buffer = vec![0_u16; capacity];
    // SAFETY: buffer is writable for its reported UTF-16 capacity
    let written = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len()).map_err(|_| {
                HelperFailure::InvalidWindowsPath("canonical path is too long".into())
            })?,
            flags,
        )
    };
    if written == 0 {
        return Err(last_error("GetFinalPathNameByHandleW"));
    }
    let written = usize::try_from(written)
        .map_err(|_| HelperFailure::InvalidWindowsPath("canonical path is too long".into()))?;
    let path = String::from_utf16_lossy(
        buffer
            .get(..written)
            .ok_or_else(|| HelperFailure::InvalidWindowsPath("canonical path truncated".into()))?,
    );
    Ok(strip_extended_prefix(&path))
}

/// Accepts drive-absolute and UNC paths without resolving relative input.
fn is_absolute_windows_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    let drive_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    let unc = bytes.len() >= 5
        && matches!(bytes[0], b'\\' | b'/')
        && matches!(bytes[1], b'\\' | b'/')
        && !matches!(bytes[2], b'\\' | b'/');
    (drive_absolute || unc) && !path.contains('\0')
}

/// Removes the Win32 extended-length prefix for stable module comparison.
fn strip_extended_prefix(path: &str) -> String {
    path.strip_prefix(r"\\?\UNC\").map_or_else(
        || path.strip_prefix(r"\\?\").unwrap_or(path).to_owned(),
        |path| format!(r"\\{path}"),
    )
}
