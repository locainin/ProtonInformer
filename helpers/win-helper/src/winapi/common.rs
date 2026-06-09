//! Shared handle, string, and error utilities for the Win32 boundary.

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};

use crate::error::HelperFailure;

/// Owned Windows handle closed automatically.
pub(super) struct OwnedHandle(HANDLE);

impl OwnedHandle {
    /// Wraps a valid non-null handle.
    pub(super) fn new(handle: HANDLE, operation: &'static str) -> Result<Self, HelperFailure> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(last_error(operation));
        }
        Ok(Self(handle))
    }

    /// Returns the raw handle for one immediate API call.
    pub(super) const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: OwnedHandle is constructed only from a valid owned handle
        // and Drop runs exactly once
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Encodes one non-empty Windows string with a trailing NUL.
pub(super) fn null_terminated_wide(value: &str) -> Result<Vec<u16>, HelperFailure> {
    if value.is_empty() || value.contains('\0') {
        return Err(HelperFailure::Validation(
            "Windows path must be non-empty and contain no NUL".into(),
        ));
    }
    Ok(value.encode_utf16().chain(std::iter::once(0)).collect())
}

/// Converts a fixed NUL-terminated UTF-16 array into owned text.
pub(super) fn wide_string<const N: usize>(value: &[u16; N]) -> String {
    let length = value.iter().position(|unit| *unit == 0).unwrap_or(N);
    String::from_utf16_lossy(&value[..length])
}

/// Captures the current Windows error immediately.
pub(super) fn last_error(operation: &'static str) -> HelperFailure {
    // SAFETY: GetLastError has no preconditions and is read immediately
    let code = unsafe { GetLastError() };
    HelperFailure::Windows { code, operation }
}
