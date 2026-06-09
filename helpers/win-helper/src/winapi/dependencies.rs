//! Windows dependency search-path checks.

use std::ptr;

use windows_sys::Win32::Storage::FileSystem::SearchPathW;

use super::common::null_terminated_wide;
use crate::error::HelperFailure;

const MAX_WINDOWS_PATH: usize = 32_768;

/// Returns whether the current Wine prefix search path resolves one DLL name.
pub fn dependency_visible(name: &str) -> Result<bool, HelperFailure> {
    let name = null_terminated_wide(name)?;
    let mut buffer = vec![0_u16; MAX_WINDOWS_PATH];
    let capacity = u32::try_from(buffer.len())
        .map_err(|_| HelperFailure::Validation("search path buffer is too large".into()))?;
    // SAFETY: name and output buffer are valid NUL-terminated Windows buffers
    let length = unsafe {
        SearchPathW(
            ptr::null(),
            name.as_ptr(),
            ptr::null(),
            capacity,
            buffer.as_mut_ptr(),
            ptr::null_mut(),
        )
    };
    Ok(length != 0 && length < capacity)
}
