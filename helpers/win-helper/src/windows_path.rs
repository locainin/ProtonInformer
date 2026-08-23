//! Windows string and path equality used by identity checks

/// Compares Windows paths with separator and extended-prefix normalization
pub fn windows_path_equal(left: &str, right: &str) -> bool {
    windows_string_equal(&normalize_path(left), &normalize_path(right))
}

/// Compares Windows text with the operating system's ordinal case table
pub fn windows_string_equal(left: &str, right: &str) -> bool {
    #[cfg(windows)]
    {
        ordinal_case_insensitive_equal(left, right)
    }
    #[cfg(not(windows))]
    {
        // Host-native helper builds never perform Windows identity decisions
        left.to_lowercase() == right.to_lowercase()
    }
}

/// Produces a stable display-order key without changing comparison semantics
#[cfg(windows)]
pub(crate) fn windows_path_sort_key(path: &str) -> String {
    normalize_path(path).to_lowercase()
}

/// Normalizes syntax that is equivalent before Windows case comparison
fn normalize_path(path: &str) -> String {
    path.strip_prefix(r"\\?\UNC\")
        .map_or_else(
            || path.strip_prefix(r"\\?\").unwrap_or(path).to_owned(),
            |path| format!(r"\\{path}"),
        )
        .replace('/', "\\")
}

#[cfg(windows)]
fn ordinal_case_insensitive_equal(left: &str, right: &str) -> bool {
    use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};

    let left: Vec<u16> = left.encode_utf16().collect();
    let right: Vec<u16> = right.encode_utf16().collect();
    let Ok(left_length) = i32::try_from(left.len()) else {
        return false;
    };
    let Ok(right_length) = i32::try_from(right.len()) else {
        return false;
    };
    // SAFETY: explicit UTF-16 lengths keep both buffers within their bounds
    unsafe {
        CompareStringOrdinal(left.as_ptr(), left_length, right.as_ptr(), right_length, 1)
            == CSTR_EQUAL
    }
}
