//! Startup DLL override planning for Wine prefixes

use std::path::Path;

use crate::binary::{BinaryFormat, BinaryInspection};
use crate::error::{Error, Result};
use crate::wine;

use super::model::{Backend, OverridePlacement, OverridePlan};

/// Plans Wine startup DLL override behavior without requiring a running PID
///
/// # Errors
///
/// Returns an error when the payload is not a PE DLL, the prefix is missing,
/// the override name is invalid, or the payload has no configured drive path
pub fn plan_override(
    payload: BinaryInspection,
    prefix: &Path,
    app_id: Option<u32>,
    dll_name: &str,
) -> Result<OverridePlan> {
    if payload.format != BinaryFormat::PeDll {
        return Err(Error::Rejected(format!(
            "startup override requires a PE DLL, detected {}",
            payload.format
        )));
    }
    if !prefix.is_dir() {
        return Err(Error::InvalidInput(format!(
            "Wine prefix does not exist: {}",
            prefix.display()
        )));
    }

    let dll_name = normalize_dll_name(dll_name)?;
    let payload_windows_path = wine::unix_path_to_windows(prefix, &payload.path)?;

    Ok(OverridePlan {
        payload,
        app_id,
        prefix: prefix.to_path_buf(),
        launch_option: format!("WINEDLLOVERRIDES=\"{dll_name}=n,b\" %command%"),
        dll_name,
        payload_windows_path,
        backend: Backend::WineDllOverride,
        files_modified: false,
        placement: OverridePlacement::InstructionsOnly,
        placement_note: "launch options only select native versus builtin DLL resolution; place \
                         the payload in the application's DLL search path under the planned name"
            .into(),
    })
}

fn normalize_dll_name(value: &str) -> Result<String> {
    // Accept names with or without the final `.dll` suffix for CLI ergonomics
    let without_extension = value
        .strip_suffix(".dll")
        .or_else(|| value.strip_suffix(".DLL"))
        .unwrap_or(value);
    if without_extension.is_empty()
        || !without_extension
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(Error::InvalidInput(
            "DLL override name must contain only letters, digits, '-' or '_'".into(),
        ));
    }
    Ok(without_extension.to_ascii_lowercase())
}
