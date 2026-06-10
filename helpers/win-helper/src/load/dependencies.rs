//! Dependency preflight for one validated PE payload

use std::path::Path;

use proton_informer_helper_protocol::{WindowsModuleInfo, WindowsProcessInfo};

use crate::error::HelperFailure;

/// Reports imported DLLs that are not visible through common loader paths
pub(super) fn dependency_warnings(
    payload_path: &str,
    process: &WindowsProcessInfo,
    modules: &[WindowsModuleInfo],
) -> Result<Vec<String>, HelperFailure> {
    let payload = Path::new(payload_path);
    let payload_directory = payload.parent();
    let process_directory = process
        .executable_windows_path
        .as_deref()
        .and_then(|path| Path::new(path).parent());
    let imports = crate::imports::dll_names(payload)?;
    let mut warnings = Vec::new();

    for import in imports {
        let normalized = import.to_ascii_lowercase();
        if normalized.starts_with("api-ms-win-") || normalized.starts_with("ext-ms-win-") {
            continue;
        }
        let loaded = modules
            .iter()
            .any(|module| module.module_name.eq_ignore_ascii_case(&import));
        let adjacent = payload_directory.is_some_and(|directory| directory.join(&import).is_file())
            || process_directory.is_some_and(|directory| directory.join(&import).is_file());
        if !loaded && !adjacent && !platform_dependency_visible(&import)? {
            warnings.push(format!(
                "payload imports {import}, but no matching module or file was found in common \
                 prefix search paths"
            ));
        }
    }
    Ok(warnings)
}

/// Checks Wine's Windows dependency search path
#[cfg(windows)]
fn platform_dependency_visible(name: &str) -> Result<bool, HelperFailure> {
    crate::winapi::dependency_visible(name)
}

/// Refuses dependency search emulation from a host-native helper build
#[cfg(not(windows))]
fn platform_dependency_visible(_name: &str) -> Result<bool, HelperFailure> {
    Err(HelperFailure::UnsupportedOperation(
        "dependency preflight requires a Windows helper build".into(),
    ))
}
