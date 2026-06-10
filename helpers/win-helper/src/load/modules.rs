//! Loaded-module identity and conflict checks

use std::path::Path;

use proton_informer_helper_protocol::{HelperPayload, WindowsModuleInfo};

use super::payload::sha256_file;

/// Confirms an already-loaded same-name module is byte-identical
pub(super) fn module_matches_payload(module: &WindowsModuleInfo, payload: &HelperPayload) -> bool {
    let path = Path::new(&module.windows_path);
    path.metadata().is_ok_and(|metadata| {
        metadata.is_file()
            && metadata.len() == payload.size_bytes
            && sha256_file(path, payload.size_bytes).is_ok_and(|hash| hash == payload.sha256)
    })
}

/// Finds an exact case-insensitive Windows module path
pub(super) fn find_module<'a>(
    modules: &'a [WindowsModuleInfo],
    expected_path: &str,
) -> Option<&'a WindowsModuleInfo> {
    modules
        .iter()
        .find(|module| normalized_path(&module.windows_path) == normalized_path(expected_path))
}

/// Finds a same-name module loaded from a different full path
pub(super) fn find_basename_conflict<'a>(
    modules: &'a [WindowsModuleInfo],
    expected_path: &str,
) -> Option<&'a WindowsModuleInfo> {
    let expected_name = windows_basename(expected_path)?;
    modules.iter().find(|module| {
        module.module_name.eq_ignore_ascii_case(expected_name)
            && normalized_path(&module.windows_path) != normalized_path(expected_path)
    })
}

/// Normalizes separators and extended prefixes for case-insensitive comparison
fn normalized_path(path: &str) -> String {
    normalize_extended_path(path)
        .replace('/', "\\")
        .to_ascii_lowercase()
}

/// Removes extended prefixes while preserving a valid UNC prefix
fn normalize_extended_path(path: &str) -> String {
    path.strip_prefix(r"\\?\UNC\").map_or_else(
        || path.strip_prefix(r"\\?\").unwrap_or(path).to_owned(),
        |path| format!(r"\\{path}"),
    )
}

/// Returns the final Windows path component
fn windows_basename(path: &str) -> Option<&str> {
    path.rsplit(['\\', '/'])
        .find(|component| !component.is_empty())
}
