//! Exact Windows module-path identity rules

use proton_informer_helper_protocol::WindowsModuleInfo;

use crate::windows_path::{windows_path_equal, windows_string_equal};

/// Finds the module whose canonical Windows path is the requested path
#[must_use]
pub fn find_exact<'a>(
    modules: &'a [WindowsModuleInfo],
    expected_path: &str,
) -> Option<&'a WindowsModuleInfo> {
    modules
        .iter()
        .find(|module| windows_path_equal(&module.windows_path, expected_path))
}

/// Finds a same-basename module loaded from a different full path
#[must_use]
pub fn find_basename_conflict<'a>(
    modules: &'a [WindowsModuleInfo],
    expected_path: &str,
) -> Option<&'a WindowsModuleInfo> {
    let expected_name = windows_basename(expected_path)?;
    modules.iter().find(|module| {
        windows_string_equal(&module.module_name, expected_name)
            && !windows_path_equal(&module.windows_path, expected_path)
    })
}

/// Returns the final non-empty Windows path component
fn windows_basename(path: &str) -> Option<&str> {
    path.rsplit(['\\', '/'])
        .find(|component| !component.is_empty())
}
