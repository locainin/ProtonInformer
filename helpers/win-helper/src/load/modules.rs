//! Loaded-module identity and conflict checks

use proton_informer_helper_protocol::WindowsModuleInfo;

use crate::module_identity;

/// Finds an exact case-insensitive Windows module path
pub(super) fn find_module<'a>(
    modules: &'a [WindowsModuleInfo],
    expected_path: &str,
) -> Option<&'a WindowsModuleInfo> {
    module_identity::find_exact(modules, expected_path)
}

/// Finds a same-name module loaded from a different full path
pub(super) fn find_basename_conflict<'a>(
    modules: &'a [WindowsModuleInfo],
    expected_path: &str,
) -> Option<&'a WindowsModuleInfo> {
    module_identity::find_basename_conflict(modules, expected_path)
}
