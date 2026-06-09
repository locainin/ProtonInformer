//! Safe module-query operation.

use proton_informer_helper_protocol::{HelperTarget, ModuleQueryResult};

use crate::error::HelperFailure;

/// Resolves a target and enumerates its loaded modules.
pub fn query(target: &HelperTarget) -> Result<ModuleQueryResult, HelperFailure> {
    let process = crate::process::resolve(target)?;
    let modules = platform_modules(process.windows_pid)?;
    Ok(ModuleQueryResult {
        modules,
        target: process,
    })
}

/// Calls the Windows module enumeration wrapper.
#[cfg(windows)]
fn platform_modules(
    windows_pid: u32,
) -> Result<Vec<proton_informer_helper_protocol::WindowsModuleInfo>, HelperFailure> {
    crate::winapi::modules(windows_pid)
}

/// Refuses to emulate module enumeration on a non-Windows build.
#[cfg(not(windows))]
fn platform_modules(
    _windows_pid: u32,
) -> Result<Vec<proton_informer_helper_protocol::WindowsModuleInfo>, HelperFailure> {
    Err(HelperFailure::UnsupportedOperation(
        "module enumeration requires a Windows helper build".into(),
    ))
}
