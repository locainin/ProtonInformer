//! Safe remote load flow built on the isolated Windows API boundary

mod dependencies;
mod modules;
mod payload;
mod platform;

use proton_informer_helper_protocol::{
    HelperOptions, HelperPayload, HelperTarget, LoadLibraryResult, WindowsModuleInfo,
};

use self::dependencies::dependency_warnings;
use self::modules::{find_basename_conflict, find_module, module_matches_payload};
use self::payload::{is_absolute_windows_path, validate_payload};
use self::platform::{load_library, lock_payload, modules};
use crate::error::HelperFailure;

/// Validates, loads, and verifies one DLL in the resolved target
///
/// # Errors
///
/// Returns an error when payload validation, process identity checks, remote
/// loading, or final module verification fails
pub fn run(
    target: &HelperTarget,
    payload: &HelperPayload,
    options: &HelperOptions,
) -> Result<LoadLibraryResult, HelperFailure> {
    if !is_absolute_windows_path(&payload.windows_path) {
        return Err(HelperFailure::InvalidWindowsPath(format!(
            "payload path is not drive-absolute or UNC: {}",
            payload.windows_path
        )));
    }
    let locked = lock_payload(&payload.windows_path)?;
    validate_payload(
        payload,
        locked.canonical_path(),
        target.expected_architecture,
    )?;
    let process = crate::process::resolve(target)?;
    let modules_before = modules(process.windows_pid)?;
    let dependency_warnings =
        advisory_dependency_warnings(locked.canonical_path(), &process, &modules_before);

    // Repeated requests are idempotent when the exact payload path is loaded
    if let Some(module) = find_module(&modules_before, locked.canonical_path()) {
        return Ok(result(
            &process,
            module.windows_path.clone(),
            None,
            dependency_warnings,
            true,
            &modules_before,
            &modules_before,
        ));
    }
    if let Some(module) = find_basename_conflict(&modules_before, locked.canonical_path()) {
        if module_matches_payload(module, payload) {
            return Ok(result(
                &process,
                module.windows_path.clone(),
                None,
                dependency_warnings,
                true,
                &modules_before,
                &modules_before,
            ));
        }
        return Err(HelperFailure::ModuleConflict(format!(
            "{} is already loaded from {}, requested {}",
            module.module_name,
            module.windows_path,
            locked.canonical_path()
        )));
    }

    let thread = load_library(
        process.windows_pid,
        locked.canonical_path(),
        options.timeout_ms,
        process.creation_time_100ns.ok_or_else(|| {
            HelperFailure::TargetIdentityChanged(
                "selected process creation time is unavailable".into(),
            )
        })?,
    )?;
    let process_after = crate::process::resolve(target)?;
    if process_after.windows_pid != process.windows_pid
        || process_after.creation_time_100ns != process.creation_time_100ns
    {
        return Err(HelperFailure::TargetIdentityChanged(
            "selected process identity changed before module verification".into(),
        ));
    }
    let modules_after = modules(process.windows_pid)?;
    let Some(loaded) = find_module(&modules_after, locked.canonical_path()) else {
        return if thread.load_library_return == 0 {
            Err(HelperFailure::LoadLibraryRejected {
                code: thread.windows_error,
                message: "LoadLibraryW returned NULL; target-side GetLastError is unavailable in \
                          standard loader mode."
                    .into(),
            })
        } else {
            Err(HelperFailure::ModuleVerificationFailed(format!(
                "LoadLibraryW returned {:#018x}, but {} was not observed",
                thread.load_library_return,
                locked.canonical_path()
            )))
        };
    };

    Ok(result(
        &process,
        loaded.windows_path.clone(),
        Some(thread.exit_code_low32),
        dependency_warnings,
        false,
        &modules_before,
        &modules_after,
    ))
}

/// Runs dependency preflight without making advisory checks authoritative
///
/// A valid payload may use PE layouts or Wine search behavior that the bounded
/// preflight does not understand. Windows remains the final loader authority,
/// so preflight failures become visible warnings instead of blocking the load
#[must_use]
fn advisory_dependency_warnings(
    payload_path: &str,
    process: &proton_informer_helper_protocol::WindowsProcessInfo,
    modules: &[proton_informer_helper_protocol::WindowsModuleInfo],
) -> Vec<String> {
    dependency_warnings(payload_path, process, modules)
        .unwrap_or_else(|error| vec![format!("dependency preflight skipped: {error}")])
}

/// Builds one verified result without exposing internal process types
fn result(
    process: &proton_informer_helper_protocol::WindowsProcessInfo,
    loaded_module_path: String,
    thread_exit_code_low32: Option<u32>,
    dependency_warnings: Vec<String>,
    already_loaded: bool,
    modules_before: &[WindowsModuleInfo],
    modules_after: &[WindowsModuleInfo],
) -> LoadLibraryResult {
    let modules_added = modules_added(modules_before, modules_after);
    LoadLibraryResult {
        already_loaded,
        dependency_warnings,
        loaded_module_path,
        module_count_after: modules_after.len(),
        module_count_before: modules_before.len(),
        module_verified: true,
        modules_added,
        process_name: process.process_name.clone(),
        thread_exit_code_low32,
        windows_pid: process.windows_pid,
    }
}

/// Returns modules present after loading that were not visible beforehand
fn modules_added(
    modules_before: &[WindowsModuleInfo],
    modules_after: &[WindowsModuleInfo],
) -> Vec<WindowsModuleInfo> {
    modules_after
        .iter()
        .filter(|after| {
            !modules_before.iter().any(|before| {
                before
                    .windows_path
                    .eq_ignore_ascii_case(after.windows_path.as_str())
            })
        })
        .cloned()
        .collect()
}
