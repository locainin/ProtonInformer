//! Safe remote load flow built on the isolated Windows API boundary

mod dependencies;
mod modules;
mod payload;
mod platform;

use proton_informer_helper_protocol::{
    HelperOptions, HelperPayload, HelperTarget, LoadLibraryResult, ProtocolArchitecture,
    WindowsModuleInfo,
};

use self::dependencies::dependency_warnings;
use self::modules::{find_basename_conflict, find_module};
use self::payload::{is_absolute_windows_path, validate_payload};
use self::platform::{load_library, lock_payload, modules};
use crate::error::HelperFailure;
use crate::windows_path::windows_path_equal;

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
    if find_module(&modules_before, locked.canonical_path()).is_some() {
        return Ok(result(
            &process,
            locked.canonical_path().to_owned(),
            None,
            dependency_warnings,
            true,
            &modules_before,
            &modules_before,
        ));
    }
    if let Some(module) = find_basename_conflict(&modules_before, locked.canonical_path()) {
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
    let process_after = crate::process::resolve(target).map_err(|error| {
        HelperFailure::LoadIndeterminate(format!(
            "remote load completed, but target identity could not be verified afterward: {error}"
        ))
    })?;
    if process_after.windows_pid != process.windows_pid
        || process_after.creation_time_100ns != process.creation_time_100ns
    {
        return Err(HelperFailure::LoadIndeterminate(
            "remote load completed, but the selected process identity changed before module \
             verification"
                .into(),
        ));
    }
    let modules_after = modules(process.windows_pid).map_err(|error| {
        HelperFailure::LoadIndeterminate(format!(
            "remote load completed, but module verification failed: {error}"
        ))
    })?;
    let Some(_loaded) = find_module(&modules_after, locked.canonical_path()) else {
        return Err(missing_module_failure(
            process.architecture,
            &thread,
            locked.canonical_path(),
        ));
    };

    Ok(result(
        &process,
        locked.canonical_path().to_owned(),
        Some(thread.exit_code_low32),
        dependency_warnings,
        false,
        &modules_before,
        &modules_after,
    ))
}

/// Interprets a missing post-load module without treating x64 low bits as a pointer
fn missing_module_failure(
    architecture: ProtocolArchitecture,
    thread: &self::platform::LoadThreadOutcome,
    path: &str,
) -> HelperFailure {
    if architecture == ProtocolArchitecture::X86 && thread.exit_code_low32 == 0 {
        return HelperFailure::LoadLibraryRejected {
            code: thread.windows_error,
            message: "LoadLibraryW returned a zero 32-bit thread exit status; target-side \
                      GetLastError is unavailable in standard loader mode."
                .into(),
        };
    }

    HelperFailure::LoadIndeterminate(format!(
        "LoadLibraryW returned low 32-bit thread exit code {:#010x} for {:?}, but {} was not observed",
        thread.exit_code_low32, architecture, path
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
            !modules_before
                .iter()
                .any(|before| windows_path_equal(&before.windows_path, &after.windows_path))
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{missing_module_failure, modules_added};
    use crate::error::HelperFailure;
    use crate::load::platform::LoadThreadOutcome;
    use proton_informer_helper_protocol::{ProtocolArchitecture, WindowsModuleInfo};

    fn thread(exit_code_low32: u32) -> LoadThreadOutcome {
        LoadThreadOutcome {
            exit_code_low32,
            windows_error: 126,
        }
    }

    #[test]
    fn x86_zero_status_can_prove_loader_rejection() {
        let error =
            missing_module_failure(ProtocolArchitecture::X86, &thread(0), r"C:\\payload.dll");

        assert!(matches!(error, HelperFailure::LoadLibraryRejected { .. }));
    }

    #[test]
    fn x64_zero_status_remains_indeterminate() {
        let error =
            missing_module_failure(ProtocolArchitecture::X86_64, &thread(0), r"C:\\payload.dll");

        assert!(matches!(error, HelperFailure::LoadIndeterminate(_)));
    }

    #[test]
    fn module_delta_contains_only_paths_absent_before_loading() {
        let before = WindowsModuleInfo {
            module_name: "existing.dll".into(),
            windows_path: r"C:\existing.dll".into(),
        };
        let added = WindowsModuleInfo {
            module_name: "payload.dll".into(),
            windows_path: r"C:\payload.dll".into(),
        };

        let after = [before.clone(), added.clone()];
        let delta = modules_added(std::slice::from_ref(&before), &after);

        assert_eq!(delta, vec![added]);
    }
}
