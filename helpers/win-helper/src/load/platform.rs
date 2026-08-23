//! Platform dispatch for payload locking, loading, and module enumeration

use proton_informer_helper_protocol::WindowsModuleInfo;

use crate::error::HelperFailure;

/// Platform-neutral payload lock retained through validation and loading
pub(super) struct LockedPayload {
    canonical_path: String,
    #[cfg(windows)]
    _lock: crate::winapi::LockedPayload,
}

impl LockedPayload {
    /// Returns the canonical Windows path held by this lock
    pub(super) fn canonical_path(&self) -> &str {
        &self.canonical_path
    }
}

/// Result from the remote loader thread
pub(super) struct LoadThreadOutcome {
    pub(super) exit_code_low32: u32,
    pub(super) windows_error: u32,
}

/// Locks and canonicalizes a payload through the Windows API
#[cfg(windows)]
pub(super) fn lock_payload(windows_path: &str) -> Result<LockedPayload, HelperFailure> {
    let lock = crate::winapi::lock_payload(windows_path)?;
    Ok(LockedPayload {
        canonical_path: lock.canonical_path().to_owned(),
        _lock: lock,
    })
}

/// Calls the Windows-only remote loader boundary
#[cfg(windows)]
pub(super) fn load_library(
    windows_pid: u32,
    windows_path: &str,
    timeout_ms: u64,
    expected_creation_time_100ns: u64,
) -> Result<LoadThreadOutcome, HelperFailure> {
    let result = crate::winapi::load_library(
        windows_pid,
        windows_path,
        timeout_ms,
        expected_creation_time_100ns,
    )?;
    Ok(LoadThreadOutcome {
        exit_code_low32: result.exit_code_low32,
        windows_error: result.windows_error,
    })
}

/// Enumerates modules through the Windows-only boundary
#[cfg(windows)]
pub(super) fn modules(windows_pid: u32) -> Result<Vec<WindowsModuleInfo>, HelperFailure> {
    crate::winapi::modules(windows_pid)
}

/// Refuses mutation from a host-native helper build
#[cfg(not(windows))]
pub(super) fn lock_payload(_windows_path: &str) -> Result<LockedPayload, HelperFailure> {
    Err(HelperFailure::UnsupportedOperation(
        "payload locking requires a Windows helper build".into(),
    ))
}

/// Refuses mutation from a host-native helper build
#[cfg(not(windows))]
pub(super) fn load_library(
    _windows_pid: u32,
    _windows_path: &str,
    _timeout_ms: u64,
    _expected_creation_time_100ns: u64,
) -> Result<LoadThreadOutcome, HelperFailure> {
    Err(HelperFailure::UnsupportedOperation(
        "LoadLibrary requires a Windows helper build".into(),
    ))
}

/// Refuses module inspection from a host-native helper build
#[cfg(not(windows))]
pub(super) fn modules(_windows_pid: u32) -> Result<Vec<WindowsModuleInfo>, HelperFailure> {
    Err(HelperFailure::UnsupportedOperation(
        "module enumeration requires a Windows helper build".into(),
    ))
}
