use std::path::PathBuf;

use thiserror::Error;

/// Structured errors provide stable kinds for CLI JSON output
#[derive(Debug, Error)]
pub enum Error {
    #[error("unable to access {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("payload is empty: {0}")]
    EmptyPayload(PathBuf),

    #[error("payload exceeds the {limit_bytes}-byte inspection limit: {path}")]
    PayloadTooLarge { path: PathBuf, limit_bytes: u64 },

    #[error("unsupported or malformed binary at {path}: {reason}")]
    InvalidBinary { path: PathBuf, reason: String },

    #[error("process {0} does not exist or is not readable")]
    ProcessUnavailable(u32),

    #[error(
        "process {pid} identity changed during inspection (start time {expected_start_time_ticks} -> {actual_start_time_ticks})"
    )]
    ProcessIdentityChanged {
        pid: u32,
        expected_start_time_ticks: u64,
        actual_start_time_ticks: u64,
    },

    #[error(
        "process {pid} filesystem ownership changed (expected {expected_filesystem_uid}, actual {actual_filesystem_uid}, controller {current_filesystem_uid})"
    )]
    ProcessOwnershipChanged {
        pid: u32,
        expected_filesystem_uid: u32,
        actual_filesystem_uid: u32,
        current_filesystem_uid: u32,
    },

    #[error("payload rejected: {0}")]
    Rejected(String),

    #[error("Steam metadata is malformed at {path}: {reason}")]
    SteamMetadata { path: PathBuf, reason: String },

    #[error("unable to convert path {path}: {reason}")]
    PathConversion { path: String, reason: String },

    #[error("selected process environment is invalid at {path}: {reason}")]
    InvalidProcessEnvironment { path: PathBuf, reason: String },

    #[error("Steam/Proton identity sources conflict: {details}")]
    SteamIdentityConflict { details: String },

    #[error("no configured Wine drive contains {path}")]
    NoDriveMappingForPath { path: String },

    #[error("Wine drive mapping inspection was incomplete for {path}: {details}")]
    DriveMappingInspectionIncomplete { path: String, details: String },

    #[error("Wine drive {drive}: has conflicting canonical mappings: {roots:?}")]
    AmbiguousDriveMapping { drive: char, roots: Vec<PathBuf> },

    #[error("guest executable discovery is ambiguous; candidates: {candidates:?}")]
    AmbiguousGuestExecutable { candidates: Vec<PathBuf> },

    #[error("target selection is ambiguous: {0}")]
    TargetAmbiguous(String),

    #[error("invalid command input: {0}")]
    InvalidInput(String),

    #[error("helper execution failed: {0}")]
    HelperExecution(String),

    #[error("helper rejected the request ({kind}): {message}")]
    HelperRejected {
        kind: String,
        message: String,
        windows_error: Option<u32>,
    },

    #[error("helper execution exceeded {timeout_ms} ms")]
    HelperTimeout { timeout_ms: u64 },

    #[error(
        "remote load outcome is indeterminate after {timeout_ms} ms: {detail}; automatic retry is unsafe"
    )]
    IndeterminateLoadTimeout { timeout_ms: u64, detail: String },

    #[error("remote load outcome is indeterminate: {detail}; automatic retry is unsafe")]
    IndeterminateLoad { detail: String },

    #[error("helper did not verify the requested payload module (helper path: {actual_path})")]
    ModuleVerificationFailed { actual_path: String },

    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl Error {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// Stable machine-facing category used by `--json` error responses
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Io { .. } => "io",
            Self::EmptyPayload(_) => "empty_payload",
            Self::PayloadTooLarge { .. } => "payload_too_large",
            Self::InvalidBinary { .. } => "invalid_binary",
            Self::ProcessUnavailable(_) => "process_unavailable",
            Self::ProcessIdentityChanged { .. } => "process_identity_changed",
            Self::ProcessOwnershipChanged { .. } => "process_ownership_changed",
            Self::Rejected(_) => "rejected",
            Self::SteamMetadata { .. } => "steam_metadata",
            Self::PathConversion { .. } => "path_conversion",
            Self::InvalidProcessEnvironment { .. } => "invalid_process_environment",
            Self::SteamIdentityConflict { .. } => "steam_identity_conflict",
            Self::NoDriveMappingForPath { .. } => "no_drive_mapping",
            Self::DriveMappingInspectionIncomplete { .. } => "drive_mapping_inspection_incomplete",
            Self::AmbiguousDriveMapping { .. } => "ambiguous_drive_mapping",
            Self::AmbiguousGuestExecutable { .. } => "ambiguous_guest_executable",
            Self::TargetAmbiguous(_) => "target_ambiguous",
            Self::InvalidInput(_) => "invalid_input",
            Self::HelperExecution(_) => "helper_execution",
            Self::HelperRejected { kind, .. } => match kind.as_str() {
                "architecture_mismatch" => "architecture_mismatch",
                "invalid_windows_path" => "invalid_windows_path",
                "load_library_rejected" => "load_library_rejected",
                "load_indeterminate" => "load_indeterminate",
                "load_timeout" => "load_timeout",
                "module_conflict" => "module_conflict",
                "module_verification_failed" => "module_verification_failed",
                "payload_changed" => "payload_changed",
                "payload_not_visible" => "payload_not_visible",
                "target_identity_changed" => "target_identity_changed",
                "target_not_found" => "target_not_found",
                _ => "helper_rejected",
            },
            Self::HelperTimeout { .. } => "helper_timeout",
            Self::IndeterminateLoadTimeout { .. } => "indeterminate_load_timeout",
            Self::IndeterminateLoad { .. } => "indeterminate_load",
            Self::ModuleVerificationFailed { .. } => "module_verification_failed",
            Self::Json(_) => "json",
        }
    }

    /// Returns the target-side Windows error when one was preserved
    #[must_use]
    pub const fn windows_error(&self) -> Option<u32> {
        match self {
            Self::HelperRejected { windows_error, .. } => *windows_error,
            _ => None,
        }
    }

    /// Short user-facing hint for common Windows loader errors
    #[must_use]
    pub const fn windows_error_hint(&self) -> Option<&'static str> {
        match self {
            Self::HelperRejected {
                windows_error: Some(2),
                ..
            } => Some("file not found"),
            Self::HelperRejected {
                windows_error: Some(3),
                ..
            } => Some("path not found"),
            Self::HelperRejected {
                windows_error: Some(5),
                ..
            } => Some("access denied"),
            Self::HelperRejected {
                windows_error: Some(126),
                ..
            } => Some("a required dependency DLL was not found in the Wine or Proton prefix"),
            Self::HelperRejected {
                windows_error: Some(193),
                ..
            } => Some("wrong architecture or invalid Win32 image"),
            Self::HelperRejected {
                windows_error: Some(1114),
                ..
            } => Some("DllMain returned failure during process attach"),
            Self::HelperRejected { .. }
            | Self::Io { .. }
            | Self::EmptyPayload(_)
            | Self::PayloadTooLarge { .. }
            | Self::InvalidBinary { .. }
            | Self::ProcessUnavailable(_)
            | Self::ProcessIdentityChanged { .. }
            | Self::ProcessOwnershipChanged { .. }
            | Self::Rejected(_)
            | Self::SteamMetadata { .. }
            | Self::PathConversion { .. }
            | Self::InvalidProcessEnvironment { .. }
            | Self::SteamIdentityConflict { .. }
            | Self::NoDriveMappingForPath { .. }
            | Self::DriveMappingInspectionIncomplete { .. }
            | Self::AmbiguousDriveMapping { .. }
            | Self::AmbiguousGuestExecutable { .. }
            | Self::TargetAmbiguous(_)
            | Self::InvalidInput(_)
            | Self::HelperExecution(_)
            | Self::HelperTimeout { .. }
            | Self::IndeterminateLoadTimeout { .. }
            | Self::IndeterminateLoad { .. }
            | Self::ModuleVerificationFailed { .. }
            | Self::Json(_) => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
