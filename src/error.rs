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

    #[error("payload rejected: {0}")]
    Rejected(String),

    #[error("Steam metadata is malformed at {path}: {reason}")]
    SteamMetadata { path: PathBuf, reason: String },

    #[error("unable to convert path {path}: {reason}")]
    PathConversion { path: String, reason: String },

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
            Self::Rejected(_) => "rejected",
            Self::SteamMetadata { .. } => "steam_metadata",
            Self::PathConversion { .. } => "path_conversion",
            Self::InvalidInput(_) => "invalid_input",
            Self::HelperExecution(_) => "helper_execution",
            Self::HelperRejected { kind, .. } => match kind.as_str() {
                "architecture_mismatch" => "architecture_mismatch",
                "invalid_windows_path" => "invalid_windows_path",
                "load_library_rejected" => "load_library_rejected",
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
            | Self::Rejected(_)
            | Self::SteamMetadata { .. }
            | Self::PathConversion { .. }
            | Self::InvalidInput(_)
            | Self::HelperExecution(_)
            | Self::HelperTimeout { .. }
            | Self::Json(_) => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
