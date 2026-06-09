use std::path::PathBuf;

use thiserror::Error;

/// Structured errors provide stable kinds for CLI JSON output.
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

    /// Stable machine-facing category used by `--json` error responses.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
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
            Self::HelperTimeout { .. } => "helper_timeout",
            Self::Json(_) => "json",
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
