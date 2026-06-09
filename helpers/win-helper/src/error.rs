//! Helper-local errors and protocol conversion.

use proton_informer_helper_protocol::HelperError;
use thiserror::Error;

/// Internal helper failure.
#[derive(Debug, Error)]
pub enum HelperFailure {
    /// Target selector matched more than one process.
    #[error("{0}")]
    AmbiguousTarget(String),
    /// Filesystem operation failed.
    #[error("{context}: {source}")]
    Io {
        /// Operation context.
        context: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// JSON parsing or serialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// Request bytes could not be parsed into the shared protocol.
    #[error("request protocol parse failed: {0}")]
    ProtocolParseFailed(String),
    /// No process matched the target selector.
    #[error("{0}")]
    TargetNotFound(String),
    /// The selected process identity changed between validation and mutation.
    #[error("{0}")]
    TargetIdentityChanged(String),
    /// Helper command line is invalid.
    #[error("usage error: {0}")]
    Usage(String),
    /// Request failed semantic validation.
    #[error("invalid request: {0}")]
    Validation(String),
    /// Payload and target processor architectures do not match.
    #[error("{0}")]
    ArchitectureMismatch(String),
    /// Windows API call failed.
    #[error("{operation} failed with Windows error {code}")]
    #[cfg(windows)]
    Windows {
        /// Windows error code.
        code: u32,
        /// API operation.
        operation: &'static str,
    },
    /// Operation is not implemented by this helper build.
    #[error("{0}")]
    #[cfg(not(windows))]
    UnsupportedOperation(String),
    /// Remote loader returned failure without a transferable Windows error.
    #[error("{0}")]
    #[cfg(windows)]
    LoadFailed(String),
    /// `LoadLibraryW` rejected the DLL and returned a target-side error.
    #[error("{message}")]
    LoadLibraryRejected {
        /// Error captured in the target immediately after `LoadLibraryW`.
        code: u32,
        /// Actionable loader diagnostic.
        message: String,
    },
    /// A different module with the requested basename is already loaded.
    #[error("{0}")]
    ModuleConflict(String),
    /// Remote loading completed without exact module-path verification.
    #[error("{0}")]
    ModuleVerificationFailed(String),
    /// Payload content or identity changed during validation.
    #[error("{0}")]
    PayloadChanged(String),
    /// Windows payload path is invalid or cannot be canonicalized.
    #[error("{0}")]
    InvalidWindowsPath(String),
    /// The payload path cannot be opened inside the selected Wine prefix.
    #[error("{message}")]
    #[cfg(windows)]
    PayloadUnavailable {
        /// Windows error captured from the failed path operation.
        code: u32,
        /// Actionable path diagnostic.
        message: String,
    },
    /// Remote loader did not finish before the request deadline.
    #[error(
        "remote load exceeded {timeout_ms} ms; remote allocation retained: \
         {remote_allocation_retained}"
    )]
    #[cfg(windows)]
    LoadTimeout {
        /// Request deadline in milliseconds.
        timeout_ms: u64,
        /// Memory remains allocated because the remote thread may still use it.
        remote_allocation_retained: bool,
    },
}

impl HelperFailure {
    /// Builds an I/O failure with stable context.
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// Builds a usage failure.
    pub fn usage(message: impl Into<String>) -> Self {
        Self::Usage(message.into())
    }

    /// Converts the failure into the shared response model.
    pub fn to_protocol_error(&self) -> HelperError {
        let (kind, windows_error) = match self {
            Self::AmbiguousTarget(_) => ("ambiguous_target", None),
            Self::Io { .. } => ("io", None),
            Self::Json(_) => ("json", None),
            Self::ProtocolParseFailed(_) => ("protocol_parse_failed", None),
            Self::TargetNotFound(_) => ("target_not_found", None),
            Self::TargetIdentityChanged(_) => ("target_identity_changed", None),
            Self::Usage(_) => ("usage", None),
            Self::Validation(_) => ("invalid_request", None),
            Self::ArchitectureMismatch(_) => ("architecture_mismatch", None),
            #[cfg(windows)]
            Self::Windows { code, .. } => ("windows_api", Some(*code)),
            #[cfg(not(windows))]
            Self::UnsupportedOperation(_) => ("unsupported_operation", None),
            #[cfg(windows)]
            Self::LoadFailed(_) => ("load_failed", None),
            Self::LoadLibraryRejected { code, .. } => ("load_library_rejected", Some(*code)),
            Self::ModuleConflict(_) => ("module_conflict", None),
            Self::ModuleVerificationFailed(_) => ("module_verification_failed", None),
            Self::PayloadChanged(_) => ("payload_changed", None),
            Self::InvalidWindowsPath(_) => ("invalid_windows_path", None),
            #[cfg(windows)]
            Self::PayloadUnavailable { code, .. } => ("payload_not_visible", Some(*code)),
            #[cfg(windows)]
            Self::LoadTimeout { .. } => ("load_timeout", None),
        };
        HelperError {
            kind: kind.into(),
            message: self.to_string(),
            windows_error,
        }
    }
}
