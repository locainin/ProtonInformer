use thiserror::Error;

use crate::{
    HelperPayload, HelperTarget, MAX_PAYLOAD_SIZE_BYTES, ProtocolArchitecture, TargetSelector,
};

/// Semantic request validation failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolValidationError {
    /// Request ID is missing.
    #[error("request_id must not be empty")]
    EmptyRequestId,
    /// Payload hash is not lowercase hexadecimal SHA-256.
    #[error("payload sha256 must be 64 lowercase hexadecimal characters")]
    InvalidPayloadHash,
    /// Payload path is not an absolute Windows drive or UNC path.
    #[error("payload path must be an absolute Windows drive or UNC path")]
    InvalidPayloadPath,
    /// Payload is empty or exceeds the protocol limit.
    #[error("payload size must be between 1 and {MAX_PAYLOAD_SIZE_BYTES} bytes")]
    InvalidPayloadSize,
    /// Expected executable path is not an absolute Windows drive or UNC path.
    #[error("expected executable path must be an absolute Windows drive or UNC path")]
    InvalidExecutablePath,
    /// Process name is missing or contains a path separator.
    #[error("expected process name must be a basename")]
    InvalidProcessName,
    /// Target architecture cannot select a helper safely.
    #[error("expected target architecture must be known")]
    InvalidTargetArchitecture,
    /// Timeout is outside the accepted range.
    #[error("timeout_ms must be between 1 and 300000")]
    InvalidTimeout,
    /// Operation requires a payload.
    #[error("operation requires payload")]
    MissingPayload,
    /// Exact PID loading requires a process creation timestamp.
    #[error("load_library with by_windows_pid requires expected_creation_time_100ns")]
    MissingCreationTime,
    /// Exact PID loading requires the observed Windows executable path.
    #[error("load_library with by_windows_pid requires expected_executable_windows_path")]
    MissingExecutablePath,
    /// Operation requires a target.
    #[error("operation requires target")]
    MissingTarget,
    /// Load operations must always prove the resulting module path.
    #[error("load_library requires module verification")]
    ModuleVerificationRequired,
    /// Operation received a field that it does not use.
    #[error("operation contains an unexpected target or payload field")]
    UnexpectedOperationField,
    /// Placeholder operation cannot be submitted as a request.
    #[error("unknown helper operation")]
    UnknownOperation,
    /// Request schema is unsupported.
    #[error("unsupported schema version {0}")]
    UnsupportedSchema(u32),
}

/// Validates one operation target.
pub fn validate_target(
    target: Option<&HelperTarget>,
) -> Result<&HelperTarget, ProtocolValidationError> {
    let target = target.ok_or(ProtocolValidationError::MissingTarget)?;
    if target.expected_architecture == ProtocolArchitecture::Unknown {
        return Err(ProtocolValidationError::InvalidTargetArchitecture);
    }
    let name = target.expected_process_name.trim();
    if name.is_empty() || name.contains(['/', '\\']) {
        return Err(ProtocolValidationError::InvalidProcessName);
    }
    if let Some(path) = target.expected_executable_windows_path.as_deref() {
        if !is_absolute_windows_path(path) {
            return Err(ProtocolValidationError::InvalidExecutablePath);
        }
    } else if matches!(
        target.selector,
        TargetSelector::ByProcessNameAndExecutablePath
    ) {
        return Err(ProtocolValidationError::MissingExecutablePath);
    }
    Ok(target)
}

/// Validates one load payload.
pub fn validate_payload(payload: Option<&HelperPayload>) -> Result<(), ProtocolValidationError> {
    let payload = payload.ok_or(ProtocolValidationError::MissingPayload)?;
    if !is_absolute_windows_path(&payload.windows_path) {
        return Err(ProtocolValidationError::InvalidPayloadPath);
    }
    if payload.size_bytes == 0 || payload.size_bytes > MAX_PAYLOAD_SIZE_BYTES {
        return Err(ProtocolValidationError::InvalidPayloadSize);
    }
    if payload.sha256.len() != 64
        || !payload
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ProtocolValidationError::InvalidPayloadHash);
    }
    Ok(())
}

/// Checks for an absolute drive or UNC path without normalizing it.
fn is_absolute_windows_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    let drive_absolute = bytes.len() >= 3
        && bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes.get(1) == Some(&b':')
        && matches!(bytes.get(2), Some(b'\\' | b'/'));
    let unc = bytes.len() >= 5
        && matches!(bytes.first(), Some(b'\\' | b'/'))
        && matches!(bytes.get(1), Some(b'\\' | b'/'))
        && !matches!(bytes.get(2), Some(b'\\' | b'/'));
    (drive_absolute || unc)
        && !path.contains('\0')
        && !path.split(['\\', '/']).any(|component| component == "..")
}
