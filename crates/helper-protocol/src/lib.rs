//! Versioned JSON contract shared by the Linux controller and Windows helper.

#![forbid(unsafe_code)]
#![deny(warnings)]
#![warn(clippy::pedantic, clippy::nursery)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current helper protocol schema.
pub const SCHEMA_VERSION: u32 = 1;
/// Largest payload accepted by controller and helper validation.
pub const MAX_PAYLOAD_SIZE_BYTES: u64 = 256 * 1024 * 1024;
/// Largest helper request document accepted from disk.
pub const MAX_REQUEST_SIZE_BYTES: u64 = 1024 * 1024;

/// Stable processor architecture names used across the helper boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolArchitecture {
    /// 64-bit ARM.
    Aarch64,
    /// 32-bit ARM.
    Arm,
    /// Architecture could not be established.
    Unknown,
    /// 32-bit Intel or AMD.
    X86,
    /// 64-bit Intel or AMD.
    X86_64,
}

/// Operations accepted through a request JSON file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperOperation {
    /// Load a validated PE DLL into one selected process.
    LoadLibrary,
    /// Enumerate modules loaded by one selected process.
    QueryModules,
    /// Enumerate Windows processes visible inside the current runtime.
    QueryProcesses,
    /// Placeholder used only when malformed input prevents operation recovery.
    Unknown,
}

/// Capabilities advertised by a helper build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperCapability {
    /// Remote `LoadLibraryW` operation.
    LoadLibrary,
    /// Loaded-module enumeration.
    QueryModules,
    /// Process enumeration.
    QueryProcesses,
    /// Non-mutating environment checks.
    SelfTest,
    /// Version and schema reporting.
    Version,
}

/// Selector used by the helper to identify the Windows process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum TargetSelector {
    /// Exact Windows process identifier supplied explicitly.
    ByWindowsPid(u32),
    /// Exact process basename with uniqueness required.
    ByProcessName,
    /// Exact process basename and executable path.
    ByProcessNameAndExecutablePath,
}

/// Identity constraints for a Windows target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperTarget {
    /// Required process architecture.
    pub expected_architecture: ProtocolArchitecture,
    /// Optional full Windows executable path.
    pub expected_executable_windows_path: Option<String>,
    /// Exact case-insensitive process basename.
    pub expected_process_name: String,
    /// Selection strategy.
    pub selector: TargetSelector,
}

/// Validated payload facts supplied by the controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperPayload {
    /// Lowercase hexadecimal SHA-256 digest.
    pub sha256: String,
    /// Exact payload size.
    pub size_bytes: u64,
    /// Absolute Windows path visible in the target prefix.
    pub windows_path: String,
}

/// Execution limits and verification requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperOptions {
    /// Maximum operation duration.
    pub timeout_ms: u64,
    /// Require module enumeration to confirm the loaded path.
    pub verify_module_after_load: bool,
}

impl Default for HelperOptions {
    fn default() -> Self {
        Self {
            timeout_ms: 10_000,
            verify_module_after_load: true,
        }
    }
}

/// One helper request persisted by the Linux controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperRequest {
    /// Requested operation.
    pub operation: HelperOperation,
    /// Operation limits.
    pub options: HelperOptions,
    /// Payload required only by `load_library`.
    pub payload: Option<HelperPayload>,
    /// Unique correlation identifier.
    pub request_id: String,
    /// Protocol schema.
    pub schema_version: u32,
    /// Target required by module queries and loading.
    pub target: Option<HelperTarget>,
}

impl HelperRequest {
    /// Validates schema and operation-specific fields before any API call.
    ///
    /// # Errors
    ///
    /// Returns a validation error for unsupported schemas, empty request IDs,
    /// missing operation fields, invalid paths, hashes, names, or timeouts.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ProtocolValidationError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        if self.request_id.trim().is_empty() {
            return Err(ProtocolValidationError::EmptyRequestId);
        }
        if self.options.timeout_ms == 0 || self.options.timeout_ms > 300_000 {
            return Err(ProtocolValidationError::InvalidTimeout);
        }

        match self.operation {
            HelperOperation::QueryProcesses => {
                if self.target.is_some() || self.payload.is_some() {
                    return Err(ProtocolValidationError::UnexpectedOperationField);
                }
            }
            HelperOperation::QueryModules => {
                validate_target(self.target.as_ref())?;
                if self.payload.is_some() {
                    return Err(ProtocolValidationError::UnexpectedOperationField);
                }
            }
            HelperOperation::LoadLibrary => {
                if !self.options.verify_module_after_load {
                    return Err(ProtocolValidationError::ModuleVerificationRequired);
                }
                validate_target(self.target.as_ref())?;
                validate_payload(self.payload.as_ref())?;
            }
            HelperOperation::Unknown => {
                return Err(ProtocolValidationError::UnknownOperation);
            }
        }

        Ok(())
    }
}

/// Version information emitted by `--version-json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperVersion {
    /// Architecture of the helper executable.
    pub architecture: ProtocolArchitecture,
    /// Operations implemented by this build.
    pub capabilities: Vec<HelperCapability>,
    /// Stable helper product name.
    pub helper_name: String,
    /// Semantic helper version.
    pub helper_version: String,
    /// Highest schema emitted by this helper.
    pub schema_version: u32,
    /// Every accepted request schema.
    pub schema_versions: Vec<u32>,
}

/// Result emitted by `--self-test-json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfTestResult {
    /// Individual non-mutating checks.
    pub checks: Vec<SelfTestCheck>,
    /// Overall self-test status.
    pub passed: bool,
}

/// One self-test check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfTestCheck {
    /// Human-readable diagnostic.
    pub detail: String,
    /// Stable check name.
    pub name: String,
    /// Check status.
    pub passed: bool,
}

/// Process information returned by the Windows helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsProcessInfo {
    /// Detected process architecture.
    pub architecture: ProtocolArchitecture,
    /// Full executable path when readable.
    pub executable_windows_path: Option<String>,
    /// Process basename.
    pub process_name: String,
    /// Windows process identifier.
    pub windows_pid: u32,
}

/// Module information returned by the Windows helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsModuleInfo {
    /// Module basename.
    pub module_name: String,
    /// Full Windows module path.
    pub windows_path: String,
}

/// Successful process enumeration result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessQueryResult {
    /// Visible processes.
    pub processes: Vec<WindowsProcessInfo>,
}

/// Successful module enumeration result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleQueryResult {
    /// Loaded modules.
    pub modules: Vec<WindowsModuleInfo>,
    /// Resolved target.
    pub target: WindowsProcessInfo,
}

/// Successful load result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadLibraryResult {
    /// Path reported by module verification.
    pub loaded_module_path: String,
    /// Whether the exact module path was observed after loading.
    pub module_verified: bool,
    /// Resolved process basename.
    pub process_name: String,
    /// Resolved Windows process identifier.
    pub windows_pid: u32,
    /// Low 32 bits returned by the remote loader thread when one was started.
    pub thread_exit_code_low32: Option<u32>,
}

/// Typed success payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum HelperResult {
    /// Remote DLL load result.
    LoadLibrary(LoadLibraryResult),
    /// Module enumeration result.
    QueryModules(ModuleQueryResult),
    /// Process enumeration result.
    QueryProcesses(ProcessQueryResult),
    /// Non-mutating helper self-test.
    SelfTest(SelfTestResult),
    /// Helper identity.
    Version(HelperVersion),
}

/// Structured helper failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperError {
    /// Stable machine-facing category.
    pub kind: String,
    /// Human-readable detail.
    pub message: String,
    /// Optional Windows error code.
    pub windows_error: Option<u32>,
}

/// One helper response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperResponse {
    /// Structured error when `ok` is false.
    pub error: Option<HelperError>,
    /// Operation success.
    pub ok: bool,
    /// Operation represented by the response.
    pub operation: HelperOperation,
    /// Unique request correlation identifier.
    pub request_id: String,
    /// Typed result when `ok` is true.
    pub result: Option<HelperResult>,
    /// Protocol schema.
    pub schema_version: u32,
    /// Non-fatal diagnostics.
    pub warnings: Vec<String>,
}

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
fn validate_target(target: Option<&HelperTarget>) -> Result<(), ProtocolValidationError> {
    let target = target.ok_or(ProtocolValidationError::MissingTarget)?;
    if target.expected_architecture == ProtocolArchitecture::Unknown {
        return Err(ProtocolValidationError::InvalidTargetArchitecture);
    }
    let name = target.expected_process_name.trim();
    if name.is_empty() || name.contains(['/', '\\']) {
        return Err(ProtocolValidationError::InvalidProcessName);
    }
    if matches!(
        target.selector,
        TargetSelector::ByProcessNameAndExecutablePath
    ) && target
        .expected_executable_windows_path
        .as_deref()
        .is_none_or(|path| !is_absolute_windows_path(path))
    {
        return Err(ProtocolValidationError::InvalidExecutablePath);
    }
    Ok(())
}

/// Validates one load payload.
fn validate_payload(payload: Option<&HelperPayload>) -> Result<(), ProtocolValidationError> {
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
