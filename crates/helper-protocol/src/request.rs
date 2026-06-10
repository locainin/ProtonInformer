use serde::{Deserialize, Serialize};

use crate::validation::{validate_payload, validate_target};
use crate::{
    HelperOperation, HelperPayload, HelperTarget, ProtocolValidationError, SCHEMA_VERSION,
    TargetSelector,
};

/// Execution limits and verification requirements
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperOptions {
    /// Maximum operation duration
    pub timeout_ms: u64,
    /// Reserved load verification switch. Load requests must keep this true
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

/// One helper request persisted by the Linux controller
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperRequest {
    /// Requested operation
    pub operation: HelperOperation,
    /// Operation limits
    pub options: HelperOptions,
    /// Payload required only by `load_library`
    pub payload: Option<HelperPayload>,
    /// Unique correlation identifier
    pub request_id: String,
    /// Protocol schema
    pub schema_version: u32,
    /// Target required by module queries and loading
    pub target: Option<HelperTarget>,
}

impl HelperRequest {
    /// Validates schema and operation-specific fields before any API call
    ///
    /// # Errors
    ///
    /// Returns a validation error for unsupported schemas, empty request IDs,
    /// missing operation fields, invalid paths, hashes, names, or timeouts
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
                let target = validate_target(self.target.as_ref())?;
                if matches!(target.selector, TargetSelector::ByWindowsPid(_)) {
                    if target.expected_creation_time_100ns.is_none() {
                        return Err(ProtocolValidationError::MissingCreationTime);
                    }
                    if target.expected_executable_windows_path.is_none() {
                        return Err(ProtocolValidationError::MissingExecutablePath);
                    }
                }
                validate_payload(self.payload.as_ref())?;
            }
            HelperOperation::Unknown => {
                return Err(ProtocolValidationError::UnknownOperation);
            }
        }

        Ok(())
    }
}
