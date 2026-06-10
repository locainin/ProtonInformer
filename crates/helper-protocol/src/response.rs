use serde::{Deserialize, Serialize};

use crate::{HelperOperation, HelperResult};

/// Structured helper failure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperError {
    /// Stable machine-facing category
    pub kind: String,
    /// User-readable detail
    pub message: String,
    /// Optional Windows error code
    pub windows_error: Option<u32>,
}

/// One helper response
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperResponse {
    /// Structured error when `ok` is false
    pub error: Option<HelperError>,
    /// Operation success
    pub ok: bool,
    /// Operation represented by the response
    pub operation: HelperOperation,
    /// Unique request correlation identifier
    pub request_id: String,
    /// Typed result when `ok` is true
    pub result: Option<HelperResult>,
    /// Protocol schema
    pub schema_version: u32,
    /// Non-fatal diagnostics
    pub warnings: Vec<String>,
}
