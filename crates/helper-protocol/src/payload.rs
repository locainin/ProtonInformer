use serde::{Deserialize, Serialize};

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
