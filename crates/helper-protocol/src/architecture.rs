use serde::{Deserialize, Serialize};

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
