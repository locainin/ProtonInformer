//! Serializable doctor report models

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Passed,
    Warning,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub checks: Vec<DoctorCheck>,
    pub process_planning: CapabilityReadiness,
    pub steam_discovery: CapabilityReadiness,
    pub wine_helper_x86: CapabilityReadiness,
    pub wine_helper_x86_64: CapabilityReadiness,
}

/// Readiness of one independently usable capability
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityReadiness {
    /// Required checks passed
    Ready,
    /// One or more required checks did not pass
    Unavailable,
}
