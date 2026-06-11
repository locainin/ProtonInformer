//! Serializable planning models for load and startup override decisions

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::binary::BinaryInspection;
use crate::doctor::CheckStatus;
use crate::process::ProcessInfo;
use crate::types::Architecture;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    WinePeHelper,
    WineDllOverride,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequirementCheck {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadPlan {
    pub payload: BinaryInspection,
    pub target: ProcessInfo,
    pub target_architecture: Architecture,
    pub backend: Backend,
    pub requirements: Vec<RequirementCheck>,
    pub executable_now: bool,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverridePlan {
    pub payload: BinaryInspection,
    pub app_id: Option<u32>,
    pub prefix: PathBuf,
    pub dll_name: String,
    pub payload_windows_path: String,
    pub backend: Backend,
    pub launch_option: String,
    pub files_modified: bool,
    pub placement: OverridePlacement,
    pub placement_note: String,
}

/// File-placement state required before a Wine DLL override can work
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum OverridePlacement {
    /// The planner does not know the target application's DLL search path
    InstructionsOnly,
}
