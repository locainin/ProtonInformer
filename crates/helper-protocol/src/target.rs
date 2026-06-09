use serde::{Deserialize, Serialize};

use crate::ProtocolArchitecture;

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
    /// Optional Windows creation timestamp used to reject PID reuse.
    pub expected_creation_time_100ns: Option<u64>,
    /// Required process architecture.
    pub expected_architecture: ProtocolArchitecture,
    /// Optional full Windows executable path.
    pub expected_executable_windows_path: Option<String>,
    /// Exact case-insensitive process basename.
    pub expected_process_name: String,
    /// Selection strategy.
    pub selector: TargetSelector,
}
