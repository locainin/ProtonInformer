use serde::{Deserialize, Serialize};

use crate::{HelperVersion, ProtocolArchitecture};

/// Result emitted by `--self-test-json`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfTestResult {
    /// Individual non-mutating checks
    pub checks: Vec<SelfTestCheck>,
    /// Overall self-test status
    pub passed: bool,
}

/// One self-test check
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfTestCheck {
    /// User-readable diagnostic
    pub detail: String,
    /// Stable check name
    pub name: String,
    /// Check status
    pub passed: bool,
}

/// Process information returned by the Windows helper
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsProcessInfo {
    /// Detected process architecture
    pub architecture: ProtocolArchitecture,
    /// Windows process creation timestamp in 100-nanosecond units
    pub creation_time_100ns: Option<u64>,
    /// Full executable path when readable
    pub executable_windows_path: Option<String>,
    /// Process basename
    pub process_name: String,
    /// Windows process identifier
    pub windows_pid: u32,
}

/// Module information returned by the Windows helper
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsModuleInfo {
    /// Module basename
    pub module_name: String,
    /// Full Windows module path
    pub windows_path: String,
}

/// Process enumeration result with any partial-read diagnostics
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessQueryResult {
    /// Visible processes
    pub processes: Vec<WindowsProcessInfo>,
    /// Per-process identity fields that could not be read
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejections: Vec<ProcessQueryRejection>,
}

/// One process identity read that was retained instead of silently discarded
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessQueryRejection {
    /// Stable helper error category
    pub kind: String,
    /// Detailed operation failure
    pub message: String,
    /// Windows error when the API supplied one
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows_error: Option<u32>,
    /// Process whose identity could not be fully inspected
    pub windows_pid: u32,
    /// Process basename captured from the process snapshot
    #[serde(default)]
    pub process_name: String,
}

/// Successful module enumeration result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleQueryResult {
    /// Loaded modules
    pub modules: Vec<WindowsModuleInfo>,
    /// Resolved target
    pub target: WindowsProcessInfo,
}

/// Successful load result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadLibraryResult {
    /// Non-fatal dependency visibility findings collected before loading
    pub dependency_warnings: Vec<String>,
    /// Windows final path reported by the helper's verified module identity
    pub loaded_module_path: String,
    /// Whether the helper observed the verified canonical module after loading
    pub module_verified: bool,
    /// Resolved process basename
    pub process_name: String,
    /// Low 32 bits returned by the remote loader thread when one was started
    pub thread_exit_code_low32: Option<u32>,
    /// Resolved Windows process identifier
    pub windows_pid: u32,
    /// Whether the requested module was already loaded before this request
    pub already_loaded: bool,
    /// Modules observed after loading that were absent before loading
    pub modules_added: Vec<WindowsModuleInfo>,
    /// Number of modules observed before loading
    pub module_count_before: usize,
    /// Number of modules observed after loading
    pub module_count_after: usize,
}

/// Typed success payload
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum HelperResult {
    /// Remote DLL load result
    LoadLibrary(LoadLibraryResult),
    /// Module enumeration result
    QueryModules(ModuleQueryResult),
    /// Process enumeration result
    QueryProcesses(ProcessQueryResult),
    /// Non-mutating helper self-test
    SelfTest(SelfTestResult),
    /// Helper identity
    Version(HelperVersion),
}
