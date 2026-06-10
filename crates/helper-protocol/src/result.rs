use serde::{Deserialize, Serialize};

use crate::{HelperVersion, ProtocolArchitecture};

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
    /// Windows process creation timestamp in 100-nanosecond units.
    pub creation_time_100ns: Option<u64>,
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
    /// Non-fatal dependency visibility findings collected before loading.
    pub dependency_warnings: Vec<String>,
    /// Path reported by module verification.
    pub loaded_module_path: String,
    /// Whether the exact module path was observed after loading.
    pub module_verified: bool,
    /// Resolved process basename.
    pub process_name: String,
    /// Low 32 bits returned by the remote loader thread when one was started.
    pub thread_exit_code_low32: Option<u32>,
    /// Resolved Windows process identifier.
    pub windows_pid: u32,
    /// Whether the requested module was already loaded before this request.
    pub already_loaded: bool,
    /// Modules observed after loading that were absent before loading.
    pub modules_added: Vec<WindowsModuleInfo>,
    /// Number of modules observed before loading.
    pub module_count_before: usize,
    /// Number of modules observed after loading.
    pub module_count_after: usize,
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
