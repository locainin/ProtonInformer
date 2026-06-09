use serde::{Deserialize, Serialize};

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
