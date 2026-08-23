//! Serializable helper runtime, invocation, and planning models

use std::collections::BTreeMap;
use std::path::PathBuf;

use proton_informer_helper_protocol::HelperRequest;
use serde::{Deserialize, Serialize};

/// Host path choice used when building the helper load request
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadPathMode {
    /// Copy the payload to private run state before loading
    StagedCopy,
    /// Load the original payload path after validation
    OriginalPath,
}

/// Runtime used to execute the Windows helper
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum HelperRuntime {
    /// Steam Proton invocation with target identity variables
    Proton {
        /// Steam application identifier
        app_id: u32,
        /// Steam compatdata directory
        compatdata_dir: PathBuf,
        /// Proton launcher script
        proton_path: PathBuf,
        /// Steam client root
        steam_client_path: PathBuf,
    },
    /// Plain Wine invocation
    Wine {
        /// Existing Wine prefix
        prefix: PathBuf,
        /// Wine executable
        wine_binary: PathBuf,
    },
}

/// Exact executable, arguments, and environment for one helper run
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperInvocation {
    /// Helper command arguments
    pub arguments: Vec<String>,
    /// Environment variables required by the runtime
    pub environment: BTreeMap<String, String>,
    /// Program launched by the controller
    pub program: PathBuf,
    /// Runtime classification
    pub runtime: HelperRuntime,
}

/// Persisted dry-run artifacts and typed invocation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadDryRunPlan {
    /// Linux PID selected for the helper operation
    pub target_pid: u32,
    /// Linux process start time captured during target inspection
    pub target_start_time_ticks: u64,
    /// Linux target filesystem UID captured during target inspection
    pub target_filesystem_uid: u32,
    /// Windows helper path visible inside the selected prefix
    pub helper_windows_path: String,
    /// Exact helper invocation
    pub invocation: HelperInvocation,
    /// Path mode used for the helper request
    pub payload_path_mode: PayloadPathMode,
    /// Host payload path referenced by the helper request
    pub payload_host_path: PathBuf,
    /// Validated request body
    pub request: HelperRequest,
    /// Host request path
    pub request_host_path: PathBuf,
    /// Windows request path visible inside the prefix
    pub request_windows_path: String,
    /// Per-request state directory
    pub run_directory: PathBuf,
}
