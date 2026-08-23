//! Serializable process identity and classification models

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::types::Architecture;

/// Confidence assigned to Wine or native process classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationConfidence {
    /// Multiple trusted indicators agree
    High,
    /// One runtime indicator is supported by guest executable evidence
    Medium,
    /// Only one runtime indicator is available
    Low,
}

/// Result of reading selected process environment keys
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentStatus {
    /// Environment was not read because cheap evidence ruled out a target
    NotInspected,
    /// Selected environment keys were read
    Read,
    /// Kernel permissions blocked environment access
    PermissionDenied,
    /// The environment disappeared or could not be read
    Missing,
}

/// How a guest executable path was discovered
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestExecutableSource {
    /// An absolute Unix argument named an existing PE executable
    AbsoluteUnixArgument,
    /// A relative Unix argument resolved through the process working directory
    RelativeUnixArgument,
    /// A Windows drive argument resolved through prefix mappings
    WindowsDriveArgument,
}

/// Existing guest executable and the evidence that identified it
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestExecutableCandidate {
    /// Existing host path to the guest PE executable
    pub path: PathBuf,
    /// Command-line evidence used to resolve the path
    pub source: GuestExecutableSource,
}

/// One optional process fact that could not be read without discarding the PID
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessEvidenceFailure {
    /// Stable error category
    pub kind: String,
    /// Detailed read or resolution reason
    pub message: String,
}

/// Real, effective, saved, and filesystem UIDs from `/proc/<pid>/status`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessUids {
    /// Effective UID used for most access checks
    pub effective: u32,
    /// Filesystem UID used for filesystem permission checks
    pub filesystem: u32,
    /// Real UID associated with the process owner
    pub real: u32,
    /// Saved UID retained for privilege transitions
    pub saved: u32,
}

/// Process facts used by backend planning
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Confidence in the native or Wine classification
    pub classification_confidence: ClassificationConfidence,
    /// Display command line with NUL separators decoded lossily
    pub command: Vec<String>,
    /// Proton compatdata directory when known
    pub compatdata_dir: Option<PathBuf>,
    /// Result of reading selected environment keys
    pub environment_status: EnvironmentStatus,
    /// Optional evidence failures retained with an otherwise usable process row
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_failures: Vec<ProcessEvidenceFailure>,
    /// Native host executable when readable
    pub executable: Option<PathBuf>,
    /// Architecture of the discovered guest PE executable
    pub guest_architecture: Option<Architecture>,
    /// Existing guest executable and discovery source
    pub guest_executable: Option<GuestExecutableCandidate>,
    /// Kernel process name
    pub name: String,
    /// Whether filesystem ownership matches the current process
    pub owned_by_current_user: Option<bool>,
    /// Linux process identifier
    pub pid: u32,
    /// Linux process start time in clock ticks after system boot
    pub start_time_ticks: u64,
    /// Proton distribution path when exported by the runtime
    pub proton_dist: Option<PathBuf>,
    /// Steam application identifier when known
    pub steam_app_id: Option<u32>,
    /// Steam client root exported to the compatibility runtime
    pub steam_client_path: Option<PathBuf>,
    /// Native Linux or Wine/Proton target classification
    pub target_kind: TargetKind,
    /// Process UID set
    pub uids: Option<ProcessUids>,
    /// Existing Wine prefix when known
    pub wine_prefix: Option<PathBuf>,
}

/// One process that could not be inspected during a live `/proc` scan
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInspectionFailure {
    /// Linux PID when the directory name identified one
    pub pid: Option<u32>,
    /// Stable error category
    pub kind: String,
    /// Detailed rejection reason retained for diagnostics
    pub message: String,
}

/// Process results plus operational failures from the same scan
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessListReport {
    /// Processes whose required evidence was collected
    pub processes: Vec<ProcessInfo>,
    /// Non-transient process inspection failures
    pub rejections: Vec<ProcessInspectionFailure>,
}

/// Loader world used by the target process
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    /// Native Linux process using ELF modules
    NativeLinux,
    /// Windows process hosted by Wine or Proton
    WineProtonWindows,
}
