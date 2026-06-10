use serde::{Deserialize, Serialize};

use crate::{HelperCapability, ProtocolArchitecture};

/// Version information emitted by `--version-json`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperVersion {
    /// Architecture of the helper executable
    pub architecture: ProtocolArchitecture,
    /// Operations implemented by this build
    pub capabilities: Vec<HelperCapability>,
    /// Stable helper product name
    pub helper_name: String,
    /// Semantic helper version
    pub helper_version: String,
    /// Highest schema emitted by this helper
    pub schema_version: u32,
    /// Every accepted request schema
    pub schema_versions: Vec<u32>,
}
