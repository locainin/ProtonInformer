//! Shared command execution options.

use crate::error::{Error, Result};
use crate::helper_runtime::PayloadPathMode;

/// Explicit behavior selected for one validated load request
#[derive(Clone, Copy)]
pub(super) enum LoadMode {
    /// Build and print request artifacts without starting the helper
    DryRun,
    /// Execute the helper and require verified module evidence
    Execute,
}

/// Terminal or machine-readable output selection
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum OutputMode {
    Human,
    Json,
}

impl OutputMode {
    /// Converts the global JSON flag once at the command boundary
    pub(super) const fn from_json(json: bool) -> Self {
        if json { Self::Json } else { Self::Human }
    }
}

/// Converts command flags into one explicit load behavior
pub(super) fn requested_load_mode(dry_run: bool, yes: bool) -> Result<LoadMode> {
    match (dry_run, yes) {
        (true, false) => Ok(LoadMode::DryRun),
        (false, true) => Ok(LoadMode::Execute),
        _ => Err(Error::InvalidInput(
            "select --dry-run to inspect the request or --yes to execute it".into(),
        )),
    }
}

/// Converts a compatibility flag into an explicit payload path mode
pub(super) const fn payload_path_mode(original_payload_path: bool) -> PayloadPathMode {
    if original_payload_path {
        PayloadPathMode::OriginalPath
    } else {
        PayloadPathMode::StagedCopy
    }
}
