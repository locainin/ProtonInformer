use crate::error::{Error, Result};
use crate::helper_runtime::PayloadPathMode;

#[derive(Clone, Copy)]
pub(super) enum LoadMode {
    DryRun,
    Execute,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum OutputMode {
    Text,
    Json,
}

impl OutputMode {
    pub(super) const fn from_json(json: bool) -> Self {
        if json { Self::Json } else { Self::Text }
    }
}

pub(super) fn requested_load_mode(dry_run: bool, yes: bool) -> Result<LoadMode> {
    match (dry_run, yes) {
        (true, false) => Ok(LoadMode::DryRun),
        (false, true) => Ok(LoadMode::Execute),
        _ => Err(Error::InvalidInput(
            "select --dry-run to inspect the request or --yes to execute it".into(),
        )),
    }
}

pub(super) const fn payload_path_mode(original_payload_path: bool) -> PayloadPathMode {
    if original_payload_path {
        PayloadPathMode::OriginalPath
    } else {
        PayloadPathMode::StagedCopy
    }
}
