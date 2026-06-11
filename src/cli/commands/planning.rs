use std::path::{Path, PathBuf};

use crate::binary;
use crate::decision;
use crate::error::{Error, Result};
use crate::helper_runtime::PayloadPathMode;
use crate::process;
use crate::steam;

use crate::cli::output;

/// Inspects one payload from binary headers
pub(super) fn run_inspect(payload: &Path, json: bool) -> Result<()> {
    let inspection = binary::inspect(payload)?;
    if json {
        output::error::print_json(&inspection)
    } else {
        output::planning::print_inspection(&inspection);
        Ok(())
    }
}

/// Runs startup override planning
pub(super) fn run_override_plan(
    payload: &Path,
    dll_name: &str,
    app_id: Option<u32>,
    prefix: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    let payload = binary::inspect(payload)?;
    let prefix = resolve_prefix(app_id, prefix)?;
    let plan = decision::plan_override(payload, &prefix, app_id, dll_name)?;
    if json {
        output::error::print_json(&plan)
    } else {
        output::planning::print_override_plan(&plan);
        Ok(())
    }
}

/// Runs non-mutating backend planning
pub(super) fn run_plan(
    payload: &Path,
    pid: u32,
    target_architecture: Option<crate::types::Architecture>,
    payload_path_mode: PayloadPathMode,
    json: bool,
) -> Result<()> {
    let payload = binary::inspect(payload)?;
    let target = process::inspect(pid)?;
    let plan = decision::plan_running(payload, target, target_architecture, payload_path_mode)?;
    if json {
        output::error::print_json(&plan)
    } else {
        output::planning::print_load_plan(&plan);
        Ok(())
    }
}

/// Resolves a manually supplied prefix or an existing Steam compatdata prefix
fn resolve_prefix(app_id: Option<u32>, prefix: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(prefix) = prefix {
        return Ok(prefix);
    }

    let app_id = app_id.ok_or_else(|| {
        Error::InvalidInput("either --app-id or --prefix must be supplied".into())
    })?;
    let (game, warnings) = steam::find_game(app_id);
    let game = game.ok_or_else(|| {
        let suffix = if warnings.is_empty() {
            String::new()
        } else {
            format!("; Steam discovery reported {} warning(s)", warnings.len())
        };
        Error::InvalidInput(format!("Steam AppID {app_id} was not found{suffix}"))
    })?;

    game.proton_prefix.ok_or_else(|| {
        Error::InvalidInput(format!(
            "Steam AppID {app_id} has no existing Proton prefix at {}",
            game.compatdata_dir.join("pfx").display()
        ))
    })
}
