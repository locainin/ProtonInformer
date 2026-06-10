use crate::doctor;
use crate::error::Result;
use crate::install;
use crate::process;
use crate::steam;

use crate::cli::output;

/// Runs helper readiness checks
pub(super) fn run_doctor(pid: Option<u32>, json: bool) -> Result<()> {
    let report = pid.map_or_else(|| Ok(doctor::run()), doctor::run_for_process)?;
    if json {
        output::error::print_json(&report)
    } else {
        output::diagnostics::print_doctor(report);
        Ok(())
    }
}

/// Lists Steam games and retained metadata warnings
pub(super) fn run_steam_games(json: bool) -> Result<()> {
    let report = steam::discover_games();
    if json {
        output::error::print_json(&report)
    } else {
        output::inventory::print_steam_games(report);
        Ok(())
    }
}

/// Verifies packaged helpers offline or adds a live runtime probe
pub(super) fn run_verify_install(
    architecture: Option<crate::types::Architecture>,
    pid: Option<u32>,
    json: bool,
) -> Result<()> {
    let reports = if let Some(pid) = pid {
        let target = process::inspect(pid)?;
        vec![install::verify_for_target(&target)?]
    } else if let Some(architecture) = architecture {
        vec![install::verify_static(architecture)?]
    } else {
        install::verify_all_static()?
    };
    if json {
        output::error::print_json(&reports)
    } else {
        output::diagnostics::print_install_verifications(&reports);
        Ok(())
    }
}
