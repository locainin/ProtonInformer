//! Parsed command execution for the CLI boundary.

mod common;
mod diagnostics;
mod inventory;
mod load;
mod planning;
mod state;

use crate::error::{Error, Result};
use crate::inject;
use crate::modules::ModuleFilters;

use self::common::{LoadMode, OutputMode, payload_path_mode, requested_load_mode};
use self::diagnostics::{run_doctor, run_steam_games, run_verify_install};
use self::inventory::{run_modules, run_processes};
use self::load::{InjectOptions, LoadOptions, run_inject, run_load};
use self::planning::{run_inspect, run_override_plan, run_plan};
use self::state::{run_cleanup, run_runs};
use super::args::{Cli, Command};

/// Executes one fully parsed command.
pub(super) fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Cleanup { older_than, prefix } => {
            run_cleanup(older_than.as_deref(), prefix.as_deref(), cli.json)?;
        }
        Command::Doctor { pid } => run_doctor(pid, cli.json)?,
        Command::Inspect { payload } => run_inspect(&payload, cli.json)?,
        Command::Inject {
            payload,
            pid,
            app_id,
            process,
            wait_for,
            dry_run,
            yes,
            keep_run_files,
            original_payload_path,
            timeout_ms,
        } => run_inject(&InjectOptions {
            payload,
            pid,
            app_id,
            process,
            wait_for: wait_for
                .as_deref()
                .map(inject::parse_wait_duration)
                .transpose()?,
            mode: requested_load_mode(dry_run, yes)?,
            keep_run_files,
            payload_path_mode: payload_path_mode(original_payload_path),
            timeout_ms,
            output: OutputMode::from_json(cli.json),
        })?,
        Command::Load {
            payload,
            pid,
            target_arch,
            dry_run,
            yes,
            keep_run_files,
            original_payload_path,
            timeout_ms,
        } => run_load(&LoadOptions {
            payload,
            pid,
            target_arch,
            mode: requested_load_mode_for_load(dry_run, yes)?,
            keep_run_files,
            payload_path_mode: payload_path_mode(original_payload_path),
            timeout_ms,
            json: cli.json,
        })?,
        Command::Modules {
            pid,
            app_id,
            process,
            filter,
            contains,
        } => run_modules(
            pid,
            app_id,
            process.as_deref(),
            &ModuleFilters {
                name: filter,
                contains,
            },
            cli.json,
        )?,
        Command::OverridePlan {
            payload,
            dll_name,
            app_id,
            prefix,
        } => run_override_plan(&payload, &dll_name, app_id, prefix, cli.json)?,
        Command::Plan {
            payload,
            pid,
            target_arch,
        } => run_plan(&payload, pid, target_arch, cli.json)?,
        Command::Processes { wine_only } => run_processes(wine_only, cli.json)?,
        Command::Runs { prefix } => run_runs(prefix.as_deref(), cli.json)?,
        Command::SteamGames => run_steam_games(cli.json)?,
        Command::VerifyInstall { arch, pid } => run_verify_install(arch, pid, cli.json)?,
    }

    Ok(())
}

/// Preserves the original load-command validation message.
fn requested_load_mode_for_load(dry_run: bool, yes: bool) -> Result<LoadMode> {
    if dry_run {
        Ok(LoadMode::DryRun)
    } else if yes {
        Ok(LoadMode::Execute)
    } else {
        Err(Error::InvalidInput(
            "select exactly one of --dry-run or --yes".into(),
        ))
    }
}
