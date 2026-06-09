//! Command-line orchestration kept separate from the executable entry point.

mod args;
mod output;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, error::ErrorKind};

use self::args::{Cli, Command};
use crate::binary;
use crate::decision;
use crate::doctor;
use crate::error::{Error, Result};
use crate::helper_runtime;
use crate::load;
use crate::process::{self, TargetKind};
use crate::steam;

/// Parses process arguments, runs one command, and returns its exit status.
#[must_use]
pub fn launch() -> ExitCode {
    launch_from(std::env::args_os())
}

/// Runs the CLI from an explicit argument source.
///
/// Keeping parsing here allows tests and other clients to exercise the same
/// command boundary without adding logic to `main.rs`.
fn launch_from<I, T>(arguments: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let collected: Vec<OsString> = arguments.into_iter().map(Into::into).collect();
    let json_requested = collected.iter().any(|argument| argument == "--json");
    let cli = match Cli::try_parse_from(collected) {
        Ok(cli) => cli,
        Err(error) => {
            let informational = matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            );
            if informational {
                if let Err(print_error) = error.print() {
                    eprintln!("Error: {print_error}");
                }
                return ExitCode::SUCCESS;
            }
            if json_requested {
                output::print_error("cli_parse", &error.to_string());
            } else if let Err(print_error) = error.print() {
                eprintln!("Error: {print_error}");
            }
            return ExitCode::from(2);
        }
    };
    let json = cli.json;

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if json {
                output::print_error(error.kind(), &error.to_string());
            } else {
                eprintln!("Error: {error}");
            }
            ExitCode::FAILURE
        }
    }
}

/// Executes one fully parsed command.
fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Doctor { pid } => {
            let report = pid.map_or_else(|| Ok(doctor::run()), doctor::run_for_process)?;
            if cli.json {
                output::print_json(&report)?;
            } else {
                output::print_doctor(report);
            }
        }
        Command::Inspect { payload } => {
            let inspection = binary::inspect(&payload)?;
            if cli.json {
                output::print_json(&inspection)?;
            } else {
                output::print_inspection(&inspection);
            }
        }
        Command::Load {
            payload,
            pid,
            target_arch,
            dry_run,
            yes,
            keep_run_files,
            timeout_ms,
        } => run_load(&LoadOptions {
            payload,
            pid,
            target_arch,
            mode: if dry_run {
                LoadMode::DryRun
            } else if yes {
                LoadMode::Execute
            } else {
                return Err(Error::InvalidInput(
                    "select exactly one of --dry-run or --yes".into(),
                ));
            },
            keep_run_files,
            timeout_ms,
            json: cli.json,
        })?,
        Command::OverridePlan {
            payload,
            dll_name,
            app_id,
            prefix,
        } => {
            let payload = binary::inspect(&payload)?;
            let prefix = resolve_prefix(app_id, prefix)?;
            let plan = decision::plan_override(payload, &prefix, app_id, &dll_name)?;
            if cli.json {
                output::print_json(&plan)?;
            } else {
                output::print_override_plan(&plan);
            }
        }
        Command::Plan {
            payload,
            pid,
            target_arch,
        } => {
            let payload = binary::inspect(&payload)?;
            let target = process::inspect(pid)?;
            let plan = decision::plan_running(payload, target, target_arch)?;
            if cli.json {
                output::print_json(&plan)?;
            } else {
                output::print_load_plan(&plan);
            }
        }
        Command::Processes { wine_only } => {
            let mut processes = process::list();
            if wine_only {
                processes.retain(|process| process.target_kind == TargetKind::WineProtonWindows);
            }
            if cli.json {
                output::print_json(&processes)?;
            } else {
                for process in processes {
                    output::print_process(&process);
                    println!();
                }
            }
        }
        Command::SteamGames => {
            let report = steam::discover_games();
            if cli.json {
                output::print_json(&report)?;
            } else {
                output::print_steam_games(report);
            }
        }
    }

    Ok(())
}

/// Explicit behavior selected for one validated load request.
enum LoadMode {
    /// Build and print request artifacts without starting the helper.
    DryRun,
    /// Execute the helper and require verified module evidence.
    Execute,
}

/// Fully parsed inputs for one helper-backed load.
struct LoadOptions {
    payload: PathBuf,
    pid: u32,
    target_arch: Option<crate::types::Architecture>,
    mode: LoadMode,
    keep_run_files: bool,
    timeout_ms: u64,
    json: bool,
}

/// Validates and prepares one helper-backed running-process load.
fn run_load(options: &LoadOptions) -> Result<()> {
    let payload = binary::inspect(&options.payload)?;
    let target = process::inspect(options.pid)?;
    let plan = decision::plan_running(payload, target, options.target_arch)?;
    if !plan.executable_now {
        return Err(Error::Rejected(
            "load is not executable because one or more requirements did not fully pass; run plan \
             or doctor for details"
                .into(),
        ));
    }
    let helper_plan =
        helper_runtime::plan_load_dry_run(&plan.payload, &plan.target, options.timeout_ms)?;
    match options.mode {
        LoadMode::DryRun => {
            if options.json {
                output::print_json(&helper_plan)
            } else {
                output::print_load_dry_run(&helper_plan);
                Ok(())
            }
        }
        LoadMode::Execute => {
            let result = load::execute(&helper_plan, options.keep_run_files)?;
            if options.json {
                output::print_json(&result)
            } else {
                output::print_load_result(&result);
                Ok(())
            }
        }
    }
}

/// Resolves a manually supplied prefix or an existing Steam compatdata prefix.
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
