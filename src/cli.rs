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
use crate::inject;
use crate::install;
use crate::load;
use crate::process::{self, TargetKind};
use crate::runs;
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
        Command::Cleanup { older_than } => {
            run_cleanup(older_than.as_deref(), cli.json)?;
        }
        Command::Doctor { pid } => run_doctor(pid, cli.json)?,
        Command::Inspect { payload } => run_inspect(&payload, cli.json)?,
        Command::Inject {
            payload,
            pid,
            app_id,
            process,
            dry_run,
            yes,
            keep_run_files,
            timeout_ms,
        } => run_inject(&InjectOptions {
            payload,
            pid,
            app_id,
            process,
            mode: requested_load_mode(dry_run, yes)?,
            keep_run_files,
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
        Command::Modules {
            pid,
            app_id,
            process,
        } => run_modules(pid, app_id, process.as_deref(), cli.json)?,
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
        Command::Runs => run_runs(cli.json)?,
        Command::SteamGames => run_steam_games(cli.json)?,
        Command::VerifyInstall { arch, pid } => run_verify_install(arch, pid, cli.json)?,
    }

    Ok(())
}

/// Lists safe managed run-state directories.
fn run_runs(json: bool) -> Result<()> {
    let report = runs::list()?;
    if json {
        output::print_json(&report)
    } else {
        output::print_runs(&report);
        Ok(())
    }
}

/// Removes all or age-filtered managed run-state directories.
fn run_cleanup(older_than: Option<&str>, json: bool) -> Result<()> {
    let threshold = older_than.map(runs::parse_age).transpose()?;
    let report = runs::cleanup(threshold)?;
    if json {
        output::print_json(&report)
    } else {
        output::print_cleanup(&report);
        Ok(())
    }
}

/// Resolves one target and prints the helper's loaded-module inventory.
fn run_modules(
    pid: Option<u32>,
    app_id: Option<u32>,
    process_name: Option<&str>,
    json: bool,
) -> Result<()> {
    let target = inject::select_target(pid, app_id, process_name)?;
    let result = helper_runtime::query_modules(&target)?;
    if json {
        output::print_json(&result)
    } else {
        output::print_modules(&result);
        Ok(())
    }
}

/// Fully parsed inputs for the product-level injection command.
struct InjectOptions {
    payload: PathBuf,
    pid: Option<u32>,
    app_id: Option<u32>,
    process: Option<String>,
    mode: LoadMode,
    keep_run_files: bool,
    timeout_ms: u64,
    output: OutputMode,
}

/// Runs helper readiness checks.
fn run_doctor(pid: Option<u32>, json: bool) -> Result<()> {
    let report = pid.map_or_else(|| Ok(doctor::run()), doctor::run_for_process)?;
    if json {
        output::print_json(&report)
    } else {
        output::print_doctor(report);
        Ok(())
    }
}

/// Inspects one payload from binary headers.
fn run_inspect(payload: &std::path::Path, json: bool) -> Result<()> {
    let inspection = binary::inspect(payload)?;
    if json {
        output::print_json(&inspection)
    } else {
        output::print_inspection(&inspection);
        Ok(())
    }
}

/// Runs target discovery followed by the existing validated load flow.
fn run_inject(options: &InjectOptions) -> Result<()> {
    let target = inject::select_target(options.pid, options.app_id, options.process.as_deref())?;
    if options.output == OutputMode::Human {
        output::print_selected_target(&target);
    }
    run_load_for_target(
        &options.payload,
        target,
        None,
        options.mode,
        options.keep_run_files,
        options.timeout_ms,
        options.output == OutputMode::Json,
    )
}

/// Converts command flags into one explicit load behavior.
fn requested_load_mode(dry_run: bool, yes: bool) -> Result<LoadMode> {
    match (dry_run, yes) {
        (true, false) => Ok(LoadMode::DryRun),
        (false, true) => Ok(LoadMode::Execute),
        _ => Err(Error::InvalidInput(
            "select --dry-run to inspect the request or --yes to execute it".into(),
        )),
    }
}

/// Runs startup override planning.
fn run_override_plan(
    payload: &std::path::Path,
    dll_name: &str,
    app_id: Option<u32>,
    prefix: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    let payload = binary::inspect(payload)?;
    let prefix = resolve_prefix(app_id, prefix)?;
    let plan = decision::plan_override(payload, &prefix, app_id, dll_name)?;
    if json {
        output::print_json(&plan)
    } else {
        output::print_override_plan(&plan);
        Ok(())
    }
}

/// Runs non-mutating backend planning.
fn run_plan(
    payload: &std::path::Path,
    pid: u32,
    target_architecture: Option<crate::types::Architecture>,
    json: bool,
) -> Result<()> {
    let payload = binary::inspect(payload)?;
    let target = process::inspect(pid)?;
    let plan = decision::plan_running(payload, target, target_architecture)?;
    if json {
        output::print_json(&plan)
    } else {
        output::print_load_plan(&plan);
        Ok(())
    }
}

/// Lists readable process evidence.
fn run_processes(wine_only: bool, json: bool) -> Result<()> {
    let mut processes = process::list();
    if wine_only {
        processes.retain(|process| process.target_kind == TargetKind::WineProtonWindows);
    }
    if json {
        output::print_json(&processes)
    } else {
        for process in processes {
            output::print_process(&process);
            println!();
        }
        Ok(())
    }
}

/// Lists Steam games and retained metadata warnings.
fn run_steam_games(json: bool) -> Result<()> {
    let report = steam::discover_games();
    if json {
        output::print_json(&report)
    } else {
        output::print_steam_games(report);
        Ok(())
    }
}

/// Verifies packaged helpers offline or adds a live runtime probe.
fn run_verify_install(
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
        output::print_json(&reports)
    } else {
        output::print_install_verifications(&reports);
        Ok(())
    }
}

/// Explicit behavior selected for one validated load request.
#[derive(Clone, Copy)]
enum LoadMode {
    /// Build and print request artifacts without starting the helper.
    DryRun,
    /// Execute the helper and require verified module evidence.
    Execute,
}

/// Terminal or machine-readable output selection.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    Human,
    Json,
}

impl OutputMode {
    /// Converts the global JSON flag once at the command boundary.
    const fn from_json(json: bool) -> Self {
        if json { Self::Json } else { Self::Human }
    }
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
    let target = process::inspect(options.pid)?;
    run_load_for_target(
        &options.payload,
        target,
        options.target_arch,
        options.mode,
        options.keep_run_files,
        options.timeout_ms,
        options.json,
    )
}

/// Runs the shared validated helper flow for one already selected target.
fn run_load_for_target(
    payload_path: &std::path::Path,
    target: crate::process::ProcessInfo,
    target_architecture: Option<crate::types::Architecture>,
    mode: LoadMode,
    keep_run_files: bool,
    timeout_ms: u64,
    json: bool,
) -> Result<()> {
    let payload = binary::inspect(payload_path)?;
    let plan = decision::plan_running(payload, target, target_architecture)?;
    if !plan.executable_now {
        return Err(Error::Rejected(
            "load is not executable because one or more requirements did not fully pass; run plan \
             or doctor for details"
                .into(),
        ));
    }
    let helper_plan = helper_runtime::plan_load_dry_run(&plan.payload, &plan.target, timeout_ms)?;
    match mode {
        LoadMode::DryRun => {
            if json {
                output::print_json(&helper_plan)
            } else {
                output::print_load_dry_run(&helper_plan);
                Ok(())
            }
        }
        LoadMode::Execute => {
            let result = load::execute(&helper_plan, keep_run_files)?;
            if json {
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
