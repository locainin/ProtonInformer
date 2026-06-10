//! Parsed command execution for the CLI boundary

use std::path::PathBuf;

use crate::binary;
use crate::decision;
use crate::doctor;
use crate::error::{Error, Result};
use crate::helper_runtime::{self, PayloadPathMode};
use crate::inject;
use crate::install;
use crate::load;
use crate::modules::{self, ModuleFilters};
use crate::process::{self, TargetKind};
use crate::runs;
use crate::steam;

use super::args::{Cli, Command};
use super::output;

/// Executes one fully parsed command
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

/// Lists safe managed run-state directories
fn run_runs(prefix: Option<&std::path::Path>, json: bool) -> Result<()> {
    let report = prefix.map_or_else(runs::list, runs::list_for_prefix)?;
    if json {
        output::print_json(&report)
    } else {
        output::print_runs(&report);
        Ok(())
    }
}

/// Removes all or age-filtered managed run-state directories
fn run_cleanup(
    older_than: Option<&str>,
    prefix: Option<&std::path::Path>,
    json: bool,
) -> Result<()> {
    let threshold = older_than.map(runs::parse_age).transpose()?;
    let report = prefix.map_or_else(
        || runs::cleanup(threshold),
        |prefix| runs::cleanup_for_prefix(prefix, threshold),
    )?;
    if json {
        output::print_json(&report)
    } else {
        output::print_cleanup(&report);
        Ok(())
    }
}

/// Resolves one target and prints the helper's loaded-module inventory
fn run_modules(
    pid: Option<u32>,
    app_id: Option<u32>,
    process_name: Option<&str>,
    filters: &ModuleFilters,
    json: bool,
) -> Result<()> {
    let target = inject::select_target(pid, app_id, process_name)?;
    let mut result = helper_runtime::query_modules(&target)?;
    modules::apply(&mut result, filters);
    if json {
        output::print_json(&result)
    } else {
        output::print_modules(&result);
        Ok(())
    }
}

/// Fully parsed inputs for the product-level injection command
struct InjectOptions {
    payload: PathBuf,
    pid: Option<u32>,
    app_id: Option<u32>,
    process: Option<String>,
    wait_for: Option<std::time::Duration>,
    mode: LoadMode,
    keep_run_files: bool,
    payload_path_mode: PayloadPathMode,
    timeout_ms: u64,
    output: OutputMode,
}

/// Runs helper readiness checks
fn run_doctor(pid: Option<u32>, json: bool) -> Result<()> {
    let report = pid.map_or_else(|| Ok(doctor::run()), doctor::run_for_process)?;
    if json {
        output::print_json(&report)
    } else {
        output::print_doctor(report);
        Ok(())
    }
}

/// Inspects one payload from binary headers
fn run_inspect(payload: &std::path::Path, json: bool) -> Result<()> {
    let inspection = binary::inspect(payload)?;
    if json {
        output::print_json(&inspection)
    } else {
        output::print_inspection(&inspection);
        Ok(())
    }
}

/// Runs target discovery followed by the existing validated load flow
fn run_inject(options: &InjectOptions) -> Result<()> {
    let target = inject::select_target_with_wait(
        options.pid,
        options.app_id,
        options.process.as_deref(),
        options.wait_for,
    )?;
    if options.output == OutputMode::Human {
        output::print_selected_target(&target);
    }
    run_load_for_target(&TargetLoadOptions {
        payload_path: &options.payload,
        target,
        target_architecture: None,
        mode: options.mode,
        keep_run_files: options.keep_run_files,
        payload_path_mode: options.payload_path_mode,
        timeout_ms: options.timeout_ms,
        json: options.output == OutputMode::Json,
    })
}

/// Converts command flags into one explicit load behavior
fn requested_load_mode(dry_run: bool, yes: bool) -> Result<LoadMode> {
    match (dry_run, yes) {
        (true, false) => Ok(LoadMode::DryRun),
        (false, true) => Ok(LoadMode::Execute),
        _ => Err(Error::InvalidInput(
            "select --dry-run to inspect the request or --yes to execute it".into(),
        )),
    }
}

/// Converts a compatibility flag into an explicit payload path mode
const fn payload_path_mode(original_payload_path: bool) -> PayloadPathMode {
    if original_payload_path {
        PayloadPathMode::OriginalPath
    } else {
        PayloadPathMode::StagedCopy
    }
}

/// Runs startup override planning
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

/// Runs non-mutating backend planning
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

/// Lists readable process evidence
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

/// Lists Steam games and retained metadata warnings
fn run_steam_games(json: bool) -> Result<()> {
    let report = steam::discover_games();
    if json {
        output::print_json(&report)
    } else {
        output::print_steam_games(report);
        Ok(())
    }
}

/// Verifies packaged helpers offline or adds a live runtime probe
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

/// Explicit behavior selected for one validated load request
#[derive(Clone, Copy)]
enum LoadMode {
    /// Build and print request artifacts without starting the helper
    DryRun,
    /// Execute the helper and require verified module evidence
    Execute,
}

/// Terminal or machine-readable output selection
#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    Human,
    Json,
}

impl OutputMode {
    /// Converts the global JSON flag once at the command boundary
    const fn from_json(json: bool) -> Self {
        if json { Self::Json } else { Self::Human }
    }
}

/// Fully parsed inputs for one helper-backed load
struct LoadOptions {
    payload: PathBuf,
    pid: u32,
    target_arch: Option<crate::types::Architecture>,
    mode: LoadMode,
    keep_run_files: bool,
    payload_path_mode: PayloadPathMode,
    timeout_ms: u64,
    json: bool,
}

/// Validates and prepares one helper-backed running-process load
fn run_load(options: &LoadOptions) -> Result<()> {
    let target = process::inspect(options.pid)?;
    run_load_for_target(&TargetLoadOptions {
        payload_path: &options.payload,
        target,
        target_architecture: options.target_arch,
        mode: options.mode,
        keep_run_files: options.keep_run_files,
        payload_path_mode: options.payload_path_mode,
        timeout_ms: options.timeout_ms,
        json: options.json,
    })
}

/// Fully resolved load inputs for one already selected target
struct TargetLoadOptions<'a> {
    payload_path: &'a std::path::Path,
    target: crate::process::ProcessInfo,
    target_architecture: Option<crate::types::Architecture>,
    mode: LoadMode,
    keep_run_files: bool,
    payload_path_mode: PayloadPathMode,
    timeout_ms: u64,
    json: bool,
}

/// Runs the shared validated helper flow for one already selected target
fn run_load_for_target(options: &TargetLoadOptions<'_>) -> Result<()> {
    let payload = binary::inspect(options.payload_path)?;
    let plan =
        decision::plan_running(payload, options.target.clone(), options.target_architecture)?;
    if !plan.executable_now {
        return Err(Error::Rejected(
            "load is not executable because one or more requirements did not fully pass; run plan \
             or doctor for details"
                .into(),
        ));
    }
    let helper_plan = helper_runtime::plan_load_dry_run(
        &plan.payload,
        &plan.target,
        options.timeout_ms,
        options.payload_path_mode,
    )?;
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
