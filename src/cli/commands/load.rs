//! Load and inject command execution.

use std::path::PathBuf;

use crate::binary;
use crate::decision;
use crate::error::{Error, Result};
use crate::helper_runtime::{self, PayloadPathMode};
use crate::inject;
use crate::load;
use crate::process;

use super::common::{LoadMode, OutputMode};
use crate::cli::output;

/// Fully parsed inputs for the product-level injection command
pub(super) struct InjectOptions {
    pub(super) payload: PathBuf,
    pub(super) pid: Option<u32>,
    pub(super) app_id: Option<u32>,
    pub(super) process: Option<String>,
    pub(super) wait_for: Option<std::time::Duration>,
    pub(super) mode: LoadMode,
    pub(super) keep_run_files: bool,
    pub(super) payload_path_mode: PayloadPathMode,
    pub(super) timeout_ms: u64,
    pub(super) output: OutputMode,
}

/// Fully parsed inputs for one helper-backed load
pub(super) struct LoadOptions {
    pub(super) payload: PathBuf,
    pub(super) pid: u32,
    pub(super) target_arch: Option<crate::types::Architecture>,
    pub(super) mode: LoadMode,
    pub(super) keep_run_files: bool,
    pub(super) payload_path_mode: PayloadPathMode,
    pub(super) timeout_ms: u64,
    pub(super) json: bool,
}

/// Runs target discovery followed by the existing validated load flow
pub(super) fn run_inject(options: &InjectOptions) -> Result<()> {
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

/// Validates and prepares one helper-backed running-process load
pub(super) fn run_load(options: &LoadOptions) -> Result<()> {
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
