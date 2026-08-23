use crate::error::Result;
use crate::helper_runtime;
use crate::inject;
use crate::modules::{self, ModuleFilters};
use crate::process::{self, TargetKind};

use crate::cli::output;

/// Resolves one target and prints the helper's loaded-module inventory
pub(super) fn run_modules(
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
        output::error::print_json(&result)
    } else {
        output::inventory::print_modules(&result);
        Ok(())
    }
}

/// Lists readable process evidence
pub(super) fn run_processes(wine_only: bool, json: bool, debug: bool) -> Result<()> {
    let mut report = process::list_report();
    let mut processes = std::mem::take(&mut report.processes);
    if wine_only {
        processes.retain(|process| process.target_kind == TargetKind::WineProtonWindows);
    }
    if json {
        // Keep the established JSON contract as a top-level process array
        output::error::print_json(&processes)
    } else {
        for process in processes {
            output::inventory::print_process(&process);
            if debug {
                output::inventory::print_process_evidence_failures(&process);
            }
            println!();
        }
        if debug {
            output::inventory::print_process_rejections(&report.rejections);
        }
        Ok(())
    }
}
