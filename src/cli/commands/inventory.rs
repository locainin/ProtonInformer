//! Target module and process inventory command execution.

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
        output::print_json(&result)
    } else {
        output::print_modules(&result);
        Ok(())
    }
}

/// Lists readable process evidence
pub(super) fn run_processes(wine_only: bool, json: bool) -> Result<()> {
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
