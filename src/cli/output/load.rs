use crate::cli::style;
use crate::helper_runtime::LoadDryRunPlan;
use crate::load::LoadExecutionResult;

/// Writes the generated request and exact no-shell helper invocation
pub(in crate::cli) fn print_load_dry_run(plan: &LoadDryRunPlan) {
    println!("Load Dry Run");
    println!("  Request ID:   {}", plan.request.request_id);
    println!("  Run state:    {}", plan.run_directory.display());
    println!("  Request file: {}", plan.request_host_path.display());
    println!("  Payload mode: {:?}", plan.payload_path_mode);
    println!("  Payload path: {}", plan.payload_host_path.display());
    println!("  Helper:       {}", plan.helper_windows_path);
    println!("  Program:      {}", plan.invocation.program.display());
    for (name, value) in &plan.invocation.environment {
        println!("  Environment:  {name}={value}");
    }
    for argument in &plan.invocation.arguments {
        println!("  Argument:     {argument}");
    }
    println!("  Executed:     no");
}

/// Writes a verified live helper result and its audit path
pub(in crate::cli) fn print_load_result(result: &LoadExecutionResult) {
    println!("Load Result");
    println!("  Request ID:    {}", result.response.request_id);
    println!("  Response file: {}", result.response_host_path.display());
    if let Some(proton_informer_helper_protocol::HelperResult::LoadLibrary(load)) =
        &result.response.result
    {
        println!("  Windows PID:   {}", load.windows_pid);
        println!("  Process:       {}", load.process_name);
        if load.already_loaded {
            println!("  {}:", style::warning_word("Already loaded"));
        } else {
            println!("  {}:", style::success_word("Loaded"));
        }
        println!("    {}", load.loaded_module_path);
        println!("  Module diff:");
        println!("    before: {}", load.module_count_before);
        println!("    after:  {}", load.module_count_after);
        println!("    added:");
        if load.modules_added.is_empty() {
            println!("      none");
        } else {
            for module in &load.modules_added {
                println!("      + {}", module.windows_path);
            }
        }
        println!(
            "  {}:      {}",
            if load.module_verified {
                style::success_word("Verified")
            } else {
                style::failure_word("Verified")
            },
            load.module_verified
        );
        for warning in &load.dependency_warnings {
            println!("  {}:       {warning}", style::warning_word("Warning"));
        }
    }
}
