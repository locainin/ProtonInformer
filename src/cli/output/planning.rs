use crate::binary::BinaryInspection;
use crate::decision::{LoadPlan, OverridePlan};

use crate::cli::style;

use super::inventory::print_process;

/// Writes payload inspection details for terminal use
pub(in crate::cli) fn print_inspection(inspection: &BinaryInspection) {
    println!("Selected file: {}", inspection.path.display());
    println!(
        "Detected: {} {}",
        inspection.architecture, inspection.format
    );
    println!("Size: {} bytes", inspection.size_bytes);
    if let Some(warning) = &inspection.extension_warning {
        println!("{}: {warning}", style::warning_word("Warning"));
    }
}

/// Writes a running-load plan and every readiness requirement
pub(in crate::cli) fn print_load_plan(plan: &LoadPlan) {
    print_process(&plan.target);
    println!();
    println!("Payload");
    println!("  Path:                {}", plan.payload.path.display());
    println!("  Format:              {}", plan.payload.format);
    println!("  Architecture:        {}", plan.payload.architecture);
    println!("  Size:                {} bytes", plan.payload.size_bytes);
    println!();
    println!("Decision");
    println!("  Backend:             {:?}", plan.backend);
    println!("  Target architecture: {}", plan.target_architecture);
    println!("  Payload path mode:   {:?}", plan.payload_path_mode);
    println!("  Executable now:      {}", plan.executable_now);
    println!("  Reason:              {}", plan.note);
    for requirement in &plan.requirements {
        println!(
            "  [{}] {}: {}",
            style::status(requirement.status),
            requirement.name,
            requirement.detail
        );
    }
}

/// Writes a startup override plan without implying that placement is complete
pub(in crate::cli) fn print_override_plan(plan: &OverridePlan) {
    println!("Startup Override");
    println!(
        "  AppID:         {}",
        plan.app_id
            .map_or_else(|| "<none>".into(), |id| id.to_string())
    );
    println!("  Prefix:        {}", plan.prefix.display());
    println!("  Payload:       {}", plan.payload.path.display());
    println!("  Windows path:  {}", plan.payload_windows_path);
    println!("  DLL name:      {}", plan.dll_name);
    println!("  Launch option: {}", plan.launch_option);
    println!("  Placement:     {:?}", plan.placement);
    println!("  Files changed: {}", plan.files_modified);
    println!(
        "  {}:       {}",
        style::warning_word("Warning"),
        plan.placement_note
    );
}
