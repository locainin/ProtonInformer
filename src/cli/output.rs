//! Human and JSON presentation for typed application results.

use std::path::Path;

use serde::Serialize;

use crate::binary::BinaryInspection;
use crate::decision::{LoadPlan, OverridePlan};
use crate::doctor::DoctorReport;
use crate::error::{Error, Result};
use crate::helper_runtime::LoadDryRunPlan;
use crate::install::InstallVerification;
use crate::load::LoadExecutionResult;
use crate::process::ProcessInfo;
use crate::runs::{CleanupReport, RunStateReport};
use crate::steam::SteamDiscoveryReport;
use proton_informer_helper_protocol::ModuleQueryResult;

/// Machine-readable error response.
#[derive(Debug, Serialize)]
struct ErrorEnvelope<'a> {
    error: ErrorBody<'a>,
    ok: bool,
}

/// Stable error category and user-facing detail.
#[derive(Debug, Serialize)]
struct ErrorBody<'a> {
    kind: &'static str,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    windows_error: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    windows_error_hint: Option<&'static str>,
}

/// Writes a serialized value to standard output.
pub(super) fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let output = serde_json::to_string_pretty(value).map_err(Error::from)?;
    println!("{output}");
    Ok(())
}

/// Writes a structured error to standard error.
pub(super) fn print_error(
    kind: &'static str,
    message: &str,
    windows_error: Option<u32>,
    windows_error_hint: Option<&'static str>,
) {
    let envelope = ErrorEnvelope {
        error: ErrorBody {
            kind,
            message,
            windows_error,
            windows_error_hint,
        },
        ok: false,
    };

    // String-only serialization is expected to succeed. The fallback keeps
    // diagnostics visible if the response model changes later.
    match serde_json::to_string_pretty(&envelope) {
        Ok(output) => eprintln!("{output}"),
        Err(_) => eprintln!("Error: {message}"),
    }
}

/// Writes payload inspection details for terminal use.
pub(super) fn print_inspection(inspection: &BinaryInspection) {
    println!("Selected file: {}", inspection.path.display());
    println!(
        "Detected: {} {}",
        inspection.architecture, inspection.format
    );
    println!("Size: {} bytes", inspection.size_bytes);
    if let Some(warning) = &inspection.extension_warning {
        println!("Warning: {warning}");
    }
}

/// Writes a running-load plan and every readiness requirement.
pub(super) fn print_load_plan(plan: &LoadPlan) {
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
    println!("  Executable now:      {}", plan.executable_now);
    println!("  Reason:              {}", plan.note);
    for requirement in &plan.requirements {
        println!(
            "  [{:?}] {}: {}",
            requirement.status, requirement.name, requirement.detail
        );
    }
}

/// Writes the generated request and exact no-shell helper invocation.
pub(super) fn print_load_dry_run(plan: &LoadDryRunPlan) {
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

/// Writes a verified live helper result and its audit path.
pub(super) fn print_load_result(result: &LoadExecutionResult) {
    println!("Load Result");
    println!("  Request ID:    {}", result.response.request_id);
    println!("  Response file: {}", result.response_host_path.display());
    if let Some(proton_informer_helper_protocol::HelperResult::LoadLibrary(load)) =
        &result.response.result
    {
        println!("  Windows PID:   {}", load.windows_pid);
        println!("  Process:       {}", load.process_name);
        if load.already_loaded {
            println!("  Already loaded:");
        } else {
            println!("  Loaded:");
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
        println!("  Verified:      {}", load.module_verified);
        for warning in &load.dependency_warnings {
            println!("  Warning:       {warning}");
        }
    }
}

/// Writes one process with the evidence needed to diagnose planning.
pub(super) fn print_process(process: &ProcessInfo) {
    println!("Process");
    println!("  PID:                 {}", process.pid);
    println!("  UIDs:                {:?}", process.uids);
    println!("  Name:                {}", process.name);
    println!("  Kind:                {:?}", process.target_kind);
    println!(
        "  Confidence:          {:?}",
        process.classification_confidence
    );
    println!("  Environment:         {:?}", process.environment_status);
    println!("  Host architecture:   {}", process.host_architecture);
    println!(
        "  Guest executable:    {}",
        display_optional_path(
            process
                .guest_executable
                .as_ref()
                .map(|candidate| candidate.path.as_path())
        )
    );
    println!(
        "  Guest architecture:  {}",
        process.guest_architecture.map_or_else(
            || "<unknown>".into(),
            |architecture| architecture.to_string()
        )
    );
    println!(
        "  Wine prefix:         {}",
        display_optional_path(process.wine_prefix.as_deref())
    );
    println!(
        "  Compatdata:          {}",
        display_optional_path(process.compatdata_dir.as_deref())
    );
    println!(
        "  Steam AppID:         {}",
        process
            .steam_app_id
            .map_or_else(|| "<unknown>".into(), |id| id.to_string())
    );
}

/// Writes the unique target selected by the one-command workflow.
pub(super) fn print_selected_target(process: &ProcessInfo) {
    println!("Selected Target");
    println!("  Linux PID:           {}", process.pid);
    println!(
        "  Guest executable:    {}",
        display_optional_path(
            process
                .guest_executable
                .as_ref()
                .map(|candidate| candidate.path.as_path())
        )
    );
    println!(
        "  Steam AppID:         {}",
        process
            .steam_app_id
            .map_or_else(|| "<unknown>".into(), |id| id.to_string())
    );
}

/// Writes loaded modules returned by the exact Windows target.
pub(super) fn print_modules(result: &ModuleQueryResult) {
    println!("Modules");
    println!("  Windows PID: {}", result.target.windows_pid);
    println!("  Process:     {}", result.target.process_name);
    for module in &result.modules {
        println!("  {}  {}", module.module_name, module.windows_path);
    }
}

/// Writes managed run-state directories and retained warnings.
pub(super) fn print_runs(report: &RunStateReport) {
    println!("Run State");
    println!("  Root: {}", report.root.display());
    for run in &report.runs {
        println!(
            "  {}  age={}s  {}",
            run.request_id,
            run.age_seconds,
            run.path.display()
        );
    }
    for warning in &report.warnings {
        eprintln!("Warning: {warning}");
    }
}

/// Writes one cleanup summary and every skipped-entry warning.
pub(super) fn print_cleanup(report: &CleanupReport) {
    println!("Run Cleanup");
    println!("  Root:    {}", report.root.display());
    println!("  Removed: {}", report.removed);
    for warning in &report.warnings {
        eprintln!("Warning: {warning}");
    }
}

/// Writes Steam discovery results and retained metadata warnings.
pub(super) fn print_steam_games(report: SteamDiscoveryReport) {
    for game in report.games {
        println!("{}  {}", game.app_id, game.name);
        println!("  Game:    {}", game.game_dir.display());
        println!(
            "  Prefix:  {}",
            game.proton_prefix
                .as_deref()
                .map_or_else(|| "<not created>".into(), |path| path.display().to_string())
        );
    }
    for warning in report.warnings {
        eprintln!("Warning: {}: {}", warning.path.display(), warning.message);
    }
}

/// Writes a startup override plan without implying that placement is complete.
pub(super) fn print_override_plan(plan: &OverridePlan) {
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
    println!("  Warning:       {}", plan.placement_note);
}

/// Writes readiness by capability rather than one broad Wine status.
pub(super) fn print_doctor(report: DoctorReport) {
    println!("Process planning: {:?}", report.process_planning);
    println!("Steam discovery: {:?}", report.steam_discovery);
    println!("Wine helper x86: {:?}", report.wine_helper_x86);
    println!("Wine helper x86_64: {:?}", report.wine_helper_x86_64);
    for check in report.checks {
        println!("  [{:?}] {}: {}", check.status, check.name, check.detail);
    }
}

/// Formats an optional path without exposing platform-specific sentinel values.
fn display_optional_path(path: Option<&Path>) -> String {
    path.map_or_else(|| "<unknown>".into(), |path| path.display().to_string())
}

/// Writes every verified helper installation identity.
pub(super) fn print_install_verifications(reports: &[InstallVerification]) {
    for (index, report) in reports.iter().enumerate() {
        if index != 0 {
            println!();
        }
        println!("Helper Installation");
        println!("  Path:             {}", report.helper_path.display());
        println!("  Architecture:     {}", report.architecture);
        println!(
            "  Version:          {}",
            report.version.as_deref().unwrap_or("<not probed>")
        );
        println!(
            "  Schema:           {}",
            report
                .schema_version
                .map_or_else(|| "<not probed>".into(), |version| version.to_string())
        );
        println!("  SHA-256:          {}", report.helper_sha256);
        println!("  Static verified:  yes");
        println!("  Runtime verified: {}", report.runtime_verified);
    }
}
