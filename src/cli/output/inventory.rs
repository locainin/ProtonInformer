use crate::process::{ProcessEvidenceFailure, ProcessInfo, ProcessInspectionFailure};
use crate::steam::SteamDiscoveryReport;
use proton_informer_helper_protocol::ModuleQueryResult;

use crate::cli::style;

use super::common::display_optional_path;

/// Writes one process with the evidence needed to diagnose planning
pub(in crate::cli) fn print_process(process: &ProcessInfo) {
    println!("Process");
    println!("  PID:                 {}", process.pid);
    println!("  Start time ticks:    {}", process.start_time_ticks);
    println!("  UIDs:                {:?}", process.uids);
    println!("  Name:                {}", process.name);
    println!("  Kind:                {:?}", process.target_kind);
    println!(
        "  Confidence:          {:?}",
        process.classification_confidence
    );
    println!("  Environment:         {:?}", process.environment_status);
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
        "  Proton runtime:      {}",
        display_optional_path(process.proton_dist.as_deref())
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

/// Writes retained process-scan failures only in diagnostic text mode
pub(in crate::cli) fn print_process_rejections(rejections: &[ProcessInspectionFailure]) {
    for rejection in rejections {
        let pid = rejection
            .pid
            .map_or_else(|| "<proc>".into(), |pid| pid.to_string());
        eprintln!(
            "Process rejection ({pid}, {}): {}",
            rejection.kind, rejection.message
        );
    }
}

/// Writes optional evidence failures retained on a surviving process row
pub(in crate::cli) fn print_process_evidence_failures(process: &ProcessInfo) {
    for failure in &process.evidence_failures {
        print_process_evidence_failure(failure);
    }
}

/// Writes one optional evidence failure in diagnostic text mode
fn print_process_evidence_failure(failure: &ProcessEvidenceFailure) {
    eprintln!("Process evidence ({}): {}", failure.kind, failure.message);
}

/// Writes loaded modules returned by the exact Windows target
pub(in crate::cli) fn print_modules(result: &ModuleQueryResult) {
    println!("Modules");
    println!("  Windows PID: {}", result.target.windows_pid);
    println!("  Process:     {}", result.target.process_name);
    for module in &result.modules {
        println!("  {}  {}", module.module_name, module.windows_path);
    }
}

/// Writes Steam discovery results and retained metadata warnings
pub(in crate::cli) fn print_steam_games(report: SteamDiscoveryReport) {
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
        eprintln!(
            "{}: {}: {}",
            style::warning_word("Warning"),
            warning.path.display(),
            warning.message
        );
    }
}
