use crate::cli::debug;
use crate::process::ProcessInfo;

use super::common::display_optional_path;

/// Writes the unique target selected by the one-command workflow
pub(in crate::cli) fn print_selected_target(process: &ProcessInfo) {
    for line in selected_target_lines(process, debug::enabled()) {
        println!("{line}");
    }
}

/// Builds selected-target output so debug behavior can be tested without I/O
fn selected_target_lines(process: &ProcessInfo, include_debug: bool) -> Vec<String> {
    // Runtime and prefix stay visible because Proton version drift changes behavior
    let mut lines = vec![
        "Selected Target".into(),
        format!("  Linux PID:           {}", process.pid),
        format!(
            "  Guest executable:    {}",
            display_optional_path(
                process
                    .guest_executable
                    .as_ref()
                    .map(|candidate| candidate.path.as_path())
            )
        ),
        format!(
            "  Steam AppID:         {}",
            process
                .steam_app_id
                .map_or_else(|| "<unknown>".into(), |id| id.to_string())
        ),
        format!(
            "  Proton runtime:      {}",
            display_optional_path(process.proton_dist.as_deref())
        ),
        format!(
            "  Wine prefix:         {}",
            display_optional_path(process.wine_prefix.as_deref())
        ),
    ];

    if include_debug {
        // Extra evidence stays opt-in to keep default output small
        lines.extend(selected_target_debug_lines(process));
    }

    lines
}

/// Returns less-common target evidence only when `--debug` is requested
fn selected_target_debug_lines(process: &ProcessInfo) -> Vec<String> {
    vec![
        "Debug".into(),
        format!(
            "  Compatdata:          {}",
            display_optional_path(process.compatdata_dir.as_deref())
        ),
        format!(
            "  Steam client:        {}",
            display_optional_path(process.steam_client_path.as_deref())
        ),
        format!(
            "  Confidence:          {:?}",
            process.classification_confidence
        ),
        format!("  Environment:         {:?}", process.environment_status),
    ]
}
