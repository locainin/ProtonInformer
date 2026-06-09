//! Human-readable top-level and subcommand help checks.

use std::process::Command;

#[test]
fn top_level_help_lists_every_public_command() {
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer"))
        .arg("--help")
        .output()
        .expect("CLI should start");
    let stdout = String::from_utf8(output.stdout).expect("help should be UTF-8");

    assert!(output.status.success());
    for command in [
        "doctor",
        "inspect",
        "load",
        "override-plan",
        "plan",
        "processes",
        "steam-games",
    ] {
        assert!(
            stdout.contains(command),
            "top-level help should list {command}"
        );
    }
    assert!(output.stderr.is_empty());
}

#[test]
fn load_help_explains_dry_run_execution_and_diagnostic_retention() {
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer"))
        .args(["load", "--help"])
        .output()
        .expect("CLI should start");
    let stdout = String::from_utf8(output.stdout).expect("help should be UTF-8");

    assert!(output.status.success());
    assert!(stdout.contains("--dry-run"));
    assert!(stdout.contains("--yes"));
    assert!(stdout.contains("Execute the validated helper request for real"));
    assert!(stdout.contains("--keep-run-files"));
    assert!(output.stderr.is_empty());
}
