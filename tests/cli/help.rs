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
        "inject",
        "inspect",
        "load",
        "override-plan",
        "plan",
        "processes",
        "steam-games",
        "verify-install",
    ] {
        assert!(
            stdout.contains(command),
            "top-level help should list {command}"
        );
    }
    assert!(output.stderr.is_empty());
}

#[test]
fn inject_help_explains_simple_and_advanced_target_selection() {
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer"))
        .args(["inject", "--help"])
        .output()
        .expect("CLI should start");
    let stdout = String::from_utf8(output.stdout).expect("help should be UTF-8");

    assert!(output.status.success());
    assert!(stdout.contains("--app-id"));
    assert!(stdout.contains("--pid"));
    assert!(stdout.contains("--process"));
    assert!(stdout.contains("--payload"));
    assert!(stdout.contains("--dry-run"));
    assert!(stdout.contains("--yes"));
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

#[test]
fn verify_install_help_explains_offline_and_live_modes() {
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer"))
        .args(["verify-install", "--help"])
        .output()
        .expect("CLI should start");
    let stdout = String::from_utf8(output.stdout).expect("help should be UTF-8");

    assert!(output.status.success());
    assert!(stdout.contains("--arch"));
    assert!(stdout.contains("--pid"));
    assert!(stdout.contains("without a live probe"));
    assert!(stdout.contains("Wine or Proton process"));
    assert!(output.stderr.is_empty());
}
