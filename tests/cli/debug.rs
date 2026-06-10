use std::process::Command;

use serde_json::Value;

#[test]
fn debug_flag_is_listed_in_top_level_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer"))
        .arg("--help")
        .output()
        .expect("CLI should start");
    let stdout = String::from_utf8(output.stdout).expect("help should be UTF-8");

    assert!(output.status.success());
    assert!(stdout.contains("--debug"));
    assert!(stdout.contains("extra target and runtime diagnostics"));
}

#[test]
fn debug_flag_does_not_break_json_error_contract() {
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer"))
        .args([
            "--debug",
            "--json",
            "inspect",
            "/definitely/missing/payload.dll",
        ])
        .output()
        .expect("CLI should start");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("error should be UTF-8");
    assert!(!stderr.contains("\u{1b}["));

    let error: Value = serde_json::from_str(&stderr).expect("runtime error should be valid JSON");
    assert_eq!(error["ok"], false);
    assert_eq!(error["error"]["kind"], "io");
    assert!(error["error"].get("windows_error").is_none());
}

#[test]
fn debug_flag_is_accepted_after_subcommand() {
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer"))
        .args(["inspect", "--debug", "/definitely/missing/payload.dll"])
        .output()
        .expect("CLI should start");
    let stderr = String::from_utf8(output.stderr).expect("error should be UTF-8");

    assert!(!output.status.success());
    assert!(stderr.starts_with("Error: "));
    assert!(!stderr.contains("unexpected argument"));
}

#[test]
fn debug_flag_is_accepted_by_inject_without_changing_failure_kind() {
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer"))
        .args([
            "--debug",
            "--json",
            "inject",
            "--pid",
            "4294967295",
            "--payload",
            "/definitely/missing/payload.dll",
            "--dry-run",
        ])
        .output()
        .expect("CLI should start");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error: Value =
        serde_json::from_slice(&output.stderr).expect("runtime error should be valid JSON");
    assert_eq!(error["ok"], false);
    assert_eq!(error["error"]["kind"], "process_unavailable");
}
