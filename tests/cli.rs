//! Executable command and JSON contract checks.

#[path = "cli/help.rs"]
mod help;

use std::process::Command;

use serde_json::Value;

#[test]
fn json_argument_error_is_valid_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer"))
        .args(["--json", "plan", "--pid", "invalid"])
        .output()
        .expect("CLI should start");

    assert_eq!(output.status.code(), Some(2));
    let error: Value =
        serde_json::from_slice(&output.stderr).expect("argument error should be valid JSON");
    assert_eq!(error["ok"], false);
    assert_eq!(error["error"]["kind"], "cli_parse");
    assert!(error["error"].get("windows_error").is_none());
}

#[test]
fn blank_module_filter_is_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer"))
        .args(["--json", "modules", "--pid", "123", "--filter", ""])
        .output()
        .expect("CLI should start");

    assert_eq!(output.status.code(), Some(2));
    let error: Value =
        serde_json::from_slice(&output.stderr).expect("argument error should be valid JSON");
    assert_eq!(error["ok"], false);
    assert_eq!(error["error"]["kind"], "cli_parse");
}

#[test]
fn json_runtime_error_is_valid_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer"))
        .args(["--json", "inspect", "/definitely/missing/payload.dll"])
        .output()
        .expect("CLI should start");

    assert!(!output.status.success());
    let error: Value =
        serde_json::from_slice(&output.stderr).expect("runtime error should be valid JSON");
    assert_eq!(error["ok"], false);
    assert_eq!(error["error"]["kind"], "io");
}
