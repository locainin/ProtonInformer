//! Helper command-line and JSON smoke checks.

use std::process::Command;

use std::fs;

use proton_informer_helper_protocol::{
    HelperCapability, HelperOperation, HelperResponse, HelperVersion, MAX_REQUEST_SIZE_BYTES,
    SelfTestResult,
};
use tempfile::tempdir;

#[test]
fn version_json_reports_host_build_capabilities_truthfully() {
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer-win-helper"))
        .arg("--version-json")
        .output()
        .expect("helper should start");
    let version: HelperVersion =
        serde_json::from_slice(&output.stdout).expect("version output should be JSON");

    assert!(output.status.success());
    assert!(version.capabilities.contains(&HelperCapability::Version));
    assert!(version.capabilities.contains(&HelperCapability::SelfTest));
    if cfg!(windows) {
        assert!(
            version
                .capabilities
                .contains(&HelperCapability::LoadLibrary)
        );
    } else {
        assert!(
            !version
                .capabilities
                .contains(&HelperCapability::LoadLibrary)
        );
    }
}

#[test]
fn self_test_json_reports_platform_status() {
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer-win-helper"))
        .arg("--self-test-json")
        .output()
        .expect("helper should start");
    let result: SelfTestResult =
        serde_json::from_slice(&output.stdout).expect("self-test output should be JSON");

    assert!(output.status.success());
    assert_eq!(result.passed, cfg!(windows));
    assert!(!result.checks.is_empty());
}

#[test]
fn unknown_command_fails_without_running_an_operation() {
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer-win-helper"))
        .arg("--unknown")
        .output()
        .expect("helper should start");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage error"));
}

#[test]
fn help_prints_clean_usage_and_succeeds() {
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer-win-helper"))
        .arg("--help")
        .output()
        .expect("helper should start");

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("--request-json <PATH>"));
    assert!(output.stderr.is_empty());
}

#[test]
fn malformed_request_returns_a_correlated_protocol_failure() {
    let directory = tempdir().expect("temporary directory");
    let request_path = directory.path().join("request.json");
    fs::write(&request_path, b"{not-json").expect("malformed request fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer-win-helper"))
        .args(["--request-json", request_path.to_str().expect("UTF-8 path")])
        .output()
        .expect("helper should start");
    let response: HelperResponse =
        serde_json::from_slice(&output.stdout).expect("failure should use protocol JSON");

    assert!(output.status.success());
    assert!(!response.ok);
    assert_eq!(response.request_id, "unknown");
    assert_eq!(response.operation, HelperOperation::Unknown);
    assert_eq!(
        response.error.expect("error body").kind,
        "protocol_parse_failed"
    );
}

#[test]
fn oversized_request_is_rejected_before_json_parsing() {
    let directory = tempdir().expect("temporary directory");
    let request_path = directory.path().join("request.json");
    let oversized = vec![b' '; usize::try_from(MAX_REQUEST_SIZE_BYTES + 1).expect("test size")];
    fs::write(&request_path, oversized).expect("oversized request fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer-win-helper"))
        .args(["--request-json", request_path.to_str().expect("UTF-8 path")])
        .output()
        .expect("helper should start");
    let response: HelperResponse =
        serde_json::from_slice(&output.stdout).expect("failure should use protocol JSON");

    assert!(output.status.success());
    assert!(!response.ok);
    assert_eq!(
        response.error.expect("error body").kind,
        "protocol_parse_failed"
    );
}
