//! Helper command-line and JSON smoke checks

use std::process::Command;

use std::fs;

use proton_informer_helper_protocol::{
    HelperCapability, HelperOperation, HelperResponse, HelperVersion, MAX_REQUEST_SIZE_BYTES,
    SelfTestResult,
};
use tempfile::tempdir;

/// Confirms version output reports capabilities for the compiled platform
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

/// Confirms the self-test reports platform support without mutating a process
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

/// Confirms unknown commands stop before protocol dispatch
#[test]
fn unknown_command_fails_without_running_an_operation() {
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer-win-helper"))
        .arg("--unknown")
        .output()
        .expect("helper should start");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage error"));
}

/// Confirms an empty command line returns a direct usage failure
#[test]
fn missing_command_prints_a_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer-win-helper"))
        .output()
        .expect("helper should start");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing command"));
}

/// Confirms request execution accepts one path and rejects extra arguments
#[test]
fn request_command_requires_exactly_one_path() {
    let missing = Command::new(env!("CARGO_BIN_EXE_proton-informer-win-helper"))
        .arg("--request-json")
        .output()
        .expect("helper should start");
    let extra = Command::new(env!("CARGO_BIN_EXE_proton-informer-win-helper"))
        .args(["--version-json", "extra"])
        .output()
        .expect("helper should start");

    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("requires a path"));
    assert!(!extra.status.success());
    assert!(String::from_utf8_lossy(&extra.stderr).contains("unexpected extra argument"));
}

/// Confirms long help prints the documented helper interface
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

/// Confirms short and long help flags remain equivalent
#[test]
fn short_help_matches_long_help() {
    let short = Command::new(env!("CARGO_BIN_EXE_proton-informer-win-helper"))
        .arg("-h")
        .output()
        .expect("helper should start");
    let long = Command::new(env!("CARGO_BIN_EXE_proton-informer-win-helper"))
        .arg("--help")
        .output()
        .expect("helper should start");

    assert!(short.status.success());
    assert_eq!(short.stdout, long.stdout);
    assert!(short.stderr.is_empty());
}

/// Confirms malformed JSON uses an uncorrelated protocol failure
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

/// Confirms oversized requests fail before unbounded JSON parsing
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
