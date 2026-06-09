//! Request validation, dispatch, and response correlation checks

use std::process::Command;

#[path = "support/common.rs"]
mod common;

use proton_informer_helper_protocol::{
    HelperOperation, HelperOptions, HelperRequest, HelperResponse, HelperResult, SCHEMA_VERSION,
};
use tempfile::tempdir;

/// Builds the smallest valid non-mutating helper request
fn query_processes_request() -> HelperRequest {
    HelperRequest {
        operation: HelperOperation::QueryProcesses,
        options: HelperOptions::default(),
        payload: None,
        request_id: "protocol-query-processes".into(),
        schema_version: SCHEMA_VERSION,
        target: None,
    }
}

/// Confirms validation failures retain the parsed request identity
#[test]
fn semantic_validation_failure_keeps_request_correlation() {
    let mut request = query_processes_request();
    request.options.timeout_ms = 0;
    let directory = tempdir().expect("temporary directory");

    let response = common::run_request(&request, &directory.path().join("request.json"));

    assert!(!response.ok);
    assert_eq!(response.request_id, request.request_id);
    assert_eq!(response.operation, HelperOperation::QueryProcesses);
    assert_eq!(response.error.expect("error body").kind, "invalid_request");
}

/// Confirms dispatch reports the capabilities of the compiled platform
#[test]
fn query_processes_dispatch_reports_platform_behavior_truthfully() {
    let request = query_processes_request();
    let directory = tempdir().expect("temporary directory");

    let response = common::run_request(&request, &directory.path().join("request.json"));

    assert_eq!(response.request_id, request.request_id);
    assert_eq!(response.operation, HelperOperation::QueryProcesses);
    // Windows builds enumerate processes while host builds reject the operation
    if cfg!(windows) {
        assert!(response.ok);
        let HelperResult::QueryProcesses(result) = response.result.expect("process result") else {
            panic!("query_processes returned the wrong result type");
        };
        assert!(!result.processes.is_empty());
    } else {
        assert!(!response.ok);
        assert_eq!(
            response.error.expect("error body").kind,
            "unsupported_operation"
        );
    }
}

/// Confirms unreadable request paths still return protocol-shaped JSON
#[test]
fn missing_request_file_returns_protocol_json() {
    let directory = tempdir().expect("temporary directory");
    let missing = directory.path().join("missing.json");
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer-win-helper"))
        .args([
            "--request-json",
            missing.to_str().expect("UTF-8 fixture path"),
        ])
        .output()
        .expect("helper should start");
    let response: HelperResponse =
        serde_json::from_slice(&output.stdout).expect("protocol response");

    assert!(output.status.success());
    assert_eq!(response.request_id, "unknown");
    assert_eq!(response.operation, HelperOperation::Unknown);
    assert_eq!(response.error.expect("error body").kind, "io");
}
