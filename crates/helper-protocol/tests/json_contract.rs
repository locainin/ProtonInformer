//! Protocol serialization and semantic validation.

use proton_informer_helper_protocol::{
    HelperOperation, HelperOptions, HelperPayload, HelperRequest, HelperTarget,
    MAX_PAYLOAD_SIZE_BYTES, ProtocolArchitecture, SCHEMA_VERSION, TargetSelector,
};

fn load_request() -> HelperRequest {
    HelperRequest {
        operation: HelperOperation::LoadLibrary,
        options: HelperOptions::default(),
        payload: Some(HelperPayload {
            sha256: "a".repeat(64),
            size_bytes: 4_096,
            windows_path: r"S:\common\Game\mod.dll".into(),
        }),
        request_id: "request-123".into(),
        schema_version: SCHEMA_VERSION,
        target: Some(HelperTarget {
            expected_creation_time_100ns: Some(123),
            expected_architecture: ProtocolArchitecture::X86_64,
            expected_executable_windows_path: Some(r"S:\common\Game\Game.exe".into()),
            expected_process_name: "Game.exe".into(),
            selector: TargetSelector::ByProcessNameAndExecutablePath,
        }),
    }
}

#[test]
fn load_request_round_trips_without_losing_typed_fields() {
    let request = load_request();
    let json = serde_json::to_string_pretty(&request).expect("serialize request");
    let decoded: HelperRequest = serde_json::from_str(&json).expect("deserialize request");

    assert_eq!(decoded, request);
    assert!(decoded.validate().is_ok());
}

#[test]
fn request_id_is_mandatory() {
    let mut request = load_request();
    request.request_id.clear();

    assert!(request.validate().is_err());
}

#[test]
fn query_processes_rejects_unused_target_and_payload() {
    let mut request = load_request();
    request.operation = HelperOperation::QueryProcesses;

    assert!(request.validate().is_err());
}

#[test]
fn payload_hash_must_be_lowercase_sha256() {
    let mut request = load_request();
    request.payload.as_mut().expect("payload fixture").sha256 = "Z".repeat(64);

    assert!(request.validate().is_err());
}

#[test]
fn oversized_payload_is_rejected_before_helper_work() {
    let mut request = load_request();
    request
        .payload
        .as_mut()
        .expect("payload fixture")
        .size_bytes = MAX_PAYLOAD_SIZE_BYTES + 1;

    let error = request.validate().expect_err("oversized payload must fail");

    assert!(error.to_string().contains("payload size"));
}

#[test]
fn unknown_target_architecture_is_rejected() {
    let mut request = load_request();
    request
        .target
        .as_mut()
        .expect("target fixture")
        .expected_architecture = ProtocolArchitecture::Unknown;

    let error = request
        .validate()
        .expect_err("unknown architecture must fail");

    assert!(error.to_string().contains("architecture"));
}

#[test]
fn load_request_requires_post_load_module_verification() {
    let mut request = load_request();
    request.options.verify_module_after_load = false;

    let error = request
        .validate()
        .expect_err("load requests must always verify the module");

    assert!(error.to_string().contains("module verification"));
}

#[test]
fn payload_parent_components_are_rejected() {
    let mut request = load_request();
    request
        .payload
        .as_mut()
        .expect("payload fixture")
        .windows_path = r"S:\mods\..\payload.dll".into();

    assert!(request.validate().is_err());
}

#[test]
fn absolute_unc_payload_paths_are_accepted() {
    let mut request = load_request();
    request
        .payload
        .as_mut()
        .expect("payload fixture")
        .windows_path = r"\\server\share\payload.dll".into();

    assert!(request.validate().is_ok());
}

#[test]
fn unknown_operation_is_never_a_valid_request() {
    let mut request = load_request();
    request.operation = HelperOperation::Unknown;

    assert!(request.validate().is_err());
}

#[test]
fn exact_pid_load_requires_process_creation_time() {
    let mut request = load_request();
    let target = request.target.as_mut().expect("target fixture");
    target.selector = TargetSelector::ByWindowsPid(316);
    target.expected_creation_time_100ns = None;

    let error = request
        .validate()
        .expect_err("exact PID load must reject missing creation time");

    assert!(error.to_string().contains("expected_creation_time_100ns"));
}

#[test]
fn exact_pid_load_requires_observed_executable_path() {
    let mut request = load_request();
    let target = request.target.as_mut().expect("target fixture");
    target.selector = TargetSelector::ByWindowsPid(316);
    target.expected_executable_windows_path = None;

    let error = request
        .validate()
        .expect_err("exact PID load must reject missing executable path");

    assert!(
        error
            .to_string()
            .contains("expected_executable_windows_path")
    );
}

#[test]
fn exact_pid_selector_rejects_malformed_optional_executable_path() {
    let mut request = load_request();
    let target = request.target.as_mut().expect("target fixture");
    target.selector = TargetSelector::ByWindowsPid(316);
    target.expected_executable_windows_path = Some("relative.exe".into());

    let error = request
        .validate()
        .expect_err("malformed exact PID path must fail");

    assert!(error.to_string().contains("absolute Windows"));
}
