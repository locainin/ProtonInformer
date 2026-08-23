//! Helper-backed load execution checks

use std::collections::BTreeMap;
use std::path::PathBuf;

use proton_informer::helper;
use proton_informer::helper_runtime::{HelperInvocation, HelperRuntime, LoadDryRunPlan};
use proton_informer::{Error, load};
use proton_informer_helper_protocol::{
    HelperError, HelperOperation, HelperOptions, HelperRequest, HelperResponse, HelperResult,
    LoadLibraryResult, SCHEMA_VERSION,
};
use tempfile::tempdir;

#[test]
fn empty_successful_helper_output_is_reported_as_helper_execution_failure() {
    let directory = tempdir().expect("temporary directory");
    let true_command = helper::find_command("true").expect("true command");
    let identity = proton_informer::process::inspect(std::process::id())
        .expect("inspect current test process");
    let plan = LoadDryRunPlan {
        target_pid: identity.pid,
        target_start_time_ticks: identity.start_time_ticks,
        target_filesystem_uid: identity.uids.expect("test process UIDs").filesystem,
        helper_windows_path: "Z:\\helper.exe".into(),
        invocation: HelperInvocation {
            arguments: Vec::new(),
            environment: BTreeMap::new(),
            program: true_command,
            runtime: HelperRuntime::Wine {
                prefix: PathBuf::from("/unused"),
                wine_binary: PathBuf::from("/unused"),
            },
        },
        payload_host_path: PathBuf::from("/unused/payload.dll"),
        payload_path_mode: proton_informer::helper_runtime::PayloadPathMode::OriginalPath,
        request: HelperRequest {
            operation: HelperOperation::LoadLibrary,
            options: HelperOptions {
                timeout_ms: 1_000,
                verify_module_after_load: true,
            },
            payload: None,
            request_id: "empty-output-regression".into(),
            schema_version: SCHEMA_VERSION,
            target: None,
        },
        request_host_path: directory.path().join("request.json"),
        request_windows_path: "Z:\\request.json".into(),
        run_directory: directory.path().to_path_buf(),
    };

    let error = load::execute(&plan, false).expect_err("empty protocol output must fail");

    assert!(matches!(error, Error::HelperExecution(_)));
    assert!(
        error
            .to_string()
            .contains("helper produced no protocol output")
    );
    assert_eq!(error.kind(), "helper_execution");
}

#[test]
fn successful_helper_response_uses_helper_verified_canonical_path() {
    let directory = tempdir().expect("temporary directory");
    let printf = helper::find_command("printf").expect("printf command");
    let response = success_response(r"Z:\other\payload.dll", "exact-path-regression");
    let plan = load_plan(
        directory.path(),
        printf,
        response,
        "exact-path-regression",
        Some(r"Z:\requested\payload.dll"),
    );

    let result = load::execute(&plan, false)
        .expect("Windows final path spelling is owned by the helper authority");

    assert!(result.response.result.is_some());
}

#[test]
fn successful_helper_response_accepts_normalized_windows_path_spelling() {
    let directory = tempdir().expect("temporary directory");
    let printf = helper::find_command("printf").expect("printf command");
    let response = success_response(r"z:/requested/payload.dll", "normalized-path-regression");
    let plan = load_plan(
        directory.path(),
        printf,
        response,
        "normalized-path-regression",
        Some(r"Z:\requested\payload.dll"),
    );

    load::execute(&plan, false).expect("equivalent Windows path spelling is valid");
}

#[test]
fn successful_response_without_module_verification_is_rejected() {
    let directory = tempdir().expect("temporary directory");
    let printf = helper::find_command("printf").expect("printf command");
    let response = serde_json::to_string(&HelperResponse {
        error: None,
        ok: true,
        operation: HelperOperation::LoadLibrary,
        request_id: "unverified-module".into(),
        result: Some(HelperResult::LoadLibrary(LoadLibraryResult {
            already_loaded: false,
            dependency_warnings: Vec::new(),
            loaded_module_path: r"C:\\canonical\\payload.dll".into(),
            module_count_after: 1,
            module_count_before: 1,
            module_verified: false,
            modules_added: Vec::new(),
            process_name: "game.exe".into(),
            thread_exit_code_low32: None,
            windows_pid: 7,
        })),
        schema_version: SCHEMA_VERSION,
        warnings: Vec::new(),
    })
    .expect("serialize unverified response");
    let plan = load_plan(
        directory.path(),
        printf,
        response,
        "unverified-module",
        Some(r"Z:\requested\payload.dll"),
    );

    let error = load::execute(&plan, false).expect_err("unverified module is not success");

    assert!(matches!(error, Error::ModuleVerificationFailed { .. }));
    assert_eq!(error.kind(), "module_verification_failed");
}

#[test]
fn helper_load_timeout_is_reported_as_indeterminate_and_not_retryable() {
    let directory = tempdir().expect("temporary directory");
    let printf = helper::find_command("printf").expect("printf command");
    let response = serde_json::to_string(&HelperResponse {
        error: Some(HelperError {
            kind: "load_timeout".into(),
            message: "remote load exceeded the request deadline".into(),
            windows_error: None,
        }),
        ok: false,
        operation: HelperOperation::LoadLibrary,
        request_id: "indeterminate-timeout".into(),
        result: None,
        schema_version: SCHEMA_VERSION,
        warnings: Vec::new(),
    })
    .expect("serialize timeout response");
    let plan = load_plan(
        directory.path(),
        printf,
        response,
        "indeterminate-timeout",
        Some(r"Z:\requested\payload.dll"),
    );

    let error = load::execute(&plan, false).expect_err("timeout must not look like rejection");

    assert!(matches!(error, Error::IndeterminateLoadTimeout { .. }));
    assert_eq!(error.kind(), "indeterminate_load_timeout");
    assert!(error.to_string().contains("automatic retry is unsafe"));
}

#[test]
fn helper_indeterminate_load_is_not_reclassified_as_a_normal_rejection() {
    let directory = tempdir().expect("temporary directory");
    let printf = helper::find_command("printf").expect("printf command");
    let response = serde_json::to_string(&HelperResponse {
        error: Some(HelperError {
            kind: "load_indeterminate".into(),
            message: "module verification could not prove the remote outcome".into(),
            windows_error: None,
        }),
        ok: false,
        operation: HelperOperation::LoadLibrary,
        request_id: "indeterminate-load".into(),
        result: None,
        schema_version: SCHEMA_VERSION,
        warnings: Vec::new(),
    })
    .expect("serialize indeterminate response");
    let plan = load_plan(
        directory.path(),
        printf,
        response,
        "indeterminate-load",
        Some(r"Z:\requested\payload.dll"),
    );

    let error = load::execute(&plan, false).expect_err("indeterminate load must remain explicit");

    assert!(matches!(error, Error::IndeterminateLoad { .. }));
    assert_eq!(error.kind(), "indeterminate_load");
    assert!(error.to_string().contains("automatic retry is unsafe"));
}

#[test]
fn load_execution_revalidates_target_filesystem_ownership_before_helper() {
    let directory = tempdir().expect("temporary directory");
    let true_command = helper::find_command("true").expect("true command");
    let response = success_response(r"Z:\payload.dll", "ownership-boundary");
    let mut plan = load_plan(
        directory.path(),
        true_command,
        response,
        "ownership-boundary",
        Some(r"Z:\payload.dll"),
    );
    plan.target_filesystem_uid = plan.target_filesystem_uid.saturating_add(1);

    let error = load::execute(&plan, false).expect_err("ownership must be checked before helper");

    assert!(matches!(error, Error::ProcessOwnershipChanged { .. }));
}

fn load_plan(
    directory: &std::path::Path,
    program: PathBuf,
    response: String,
    request_id: &str,
    requested_path: Option<&str>,
) -> LoadDryRunPlan {
    let identity = proton_informer::process::inspect(std::process::id())
        .expect("inspect current test process");
    let request = HelperRequest {
        operation: HelperOperation::LoadLibrary,
        options: HelperOptions {
            timeout_ms: 1_000,
            verify_module_after_load: true,
        },
        payload: requested_path.map(|windows_path| {
            proton_informer_helper_protocol::HelperPayload {
                sha256: "0".repeat(64),
                size_bytes: 1,
                windows_path: windows_path.into(),
            }
        }),
        request_id: request_id.into(),
        schema_version: SCHEMA_VERSION,
        target: None,
    };
    LoadDryRunPlan {
        target_pid: identity.pid,
        target_start_time_ticks: identity.start_time_ticks,
        target_filesystem_uid: identity.uids.expect("test process UIDs").filesystem,
        helper_windows_path: r"Z:\helper.exe".into(),
        invocation: HelperInvocation {
            arguments: vec!["%s".into(), response],
            environment: BTreeMap::new(),
            program,
            runtime: HelperRuntime::Wine {
                prefix: PathBuf::from("/unused"),
                wine_binary: PathBuf::from("/unused"),
            },
        },
        payload_host_path: PathBuf::from("/unused/payload.dll"),
        payload_path_mode: proton_informer::helper_runtime::PayloadPathMode::OriginalPath,
        request,
        request_host_path: directory.join("request.json"),
        request_windows_path: r"Z:\request.json".into(),
        run_directory: directory.to_path_buf(),
    }
}

fn success_response(loaded_module_path: &str, request_id: &str) -> String {
    serde_json::to_string(&HelperResponse {
        error: None,
        ok: true,
        operation: HelperOperation::LoadLibrary,
        request_id: request_id.into(),
        result: Some(HelperResult::LoadLibrary(LoadLibraryResult {
            already_loaded: false,
            dependency_warnings: Vec::new(),
            loaded_module_path: loaded_module_path.into(),
            module_count_after: 2,
            module_count_before: 1,
            module_verified: true,
            modules_added: Vec::new(),
            process_name: "game.exe".into(),
            thread_exit_code_low32: Some(1),
            windows_pid: 7,
        })),
        schema_version: SCHEMA_VERSION,
        warnings: Vec::new(),
    })
    .expect("serialize success response")
}
