//! Helper-backed load execution checks

use std::collections::BTreeMap;
use std::path::PathBuf;

use proton_informer::helper;
use proton_informer::helper_runtime::{HelperInvocation, HelperRuntime, LoadDryRunPlan};
use proton_informer::{Error, load};
use proton_informer_helper_protocol::{
    HelperOperation, HelperOptions, HelperRequest, SCHEMA_VERSION,
};
use tempfile::tempdir;

#[test]
fn empty_successful_helper_output_is_reported_as_helper_execution_failure() {
    let directory = tempdir().expect("temporary directory");
    let true_command = helper::find_command("true").expect("true command");
    let plan = LoadDryRunPlan {
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
