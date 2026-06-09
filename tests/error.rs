//! Stable error categories.

use proton_informer::Error;

#[test]
fn invalid_input_has_stable_json_kind() {
    let error = Error::InvalidInput("fixture".into());

    assert_eq!(error.kind(), "invalid_input");
}

#[test]
fn known_helper_failure_preserves_its_specific_json_kind() {
    let error = Error::HelperRejected {
        kind: "module_conflict".into(),
        message: "fixture".into(),
        windows_error: None,
    };

    assert_eq!(error.kind(), "module_conflict");
}
