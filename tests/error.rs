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

#[test]
fn helper_rejection_preserves_target_side_windows_error() {
    let error = Error::HelperRejected {
        kind: "load_library_rejected".into(),
        message: "LoadLibraryW failed".into(),
        windows_error: Some(126),
    };

    assert_eq!(error.windows_error(), Some(126));
}
