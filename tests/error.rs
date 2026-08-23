//! Stable error categories

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
fn indeterminate_helper_failure_preserves_its_specific_json_kind() {
    let error = Error::HelperRejected {
        kind: "load_indeterminate".into(),
        message: "fixture".into(),
        windows_error: None,
    };

    assert_eq!(error.kind(), "load_indeterminate");
}

#[test]
fn conflicting_wine_drive_mappings_have_a_specific_json_kind() {
    let error = Error::AmbiguousDriveMapping {
        drive: 'c',
        roots: vec!["/first".into(), "/second".into()],
    };

    assert_eq!(error.kind(), "ambiguous_drive_mapping");
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

#[test]
fn known_windows_loader_errors_return_user_hints() {
    let error = Error::HelperRejected {
        kind: "load_library_rejected".into(),
        message: "LoadLibraryW failed".into(),
        windows_error: Some(193),
    };

    assert_eq!(
        error.windows_error_hint(),
        Some("wrong architecture or invalid Win32 image")
    );
}

#[test]
fn unknown_windows_loader_errors_keep_only_the_raw_code() {
    let error = Error::HelperRejected {
        kind: "load_library_rejected".into(),
        message: "LoadLibraryW failed".into(),
        windows_error: Some(9999),
    };

    assert_eq!(error.windows_error(), Some(9999));
    assert_eq!(error.windows_error_hint(), None);
}

#[test]
fn target_identity_changes_keep_their_specific_json_kind() {
    let error = Error::HelperRejected {
        kind: "target_identity_changed".into(),
        message: "process was replaced".into(),
        windows_error: None,
    };

    assert_eq!(error.kind(), "target_identity_changed");
}

#[test]
fn linux_process_identity_changes_have_a_specific_json_kind() {
    let error = Error::ProcessIdentityChanged {
        pid: 123,
        expected_start_time_ticks: 10,
        actual_start_time_ticks: 11,
    };

    assert_eq!(error.kind(), "process_identity_changed");
}

#[test]
fn linux_process_ownership_changes_have_a_specific_json_kind() {
    let error = Error::ProcessOwnershipChanged {
        pid: 123,
        expected_filesystem_uid: 1_000,
        actual_filesystem_uid: 1_001,
        current_filesystem_uid: 1_000,
    };

    assert_eq!(error.kind(), "process_ownership_changed");
}

#[test]
fn invalid_selected_environment_has_a_specific_json_kind() {
    let error = Error::InvalidProcessEnvironment {
        path: "/proc/1234/environ".into(),
        reason: "invalid UTF-8".into(),
    };

    assert_eq!(error.kind(), "invalid_process_environment");
}

#[test]
fn conflicting_steam_identity_has_a_specific_json_kind() {
    let error = Error::SteamIdentityConflict {
        details: "AppID candidates disagree".into(),
    };

    assert_eq!(error.kind(), "steam_identity_conflict");
}

#[test]
fn indeterminate_load_timeout_has_a_distinct_machine_kind() {
    let error = Error::IndeterminateLoadTimeout {
        timeout_ms: 1_000,
        detail: "fixture".into(),
    };

    assert_eq!(error.kind(), "indeterminate_load_timeout");
    assert!(error.to_string().contains("automatic retry is unsafe"));
}

#[test]
fn indeterminate_load_has_a_distinct_machine_kind() {
    let error = Error::IndeterminateLoad {
        detail: "fixture".into(),
    };

    assert_eq!(error.kind(), "indeterminate_load");
    assert!(error.to_string().contains("automatic retry is unsafe"));
}
