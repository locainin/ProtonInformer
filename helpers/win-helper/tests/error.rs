//! Stable helper failure-to-protocol mappings

use proton_informer_win_helper::error::HelperFailure;

/// Confirms common internal failures retain machine-readable categories
#[test]
fn common_failures_keep_stable_protocol_kinds() {
    let cases = [
        (
            HelperFailure::AmbiguousTarget("ambiguous".into()),
            "ambiguous_target",
        ),
        (
            HelperFailure::ProtocolParseFailed("parse".into()),
            "protocol_parse_failed",
        ),
        (
            HelperFailure::TargetNotFound("missing".into()),
            "target_not_found",
        ),
        (
            HelperFailure::TargetIdentityChanged("changed".into()),
            "target_identity_changed",
        ),
        (
            HelperFailure::Validation("invalid".into()),
            "invalid_request",
        ),
        (
            HelperFailure::ArchitectureMismatch("wrong".into()),
            "architecture_mismatch",
        ),
        (
            HelperFailure::ModuleConflict("conflict".into()),
            "module_conflict",
        ),
        (
            HelperFailure::ModuleVerificationFailed("missing".into()),
            "module_verification_failed",
        ),
        (
            HelperFailure::PayloadChanged("changed".into()),
            "payload_changed",
        ),
        (
            HelperFailure::InvalidWindowsPath("invalid".into()),
            "invalid_windows_path",
        ),
    ];

    // Check the full table so newly reordered variants cannot change a kind
    for (failure, expected_kind) in cases {
        assert_eq!(failure.to_protocol_error().kind, expected_kind);
    }
}

/// Confirms target-side Windows errors survive protocol conversion
#[test]
fn load_library_rejection_preserves_the_windows_error() {
    let error = HelperFailure::LoadLibraryRejected {
        code: 126,
        message: "missing dependency".into(),
    }
    .to_protocol_error();

    assert_eq!(error.kind, "load_library_rejected");
    assert_eq!(error.windows_error, Some(126));
}

/// Confirms standard loader failures do not expose a fake error code
#[test]
fn load_library_rejection_omits_unavailable_windows_error() {
    let error = HelperFailure::LoadLibraryRejected {
        code: 0,
        message: "LoadLibraryW returned NULL".into(),
    }
    .to_protocol_error();

    assert_eq!(error.kind, "load_library_rejected");
    assert_eq!(error.windows_error, None);
}

/// Confirms filesystem context remains actionable in protocol output
#[test]
fn io_failure_keeps_context_without_exposing_an_unstable_kind() {
    let error = HelperFailure::io(
        "unable to read request",
        std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    )
    .to_protocol_error();

    assert_eq!(error.kind, "io");
    assert!(error.message.contains("unable to read request"));
}
