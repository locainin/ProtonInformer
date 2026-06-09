//! Live `/proc` inspection checks.

use proton_informer::process::{self, EnvironmentStatus, TargetKind};

#[test]
fn current_process_has_complete_uid_identity() {
    let process = process::inspect(std::process::id()).expect("inspect current process");
    let uids = process.uids.expect("current process UIDs");

    assert_eq!(uids.real, uids.effective);
    assert_eq!(uids.effective, uids.filesystem);
    assert_eq!(process.owned_by_current_user, Some(true));
}

#[test]
fn current_native_test_process_is_not_misclassified_as_wine() {
    let process = process::inspect(std::process::id()).expect("inspect current process");

    assert_eq!(process.target_kind, TargetKind::NativeLinux);
    assert_eq!(process.environment_status, EnvironmentStatus::Read);
}

#[test]
fn missing_process_is_rejected() {
    let error = process::inspect(u32::MAX).expect_err("missing process should fail");

    assert!(error.to_string().contains("does not exist"));
}
