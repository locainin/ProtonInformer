//! Compatibility runtime selection checks.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use proton_informer::helper_runtime::{create_request_directory, select_runtime};
use proton_informer::process::{
    ClassificationConfidence, EnvironmentStatus, ProcessInfo, TargetKind,
};
use proton_informer::types::Architecture;
use tempfile::tempdir;

/// Builds a minimal Wine process model for runtime selection.
fn target() -> ProcessInfo {
    ProcessInfo {
        classification_confidence: ClassificationConfidence::High,
        command: Vec::new(),
        compatdata_dir: None,
        environment_status: EnvironmentStatus::Read,
        executable: None,
        guest_architecture: Some(Architecture::X86_64),
        guest_executable: None,
        host_architecture: Architecture::X86_64,
        name: "game.exe".into(),
        owned_by_current_user: Some(true),
        pid: 1_000,
        proton_dist: None,
        steam_app_id: None,
        steam_client_path: None,
        target_kind: TargetKind::WineProtonWindows,
        uids: None,
        wine_prefix: Some(PathBuf::from("/prefix")),
    }
}

#[test]
fn incomplete_proton_identity_never_falls_back_to_system_wine() {
    let mut proton_target = target();
    proton_target.compatdata_dir = Some(PathBuf::from("/steam/compatdata/311210"));
    proton_target.steam_app_id = Some(311_210);
    let error = select_runtime(&proton_target).expect_err("partial Proton identity must fail");

    assert!(error.to_string().contains("identity is incomplete"));
}

#[test]
fn request_directory_falls_back_to_the_configured_c_drive() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    let drive_c = prefix.join("drive_c");
    fs::create_dir_all(prefix.join("dosdevices")).expect("dosdevices directory");
    fs::create_dir_all(&drive_c).expect("drive C directory");
    symlink("../drive_c", prefix.join("dosdevices/c:")).expect("C drive mapping");

    let request_directory =
        create_request_directory(&prefix, "9f267cf7-372a-48da-b7bb-35db56ab123d")
            .expect("mapped request directory");

    assert!(request_directory.starts_with(drive_c));
    assert!(request_directory.is_dir());
}
