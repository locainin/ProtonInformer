//! Compatibility runtime selection checks.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use proton_informer::binary;
use proton_informer::helper_runtime::{
    PayloadPathMode, create_request_directory, prepare_payload_for_request, select_runtime,
};
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

#[test]
fn staged_payload_mode_uses_a_private_copy() {
    let directory = tempdir().expect("temporary directory");
    let run_directory = directory.path().join("run");
    let source_path = directory.path().join("payload.dll");
    fs::create_dir(&run_directory).expect("run directory");
    write_minimal_pe_dll(&source_path);
    let payload = binary::inspect(&source_path).expect("payload inspection");

    let selected =
        prepare_payload_for_request(&payload, &run_directory, PayloadPathMode::StagedCopy)
            .expect("staged payload");

    assert_ne!(selected.path, source_path);
    assert_eq!(selected.path, run_directory.join("payload/payload.dll"));
    assert_eq!(
        fs::read(&selected.path).expect("staged bytes"),
        fs::read(&source_path).expect("source bytes")
    );
}

#[test]
fn staged_payload_mode_does_not_collide_with_controller_files() {
    let directory = tempdir().expect("temporary directory");
    let run_directory = directory.path().join("run");
    let source_path = directory.path().join("request.json");
    fs::create_dir(&run_directory).expect("run directory");
    write_minimal_pe_dll(&source_path);
    let payload = binary::inspect(&source_path).expect("payload inspection");

    let selected =
        prepare_payload_for_request(&payload, &run_directory, PayloadPathMode::StagedCopy)
            .expect("staged payload");

    assert_eq!(selected.path, run_directory.join("payload/request.json"));
    assert!(!run_directory.join("request.json").exists());
}

#[test]
fn original_payload_mode_keeps_the_source_path() {
    let directory = tempdir().expect("temporary directory");
    let run_directory = directory.path().join("run");
    let source_path = directory.path().join("payload.dll");
    fs::create_dir(&run_directory).expect("run directory");
    write_minimal_pe_dll(&source_path);
    let payload = binary::inspect(&source_path).expect("payload inspection");

    let selected =
        prepare_payload_for_request(&payload, &run_directory, PayloadPathMode::OriginalPath)
            .expect("original payload");

    assert_eq!(selected, payload);
    assert_eq!(
        fs::read_dir(&run_directory)
            .expect("run directory listing")
            .count(),
        0
    );
}

#[test]
fn request_directory_creation_matches_cleanup_safety_rules() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    let drive_c = prefix.join("drive_c");
    fs::create_dir_all(prefix.join("dosdevices")).expect("dosdevices directory");
    fs::create_dir_all(&drive_c).expect("drive C directory");
    symlink("../drive_c", prefix.join("dosdevices/c:")).expect("C drive mapping");

    let request_directory =
        create_request_directory(&prefix, "6ed07ed4-51dd-4cb6-a003-57d6a48e7792")
            .expect("mapped request directory");

    for path in [
        drive_c.join(".proton-informer"),
        drive_c.join(".proton-informer/runs"),
        request_directory,
    ] {
        let metadata = fs::symlink_metadata(&path).expect("state directory metadata");
        assert!(metadata.is_dir());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }
}

fn write_minimal_pe_dll(path: &std::path::Path) {
    let mut bytes = vec![0_u8; 0x188];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");

    let coff = 0x84;
    bytes[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
    bytes[coff + 16..coff + 18].copy_from_slice(&0xf0_u16.to_le_bytes());
    bytes[coff + 18..coff + 20].copy_from_slice(&0x2022_u16.to_le_bytes());

    let optional = coff + 20;
    bytes[optional..optional + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
    bytes[optional + 16..optional + 20].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[optional + 24..optional + 32].copy_from_slice(&0x1_4000_0000_u64.to_le_bytes());
    bytes[optional + 32..optional + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[optional + 36..optional + 40].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[optional + 56..optional + 60].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[optional + 60..optional + 64].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[optional + 68..optional + 70].copy_from_slice(&3_u16.to_le_bytes());
    bytes[optional + 92..optional + 96].copy_from_slice(&16_u32.to_le_bytes());

    fs::write(path, bytes).expect("minimal PE DLL fixture");
}
