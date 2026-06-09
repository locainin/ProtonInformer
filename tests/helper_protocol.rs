//! Linux controller request construction checks.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use proton_informer::binary::{BinaryFormat, BinaryInspection};
use proton_informer::helper_protocol::load_request;
use proton_informer::process::{
    ClassificationConfidence, EnvironmentStatus, GuestExecutableCandidate, GuestExecutableSource,
    ProcessInfo, TargetKind,
};
use proton_informer::types::Architecture;
use proton_informer_helper_protocol::{ProtocolArchitecture, TargetSelector};
use tempfile::tempdir;

/// Builds a Wine target with enough trusted identity for helper planning.
fn target(prefix: PathBuf, executable: PathBuf) -> ProcessInfo {
    ProcessInfo {
        classification_confidence: ClassificationConfidence::High,
        command: vec![executable.display().to_string()],
        compatdata_dir: None,
        environment_status: EnvironmentStatus::Read,
        executable: None,
        guest_architecture: Some(Architecture::X86_64),
        guest_executable: Some(GuestExecutableCandidate {
            path: executable,
            source: GuestExecutableSource::AbsoluteUnixArgument,
        }),
        host_architecture: Architecture::X86_64,
        name: "wine64".into(),
        owned_by_current_user: Some(true),
        pid: 1_000,
        proton_dist: None,
        steam_app_id: None,
        steam_client_path: None,
        target_kind: TargetKind::WineProtonWindows,
        uids: None,
        wine_prefix: Some(prefix),
    }
}

#[test]
fn load_request_hashes_the_exact_payload_and_uses_guest_identity() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    let game = directory.path().join("BlackOps3.exe");
    let payload_path = directory.path().join("mod.dll");
    fs::create_dir_all(prefix.join("dosdevices")).expect("prefix drive directory");
    fs::write(&game, b"game fixture").expect("game fixture");
    fs::write(&payload_path, b"abc").expect("payload fixture");
    symlink("/", prefix.join("dosdevices/z:")).expect("root drive mapping");

    let payload = BinaryInspection {
        architecture: Architecture::X86_64,
        extension_warning: None,
        format: BinaryFormat::PeDll,
        path: payload_path,
        size_bytes: 3,
    };
    let request = load_request(&payload, &target(prefix, game), 10_000, "request-1".into())
        .expect("valid load request");
    let target = request.target.expect("request target");
    let payload = request.payload.expect("request payload");

    assert_eq!(
        payload.sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(target.expected_process_name, "BlackOps3.exe");
    assert_eq!(
        target.selector,
        TargetSelector::ByProcessNameAndExecutablePath
    );
    assert_eq!(target.expected_architecture, ProtocolArchitecture::X86_64);
}

#[test]
fn load_request_rejects_a_payload_changed_after_inspection() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    let game = directory.path().join("game.exe");
    let payload_path = directory.path().join("mod.dll");
    fs::create_dir_all(prefix.join("dosdevices")).expect("prefix drive directory");
    fs::write(&game, b"game fixture").expect("game fixture");
    fs::write(&payload_path, b"longer").expect("payload fixture");
    symlink("/", prefix.join("dosdevices/z:")).expect("root drive mapping");

    let payload = BinaryInspection {
        architecture: Architecture::X86_64,
        extension_warning: None,
        format: BinaryFormat::PeDll,
        path: payload_path,
        size_bytes: 3,
    };
    let error = load_request(&payload, &target(prefix, game), 10_000, "request-2".into())
        .expect_err("size mismatch must fail");

    assert!(error.to_string().contains("changed after inspection"));
}

#[test]
fn load_request_rejects_unknown_architecture() {
    let payload = BinaryInspection {
        architecture: Architecture::Unknown,
        extension_warning: None,
        format: BinaryFormat::PeDll,
        path: PathBuf::from("/missing.dll"),
        size_bytes: 1,
    };
    let mut wine_target = target(PathBuf::from("/prefix"), PathBuf::from("/game.exe"));
    wine_target.guest_executable = None;
    let error = load_request(&payload, &wine_target, 10_000, "request-3".into())
        .expect_err("unknown architecture must fail before path access");

    assert!(error.to_string().contains("architecture must be known"));
}
