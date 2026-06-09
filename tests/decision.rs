//! Public planning decision matrix.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use proton_informer::binary::{BinaryFormat, BinaryInspection};
use proton_informer::decision::{Backend, OverridePlacement, plan_override, plan_running};
use proton_informer::process::{
    ClassificationConfidence, EnvironmentStatus, ProcessInfo, ProcessUids, TargetKind,
};
use proton_informer::types::Architecture;
use tempfile::tempdir;

fn payload(format: BinaryFormat) -> BinaryInspection {
    BinaryInspection {
        architecture: Architecture::X86_64,
        extension_warning: None,
        format,
        path: PathBuf::from("/mods/payload.bin"),
        size_bytes: 4_096,
    }
}

fn target(kind: TargetKind) -> ProcessInfo {
    ProcessInfo {
        classification_confidence: ClassificationConfidence::High,
        command: Vec::new(),
        compatdata_dir: None,
        environment_status: EnvironmentStatus::Read,
        executable: None,
        guest_architecture: Some(Architecture::X86_64),
        guest_executable: None,
        host_architecture: Architecture::X86_64,
        name: "target".into(),
        owned_by_current_user: Some(true),
        pid: 100,
        proton_dist: None,
        steam_app_id: None,
        steam_client_path: None,
        target_kind: kind,
        uids: Some(ProcessUids {
            effective: 1_000,
            filesystem: 1_000,
            real: 1_000,
            saved: 1_000,
        }),
        wine_prefix: None,
    }
}

#[test]
fn architecture_mismatch_is_rejected() {
    let mut x86_payload = payload(BinaryFormat::PeDll);
    x86_payload.architecture = Architecture::X86;
    let error = plan_running(x86_payload, target(TargetKind::WineProtonWindows), None)
        .expect_err("reject architecture mismatch");

    assert!(error.to_string().contains("does not match"));
}

#[test]
fn explicit_architecture_cannot_contradict_discovered_guest() {
    let error = plan_running(
        payload(BinaryFormat::PeDll),
        target(TargetKind::WineProtonWindows),
        Some(Architecture::X86),
    )
    .expect_err("contradictory architecture evidence must fail");

    assert!(error.to_string().contains("contradicts discovered"));
}

#[test]
fn explicit_guest_architecture_allows_wine_plan() {
    let mut wine_target = target(TargetKind::WineProtonWindows);
    wine_target.guest_architecture = None;
    let mut x86_payload = payload(BinaryFormat::PeDll);
    x86_payload.architecture = Architecture::X86;

    let result = plan_running(x86_payload, wine_target, Some(Architecture::X86))
        .expect("explicit architecture plan");

    assert_eq!(result.backend, Backend::WinePeHelper);
}

#[test]
fn override_plan_states_that_placement_is_incomplete() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    let payload_path = directory.path().join("winhttp.dll");
    fs::create_dir_all(prefix.join("dosdevices")).expect("create prefix");
    fs::write(&payload_path, b"fixture").expect("create payload");
    symlink("/", prefix.join("dosdevices/z:")).expect("create drive mapping");

    let mut dll = payload(BinaryFormat::PeDll);
    dll.path = payload_path;
    let plan =
        plan_override(dll, &prefix, Some(311_210), "winhttp.dll").expect("create override plan");

    assert_eq!(plan.backend, Backend::WineDllOverride);
    assert_eq!(plan.placement, OverridePlacement::InstructionsOnly);
    assert!(!plan.files_modified);
    assert!(plan.placement_note.contains("DLL search path"));
}

#[test]
fn pe_dll_is_rejected_for_native_target() {
    let error = plan_running(
        payload(BinaryFormat::PeDll),
        target(TargetKind::NativeLinux),
        None,
    )
    .expect_err("reject PE DLL for ELF loader");

    assert!(error.to_string().contains("Windows DLLs cannot be loaded"));
}

#[test]
fn wine_target_never_falls_back_to_host_architecture() {
    let mut wine_target = target(TargetKind::WineProtonWindows);
    wine_target.guest_architecture = None;
    let error = plan_running(payload(BinaryFormat::PeDll), wine_target, None)
        .expect_err("unknown guest architecture must fail");

    assert!(error.to_string().contains("--target-arch"));
}
