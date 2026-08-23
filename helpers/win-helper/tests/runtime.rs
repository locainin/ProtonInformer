//! Real Windows process correlation and module-query checks

#![cfg(windows)]

use std::process::{Child, Command};
use std::thread;
use std::time::Duration;
use std::{fmt::Write as _, path::Path};

#[path = "support/common.rs"]
mod common;

use proton_informer_helper_protocol::{
    HelperOperation, HelperOptions, HelperPayload, HelperRequest, HelperResult, HelperTarget,
    ProcessQueryResult, ProtocolArchitecture, SCHEMA_VERSION, TargetSelector, WindowsProcessInfo,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const FIXTURE_ENV: &str = "PROTON_INFORMER_RUNTIME_FIXTURE";

struct FixtureProcess(Child);

impl FixtureProcess {
    /// Spawns another copy of this Windows test binary as a stable target
    fn spawn() -> Self {
        let child = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "runtime_fixture_process_waits",
                "--test-threads=1",
            ])
            .env(FIXTURE_ENV, "1")
            .spawn()
            .expect("runtime fixture process");
        Self(child)
    }

    /// Returns the real Windows PID assigned to the fixture
    fn windows_pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for FixtureProcess {
    fn drop(&mut self) {
        // Always terminate fixture processes when a test fails or completes
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Builds one request with normal helper execution limits
fn request(operation: HelperOperation, target: Option<HelperTarget>) -> HelperRequest {
    HelperRequest {
        operation,
        options: HelperOptions::default(),
        payload: None,
        request_id: format!("runtime-{operation:?}"),
        schema_version: SCHEMA_VERSION,
        target,
    }
}

/// Queries processes through the compiled helper and unwraps the typed result
fn query_processes(path: &Path) -> ProcessQueryResult {
    let response = common::run_request(&request(HelperOperation::QueryProcesses, None), path);
    assert!(response.ok);
    let HelperResult::QueryProcesses(result) = response.result.expect("process result") else {
        panic!("query_processes returned the wrong result type");
    };
    result
}

/// Waits briefly for Wine to expose a newly spawned Windows process
fn wait_for_process(windows_pid: u32, directory: &Path) -> WindowsProcessInfo {
    // Use bounded polling because Wine process registration is asynchronous
    for attempt in 0..20 {
        let result = query_processes(&directory.join(format!("processes-{attempt}.json")));
        if let Some(process) = result
            .processes
            .into_iter()
            .find(|process| process.windows_pid == windows_pid)
        {
            return process;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("fixture process was not enumerated");
}

/// Converts helper-observed process facts into the strongest target selector
fn exact_target(process: &WindowsProcessInfo) -> HelperTarget {
    HelperTarget {
        expected_creation_time_100ns: process.creation_time_100ns,
        expected_architecture: process.architecture,
        expected_executable_windows_path: process.executable_windows_path.clone(),
        expected_process_name: process.process_name.clone(),
        selector: TargetSelector::ByWindowsPid(process.windows_pid),
    }
}

/// Builds a DLL-shaped PE that passes identity checks but has no import table
fn malformed_import_payload(architecture: ProtocolArchitecture) -> Vec<u8> {
    let (machine, optional_magic) = match architecture {
        ProtocolArchitecture::X86 => (0x014c_u16, 0x010b_u16),
        ProtocolArchitecture::X86_64 => (0x8664_u16, 0x020b_u16),
        other => panic!("unsupported runtime fixture architecture: {other:?}"),
    };
    // Keep the DOS and PE headers small enough for a deterministic fixture
    let pe_offset = 0x80_usize;
    let mut bytes = vec![0_u8; pe_offset + 26];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&u32::try_from(pe_offset).expect("PE offset").to_le_bytes());
    bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
    bytes[pe_offset + 4..pe_offset + 6].copy_from_slice(&machine.to_le_bytes());
    bytes[pe_offset + 6..pe_offset + 8].copy_from_slice(&1_u16.to_le_bytes());
    bytes[pe_offset + 20..pe_offset + 22].copy_from_slice(&2_u16.to_le_bytes());
    bytes[pe_offset + 22..pe_offset + 24].copy_from_slice(&0x2000_u16.to_le_bytes());
    bytes[pe_offset + 24..pe_offset + 26].copy_from_slice(&optional_magic.to_le_bytes());
    bytes
}

/// Encodes one fixture digest in the protocol's lowercase hexadecimal form
fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(encoded, "{byte:02x}").expect("write to string");
    }
    encoded
}

/// Keeps the child test binary alive only when launched as a fixture
#[test]
fn runtime_fixture_process_waits() {
    if std::env::var_os(FIXTURE_ENV).is_some() {
        thread::sleep(Duration::from_secs(30));
    }
}

/// Confirms exact process selection returns real loaded modules
#[test]
fn exact_process_identity_returns_real_loaded_modules() {
    let fixture = FixtureProcess::spawn();
    let directory = tempdir().expect("temporary directory");
    let process = wait_for_process(fixture.windows_pid(), directory.path());
    let target = exact_target(&process);
    let response = common::run_request(
        &request(HelperOperation::QueryModules, Some(target)),
        &directory.path().join("modules.json"),
    );

    assert!(response.ok);
    let HelperResult::QueryModules(result) = response.result.expect("module result") else {
        panic!("query_modules returned the wrong result type");
    };
    assert_eq!(result.target.windows_pid, fixture.windows_pid());
    assert!(!result.modules.is_empty());
    assert!(result.modules.iter().any(|module| {
        process
            .executable_windows_path
            .as_deref()
            .is_some_and(|path| module.windows_path.eq_ignore_ascii_case(path))
    }));
}

/// Confirms creation time prevents selecting a recycled Windows PID
#[test]
fn changed_creation_time_rejects_a_reused_pid_identity() {
    let fixture = FixtureProcess::spawn();
    let directory = tempdir().expect("temporary directory");
    let process = wait_for_process(fixture.windows_pid(), directory.path());
    let mut target = exact_target(&process);
    target.expected_creation_time_100ns =
        target.expected_creation_time_100ns.map(|value| value + 1);
    let response = common::run_request(
        &request(HelperOperation::QueryModules, Some(target)),
        &directory.path().join("changed-identity.json"),
    );

    assert!(!response.ok);
    assert_eq!(response.error.expect("error body").kind, "target_not_found");
}

/// Confirms executable path remains part of exact PID selection
#[test]
fn changed_executable_path_rejects_the_target() {
    let fixture = FixtureProcess::spawn();
    let directory = tempdir().expect("temporary directory");
    let process = wait_for_process(fixture.windows_pid(), directory.path());
    let mut target = exact_target(&process);
    target.expected_executable_windows_path = Some(r"C:\missing\other.exe".into());
    let response = common::run_request(
        &request(HelperOperation::QueryModules, Some(target)),
        &directory.path().join("changed-path.json"),
    );

    assert!(!response.ok);
    assert_eq!(response.error.expect("error body").kind, "target_not_found");
}

/// Confirms advisory import parsing cannot replace the Windows loader result
#[test]
fn malformed_import_preflight_does_not_replace_windows_loader_failure() {
    let fixture = FixtureProcess::spawn();
    let directory = tempdir().expect("temporary directory");
    let process = wait_for_process(fixture.windows_pid(), directory.path());
    let bytes = malformed_import_payload(process.architecture);
    let payload_path = directory.path().join("malformed-imports.dll");
    std::fs::write(&payload_path, &bytes).expect("payload fixture");
    let payload = HelperPayload {
        sha256: sha256(&bytes),
        size_bytes: u64::try_from(bytes.len()).expect("fixture size"),
        windows_path: payload_path
            .to_str()
            .expect("UTF-8 fixture path")
            .to_owned(),
    };
    let mut request = request(HelperOperation::LoadLibrary, Some(exact_target(&process)));
    request.payload = Some(payload);
    let response = common::run_request(&request, &directory.path().join("load.json"));

    assert!(!response.ok);
    let error = response.error.expect("loader error");
    if process.architecture == ProtocolArchitecture::X86 {
        assert_eq!(error.kind, "load_library_rejected");
        assert_eq!(
            error.message,
            "LoadLibraryW returned a zero 32-bit thread exit status; target-side GetLastError is unavailable in \
             standard loader mode."
        );
        assert_eq!(error.windows_error, None);
    } else {
        assert_eq!(error.kind, "load_indeterminate");
        assert!(error.message.contains("low 32-bit thread exit code"));
        assert_eq!(error.windows_error, None);
    }
}
