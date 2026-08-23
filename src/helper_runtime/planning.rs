//! Dry-run planning and exact Windows process correlation

use std::fs;
use std::path::Path;

use proton_informer_helper_protocol::{
    HelperOperation, HelperResponse, HelperResult, ProcessQueryRejection, SCHEMA_VERSION,
    WindowsProcessInfo,
};
use uuid::Uuid;

use crate::binary::BinaryInspection;
use crate::error::{Error, Result};
use crate::helper_protocol;
use crate::install;
use crate::process::ProcessInfo;
use crate::types::Architecture;
use crate::wine;

use super::invocation::{invocation, select_runtime};
use super::model::{LoadDryRunPlan, PayloadPathMode};
use super::state::{create_request_directory, prepare_payload_for_request, write_private_json};

/// Creates secure request artifacts and a non-executing helper invocation
///
/// # Errors
///
/// Returns an error when helper discovery, runtime identity, path conversion,
/// request construction, or secure file creation fails
pub fn plan_load_dry_run(
    payload: &BinaryInspection,
    target: &ProcessInfo,
    timeout_ms: u64,
    payload_path_mode: PayloadPathMode,
) -> Result<LoadDryRunPlan> {
    let target_filesystem_uid = target
        .uids
        .ok_or_else(|| Error::InvalidInput("target filesystem UID is unknown".into()))?
        .filesystem;
    let prefix = target
        .wine_prefix
        .as_deref()
        .ok_or_else(|| Error::InvalidInput("target Wine prefix is unknown".into()))?;
    // Every helper-backed operation verifies the installed binary before use
    let helper_path = install::verify_for_target(target)?.helper_path;
    let helper_windows_path = wine::unix_path_to_windows(prefix, &helper_path)?;
    let request_id = Uuid::new_v4().to_string();
    let run_directory = create_request_directory(prefix, &request_id)?;
    let result = (|| {
        let windows_target = resolve_windows_target(
            target,
            payload.architecture,
            prefix,
            &helper_windows_path,
            &run_directory,
        )?;
        let request_payload =
            prepare_payload_for_request(payload, &run_directory, payload_path_mode)?;
        let payload_host_path = request_payload.path.clone();
        let request = helper_protocol::load_request(
            &request_payload,
            target,
            &windows_target,
            timeout_ms,
            request_id,
        )?;
        let request_host_path = run_directory.join("request.json");
        write_private_json(&request_host_path, &request)?;
        let request_windows_path = wine::unix_path_to_windows(prefix, &request_host_path)?;
        let runtime = select_runtime(target)?;
        let invocation = invocation(
            runtime,
            &helper_windows_path,
            vec!["--request-json".into(), request_windows_path.clone()],
        )?;

        Ok(LoadDryRunPlan {
            target_pid: target.pid,
            target_start_time_ticks: target.start_time_ticks,
            target_filesystem_uid,
            helper_windows_path,
            invocation,
            payload_host_path,
            payload_path_mode,
            request,
            request_host_path,
            request_windows_path,
            run_directory: run_directory.clone(),
        })
    })();
    if result.is_err() {
        // A failed plan has no usable audit record, so remove partial state
        let _ = fs::remove_dir_all(&run_directory);
    }
    result
}

/// Resolves the exact Windows PID before creating a mutating load request
pub(super) fn resolve_windows_target(
    target: &ProcessInfo,
    architecture: Architecture,
    prefix: &Path,
    helper_windows_path: &str,
    run_directory: &Path,
) -> Result<WindowsProcessInfo> {
    let request = helper_protocol::query_processes_request(Uuid::new_v4().to_string())?;
    let request_path = run_directory.join("process-query.json");
    write_private_json(&request_path, &request)?;
    let request_windows_path = wine::unix_path_to_windows(prefix, &request_path)?;
    let invocation = invocation(
        select_runtime(target)?,
        helper_windows_path,
        vec!["--request-json".into(), request_windows_path],
    )?;
    let output = crate::helper_executor::execute(&invocation, 20_000)?;
    let _ = fs::remove_file(&request_path);
    if output.exit_code != Some(0) {
        return Err(Error::HelperExecution(format!(
            "process query exited {:?}: {}",
            output.exit_code,
            output.stderr.trim()
        )));
    }
    let response = super::response::parse_helper_response(&output)?;
    validate_query_process_response(&response, &request.request_id)?;
    let HelperResult::QueryProcesses(result) = response
        .result
        .ok_or_else(|| Error::HelperExecution("process query returned no result".into()))?
    else {
        return Err(Error::HelperExecution(
            "process query returned the wrong result type".into(),
        ));
    };
    correlate_windows_process(
        target,
        architecture,
        prefix,
        result.processes,
        result.rejections,
    )
}

/// Verifies that a process-query response belongs to the request being handled
fn validate_query_process_response(response: &HelperResponse, request_id: &str) -> Result<()> {
    if response.schema_version != SCHEMA_VERSION
        || response.request_id != request_id
        || response.operation != HelperOperation::QueryProcesses
    {
        return Err(Error::HelperExecution(
            "helper process query returned an invalid response".into(),
        ));
    }
    if !response.ok {
        let error = response.error.as_ref().ok_or_else(|| {
            Error::HelperExecution("helper process query failed without an error body".into())
        })?;
        return Err(Error::HelperRejected {
            kind: error.kind.clone(),
            message: error.message.clone(),
            windows_error: error.windows_error,
        });
    }
    Ok(())
}

/// Correlates helper process data with the controller's guest executable
fn correlate_windows_process(
    target: &ProcessInfo,
    architecture: Architecture,
    prefix: &Path,
    processes: Vec<WindowsProcessInfo>,
    rejections: Vec<ProcessQueryRejection>,
) -> Result<WindowsProcessInfo> {
    let expected = target
        .guest_executable
        .as_ref()
        .ok_or_else(|| Error::InvalidInput("target guest executable is unknown".into()))?
        .path
        .canonicalize()
        .map_err(|source| Error::io("target guest executable", source))?;
    let expected_process_name = expected
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            Error::InvalidInput("target guest executable name is not valid UTF-8".into())
        })?;
    let expected_architecture = helper_protocol::protocol_architecture(architecture);
    let mut matches = Vec::new();
    let mut rejected = rejections
        .into_iter()
        .filter(|rejection| {
            rejection.process_name.is_empty()
                || rejection
                    .process_name
                    .eq_ignore_ascii_case(expected_process_name)
        })
        .map(|rejection| {
            rejection.windows_error.map_or_else(
                || {
                    format!(
                        "Windows PID {} ({}): {}",
                        rejection.windows_pid, rejection.kind, rejection.message
                    )
                },
                |code| {
                    format!(
                        "Windows PID {} ({}; error {}): {}",
                        rejection.windows_pid, rejection.kind, code, rejection.message
                    )
                },
            )
        })
        .collect::<Vec<_>>();
    for process in processes {
        if process.architecture != expected_architecture {
            continue;
        }
        let relevant_process_name = process
            .process_name
            .eq_ignore_ascii_case(expected_process_name);
        let Some(windows_path) = process.executable_windows_path.as_deref() else {
            if relevant_process_name {
                rejected.push(format!(
                    "Windows PID {} did not report an executable path",
                    process.windows_pid
                ));
            }
            continue;
        };
        let unix_path = match wine::windows_path_to_unix(prefix, windows_path) {
            Ok(path) => path,
            Err(error) => {
                if relevant_process_name {
                    rejected.push(format!(
                        "Windows PID {} path {windows_path}: {error}",
                        process.windows_pid
                    ));
                }
                continue;
            }
        };
        let unix_path = match unix_path.canonicalize() {
            Ok(path) => path,
            Err(source) => {
                if relevant_process_name {
                    rejected.push(format!(
                        "Windows PID {} path {windows_path}: unable to canonicalize: {source}",
                        process.windows_pid
                    ));
                }
                continue;
            }
        };
        if unix_path == expected {
            matches.push(process);
        }
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(Error::HelperExecution(format!(
            "target process disappeared or the helper could not correlate {}{}",
            expected.display(),
            diagnostic_suffix(&rejected)
        ))),
        count => Err(Error::TargetAmbiguous(format!(
            "Linux process {} maps ambiguously to {count} Windows processes sharing executable {}; refusing to guess",
            target.pid,
            expected.display()
        ))),
    }
}

/// Keeps correlation diagnostics concise while retaining the first failures
fn diagnostic_suffix(rejected: &[String]) -> String {
    rejected.first().map_or_else(String::new, |detail| {
        format!("; {} candidate rejection: {detail}", rejected.len())
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    use super::{correlate_windows_process, validate_query_process_response};
    use crate::process::{
        ClassificationConfidence, EnvironmentStatus, GuestExecutableCandidate,
        GuestExecutableSource, ProcessInfo, TargetKind,
    };
    use crate::types::Architecture;
    use proton_informer_helper_protocol::{
        HelperOperation, HelperResponse, ProcessQueryRejection, ProtocolArchitecture,
        SCHEMA_VERSION, WindowsProcessInfo,
    };
    use tempfile::tempdir;

    fn target(executable: PathBuf) -> ProcessInfo {
        ProcessInfo {
            classification_confidence: ClassificationConfidence::High,
            command: Vec::new(),
            compatdata_dir: None,
            environment_status: EnvironmentStatus::Read,
            evidence_failures: Vec::new(),
            executable: None,
            guest_architecture: Some(Architecture::X86_64),
            guest_executable: Some(GuestExecutableCandidate {
                path: executable,
                source: GuestExecutableSource::AbsoluteUnixArgument,
            }),
            name: "game.exe".into(),
            owned_by_current_user: Some(true),
            pid: 42,
            start_time_ticks: 1,
            proton_dist: None,
            steam_app_id: None,
            steam_client_path: None,
            target_kind: TargetKind::WineProtonWindows,
            uids: None,
            wine_prefix: None,
        }
    }

    fn process(pid: u32, path: &str, architecture: ProtocolArchitecture) -> WindowsProcessInfo {
        WindowsProcessInfo {
            architecture,
            creation_time_100ns: Some(u64::from(pid)),
            executable_windows_path: Some(path.into()),
            process_name: "game.exe".into(),
            windows_pid: pid,
        }
    }

    fn prefix_for(root: &Path) -> PathBuf {
        let prefix = root.join("pfx");
        fs::create_dir_all(prefix.join("dosdevices")).expect("create dosdevices");
        symlink(root, prefix.join("dosdevices/c:")).expect("create c mapping");
        prefix
    }

    #[test]
    fn correlation_rejects_a_process_with_the_wrong_architecture() {
        let directory = tempdir().expect("temporary directory");
        let executable = directory.path().join("game.exe");
        fs::write(&executable, b"fixture").expect("game fixture");
        let prefix = prefix_for(directory.path());

        let result = correlate_windows_process(
            &target(executable),
            Architecture::X86_64,
            &prefix,
            vec![process(1, r"C:\game.exe", ProtocolArchitecture::X86)],
            Vec::new(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn correlation_selects_only_the_exact_canonical_executable_path() {
        let directory = tempdir().expect("temporary directory");
        let executable = directory.path().join("game.exe");
        fs::write(&executable, b"fixture").expect("game fixture");
        fs::write(directory.path().join("other.exe"), b"fixture").expect("other fixture");
        let prefix = prefix_for(directory.path());

        let result = correlate_windows_process(
            &target(executable),
            Architecture::X86_64,
            &prefix,
            vec![
                process(1, r"C:\game.exe", ProtocolArchitecture::X86_64),
                process(2, r"C:\other.exe", ProtocolArchitecture::X86_64),
            ],
            Vec::new(),
        )
        .expect("exact path should correlate");

        assert_eq!(result.windows_pid, 1);
    }

    #[test]
    fn empty_process_name_rejections_are_retained_in_diagnostics() {
        let directory = tempdir().expect("temporary directory");
        let executable = directory.path().join("game.exe");
        fs::write(&executable, b"fixture").expect("game fixture");
        let error = correlate_windows_process(
            &target(executable),
            Architecture::X86_64,
            directory.path(),
            Vec::new(),
            vec![ProcessQueryRejection {
                kind: "access_denied".into(),
                message: "fixture rejection".into(),
                windows_error: Some(5),
                windows_pid: 9,
                process_name: String::new(),
            }],
        )
        .expect_err("no process should correlate");

        assert!(error.to_string().contains("fixture rejection"));
    }

    fn response(operation: HelperOperation, request_id: &str) -> HelperResponse {
        HelperResponse {
            error: None,
            ok: true,
            operation,
            request_id: request_id.into(),
            result: None,
            schema_version: SCHEMA_VERSION,
            warnings: Vec::new(),
        }
    }

    #[test]
    fn process_response_validation_requires_all_correlation_fields() {
        let valid = response(HelperOperation::QueryProcesses, "request-1");
        assert!(validate_query_process_response(&valid, "request-1").is_ok());

        let mut failed = valid.clone();
        failed.ok = false;
        assert!(validate_query_process_response(&failed, "request-1").is_err());

        let mut wrong_schema = valid.clone();
        wrong_schema.schema_version += 1;
        assert!(validate_query_process_response(&wrong_schema, "request-1").is_err());

        let mut wrong_request = valid;
        wrong_request.request_id = "request-2".into();
        assert!(validate_query_process_response(&wrong_request, "request-1").is_err());

        let wrong_operation = response(HelperOperation::QueryModules, "request-1");
        assert!(validate_query_process_response(&wrong_operation, "request-1").is_err());
    }
}
