//! Dry-run planning and exact Windows process correlation.

use std::fs;
use std::path::Path;

use proton_informer_helper_protocol::{
    HelperOperation, HelperResponse, HelperResult, SCHEMA_VERSION, WindowsProcessInfo,
};
use uuid::Uuid;

use crate::binary::BinaryInspection;
use crate::error::{Error, Result};
use crate::helper;
use crate::helper_protocol;
use crate::process::ProcessInfo;
use crate::types::Architecture;
use crate::wine;

use super::invocation::{invocation, select_runtime};
use super::model::LoadDryRunPlan;
use super::state::{create_request_directory, stage_payload, write_private_json};

/// Creates secure request artifacts and a non-executing helper invocation.
///
/// # Errors
///
/// Returns an error when helper discovery, runtime identity, path conversion,
/// request construction, or secure file creation fails.
pub fn plan_load_dry_run(
    payload: &BinaryInspection,
    target: &ProcessInfo,
    timeout_ms: u64,
) -> Result<LoadDryRunPlan> {
    let prefix = target
        .wine_prefix
        .as_deref()
        .ok_or_else(|| Error::InvalidInput("target Wine prefix is unknown".into()))?;
    let helper_path = helper::find_wine_helper(payload.architecture).ok_or_else(|| {
        Error::InvalidInput(format!(
            "no {} Windows helper is installed",
            payload.architecture
        ))
    })?;
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
        let staged_payload = stage_payload(payload, &run_directory)?;
        let staged_payload_host_path = staged_payload.path.clone();
        let request = helper_protocol::load_request(
            &staged_payload,
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
            helper_windows_path,
            invocation,
            request,
            request_host_path,
            request_windows_path,
            run_directory: run_directory.clone(),
            staged_payload_host_path,
        })
    })();
    if result.is_err() {
        // A failed plan has no usable audit record, so remove partial state
        let _ = fs::remove_dir_all(&run_directory);
    }
    result
}

/// Resolves the exact Windows PID before creating a mutating load request.
fn resolve_windows_target(
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
    let response: HelperResponse = serde_json::from_str(&output.stdout)?;
    if response.schema_version != SCHEMA_VERSION
        || response.request_id != request.request_id
        || response.operation != HelperOperation::QueryProcesses
        || !response.ok
    {
        return Err(Error::HelperExecution(
            "helper process query returned an invalid response".into(),
        ));
    }
    let HelperResult::QueryProcesses(result) = response
        .result
        .ok_or_else(|| Error::HelperExecution("process query returned no result".into()))?
    else {
        return Err(Error::HelperExecution(
            "process query returned the wrong result type".into(),
        ));
    };
    correlate_windows_process(target, architecture, prefix, result.processes)
}

/// Correlates helper process data with the controller's guest executable.
fn correlate_windows_process(
    target: &ProcessInfo,
    architecture: Architecture,
    prefix: &Path,
    processes: Vec<WindowsProcessInfo>,
) -> Result<WindowsProcessInfo> {
    let expected = target
        .guest_executable
        .as_ref()
        .ok_or_else(|| Error::InvalidInput("target guest executable is unknown".into()))?
        .path
        .canonicalize()
        .map_err(|source| Error::io("target guest executable", source))?;
    let expected_architecture = helper_protocol::protocol_architecture(architecture);
    let mut matches: Vec<_> = processes
        .into_iter()
        .filter(|process| process.architecture == expected_architecture)
        .filter(|process| {
            process
                .executable_windows_path
                .as_deref()
                .and_then(|path| wine::windows_path_to_unix(prefix, path).ok())
                .and_then(|path| path.canonicalize().ok())
                .is_some_and(|path| path == expected)
        })
        .collect();
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(Error::HelperExecution(format!(
            "target process disappeared or the helper could not correlate {}",
            expected.display()
        ))),
        count => Err(Error::HelperExecution(format!(
            "{count} Windows processes matched {}; use a more specific target",
            expected.display()
        ))),
    }
}
