//! Controller-side execution and validation of helper load responses

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use proton_informer_helper_protocol::{
    HelperOperation, HelperResponse, HelperResult, SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::helper_executor;
use crate::helper_runtime::{LoadDryRunPlan, parse_helper_response};

const HELPER_STARTUP_GRACE_MS: u64 = 10_000;

/// Verified helper response and persisted audit artifact
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadExecutionResult {
    /// Typed helper response
    pub response: HelperResponse,
    /// Owner-only response JSON retained beside the request
    pub response_host_path: PathBuf,
}

/// Executes one prepared load plan and validates its correlated response
///
/// # Errors
///
/// Returns an error for process failure, malformed or mismatched JSON, helper
/// rejection, missing module verification, or audit-file write failure
pub fn execute(plan: &LoadDryRunPlan, keep_run_files: bool) -> Result<LoadExecutionResult> {
    let execution_timeout = plan
        .request
        .options
        .timeout_ms
        .checked_add(HELPER_STARTUP_GRACE_MS)
        .ok_or_else(|| Error::InvalidInput("helper execution timeout overflowed".into()))?;
    let output = helper_executor::execute_in_directory(
        &plan.invocation,
        execution_timeout,
        &plan.run_directory,
        keep_run_files,
    )?;
    if output.exit_code != Some(0) {
        return Err(Error::HelperExecution(format!(
            "exit {:?}: {}",
            output.exit_code,
            output.stderr.trim()
        )));
    }
    let response = parse_helper_response(&output)?;
    validate_response(plan, &response)?;

    let response_host_path = plan.run_directory.join("response.json");
    write_private_json(&response_host_path, &response)?;
    Ok(LoadExecutionResult {
        response,
        response_host_path,
    })
}

/// Rejects stale, unrelated, unsuccessful, or unverified helper responses
fn validate_response(plan: &LoadDryRunPlan, response: &HelperResponse) -> Result<()> {
    if response.schema_version != SCHEMA_VERSION
        || response.request_id != plan.request.request_id
        || response.operation != HelperOperation::LoadLibrary
    {
        return Err(Error::HelperExecution(
            "helper response does not match the submitted request".into(),
        ));
    }
    if !response.ok {
        let error = response.error.as_ref().ok_or_else(|| {
            Error::HelperExecution("helper returned failure without an error body".into())
        })?;
        return Err(Error::HelperRejected {
            kind: error.kind.clone(),
            message: error.message.clone(),
            windows_error: error.windows_error,
        });
    }
    match response.result.as_ref() {
        Some(HelperResult::LoadLibrary(result)) if result.module_verified => Ok(()),
        Some(HelperResult::LoadLibrary(_)) => Err(Error::HelperExecution(
            "helper did not verify the loaded module".into(),
        )),
        _ => Err(Error::HelperExecution(
            "helper returned an unexpected result type".into(),
        )),
    }
}

/// Persists one owner-only response without replacing existing audit data
fn write_private_json<T: Serialize>(path: &std::path::Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| Error::io(path, source))?;
    file.write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|source| Error::io(path, source))
}
