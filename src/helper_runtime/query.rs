//! Exact helper-backed module enumeration for one selected Wine process.

use std::fs;

use proton_informer_helper_protocol::{
    HelperOperation, HelperResponse, HelperResult, ModuleQueryResult, SCHEMA_VERSION,
};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::helper_protocol;
use crate::install;
use crate::process::ProcessInfo;
use crate::wine;

use super::invocation::{invocation, select_runtime};
use super::planning::resolve_windows_target;
use super::state::{create_request_directory, write_private_json};

/// Resolves one exact Windows process and returns every loaded module.
///
/// # Errors
///
/// Returns an error when runtime identity, helper discovery, process
/// correlation, request execution, or response validation fails.
pub fn query_modules(target: &ProcessInfo) -> Result<ModuleQueryResult> {
    let architecture = target
        .guest_architecture
        .ok_or_else(|| Error::InvalidInput("target guest architecture is unknown".into()))?;
    let prefix = target
        .wine_prefix
        .as_deref()
        .ok_or_else(|| Error::InvalidInput("target Wine prefix is unknown".into()))?;
    // Module queries execute the same helper and require the same integrity checks
    let helper_path = install::verify_for_target(target)?.helper_path;
    let helper_windows_path = wine::unix_path_to_windows(prefix, &helper_path)?;
    let run_directory = create_request_directory(prefix, &Uuid::new_v4().to_string())?;

    let result = (|| {
        let windows_target = resolve_windows_target(
            target,
            architecture,
            prefix,
            &helper_windows_path,
            &run_directory,
        )?;
        let request = helper_protocol::query_modules_request(
            target,
            &windows_target,
            architecture,
            Uuid::new_v4().to_string(),
        )?;
        let request_path = run_directory.join("module-query.json");
        write_private_json(&request_path, &request)?;
        let request_windows_path = wine::unix_path_to_windows(prefix, &request_path)?;
        let helper_invocation = invocation(
            select_runtime(target)?,
            &helper_windows_path,
            vec!["--request-json".into(), request_windows_path],
        )?;
        let output = crate::helper_executor::execute(&helper_invocation, 20_000)?;
        if output.exit_code != Some(0) {
            return Err(Error::HelperExecution(format!(
                "module query exited {:?}: {}",
                output.exit_code,
                output.stderr.trim()
            )));
        }
        let response: HelperResponse = serde_json::from_str(&output.stdout)?;
        validate_response(&request.request_id, response)
    })();

    // Module queries are diagnostic and do not retain request state
    let _ = fs::remove_dir_all(&run_directory);
    result
}

/// Validates correlation fields before exposing a typed module result.
fn validate_response(request_id: &str, response: HelperResponse) -> Result<ModuleQueryResult> {
    if response.schema_version != SCHEMA_VERSION
        || response.request_id != request_id
        || response.operation != HelperOperation::QueryModules
    {
        return Err(Error::HelperExecution(
            "helper module query returned an invalid response".into(),
        ));
    }
    if !response.ok {
        let detail = response.error.map_or_else(
            || "helper module query failed without an error".into(),
            |error| format!("{}: {}", error.kind, error.message),
        );
        return Err(Error::HelperExecution(detail));
    }
    let HelperResult::QueryModules(result) = response
        .result
        .ok_or_else(|| Error::HelperExecution("module query returned no result".into()))?
    else {
        return Err(Error::HelperExecution(
            "module query returned the wrong result type".into(),
        ));
    };
    Ok(result)
}
