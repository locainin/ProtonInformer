//! Shared protocol dispatch and JSON file handling.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use proton_informer_helper_protocol::{
    HelperCapability, HelperOperation, HelperRequest, HelperResponse, HelperResult, HelperVersion,
    MAX_REQUEST_SIZE_BYTES, ProtocolArchitecture, SCHEMA_VERSION,
};
use serde::Serialize;

use crate::error::HelperFailure;

/// Returns helper identity without touching another process.
pub fn version() -> HelperVersion {
    HelperVersion {
        architecture: helper_architecture(),
        capabilities: capabilities(),
        helper_name: "proton-informer-win-helper".into(),
        helper_version: env!("CARGO_PKG_VERSION").into(),
        schema_version: SCHEMA_VERSION,
        schema_versions: vec![SCHEMA_VERSION],
    }
}

/// Reports only operations implemented by this platform build.
#[cfg(windows)]
fn capabilities() -> Vec<HelperCapability> {
    vec![
        HelperCapability::Version,
        HelperCapability::SelfTest,
        HelperCapability::QueryProcesses,
        HelperCapability::QueryModules,
        HelperCapability::LoadLibrary,
    ]
}

/// Reports only non-mutating smoke checks for a host-native build.
#[cfg(not(windows))]
fn capabilities() -> Vec<HelperCapability> {
    vec![HelperCapability::Version, HelperCapability::SelfTest]
}

/// Reads, validates, executes, and responds to one request file.
pub fn run_request_file(path: &Path) -> Result<(), HelperFailure> {
    let bytes = match read_request(path) {
        Ok(bytes) => bytes,
        Err(error) => return write_json(&parse_failure_response(&error)),
    };
    let request: HelperRequest = match serde_json::from_slice(&bytes) {
        Ok(request) => request,
        Err(error) => {
            return write_json(&parse_failure_response(
                &HelperFailure::ProtocolParseFailed(error.to_string()),
            ));
        }
    };
    let response = match request.validate() {
        Ok(()) => dispatch(&request),
        Err(error) => Err(HelperFailure::Validation(error.to_string())),
    }
    .map_or_else(
        |error| failure_response(&request, &error),
        |result| success_response(&request, result),
    );
    write_json(&response)
}

/// Reads at most one byte beyond the request size ceiling.
fn read_request(path: &Path) -> Result<Vec<u8>, HelperFailure> {
    let mut file = File::open(path).map_err(|source| {
        HelperFailure::io(format!("unable to open {}", path.display()), source)
    })?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_REQUEST_SIZE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| {
            HelperFailure::io(format!("unable to read {}", path.display()), source)
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_REQUEST_SIZE_BYTES {
        return Err(HelperFailure::ProtocolParseFailed(format!(
            "request exceeds the {MAX_REQUEST_SIZE_BYTES}-byte limit"
        )));
    }
    Ok(bytes)
}

/// Writes one JSON document to standard output.
pub fn write_json<T: Serialize>(value: &T) -> Result<(), HelperFailure> {
    let output = serde_json::to_vec_pretty(value)?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&output)
        .and_then(|()| stdout.write_all(b"\n"))
        .map_err(|source| HelperFailure::io("unable to write standard output", source))
}

/// Executes one semantically valid request.
fn dispatch(request: &HelperRequest) -> Result<HelperResult, HelperFailure> {
    match request.operation {
        HelperOperation::QueryProcesses => Ok(HelperResult::QueryProcesses(
            crate::process::query_processes()?,
        )),
        HelperOperation::QueryModules => {
            let target = request
                .target
                .as_ref()
                .ok_or_else(|| HelperFailure::Validation("query_modules requires target".into()))?;
            Ok(HelperResult::QueryModules(crate::modules::query(target)?))
        }
        HelperOperation::LoadLibrary => {
            let target = request
                .target
                .as_ref()
                .ok_or_else(|| HelperFailure::Validation("load_library requires target".into()))?;
            let payload = request
                .payload
                .as_ref()
                .ok_or_else(|| HelperFailure::Validation("load_library requires payload".into()))?;
            Ok(HelperResult::LoadLibrary(crate::load::run(
                target,
                payload,
                &request.options,
            )?))
        }
        HelperOperation::Unknown => Err(HelperFailure::Validation(
            "unknown operation cannot be dispatched".into(),
        )),
    }
}

/// Constructs a protocol-shaped response when no request identity is recoverable.
fn parse_failure_response(error: &HelperFailure) -> HelperResponse {
    HelperResponse {
        error: Some(error.to_protocol_error()),
        ok: false,
        operation: HelperOperation::Unknown,
        request_id: "unknown".into(),
        result: None,
        schema_version: SCHEMA_VERSION,
        warnings: Vec::new(),
    }
}

/// Constructs a successful response.
fn success_response(request: &HelperRequest, result: HelperResult) -> HelperResponse {
    HelperResponse {
        error: None,
        ok: true,
        operation: request.operation,
        request_id: request.request_id.clone(),
        result: Some(result),
        schema_version: SCHEMA_VERSION,
        warnings: Vec::new(),
    }
}

/// Constructs a failed response while retaining request correlation.
fn failure_response(request: &HelperRequest, error: &HelperFailure) -> HelperResponse {
    HelperResponse {
        error: Some(error.to_protocol_error()),
        ok: false,
        operation: request.operation,
        request_id: request.request_id.clone(),
        result: None,
        schema_version: SCHEMA_VERSION,
        warnings: Vec::new(),
    }
}

/// Returns the compile-time helper architecture.
const fn helper_architecture() -> ProtocolArchitecture {
    #[cfg(target_arch = "x86_64")]
    {
        ProtocolArchitecture::X86_64
    }
    #[cfg(target_arch = "x86")]
    {
        ProtocolArchitecture::X86
    }
    #[cfg(target_arch = "aarch64")]
    {
        ProtocolArchitecture::Aarch64
    }
    #[cfg(target_arch = "arm")]
    {
        ProtocolArchitecture::Arm
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm"
    )))]
    {
        ProtocolArchitecture::Unknown
    }
}
