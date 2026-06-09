//! Linux-side construction of shared helper requests.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::binary::BinaryInspection;
use crate::error::{Error, Result};
use crate::process::ProcessInfo;
use crate::types::Architecture;
use crate::wine;
use proton_informer_helper_protocol::{
    HelperOperation, HelperOptions, HelperPayload, HelperRequest, HelperTarget,
    ProtocolArchitecture, SCHEMA_VERSION, TargetSelector,
};
use sha2::{Digest, Sha256};

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Builds a validated load request from inspected controller data.
///
/// # Errors
///
/// Returns an error when target identity, prefix mappings, payload hashing, or
/// shared protocol validation fails.
pub fn load_request(
    payload: &BinaryInspection,
    target: &ProcessInfo,
    timeout_ms: u64,
    request_id: String,
) -> Result<HelperRequest> {
    if payload.architecture == Architecture::Unknown {
        return Err(Error::InvalidInput(
            "payload architecture must be known before helper planning".into(),
        ));
    }

    let prefix = target
        .wine_prefix
        .as_deref()
        .ok_or_else(|| Error::InvalidInput("target Wine prefix is unknown".into()))?;
    let payload_windows_path = wine::unix_path_to_windows(prefix, &payload.path)?;
    let expected_process_name = target_process_name(target)?;
    let expected_executable_windows_path = target
        .guest_executable
        .as_ref()
        .map(|candidate| wine::unix_path_to_windows(prefix, &candidate.path))
        .transpose()?
        .ok_or_else(|| {
            Error::InvalidInput(
                "guest executable path is required for safe helper target selection".into(),
            )
        })?;

    let request = HelperRequest {
        operation: HelperOperation::LoadLibrary,
        options: HelperOptions {
            timeout_ms,
            verify_module_after_load: true,
        },
        payload: Some(HelperPayload {
            sha256: sha256_file(&payload.path, payload.size_bytes)?,
            size_bytes: payload.size_bytes,
            windows_path: payload_windows_path,
        }),
        request_id,
        schema_version: SCHEMA_VERSION,
        target: Some(HelperTarget {
            expected_architecture: protocol_architecture(payload.architecture),
            expected_executable_windows_path: Some(expected_executable_windows_path),
            expected_process_name,
            selector: TargetSelector::ByProcessNameAndExecutablePath,
        }),
    };
    request
        .validate()
        .map_err(|error| Error::InvalidInput(error.to_string()))?;
    Ok(request)
}

/// Maps controller architecture values into the stable helper protocol.
#[must_use]
pub const fn protocol_architecture(architecture: Architecture) -> ProtocolArchitecture {
    match architecture {
        Architecture::Aarch64 => ProtocolArchitecture::Aarch64,
        Architecture::Arm => ProtocolArchitecture::Arm,
        Architecture::Unknown => ProtocolArchitecture::Unknown,
        Architecture::X86 => ProtocolArchitecture::X86,
        Architecture::X86_64 => ProtocolArchitecture::X86_64,
    }
}

/// Chooses the strongest available process basename.
fn target_process_name(target: &ProcessInfo) -> Result<String> {
    let name = target
        .guest_executable
        .as_ref()
        .and_then(|candidate| candidate.path.file_name())
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            Error::InvalidInput(
                "guest executable path is required for safe helper target selection".into(),
            )
        })?
        .trim();
    if name.is_empty() || name.contains(['/', '\\']) {
        return Err(Error::InvalidInput(
            "target process name is not a valid Windows basename".into(),
        ));
    }
    Ok(name.to_owned())
}

/// Hashes exactly the inspected payload size with fixed-size buffered reads.
fn sha256_file(path: &Path, expected_size: u64) -> Result<String> {
    let mut file = File::open(path).map_err(|source| Error::io(path, source))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    let mut total_bytes = 0_u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| Error::io(path, source))?;
        if count == 0 {
            break;
        }
        total_bytes = total_bytes
            .checked_add(u64::try_from(count).map_err(|_| {
                Error::InvalidInput("payload read count does not fit in u64".into())
            })?)
            .ok_or_else(|| Error::InvalidInput("payload size overflowed u64".into()))?;
        if total_bytes > expected_size {
            return Err(Error::InvalidInput(format!(
                "payload changed after inspection: expected {expected_size} bytes, read more"
            )));
        }
        hasher.update(&buffer[..count]);
    }
    if total_bytes != expected_size {
        return Err(Error::InvalidInput(format!(
            "payload changed after inspection: expected {expected_size} bytes, read {total_bytes}"
        )));
    }

    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(encoded)
}
