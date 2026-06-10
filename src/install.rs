//! Installed helper integrity and runtime compatibility verification.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use proton_informer_helper_protocol::{HelperVersion, SCHEMA_VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::process::ProcessInfo;
use crate::types::Architecture;

const HASH_BUFFER_BYTES: usize = 16 * 1024;
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Successful helper installation verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallVerification {
    /// Architecture verified on disk.
    pub architecture: Architecture,
    /// SHA-256 recorded in the adjacent release manifest.
    pub helper_sha256: String,
    /// Helper executable that passed local file checks.
    pub helper_path: PathBuf,
    /// Lookup source that selected the helper.
    pub helper_source: HelperLookupSource,
    /// Whether the helper was also executed inside Wine or Proton.
    pub runtime_verified: bool,
    /// Protocol schema reported by a live helper probe.
    pub schema_version: Option<u32>,
    /// Helper semantic version reported by a live helper probe.
    pub version: Option<String>,
    /// Non-fatal verification warnings.
    pub warnings: Vec<String>,
}

/// Source used to select one helper executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperLookupSource {
    /// Selected from `PROTON_INFORMER_HELPER_DIR`.
    EnvironmentOverride,
    /// Selected from packaged or build output directories.
    PackagedSearchPath,
}

impl fmt::Display for HelperLookupSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvironmentOverride => formatter.write_str(crate::helper::HELPER_DIR_ENV),
            Self::PackagedSearchPath => formatter.write_str("packaged search path"),
        }
    }
}

/// Verifies one helper file without requiring a running game.
///
/// # Errors
///
/// Returns an error for unsupported architectures, unsafe permissions, or
/// missing and mismatched release manifests.
pub fn verify_static(architecture: Architecture) -> Result<InstallVerification> {
    if !matches!(architecture, Architecture::X86 | Architecture::X86_64) {
        return Err(Error::InvalidInput(format!(
            "{architecture} has no supported Windows helper"
        )));
    }
    let helper_path = crate::helper::find_wine_helper(architecture).ok_or_else(|| {
        Error::InvalidInput(format!(
            "no permission-safe {architecture} Windows helper is installed"
        ))
    })?;
    if !crate::helper::helper_permissions_are_trusted(&helper_path) {
        return Err(Error::Rejected(format!(
            "helper file or directory is group-writable or world-writable: {}",
            helper_path.display()
        )));
    }
    let helper_sha256 = verify_sha256_manifest(&helper_path)?;
    let helper_source = helper_lookup_source(&helper_path);
    let warnings = helper_source_warnings(helper_source);
    Ok(InstallVerification {
        architecture,
        helper_sha256,
        helper_path,
        helper_source,
        runtime_verified: false,
        schema_version: None,
        version: None,
        warnings,
    })
}

/// Verifies every packaged helper without requiring a running game.
///
/// # Errors
///
/// Returns the first static verification failure.
pub fn verify_all_static() -> Result<Vec<InstallVerification>> {
    [Architecture::X86, Architecture::X86_64]
        .into_iter()
        .map(verify_static)
        .collect()
}

/// Classifies the selected helper path for audit output.
fn helper_lookup_source(helper_path: &Path) -> HelperLookupSource {
    if crate::helper::helper_uses_env_override(helper_path) {
        HelperLookupSource::EnvironmentOverride
    } else {
        HelperLookupSource::PackagedSearchPath
    }
}

/// Builds loud but non-fatal warnings for powerful helper lookup sources.
fn helper_source_warnings(source: HelperLookupSource) -> Vec<String> {
    match source {
        HelperLookupSource::EnvironmentOverride => vec![format!(
            "{} selected this helper; unset it to verify the packaged helper search path",
            crate::helper::HELPER_DIR_ENV
        )],
        HelperLookupSource::PackagedSearchPath => Vec::new(),
    }
}

/// Verifies one helper file and executes its version probe in the target runtime.
///
/// # Errors
///
/// Returns an error for unsafe permissions, missing or mismatched manifests,
/// incompatible helper identity, or runtime execution failure.
pub fn verify_for_target(target: &ProcessInfo) -> Result<InstallVerification> {
    let architecture = target
        .guest_architecture
        .ok_or_else(|| Error::InvalidInput("target guest architecture is unknown".into()))?;
    let mut verification = verify_static(architecture)?;
    let invocation = crate::helper_runtime::diagnostic_invocation_with_helper(
        target,
        &verification.helper_path,
        "--version-json",
    )?;
    let output = crate::helper_executor::execute(&invocation, 10_000)?;
    if output.exit_code != Some(0) {
        return Err(Error::HelperExecution(format!(
            "helper version probe exited {:?}: {}",
            output.exit_code,
            output.stderr.trim()
        )));
    }
    let version: HelperVersion = serde_json::from_str(&output.stdout)?;
    validate_version(&version, architecture)?;
    verification.runtime_verified = true;
    verification.schema_version = Some(version.schema_version);
    verification.version = Some(version.helper_version);
    Ok(verification)
}

/// Verifies an adjacent `<helper>.sha256` release manifest.
///
/// # Errors
///
/// Returns an error when the manifest is absent, malformed, or does not match.
pub fn verify_sha256_manifest(helper_path: &Path) -> Result<String> {
    let mut manifest_name = helper_path.as_os_str().to_os_string();
    manifest_name.push(".sha256");
    let manifest_path = PathBuf::from(manifest_name);
    let manifest = std::fs::read_to_string(&manifest_path)
        .map_err(|source| Error::io(&manifest_path, source))?;
    let expected = manifest
        .split_whitespace()
        .next()
        .filter(|hash| is_sha256(hash))
        .ok_or_else(|| {
            Error::InvalidInput(format!(
                "helper SHA-256 manifest is malformed: {}",
                manifest_path.display()
            ))
        })?;
    let actual = sha256_file(helper_path)?;
    if actual != expected {
        return Err(Error::Rejected(format!(
            "helper SHA-256 does not match {}",
            manifest_path.display()
        )));
    }
    Ok(actual)
}

/// Rejects helpers built for another controller or protocol.
fn validate_version(version: &HelperVersion, architecture: Architecture) -> Result<()> {
    if version.helper_name != "proton-informer-win-helper" {
        return Err(Error::Rejected(format!(
            "unexpected helper identity: {}",
            version.helper_name
        )));
    }
    if version.helper_version != env!("CARGO_PKG_VERSION") {
        return Err(Error::Rejected(format!(
            "helper version {} does not match controller {}",
            version.helper_version,
            env!("CARGO_PKG_VERSION")
        )));
    }
    if version.architecture != crate::helper_protocol::protocol_architecture(architecture) {
        return Err(Error::Rejected(format!(
            "helper architecture {:?} does not match target {architecture}",
            version.architecture
        )));
    }
    if version.schema_version != SCHEMA_VERSION
        || !version.schema_versions.contains(&SCHEMA_VERSION)
    {
        return Err(Error::Rejected(format!(
            "helper does not support protocol schema {SCHEMA_VERSION}"
        )));
    }
    Ok(())
}

/// Hashes one helper with fixed memory use.
fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(|source| Error::io(path, source))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| Error::io(path, source))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(encoded)
}

/// Checks the exact lowercase hexadecimal form used by release manifests.
fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
