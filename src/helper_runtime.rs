//! Typed helper runtime selection, secure request files, and dry-run planning.

use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use proton_informer_helper_protocol::{
    HelperOperation, HelperRequest, HelperResponse, HelperResult, SCHEMA_VERSION,
    WindowsProcessInfo,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::binary::BinaryInspection;
use crate::error::{Error, Result};
use crate::helper;
use crate::helper_protocol;
use crate::process::ProcessInfo;
use crate::types::Architecture;
use crate::wine;

/// Runtime used to execute the Windows helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum HelperRuntime {
    /// Steam Proton invocation with target identity variables.
    Proton {
        /// Steam application identifier.
        app_id: u32,
        /// Steam compatdata directory.
        compatdata_dir: PathBuf,
        /// Proton launcher script.
        proton_path: PathBuf,
        /// Steam client root.
        steam_client_path: PathBuf,
    },
    /// Plain Wine invocation.
    Wine {
        /// Existing Wine prefix.
        prefix: PathBuf,
        /// Wine executable.
        wine_binary: PathBuf,
    },
}

/// Exact executable, arguments, and environment for one helper run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperInvocation {
    /// Helper command arguments.
    pub arguments: Vec<String>,
    /// Environment variables required by the runtime.
    pub environment: BTreeMap<String, String>,
    /// Program launched by the controller.
    pub program: PathBuf,
    /// Runtime classification.
    pub runtime: HelperRuntime,
}

/// Persisted dry-run artifacts and typed invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadDryRunPlan {
    /// Windows helper path visible inside the selected prefix.
    pub helper_windows_path: String,
    /// Exact helper invocation.
    pub invocation: HelperInvocation,
    /// Validated request body.
    pub request: HelperRequest,
    /// Host request path.
    pub request_host_path: PathBuf,
    /// Windows request path visible inside the prefix.
    pub request_windows_path: String,
    /// Per-request state directory.
    pub run_directory: PathBuf,
    /// Private staged payload used for helper validation and loading.
    pub staged_payload_host_path: PathBuf,
}

/// Builds a non-mutating helper diagnostic invocation.
///
/// # Errors
///
/// Returns an error when the architecture has no helper, helper discovery
/// fails, or the target runtime identity is incomplete.
pub fn diagnostic_invocation(
    target: &ProcessInfo,
    architecture: Architecture,
    flag: &str,
) -> Result<HelperInvocation> {
    if !matches!(flag, "--version-json" | "--self-test-json") {
        return Err(Error::InvalidInput(
            "unsupported helper diagnostic flag".into(),
        ));
    }
    let helper_path = helper::find_wine_helper(architecture).ok_or_else(|| {
        Error::InvalidInput(format!("no {architecture} Windows helper is installed"))
    })?;
    let prefix = target
        .wine_prefix
        .as_deref()
        .ok_or_else(|| Error::InvalidInput("target Wine prefix is unknown".into()))?;
    let helper_windows_path = wine::unix_path_to_windows(prefix, &helper_path)?;
    let runtime = select_runtime(target)?;
    invocation(runtime, &helper_windows_path, vec![flag.into()])
}

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

/// Selects the exact compatibility runtime represented by process evidence.
///
/// # Errors
///
/// Returns an error when Proton identity is incomplete, the prefix is unknown,
/// the Proton launcher is missing, or no plain Wine command is available.
pub fn select_runtime(target: &ProcessInfo) -> Result<HelperRuntime> {
    let proton_identity_present = target.compatdata_dir.is_some()
        || target.proton_dist.is_some()
        || target.steam_app_id.is_some()
        || target.steam_client_path.is_some();
    if let (Some(proton_dist), Some(compatdata_dir), Some(steam_client_path), Some(app_id)) = (
        target.proton_dist.as_deref(),
        target.compatdata_dir.as_ref(),
        target.steam_client_path.as_ref(),
        target.steam_app_id,
    ) {
        let proton_path = if proton_dist.is_dir() {
            proton_dist.join("proton")
        } else {
            proton_dist.to_path_buf()
        };
        if !proton_path.is_file() {
            return Err(Error::InvalidInput(format!(
                "discovered Proton launcher does not exist: {}",
                proton_path.display()
            )));
        }
        return Ok(HelperRuntime::Proton {
            app_id,
            compatdata_dir: compatdata_dir.clone(),
            proton_path,
            steam_client_path: steam_client_path.clone(),
        });
    }
    if proton_identity_present {
        let mut missing = Vec::new();
        if target.proton_dist.is_none() {
            missing.push("proton_dist");
        }
        if target.compatdata_dir.is_none() {
            missing.push("compatdata_dir");
        }
        if target.steam_client_path.is_none() {
            missing.push("steam_client_path");
        }
        if target.steam_app_id.is_none() {
            missing.push("steam_app_id");
        }
        return Err(Error::InvalidInput(format!(
            "Proton target identity is incomplete; missing {}",
            missing.join(", ")
        )));
    }

    let prefix = target
        .wine_prefix
        .clone()
        .ok_or_else(|| Error::InvalidInput("target Wine prefix is unknown".into()))?;
    let wine_binary = helper::find_command("wine64")
        .or_else(|| helper::find_command("wine"))
        .ok_or_else(|| {
            Error::InvalidInput("wine or wine64 is not available through PATH".into())
        })?;
    Ok(HelperRuntime::Wine {
        prefix,
        wine_binary,
    })
}

/// Creates command fields without shell concatenation.
fn invocation(
    runtime: HelperRuntime,
    helper_windows_path: &str,
    helper_arguments: Vec<String>,
) -> Result<HelperInvocation> {
    let mut arguments = Vec::with_capacity(helper_arguments.len() + 1);
    arguments.push(helper_windows_path.to_owned());
    arguments.extend(helper_arguments);
    let (program, environment, arguments) = match &runtime {
        HelperRuntime::Proton {
            app_id,
            compatdata_dir,
            proton_path,
            steam_client_path,
        } => {
            let mut environment = base_environment()?;
            environment.insert("STEAM_COMPAT_DATA_PATH".into(), path_text(compatdata_dir)?);
            environment.insert(
                "STEAM_COMPAT_CLIENT_INSTALL_PATH".into(),
                path_text(steam_client_path)?,
            );
            environment.insert("SteamAppId".into(), app_id.to_string());
            environment.insert("SteamGameId".into(), app_id.to_string());
            // `runinprefix` invokes Proton's Wine binary without adding the
            // game-launch command path or waiting for the game to exit
            let mut proton_arguments = vec!["runinprefix".into()];
            proton_arguments.extend(arguments);
            (proton_path.clone(), environment, proton_arguments)
        }
        HelperRuntime::Wine {
            prefix,
            wine_binary,
        } => {
            let mut environment = base_environment()?;
            environment.insert("WINEPREFIX".into(), path_text(prefix)?);
            (wine_binary.clone(), environment, arguments)
        }
    };
    Ok(HelperInvocation {
        arguments,
        environment,
        program,
        runtime,
    })
}

/// Returns the minimum host environment required to launch Wine or Proton.
fn base_environment() -> Result<BTreeMap<String, String>> {
    let mut environment = BTreeMap::new();
    let home = env::var_os("HOME").ok_or_else(|| Error::InvalidInput("HOME is not set".into()))?;
    environment.insert(
        "HOME".into(),
        home.into_string()
            .map_err(|_| Error::InvalidInput("HOME is not valid UTF-8".into()))?,
    );
    // Proton uses `/usr/bin/env` in its launcher, so retain only system command
    // directories instead of inheriting user-controlled PATH entries
    environment.insert(
        "PATH".into(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
    );
    Ok(environment)
}

/// Copies one inspected payload into owner-only request state.
fn stage_payload(payload: &BinaryInspection, run_directory: &Path) -> Result<BinaryInspection> {
    let file_name = payload.path.file_name().ok_or_else(|| {
        Error::InvalidInput(format!(
            "payload path has no file name: {}",
            payload.path.display()
        ))
    })?;
    let staged_path = run_directory.join(file_name);
    let mut source = File::open(&payload.path).map_err(|error| Error::io(&payload.path, error))?;
    let source_before = source
        .metadata()
        .map_err(|error| Error::io(&payload.path, error))?;
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged_path)
        .map_err(|error| Error::io(&staged_path, error))?;
    let mut buffer = [0_u8; 16 * 1024];
    let mut copied = 0_u64;
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|error| Error::io(&payload.path, error))?;
        if count == 0 {
            break;
        }
        copied =
            copied
                .checked_add(u64::try_from(count).map_err(|_| {
                    Error::InvalidInput("payload read count does not fit u64".into())
                })?)
                .ok_or_else(|| Error::InvalidInput("payload size overflowed u64".into()))?;
        if copied > payload.size_bytes {
            return Err(Error::InvalidInput(
                "payload grew while it was being staged".into(),
            ));
        }
        destination
            .write_all(&buffer[..count])
            .map_err(|error| Error::io(&staged_path, error))?;
    }
    if copied != payload.size_bytes {
        return Err(Error::InvalidInput(format!(
            "payload changed while staging: expected {} bytes, copied {copied}",
            payload.size_bytes
        )));
    }
    let source_after = source
        .metadata()
        .map_err(|error| Error::io(&payload.path, error))?;
    if !same_file_snapshot(&source_before, &source_after) {
        return Err(Error::InvalidInput(
            "payload metadata changed while staging".into(),
        ));
    }
    destination
        .sync_all()
        .map_err(|error| Error::io(&staged_path, error))?;
    let staged = crate::binary::inspect(&staged_path)?;
    if staged.format != payload.format || staged.architecture != payload.architecture {
        return Err(Error::InvalidInput(
            "staged payload headers differ from the inspected source".into(),
        ));
    }
    Ok(staged)
}

/// Compares stable Linux file identity and change indicators around one copy.
fn same_file_snapshot(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

/// Creates one owner-only run directory.
/// Creates a request directory visible through the selected prefix mappings.
///
/// # Errors
///
/// Returns an error for invalid request identifiers, filesystem failures, or
/// prefixes with neither a mapped state directory nor a configured C: drive.
pub fn create_request_directory(prefix: &Path, request_id: &str) -> Result<PathBuf> {
    Uuid::parse_str(request_id)
        .map_err(|error| Error::InvalidInput(format!("invalid request UUID: {error}")))?;
    let primary_root = state_directory();
    let primary = create_owner_directory(&primary_root, request_id)?;
    if wine::unix_path_to_windows(prefix, &primary).is_ok() {
        return Ok(primary);
    }
    let _ = fs::remove_dir(&primary);

    // A configured C: mapping is a prefix-local fallback when no drive exposes
    // the Linux state directory
    let c_root = wine::drive_mappings(prefix)?
        .into_iter()
        .find_map(|(drive, root)| (drive == 'c').then_some(root))
        .ok_or_else(|| {
            Error::InvalidInput(
                "neither the state directory nor a configured C: drive is available to Wine".into(),
            )
        })?;
    create_owner_directory(&c_root.join(".proton-informer"), request_id)
}

/// Creates owner-only root, runs, and request directory levels.
fn create_owner_directory(root: &Path, request_id: &str) -> Result<PathBuf> {
    let runs = root.join("runs");
    let directory = runs.join(request_id);
    for path in [root, runs.as_path(), directory.as_path()] {
        fs::create_dir_all(path).map_err(|source| Error::io(path, source))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|source| Error::io(path, source))?;
    }
    Ok(directory)
}

/// Writes one owner-only JSON file without following a pre-existing file.
fn write_private_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(Error::from)?;
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

/// Returns the state root without assuming one user's home path.
fn state_directory() -> PathBuf {
    env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .unwrap_or_else(env::temp_dir)
        .join("proton-informer")
}

/// Converts one path into a command-safe UTF-8 value.
fn path_text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::InvalidInput(format!("path is not valid UTF-8: {}", path.display())))
}

/// Returns whether the current helper implementation supports an architecture.
#[must_use]
pub const fn helper_architecture_supported(architecture: Architecture) -> bool {
    matches!(architecture, Architecture::X86 | Architecture::X86_64)
}
