//! Runtime selection and no-shell helper command construction

use std::collections::BTreeMap;
use std::env;
use std::path::Path;

use crate::error::{Error, Result};
use crate::helper;
use crate::process::ProcessInfo;
use crate::types::Architecture;
use crate::wine;

use super::model::{HelperInvocation, HelperRuntime};

/// Builds a non-mutating helper diagnostic invocation
///
/// # Errors
///
/// Returns an error when the architecture has no helper, helper discovery
/// fails, or the target runtime identity is incomplete
pub fn diagnostic_invocation(
    target: &ProcessInfo,
    architecture: Architecture,
    flag: &str,
) -> Result<HelperInvocation> {
    let helper_path = helper::find_wine_helper(architecture).ok_or_else(|| {
        Error::InvalidInput(format!("no {architecture} Windows helper is installed"))
    })?;
    diagnostic_invocation_with_helper(target, &helper_path, flag)
}

/// Builds a diagnostic invocation for one already verified helper path
pub(super) fn diagnostic_invocation_with_helper(
    target: &ProcessInfo,
    helper_path: &Path,
    flag: &str,
) -> Result<HelperInvocation> {
    if !matches!(flag, "--version-json" | "--self-test-json") {
        return Err(Error::InvalidInput(
            "unsupported helper diagnostic flag".into(),
        ));
    }
    if !helper_path.is_absolute() {
        return Err(Error::InvalidInput(
            "verified helper path must be absolute".into(),
        ));
    }
    let prefix = target
        .wine_prefix
        .as_deref()
        .ok_or_else(|| Error::InvalidInput("target Wine prefix is unknown".into()))?;
    let helper_windows_path = wine::unix_path_to_windows(prefix, helper_path)?;
    let runtime = select_runtime(target)?;
    invocation(runtime, &helper_windows_path, vec![flag.into()])
}

/// Selects the exact compatibility runtime represented by process evidence
///
/// # Errors
///
/// Returns an error when Proton identity is incomplete, the prefix is unknown,
/// the Proton launcher is missing, or no plain Wine command is available
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

/// Creates command fields without shell concatenation
pub(super) fn invocation(
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

/// Returns the minimum host environment required to launch Wine or Proton
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

/// Converts one path into a command-safe UTF-8 value
fn path_text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::InvalidInput(format!("path is not valid UTF-8: {}", path.display())))
}

/// Returns whether the current helper implementation supports an architecture
#[must_use]
pub const fn helper_architecture_supported(architecture: Architecture) -> bool {
    matches!(architecture, Architecture::X86 | Architecture::X86_64)
}
