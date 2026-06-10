
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::binary::{BinaryFormat, BinaryInspection};
use crate::doctor::CheckStatus;
use crate::error::{Error, Result};
use crate::helper;
use crate::helper_runtime::{self, HelperRuntime};
use crate::process::{ClassificationConfidence, ProcessInfo, TargetKind};
use crate::types::Architecture;
use crate::wine;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    WinePeHelper,
    WineDllOverride,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequirementCheck {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadPlan {
    pub payload: BinaryInspection,
    pub target: ProcessInfo,
    pub target_architecture: Architecture,
    pub backend: Backend,
    pub requirements: Vec<RequirementCheck>,
    pub executable_now: bool,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverridePlan {
    pub payload: BinaryInspection,
    pub app_id: Option<u32>,
    pub prefix: PathBuf,
    pub dll_name: String,
    pub payload_windows_path: String,
    pub backend: Backend,
    pub launch_option: String,
    pub files_modified: bool,
    pub placement: OverridePlacement,
    pub placement_note: String,
}

/// File-placement state required before a Wine DLL override can work
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum OverridePlacement {
    /// The planner does not know the target application's DLL search path
    InstructionsOnly,
}

/// Plans a helper-backed load for an already running process
///
/// # Errors
///
/// Returns an error when format, architecture, or target compatibility checks
/// reject the requested plan
pub fn plan_running(
    payload: BinaryInspection,
    target: ProcessInfo,
    architecture_override: Option<Architecture>,
) -> Result<LoadPlan> {
    if !payload.is_loadable_payload() {
        return Err(reject(
            &payload,
            &target,
            "selected binary is not a loadable DLL or shared object",
        ));
    }

    // Wine guest architecture must never inherit the Linux host loader's value
    let target_architecture =
        resolve_target_architecture(&payload, &target, architecture_override)?;
    if payload.architecture == Architecture::Unknown {
        return Err(reject(
            &payload,
            &target,
            "payload architecture is unsupported or unknown",
        ));
    }
    if payload.architecture != target_architecture {
        return Err(reject(
            &payload,
            &target,
            &format!(
                "payload architecture {} does not match target architecture {}",
                payload.architecture, target_architecture
            ),
        ));
    }

    let backend = match (payload.format, target.target_kind) {
        (BinaryFormat::PeDll, TargetKind::WineProtonWindows) => Backend::WinePeHelper,
        (BinaryFormat::ElfSharedObject, TargetKind::NativeLinux) => {
            return Err(reject(
                &payload,
                &target,
                "native ELF loading is outside this tool's supported scope",
            ));
        }
        (BinaryFormat::PeDll, TargetKind::NativeLinux) => {
            return Err(reject(
                &payload,
                &target,
                "Windows DLLs cannot be loaded by the native Linux ELF loader",
            ));
        }
        (BinaryFormat::ElfSharedObject, TargetKind::WineProtonWindows) => {
            return Err(reject(
                &payload,
                &target,
                "ELF shared objects cannot be loaded by the Wine PE loader",
            ));
        }
        _ => unreachable!("non-loadable payloads were rejected above"),
    };

    let requirements = running_requirements(&payload, &target, target_architecture, backend);
    let no_failed_requirements = requirements
        .iter()
        .all(|check| check.status != CheckStatus::Failed);
    let all_requirements_passed = requirements
        .iter()
        .all(|check| check.status == CheckStatus::Passed);

    let executor_implemented = backend == Backend::WinePeHelper;
    Ok(LoadPlan {
        payload,
        target,
        target_architecture,
        backend,
        requirements,
        executable_now: all_requirements_passed && executor_implemented,
        note: if all_requirements_passed && executor_implemented {
            "all requirements pass; helper execution is available with explicit confirmation".into()
        } else if all_requirements_passed {
            "all requirements pass, but this backend has no executor".into()
        } else if no_failed_requirements {
            "required checks passed with warnings".into()
        } else {
            "one or more required helper conditions failed".into()
        },
    })
}

/// Reconciles explicit architecture input with discovered target evidence
fn resolve_target_architecture(
    payload: &BinaryInspection,
    target: &ProcessInfo,
    architecture_override: Option<Architecture>,
) -> Result<Architecture> {
    if let (Some(override_architecture), Some(discovered_architecture)) =
        (architecture_override, target.guest_architecture)
        && target.target_kind == TargetKind::WineProtonWindows
        && override_architecture != discovered_architecture
    {
        return Err(reject(
            payload,
            target,
            &format!(
                "explicit target architecture {override_architecture} contradicts discovered \
                 guest architecture {discovered_architecture}"
            ),
        ));
    }

    let architecture = match target.target_kind {
        TargetKind::NativeLinux => architecture_override.unwrap_or(target.host_architecture),
        TargetKind::WineProtonWindows => architecture_override
            .or(target.guest_architecture)
            .unwrap_or(Architecture::Unknown),
    };
    if architecture == Architecture::Unknown {
        return Err(reject(
            payload,
            target,
            "target architecture is unknown; provide --target-arch",
        ));
    }
    Ok(architecture)
}

/// Plans Wine startup DLL override behavior without requiring a running PID
///
/// # Errors
///
/// Returns an error when the payload is not a PE DLL, the prefix is missing,
/// the override name is invalid, or the payload has no configured drive path
pub fn plan_override(
    payload: BinaryInspection,
    prefix: &Path,
    app_id: Option<u32>,
    dll_name: &str,
) -> Result<OverridePlan> {
    if payload.format != BinaryFormat::PeDll {
        return Err(Error::Rejected(format!(
            "startup override requires a PE DLL, detected {}",
            payload.format
        )));
    }
    if !prefix.is_dir() {
        return Err(Error::InvalidInput(format!(
            "Wine prefix does not exist: {}",
            prefix.display()
        )));
    }

    let dll_name = normalize_dll_name(dll_name)?;
    let payload_windows_path = wine::unix_path_to_windows(prefix, &payload.path)?;

    Ok(OverridePlan {
        payload,
        app_id,
        prefix: prefix.to_path_buf(),
        launch_option: format!("WINEDLLOVERRIDES=\"{dll_name}=n,b\" %command%"),
        dll_name,
        payload_windows_path,
        backend: Backend::WineDllOverride,
        files_modified: false,
        placement: OverridePlacement::InstructionsOnly,
        placement_note: "launch options only select native versus builtin DLL resolution; place \
                         the payload in the application's DLL search path under the planned name"
            .into(),
    })
}

fn running_requirements(
    payload: &BinaryInspection,
    target: &ProcessInfo,
    target_architecture: Architecture,
    backend: Backend,
) -> Vec<RequirementCheck> {
    let mut checks = Vec::new();

    checks.push(requirement(
        "same_user",
        target.owned_by_current_user == Some(true),
        "target belongs to the current user",
        "target ownership is different or could not be proven",
    ));
    checks.push(RequirementCheck {
        name: "classification_confidence".into(),
        status: match target.classification_confidence {
            ClassificationConfidence::High => CheckStatus::Passed,
            ClassificationConfidence::Medium => CheckStatus::Warning,
            ClassificationConfidence::Low => CheckStatus::Failed,
        },
        detail: format!("{:?}", target.classification_confidence),
    });

    if backend == Backend::WinePeHelper {
        checks.push(requirement(
            "wine_prefix",
            target.wine_prefix.as_deref().is_some_and(Path::is_dir),
            "target Wine prefix is known",
            "target Wine prefix is missing",
        ));

        let helper_check = helper::find_wine_helper(target_architecture).map_or_else(
            || RequirementCheck {
                name: "wine_helper".into(),
                status: CheckStatus::Failed,
                detail: "matching helper is not installed".into(),
            },
            |path| match crate::binary::inspect(&path) {
                Ok(inspection)
                    if inspection.format == BinaryFormat::PeExecutable
                        && inspection.architecture == target_architecture =>
                {
                    RequirementCheck {
                        name: "wine_helper".into(),
                        status: CheckStatus::Passed,
                        detail: path.display().to_string(),
                    }
                }
                Ok(inspection) => RequirementCheck {
                    name: "wine_helper".into(),
                    status: CheckStatus::Failed,
                    detail: format!(
                        "{} is {} {}, expected {} PE executable",
                        path.display(),
                        inspection.architecture,
                        inspection.format,
                        target_architecture
                    ),
                },
                Err(error) => RequirementCheck {
                    name: "wine_helper".into(),
                    status: CheckStatus::Failed,
                    detail: error.to_string(),
                },
            },
        );
        checks.push(helper_check);

        checks.push(helper_runtime::select_runtime(target).map_or_else(
            |error| RequirementCheck {
                name: "wine_runtime".into(),
                status: CheckStatus::Failed,
                detail: error.to_string(),
            },
            |runtime| RequirementCheck {
                name: "wine_runtime".into(),
                status: CheckStatus::Passed,
                detail: match runtime {
                    HelperRuntime::Proton { proton_path, .. } => {
                        format!("Proton launcher: {}", proton_path.display())
                    }
                    HelperRuntime::Wine { wine_binary, .. } => {
                        format!("Wine command: {}", wine_binary.display())
                    }
                },
            },
        ));

        let conversion = target
            .wine_prefix
            .as_deref()
            .map(|prefix| wine::unix_path_to_windows(prefix, &payload.path));
        checks.push(RequirementCheck {
            name: "payload_windows_path".into(),
            status: if conversion.as_ref().is_some_and(Result::is_ok) {
                CheckStatus::Passed
            } else {
                CheckStatus::Failed
            },
            detail: conversion
                .and_then(Result::ok)
                .unwrap_or_else(|| "payload is outside configured Wine drives".into()),
        });
    }

    checks
}

fn normalize_dll_name(value: &str) -> Result<String> {
    let without_extension = value
        .strip_suffix(".dll")
        .or_else(|| value.strip_suffix(".DLL"))
        .unwrap_or(value);
    if without_extension.is_empty()
        || !without_extension
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(Error::InvalidInput(
            "DLL override name must contain only letters, digits, '-' or '_'".into(),
        ));
    }
    Ok(without_extension.to_ascii_lowercase())
}

fn requirement(name: &str, passed: bool, success: &str, failure: &str) -> RequirementCheck {
    RequirementCheck {
        name: name.into(),
        status: if passed {
            CheckStatus::Passed
        } else {
            CheckStatus::Failed
        },
        detail: if passed {
            success.into()
        } else {
            failure.into()
        },
    }
}

fn reject(payload: &BinaryInspection, target: &ProcessInfo, reason: &str) -> Error {
    Error::Rejected(format!(
        "\n  selected file: {}\n  detected: {} {}\n  target: {:?} process {} ({})\n  reason: {reason}",
        payload.path.display(),
        payload.architecture,
        payload.format,
        target.target_kind,
        target.pid,
        target.name
    ))
}
