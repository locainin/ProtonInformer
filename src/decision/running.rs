//! Running-process load planning and helper readiness checks

use std::path::Path;

use crate::binary::{BinaryFormat, BinaryInspection};
use crate::doctor::CheckStatus;
use crate::error::{Error, Result};
use crate::helper;
use crate::helper_runtime::{self, HelperRuntime, PayloadPathMode};
use crate::process::{ClassificationConfidence, ProcessInfo, TargetKind};
use crate::types::Architecture;
use crate::wine;

use super::model::{Backend, LoadPlan, RequirementCheck};

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
    payload_path_mode: PayloadPathMode,
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

    let backend = select_backend(&payload, &target)?;
    let requirements = running_requirements(
        &payload,
        &target,
        target_architecture,
        backend,
        payload_path_mode,
    );
    let no_failed_requirements = requirements
        .iter()
        .all(|check| check.status != CheckStatus::Failed);
    let all_requirements_passed = requirements
        .iter()
        .all(|check| check.status == CheckStatus::Passed);

    // Only PE DLL helper loading has an executor today
    let executor_implemented = backend == Backend::WinePeHelper;
    Ok(LoadPlan {
        payload,
        target,
        target_architecture,
        payload_path_mode,
        backend,
        requirements,
        executable_now: all_requirements_passed && executor_implemented,
        note: plan_note(
            all_requirements_passed,
            no_failed_requirements,
            executor_implemented,
        ),
    })
}

fn select_backend(payload: &BinaryInspection, target: &ProcessInfo) -> Result<Backend> {
    match (payload.format, target.target_kind) {
        (BinaryFormat::PeDll, TargetKind::WineProtonWindows) => Ok(Backend::WinePeHelper),
        (BinaryFormat::ElfSharedObject, TargetKind::NativeLinux) => Err(reject(
            payload,
            target,
            "native ELF loading is outside this tool's supported scope",
        )),
        (BinaryFormat::PeDll, TargetKind::NativeLinux) => Err(reject(
            payload,
            target,
            "Windows DLLs cannot be loaded by the native Linux ELF loader",
        )),
        (BinaryFormat::ElfSharedObject, TargetKind::WineProtonWindows) => Err(reject(
            payload,
            target,
            "ELF shared objects cannot be loaded by the Wine PE loader",
        )),
        _ => unreachable!("non-loadable payloads were rejected above"),
    }
}

fn plan_note(
    all_requirements_passed: bool,
    no_failed_requirements: bool,
    executor_implemented: bool,
) -> String {
    if all_requirements_passed && executor_implemented {
        "all requirements pass; helper execution is available with explicit confirmation".into()
    } else if all_requirements_passed {
        "all requirements pass, but this backend has no executor".into()
    } else if no_failed_requirements {
        "required checks passed with warnings".into()
    } else {
        "one or more required helper conditions failed".into()
    }
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

fn running_requirements(
    payload: &BinaryInspection,
    target: &ProcessInfo,
    target_architecture: Architecture,
    backend: Backend,
    payload_path_mode: PayloadPathMode,
) -> Vec<RequirementCheck> {
    let mut checks = Vec::new();

    checks.push(requirement(
        "same_user",
        target.owned_by_current_user == Some(true),
        "target belongs to the current user",
        "target ownership is different or could not be proven",
    ));
    checks.push(classification_requirement(target));

    if backend == Backend::WinePeHelper {
        // Helper-backed loading needs Wine identity and a matching helper before
        // any request files are staged or executed
        checks.push(requirement(
            "wine_prefix",
            target.wine_prefix.as_deref().is_some_and(Path::is_dir),
            "target Wine prefix is known",
            "target Wine prefix is missing",
        ));
        checks.push(helper_requirement(target_architecture));
        checks.push(runtime_requirement(target));
        match payload_path_mode {
            // Staged-copy mode converts the private copy after request state exists
            PayloadPathMode::StagedCopy => checks.push(staged_payload_requirement()),
            PayloadPathMode::OriginalPath => {
                // Original-path mode asks Wine to load the source path directly
                checks.push(payload_windows_path_requirement(payload, target));
            }
        }
    }

    checks
}

fn staged_payload_requirement() -> RequirementCheck {
    RequirementCheck {
        name: "payload_path_mode".into(),
        status: CheckStatus::Passed,
        detail: "payload will be copied into private Wine-visible run state".into(),
    }
}

fn classification_requirement(target: &ProcessInfo) -> RequirementCheck {
    RequirementCheck {
        name: "classification_confidence".into(),
        status: match target.classification_confidence {
            ClassificationConfidence::High => CheckStatus::Passed,
            ClassificationConfidence::Medium => CheckStatus::Warning,
            ClassificationConfidence::Low => CheckStatus::Failed,
        },
        detail: format!("{:?}", target.classification_confidence),
    }
}

fn helper_requirement(target_architecture: Architecture) -> RequirementCheck {
    helper::find_wine_helper(target_architecture).map_or_else(
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
    )
}

fn runtime_requirement(target: &ProcessInfo) -> RequirementCheck {
    helper_runtime::select_runtime(target).map_or_else(
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
    )
}

fn payload_windows_path_requirement(
    payload: &BinaryInspection,
    target: &ProcessInfo,
) -> RequirementCheck {
    let conversion = target
        .wine_prefix
        .as_deref()
        .map(|prefix| wine::unix_path_to_windows(prefix, &payload.path));

    RequirementCheck {
        name: "payload_windows_path".into(),
        status: if conversion.as_ref().is_some_and(Result::is_ok) {
            CheckStatus::Passed
        } else {
            CheckStatus::Failed
        },
        detail: conversion
            .and_then(Result::ok)
            .unwrap_or_else(|| "payload is outside configured Wine drives".into()),
    }
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
