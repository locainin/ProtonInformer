//! Readiness checks for Steam, Wine, helpers, `/proc`, and state storage.

use std::env;
use std::fs;
use std::path::PathBuf;

use proton_informer_helper_protocol::{HelperVersion, SCHEMA_VERSION, SelfTestResult};
use serde::{Deserialize, Serialize};

use crate::binary::{self, BinaryFormat};
use crate::error::{Error, Result};
use crate::helper;
use crate::helper_executor;
use crate::helper_runtime;
use crate::process;
use crate::steam;
use crate::types::Architecture;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Passed,
    Warning,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub checks: Vec<DoctorCheck>,
    pub process_planning: CapabilityReadiness,
    pub steam_discovery: CapabilityReadiness,
    pub wine_helper_x86: CapabilityReadiness,
    pub wine_helper_x86_64: CapabilityReadiness,
}

/// Readiness of one independently usable capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityReadiness {
    /// Required checks passed.
    Ready,
    /// One or more required checks did not pass.
    Unavailable,
}

/// Runs local checks without attaching to or changing a target process.
#[must_use]
pub fn run() -> DoctorReport {
    let mut checks = Vec::new();
    let libraries = steam::discover_libraries();
    checks.push(check(
        "steam_libraries",
        !libraries.is_empty(),
        format!("{} Steam library root(s) found", libraries.len()),
        "no Steam library roots were found",
    ));

    let discovery = steam::discover_games();
    checks.push(check(
        "steam_games",
        !discovery.games.is_empty(),
        format!("{} app manifest(s) parsed", discovery.games.len()),
        "no readable Steam app manifests were found",
    ));
    if !discovery.warnings.is_empty() {
        checks.push(DoctorCheck {
            name: "steam_metadata_warnings".into(),
            status: CheckStatus::Warning,
            detail: format!("{} discovery warning(s)", discovery.warnings.len()),
        });
    }

    checks.push(check(
        "proc_self",
        process::inspect(std::process::id()).is_ok(),
        "current process metadata and environment are readable".into(),
        "current process metadata could not be inspected",
    ));
    checks.push(command_check("wine", &["wine", "wine64"]));
    checks.push(command_check("winepath", &["winepath"]));
    if let Some(directory) = helper::helper_dir_env_override() {
        checks.push(DoctorCheck {
            name: "helper_dir_env_override".into(),
            status: CheckStatus::Warning,
            detail: format!(
                "{} is set to {}; helper lookup will prefer this directory",
                helper::HELPER_DIR_ENV,
                directory.display()
            ),
        });
    }
    checks.push(helper_check(Architecture::X86));
    checks.push(helper_check(Architecture::X86_64));
    checks.push(state_check());

    let process_planning = readiness(
        checks
            .iter()
            .find(|check| check.name == "proc_self")
            .is_some_and(|check| check.status == CheckStatus::Passed),
    );
    let steam_discovery = readiness(
        checks
            .iter()
            .find(|check| check.name == "steam_libraries")
            .is_some_and(|check| check.status == CheckStatus::Passed),
    );
    let wine_available = checks
        .iter()
        .find(|check| check.name == "wine")
        .is_some_and(|check| check.status == CheckStatus::Passed);
    let wine_helper_x86 = readiness(wine_available && helper_ready(&checks, Architecture::X86));
    let wine_helper_x86_64 =
        readiness(wine_available && helper_ready(&checks, Architecture::X86_64));

    DoctorReport {
        checks,
        process_planning,
        steam_discovery,
        wine_helper_x86,
        wine_helper_x86_64,
    }
}

/// Runs static checks plus live helper diagnostics in one target runtime.
///
/// # Errors
///
/// Returns an error when the target cannot be inspected or is not a Wine or
/// Proton process owned by the current user.
pub fn run_for_process(pid: u32) -> Result<DoctorReport> {
    let target = process::inspect(pid)?;
    if target.target_kind != process::TargetKind::WineProtonWindows {
        return Err(Error::InvalidInput(format!(
            "process {pid} is not a Wine or Proton Windows target"
        )));
    }
    if target.owned_by_current_user != Some(true) {
        return Err(Error::InvalidInput(format!(
            "ownership of process {pid} could not be proven"
        )));
    }
    let architecture = target.guest_architecture.ok_or_else(|| {
        Error::InvalidInput(format!("guest architecture for process {pid} is unknown"))
    })?;
    let mut report = run();
    report
        .checks
        .push(version_diagnostic(&target, architecture));
    report
        .checks
        .push(self_test_diagnostic(&target, architecture));
    let live_ready = report
        .checks
        .iter()
        .filter(|check| {
            matches!(
                check.name.as_str(),
                "helper_version_runtime" | "helper_self_test_runtime"
            )
        })
        .all(|check| check.status == CheckStatus::Passed);
    match architecture {
        Architecture::X86 => report.wine_helper_x86 = readiness(live_ready),
        Architecture::X86_64 => report.wine_helper_x86_64 = readiness(live_ready),
        Architecture::Arm | Architecture::Aarch64 | Architecture::Unknown => {}
    }
    Ok(report)
}

/// Executes and validates `--version-json` inside the selected runtime.
fn version_diagnostic(target: &process::ProcessInfo, architecture: Architecture) -> DoctorCheck {
    diagnostic_output(target, architecture, "--version-json").map_or_else(
        diagnostic_failure("helper_version_runtime"),
        |stdout| match serde_json::from_str::<HelperVersion>(&stdout) {
            Ok(version)
                if version.architecture
                    == crate::helper_protocol::protocol_architecture(architecture)
                    && version.schema_versions.contains(&SCHEMA_VERSION) =>
            {
                DoctorCheck {
                    name: "helper_version_runtime".into(),
                    status: CheckStatus::Passed,
                    detail: format!(
                        "{} {} supports schema {}",
                        version.helper_name, version.helper_version, SCHEMA_VERSION
                    ),
                }
            }
            Ok(version) => DoctorCheck {
                name: "helper_version_runtime".into(),
                status: CheckStatus::Failed,
                detail: format!(
                    "helper reported {:?} and schemas {:?}",
                    version.architecture, version.schema_versions
                ),
            },
            Err(error) => DoctorCheck {
                name: "helper_version_runtime".into(),
                status: CheckStatus::Failed,
                detail: format!("invalid version JSON: {error}"),
            },
        },
    )
}

/// Executes and validates `--self-test-json` inside the selected runtime.
fn self_test_diagnostic(target: &process::ProcessInfo, architecture: Architecture) -> DoctorCheck {
    diagnostic_output(target, architecture, "--self-test-json").map_or_else(
        diagnostic_failure("helper_self_test_runtime"),
        |stdout| match serde_json::from_str::<SelfTestResult>(&stdout) {
            Ok(result) if result.passed => DoctorCheck {
                name: "helper_self_test_runtime".into(),
                status: CheckStatus::Passed,
                detail: format!("{} helper self-test check(s) passed", result.checks.len()),
            },
            Ok(result) => DoctorCheck {
                name: "helper_self_test_runtime".into(),
                status: CheckStatus::Failed,
                detail: result
                    .checks
                    .iter()
                    .filter(|check| !check.passed)
                    .map(|check| format!("{}: {}", check.name, check.detail))
                    .collect::<Vec<_>>()
                    .join("; "),
            },
            Err(error) => DoctorCheck {
                name: "helper_self_test_runtime".into(),
                status: CheckStatus::Failed,
                detail: format!("invalid self-test JSON: {error}"),
            },
        },
    )
}

/// Runs one trusted diagnostic command with bounded output and time.
fn diagnostic_output(
    target: &process::ProcessInfo,
    architecture: Architecture,
    flag: &str,
) -> Result<String> {
    let invocation = helper_runtime::diagnostic_invocation(target, architecture, flag)?;
    let output = helper_executor::execute(&invocation, 10_000)?;
    if output.exit_code != Some(0) {
        return Err(Error::HelperExecution(format!(
            "exit {:?}: {}",
            output.exit_code,
            output.stderr.trim()
        )));
    }
    Ok(output.stdout)
}

/// Converts one diagnostic error into a named failed check.
fn diagnostic_failure(name: &'static str) -> impl FnOnce(Error) -> DoctorCheck {
    move |error| DoctorCheck {
        name: name.into(),
        status: CheckStatus::Failed,
        detail: error.to_string(),
    }
}

fn command_check(name: &str, candidates: &[&str]) -> DoctorCheck {
    let found = candidates
        .iter()
        .find(|candidate| helper::command_exists(candidate));
    found.map_or_else(
        || DoctorCheck {
            name: name.into(),
            status: CheckStatus::Warning,
            detail: format!(
                "none of {} are available through PATH",
                candidates.join(", ")
            ),
        },
        |command| DoctorCheck {
            name: name.into(),
            status: CheckStatus::Passed,
            detail: format!("{command} is available through PATH"),
        },
    )
}

fn helper_check(architecture: Architecture) -> DoctorCheck {
    helper::find_wine_helper(architecture).map_or_else(
        || DoctorCheck {
            name: format!("wine_helper_{architecture}"),
            status: CheckStatus::Warning,
            detail: "helper is not installed".into(),
        },
        |path| match binary::inspect(&path) {
            Ok(inspection)
                if inspection.format == BinaryFormat::PeExecutable
                    && inspection.architecture == architecture =>
            {
                DoctorCheck {
                    name: format!("wine_helper_{architecture}"),
                    status: CheckStatus::Passed,
                    detail: path.display().to_string(),
                }
            }
            Ok(inspection) => DoctorCheck {
                name: format!("wine_helper_{architecture}"),
                status: CheckStatus::Failed,
                detail: format!(
                    "{} is {} {}, expected {} PE executable",
                    path.display(),
                    inspection.architecture,
                    inspection.format,
                    architecture
                ),
            },
            Err(error) => DoctorCheck {
                name: format!("wine_helper_{architecture}"),
                status: CheckStatus::Failed,
                detail: error.to_string(),
            },
        },
    )
}

fn helper_ready(checks: &[DoctorCheck], architecture: Architecture) -> bool {
    let name = format!("wine_helper_{architecture}");
    checks
        .iter()
        .find(|check| check.name == name)
        .is_some_and(|check| check.status == CheckStatus::Passed)
}

const fn readiness(ready: bool) -> CapabilityReadiness {
    if ready {
        CapabilityReadiness::Ready
    } else {
        CapabilityReadiness::Unavailable
    }
}

fn state_check() -> DoctorCheck {
    let directory = state_directory();
    match fs::create_dir_all(&directory) {
        Ok(()) => DoctorCheck {
            name: "state_directory".into(),
            status: CheckStatus::Passed,
            detail: directory.display().to_string(),
        },
        Err(error) => DoctorCheck {
            name: "state_directory".into(),
            status: CheckStatus::Failed,
            detail: format!("{}: {error}", directory.display()),
        },
    }
}

fn state_directory() -> PathBuf {
    env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .unwrap_or_else(env::temp_dir)
        .join("proton-informer")
}

fn check(name: &str, condition: bool, passed: String, failed: &str) -> DoctorCheck {
    DoctorCheck {
        name: name.into(),
        status: if condition {
            CheckStatus::Passed
        } else {
            CheckStatus::Failed
        },
        detail: if condition { passed } else { failed.into() },
    }
}
