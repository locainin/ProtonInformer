//! Live helper diagnostics for one selected Wine or Proton target

use proton_informer_helper_protocol::{HelperVersion, SCHEMA_VERSION, SelfTestResult};

use crate::error::{Error, Result};
use crate::helper_executor;
use crate::helper_runtime;
use crate::process;
use crate::types::Architecture;

use super::model::{CheckStatus, DoctorCheck, DoctorReport};
use super::static_checks;

/// Runs static checks plus live helper diagnostics in one target runtime
pub(super) fn run_for_process(pid: u32) -> Result<DoctorReport> {
    let target = process::inspect(pid)?;
    validate_target(pid, &target)?;

    let architecture = target.guest_architecture.ok_or_else(|| {
        Error::InvalidInput(format!("guest architecture for process {pid} is unknown"))
    })?;
    let mut report = static_checks::run();

    // Runtime probes use the exact helper and Wine or Proton identity selected for this process
    report
        .checks
        .push(version_diagnostic(&target, architecture));
    report
        .checks
        .push(self_test_diagnostic(&target, architecture));

    update_live_readiness(&mut report, architecture);
    Ok(report)
}

fn validate_target(pid: u32, target: &process::ProcessInfo) -> Result<()> {
    // Live diagnostics require a Windows target because the helper is a PE executable
    if target.target_kind != process::TargetKind::WineProtonWindows {
        return Err(Error::InvalidInput(format!(
            "process {pid} is not a Wine or Proton Windows target"
        )));
    }

    // Ownership must be proven before launching anything inside the target runtime
    if target.owned_by_current_user != Some(true) {
        return Err(Error::InvalidInput(format!(
            "ownership of process {pid} could not be proven"
        )));
    }

    Ok(())
}

fn update_live_readiness(report: &mut DoctorReport, architecture: Architecture) {
    // Both probes must pass before the architecture-specific helper is marked ready
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
        Architecture::X86 => report.wine_helper_x86 = static_checks::readiness(live_ready),
        Architecture::X86_64 => report.wine_helper_x86_64 = static_checks::readiness(live_ready),
        Architecture::Arm | Architecture::Aarch64 | Architecture::Unknown => {}
    }
}

/// Executes and validates `--version-json` inside the selected runtime
fn version_diagnostic(target: &process::ProcessInfo, architecture: Architecture) -> DoctorCheck {
    diagnostic_output(target, architecture, "--version-json")
        .map_or_else(diagnostic_failure("helper_version_runtime"), |stdout| {
            parse_version_check(architecture, &stdout)
        })
}

fn parse_version_check(architecture: Architecture, stdout: &str) -> DoctorCheck {
    match serde_json::from_str::<HelperVersion>(stdout) {
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
    }
}

/// Executes and validates `--self-test-json` inside the selected runtime
fn self_test_diagnostic(target: &process::ProcessInfo, architecture: Architecture) -> DoctorCheck {
    diagnostic_output(target, architecture, "--self-test-json")
        .map_or_else(diagnostic_failure("helper_self_test_runtime"), |stdout| {
            parse_self_test_check(&stdout)
        })
}

fn parse_self_test_check(stdout: &str) -> DoctorCheck {
    match serde_json::from_str::<SelfTestResult>(stdout) {
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
    }
}

/// Runs one trusted diagnostic command with bounded output and time
fn diagnostic_output(
    target: &process::ProcessInfo,
    architecture: Architecture,
    flag: &str,
) -> Result<String> {
    let invocation = helper_runtime::diagnostic_invocation(target, architecture, flag)?;
    let output = helper_executor::execute(&invocation, 10_000)?;

    // Non-zero helper status is a runtime failure, not a JSON parse problem
    if output.exit_code != Some(0) {
        return Err(Error::HelperExecution(format!(
            "exit {:?}: {}",
            output.exit_code,
            output.stderr.trim()
        )));
    }

    Ok(output.stdout)
}

/// Converts one diagnostic error into a named failed check
fn diagnostic_failure(name: &'static str) -> impl FnOnce(Error) -> DoctorCheck {
    move |error| DoctorCheck {
        name: name.into(),
        status: CheckStatus::Failed,
        detail: error.to_string(),
    }
}
