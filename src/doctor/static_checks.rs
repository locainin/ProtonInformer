//! Static doctor checks that never attach to a target runtime

use std::env;
use std::fs;
use std::path::PathBuf;

use crate::binary::{self, BinaryFormat};
use crate::helper;
use crate::process;
use crate::steam;
use crate::types::Architecture;

use super::model::{CapabilityReadiness, CheckStatus, DoctorCheck, DoctorReport};

/// Runs local checks without attaching to or changing a target process
#[must_use]
pub(super) fn run() -> DoctorReport {
    let mut checks = Vec::new();

    // Steam roots prove that discovery has somewhere useful to start
    let libraries = steam::discover_libraries();
    checks.push(check(
        "steam_libraries",
        !libraries.is_empty(),
        format!("{} Steam library root(s) found", libraries.len()),
        "no Steam library roots were found",
    ));

    // App manifests are checked separately so broken metadata is visible
    let discovery = steam::discover_games();
    checks.push(check(
        "steam_games",
        !discovery.games.is_empty(),
        format!("{} app manifest(s) parsed", discovery.games.len()),
        "no readable Steam app manifests were found",
    ));

    // Keep metadata warnings non-fatal because one bad manifest should not hide working games
    if !discovery.warnings.is_empty() {
        checks.push(DoctorCheck {
            name: "steam_metadata_warnings".into(),
            status: CheckStatus::Warning,
            detail: format!("{} discovery warning(s)", discovery.warnings.len()),
        });
    }

    // The current process is a cheap probe for `/proc` readability
    checks.push(check(
        "proc_self",
        process::inspect(std::process::id()).is_ok(),
        "current process metadata and environment are readable".into(),
        "current process metadata could not be inspected",
    ));

    // Plain Wine commands are only a warning because Proton-only setups can still work
    checks.push(command_check("wine", &["wine", "wine64"]));
    checks.push(command_check("winepath", &["winepath"]));

    // The helper override is intentionally loud because it changes trusted helper lookup
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

    build_report(checks)
}

fn build_report(checks: Vec<DoctorCheck>) -> DoctorReport {
    // Capability summaries are derived from named checks so text and JSON stay aligned
    let process_planning = readiness(check_passed(&checks, "proc_self"));
    let steam_discovery = readiness(check_passed(&checks, "steam_libraries"));
    let wine_available = check_passed(&checks, "wine");
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

fn command_check(name: &str, candidates: &[&str]) -> DoctorCheck {
    // Candidate order lets wine64 satisfy wine checks without changing the public check name
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
        |path| validate_helper_binary(architecture, &path),
    )
}

fn validate_helper_binary(architecture: Architecture, path: &std::path::Path) -> DoctorCheck {
    // Static helper validation catches packaging mistakes before any Wine process is started
    match binary::inspect(path) {
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
    }
}

pub(super) fn helper_ready(checks: &[DoctorCheck], architecture: Architecture) -> bool {
    let name = format!("wine_helper_{architecture}");
    check_passed(checks, &name)
}

pub(super) const fn readiness(ready: bool) -> CapabilityReadiness {
    if ready {
        CapabilityReadiness::Ready
    } else {
        CapabilityReadiness::Unavailable
    }
}

fn check_passed(checks: &[DoctorCheck], name: &str) -> bool {
    checks
        .iter()
        .find(|check| check.name == name)
        .is_some_and(|check| check.status == CheckStatus::Passed)
}

fn state_check() -> DoctorCheck {
    let directory = state_directory();

    // This creates only the controller state root used by doctor reporting
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
    // Prefer the standard state location but keep doctor usable in minimal shells
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
