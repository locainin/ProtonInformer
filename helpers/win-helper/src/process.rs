//! Safe Windows process enumeration and target resolution.

use proton_informer_helper_protocol::{
    HelperTarget, ProcessQueryResult, TargetSelector, WindowsProcessInfo,
};

use crate::error::HelperFailure;

#[cfg(not(windows))]
use proton_informer_helper_protocol::ProtocolArchitecture;

/// Enumerates every visible Windows process.
pub fn query_processes() -> Result<ProcessQueryResult, HelperFailure> {
    Ok(ProcessQueryResult {
        processes: platform_processes()?,
    })
}

/// Resolves one target using strict ambiguity rules.
pub fn resolve(target: &HelperTarget) -> Result<WindowsProcessInfo, HelperFailure> {
    let processes = platform_processes()?;
    let expected_name = &target.expected_process_name;

    let matches: Vec<_> = match target.selector {
        TargetSelector::ByWindowsPid(pid) => {
            let require_path = target.expected_executable_windows_path.is_some();
            processes
                .into_iter()
                .filter(|process| {
                    process.windows_pid == pid && identity_matches(process, target, require_path)
                })
                .collect()
        }
        TargetSelector::ByProcessNameAndExecutablePath => {
            if target.expected_executable_windows_path.is_none() {
                return Err(HelperFailure::Validation(
                    "by_process_name_and_executable_path requires \
                     expected_executable_windows_path"
                        .into(),
                ));
            }
            processes
                .into_iter()
                .filter(|process| identity_matches(process, target, true))
                .collect()
        }
        TargetSelector::ByProcessName => {
            let architecture_matches: Vec<_> = processes
                .into_iter()
                .filter(|process| {
                    process.process_name.eq_ignore_ascii_case(expected_name)
                        && process.architecture == target.expected_architecture
                })
                .collect();
            if architecture_matches.is_empty() {
                return Err(HelperFailure::TargetNotFound(format!(
                    "no {expected_name} process matched architecture {:?}",
                    target.expected_architecture
                )));
            }
            architecture_matches
        }
    };

    match matches.as_slice() {
        [process] => Ok(process.clone()),
        [] => Err(HelperFailure::TargetNotFound(format!(
            "no Windows process matched {expected_name}"
        ))),
        _ => Err(HelperFailure::AmbiguousTarget(format!(
            "{} matching Windows processes were found; choose a more specific target",
            matches.len()
        ))),
    }
}

/// Compares process identity fields requested by the controller.
fn identity_matches(
    process: &WindowsProcessInfo,
    target: &HelperTarget,
    require_path: bool,
) -> bool {
    if !process
        .process_name
        .eq_ignore_ascii_case(&target.expected_process_name)
        || process.architecture != target.expected_architecture
    {
        return false;
    }
    if !require_path {
        return true;
    }

    process
        .executable_windows_path
        .as_deref()
        .zip(target.expected_executable_windows_path.as_deref())
        .is_some_and(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
}

/// Calls the platform implementation.
#[cfg(windows)]
fn platform_processes() -> Result<Vec<WindowsProcessInfo>, HelperFailure> {
    crate::winapi::processes()
}

/// Refuses to emulate Windows process behavior on a non-Windows build.
#[cfg(not(windows))]
fn platform_processes() -> Result<Vec<WindowsProcessInfo>, HelperFailure> {
    let _ = ProtocolArchitecture::Unknown;
    Err(HelperFailure::UnsupportedOperation(
        "process enumeration requires a Windows helper build".into(),
    ))
}
