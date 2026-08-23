//! Safe Windows process enumeration and target resolution

use proton_informer_helper_protocol::{
    HelperTarget, ProcessQueryRejection, ProcessQueryResult, TargetSelector, WindowsProcessInfo,
};

use crate::error::HelperFailure;
use crate::windows_path::{windows_path_equal, windows_string_equal};

#[cfg(not(windows))]
use proton_informer_helper_protocol::ProtocolArchitecture;

/// Enumerates every visible Windows process
pub fn query_processes() -> Result<ProcessQueryResult, HelperFailure> {
    let (processes, rejections) = platform_processes()?;
    Ok(ProcessQueryResult {
        processes,
        rejections,
    })
}

/// Resolves one target using strict ambiguity rules
pub fn resolve(target: &HelperTarget) -> Result<WindowsProcessInfo, HelperFailure> {
    if let TargetSelector::ByWindowsPid(pid) = target.selector {
        let process = platform_process(pid)?;
        let require_path = target.expected_executable_windows_path.is_some();
        if identity_matches(&process, target, require_path) {
            return Ok(process);
        }
        return Err(HelperFailure::TargetNotFound(format!(
            "Windows PID {pid} did not match the requested process identity"
        )));
    }

    resolve_from_discovery(target)
}

/// Resolves a target using the global snapshot required by name selectors
fn resolve_from_discovery(target: &HelperTarget) -> Result<WindowsProcessInfo, HelperFailure> {
    let (processes, rejections) = platform_processes()?;
    let expected_name = &target.expected_process_name;

    let matches: Vec<_> = match &target.selector {
        TargetSelector::ByWindowsPid(_) => {
            return Err(HelperFailure::Validation(
                "exact PID selectors must use direct process resolution".into(),
            ));
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
                    windows_string_equal(&process.process_name, expected_name)
                        && process.architecture == target.expected_architecture
                })
                .collect();
            if architecture_matches.is_empty() {
                return Err(HelperFailure::TargetNotFound(format!(
                    "no {expected_name} process matched architecture {:?}{}",
                    target.expected_architecture,
                    rejection_suffix(&rejections, expected_name)
                )));
            }
            architecture_matches
        }
    };

    select_discovered_process(&matches, expected_name, &rejections)
}

/// Applies unique-target selection after the platform snapshot is complete
fn select_discovered_process(
    matches: &[WindowsProcessInfo],
    expected_name: &str,
    rejections: &[ProcessQueryRejection],
) -> Result<WindowsProcessInfo, HelperFailure> {
    match matches {
        [process] => Ok(process.clone()),
        [] => Err(HelperFailure::TargetNotFound(format!(
            "no Windows process matched {expected_name}{}",
            rejection_suffix(rejections, expected_name)
        ))),
        _ => {
            let pids = matches
                .iter()
                .map(|process| process.windows_pid.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            Err(HelperFailure::AmbiguousTarget(format!(
                "{} matching Windows processes were found (PIDs: {pids}); choose a more specific target",
                matches.len()
            )))
        }
    }
}

/// Keeps the first relevant process-query failure in target diagnostics
fn rejection_suffix(rejections: &[ProcessQueryRejection], expected_name: &str) -> String {
    rejections
        .iter()
        .find(|rejection| windows_string_equal(&rejection.process_name, expected_name))
        .map_or_else(String::new, |rejection| {
            rejection.windows_error.map_or_else(
                || {
                    format!(
                        "; query rejection for {} (PID {}): {}",
                        rejection.process_name, rejection.windows_pid, rejection.message
                    )
                },
                |code| {
                    format!(
                        "; query rejection for {} (PID {}; error {code}): {}",
                        rejection.process_name, rejection.windows_pid, rejection.message
                    )
                },
            )
        })
}

/// Compares process identity fields requested by the controller
fn identity_matches(
    process: &WindowsProcessInfo,
    target: &HelperTarget,
    require_path: bool,
) -> bool {
    if !windows_string_equal(&process.process_name, &target.expected_process_name)
        || process.architecture != target.expected_architecture
        || target
            .expected_creation_time_100ns
            .is_some_and(|expected| process.creation_time_100ns != Some(expected))
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
        .is_some_and(|(actual, expected)| windows_path_equal(actual, expected))
}

/// Calls the platform implementation
#[cfg(windows)]
fn platform_processes()
-> Result<(Vec<WindowsProcessInfo>, Vec<ProcessQueryRejection>), HelperFailure> {
    crate::winapi::processes()
}

/// Calls the exact-PID platform implementation
#[cfg(windows)]
fn platform_process(windows_pid: u32) -> Result<WindowsProcessInfo, HelperFailure> {
    crate::winapi::process(windows_pid)
}

/// Refuses to emulate Windows process behavior on a non-Windows build
#[cfg(not(windows))]
fn platform_processes()
-> Result<(Vec<WindowsProcessInfo>, Vec<ProcessQueryRejection>), HelperFailure> {
    let _ = ProtocolArchitecture::Unknown;
    Err(HelperFailure::UnsupportedOperation(
        "process enumeration requires a Windows helper build".into(),
    ))
}

/// Refuses to emulate exact Windows process identity on a non-Windows build
#[cfg(not(windows))]
fn platform_process(windows_pid: u32) -> Result<WindowsProcessInfo, HelperFailure> {
    let _ = windows_pid;
    let _ = ProtocolArchitecture::Unknown;
    Err(HelperFailure::UnsupportedOperation(
        "process lookup requires a Windows helper build".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::identity_matches;
    use proton_informer_helper_protocol::{
        HelperTarget, ProtocolArchitecture, TargetSelector, WindowsProcessInfo,
    };

    fn process(name: &str, path: Option<&str>) -> WindowsProcessInfo {
        WindowsProcessInfo {
            architecture: ProtocolArchitecture::X86_64,
            creation_time_100ns: Some(7),
            executable_windows_path: path.map(str::to_owned),
            process_name: name.into(),
            windows_pid: 42,
        }
    }

    fn target(name: &str, path: Option<&str>) -> HelperTarget {
        HelperTarget {
            expected_creation_time_100ns: Some(7),
            expected_architecture: ProtocolArchitecture::X86_64,
            expected_executable_windows_path: path.map(str::to_owned),
            expected_process_name: name.into(),
            selector: TargetSelector::ByWindowsPid(42),
        }
    }

    #[test]
    fn optional_path_matching_accepts_a_matching_process_without_a_path() {
        assert!(identity_matches(
            &process("game.exe", None),
            &target("game.exe", None),
            false
        ));
    }

    #[test]
    fn process_name_mismatch_is_rejected_even_without_a_required_path() {
        assert!(!identity_matches(
            &process("other.exe", None),
            &target("game.exe", None),
            false
        ));
    }

    #[test]
    fn required_path_matching_rejects_a_different_executable() {
        assert!(!identity_matches(
            &process("game.exe", Some(r"C:\game.exe")),
            &target("game.exe", Some(r"C:\other.exe")),
            true
        ));
    }

    #[test]
    fn empty_discovery_matches_are_reported_as_target_not_found() {
        let error = super::select_discovered_process(&[], "game.exe", &[])
            .expect_err("empty discovery must not be ambiguous");

        assert!(matches!(
            error,
            crate::error::HelperFailure::TargetNotFound(_)
        ));
    }
}
