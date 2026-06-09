//! Non-mutating helper self-test.

use proton_informer_helper_protocol::{
    HelperCapability, HelperResult, HelperVersion, ProtocolArchitecture, SelfTestCheck,
    SelfTestResult,
};

use crate::error::HelperFailure;

/// Runs parser, process, and module checks without modifying another process.
pub fn run() -> Result<SelfTestResult, HelperFailure> {
    let version = crate::protocol::version();
    let json = serde_json::to_vec(&HelperResult::Version(version.clone()))?;
    let parsed: HelperResult = serde_json::from_slice(&json)?;
    let parsed_version = match &parsed {
        HelperResult::Version(version) => Some(version),
        _ => None,
    };
    let mut checks = vec![SelfTestCheck {
        detail: "shared result JSON round-tripped".into(),
        name: "json".into(),
        passed: matches!(parsed, HelperResult::Version(HelperVersion { .. })),
    }];
    checks.push(SelfTestCheck {
        detail: format!("helper architecture is {:?}", version.architecture),
        name: "architecture".into(),
        passed: parsed_version.is_some_and(|parsed| {
            parsed.architecture == compile_time_architecture()
                && parsed.architecture == version.architecture
        }),
    });
    let expected_capabilities = expected_capabilities();
    checks.push(SelfTestCheck {
        detail: format!("reported capabilities: {:?}", version.capabilities),
        name: "capabilities".into(),
        passed: expected_capabilities
            .iter()
            .all(|capability| version.capabilities.contains(capability))
            && version.capabilities.len() == expected_capabilities.len(),
    });

    #[cfg(windows)]
    {
        let processes = crate::process::query_processes()?.processes;
        let own_pid = crate::winapi::current_process_id();
        let own_process = processes
            .iter()
            .find(|process| process.windows_pid == own_pid);
        checks.push(SelfTestCheck {
            detail: format!("enumerated {} process(es)", processes.len()),
            name: "process_enumeration".into(),
            passed: !processes.is_empty(),
        });
        checks.push(SelfTestCheck {
            detail: format!("current Windows PID is {own_pid}"),
            name: "current_process".into(),
            passed: own_process.is_some(),
        });

        // PID zero is the documented current-process selector for module
        // snapshots and avoids Wine treating the helper as a foreign process
        let modules = crate::winapi::modules(0)?;
        checks.push(SelfTestCheck {
            detail: format!("enumerated {} current-process module(s)", modules.len()),
            name: "module_enumeration".into(),
            passed: !modules.is_empty(),
        });
    }

    #[cfg(not(windows))]
    {
        checks.push(SelfTestCheck {
            detail: "helper was not built for Windows".into(),
            name: "windows_target".into(),
            passed: false,
        });
    }

    Ok(SelfTestResult {
        passed: checks.iter().all(|check| check.passed),
        checks,
    })
}

/// Returns the exact capability set expected for this platform build.
#[cfg(windows)]
fn expected_capabilities() -> Vec<HelperCapability> {
    vec![
        HelperCapability::Version,
        HelperCapability::SelfTest,
        HelperCapability::QueryProcesses,
        HelperCapability::QueryModules,
        HelperCapability::LoadLibrary,
    ]
}

/// Returns the non-mutating capability set for host-native smoke builds.
#[cfg(not(windows))]
fn expected_capabilities() -> Vec<HelperCapability> {
    vec![HelperCapability::Version, HelperCapability::SelfTest]
}

/// Returns the architecture selected by this compilation target.
const fn compile_time_architecture() -> ProtocolArchitecture {
    #[cfg(target_arch = "x86_64")]
    {
        ProtocolArchitecture::X86_64
    }
    #[cfg(target_arch = "x86")]
    {
        ProtocolArchitecture::X86
    }
    #[cfg(target_arch = "aarch64")]
    {
        ProtocolArchitecture::Aarch64
    }
    #[cfg(target_arch = "arm")]
    {
        ProtocolArchitecture::Arm
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm"
    )))]
    {
        ProtocolArchitecture::Unknown
    }
}
