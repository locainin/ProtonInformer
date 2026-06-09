//! Module inventory filtering behavior

use proton_informer::modules::{self, ModuleFilters};
use proton_informer_helper_protocol::{
    ModuleQueryResult, ProtocolArchitecture, WindowsModuleInfo, WindowsProcessInfo,
};

#[test]
fn empty_filters_leave_all_modules_visible() {
    let mut result = sample_result();

    modules::apply(&mut result, &ModuleFilters::default());

    assert_eq!(result.modules.len(), 3);
}

#[test]
fn name_filter_matches_module_basename_case_insensitively() {
    let mut result = sample_result();

    modules::apply(
        &mut result,
        &ModuleFilters {
            name: Some("EXAMPLEPLUGIN".into()),
            contains: None,
        },
    );

    assert_eq!(module_names(&result), ["ExamplePlugin.dll"]);
}

#[test]
fn name_filter_does_not_match_only_the_path() {
    let mut result = sample_result();

    modules::apply(
        &mut result,
        &ModuleFilters {
            name: Some("mods".into()),
            contains: None,
        },
    );

    assert!(result.modules.is_empty());
}

#[test]
fn contains_filter_matches_module_path_or_name() {
    let mut result = sample_result();

    modules::apply(
        &mut result,
        &ModuleFilters {
            name: None,
            contains: Some("mods".into()),
        },
    );

    assert_eq!(module_names(&result), ["ExamplePlugin.dll"]);
}

#[test]
fn combined_filters_require_both_conditions() {
    let mut result = sample_result();

    modules::apply(
        &mut result,
        &ModuleFilters {
            name: Some("dll".into()),
            contains: Some("system32".into()),
        },
    );

    assert_eq!(module_names(&result), ["kernel32.dll", "winhttp.dll"]);
}

fn sample_result() -> ModuleQueryResult {
    ModuleQueryResult {
        modules: vec![
            module("kernel32.dll", "C:\\windows\\system32\\kernel32.dll"),
            module(
                "ExamplePlugin.dll",
                "Z:\\home\\user\\mods\\ExamplePlugin.dll",
            ),
            module("winhttp.dll", "C:\\windows\\system32\\winhttp.dll"),
        ],
        target: WindowsProcessInfo {
            architecture: ProtocolArchitecture::X86_64,
            creation_time_100ns: Some(42),
            executable_windows_path: Some("C:\\game\\BlackOps3.exe".into()),
            process_name: "BlackOps3.exe".into(),
            windows_pid: 311_210,
        },
    }
}

fn module(name: &str, path: &str) -> WindowsModuleInfo {
    WindowsModuleInfo {
        module_name: name.into(),
        windows_path: path.into(),
    }
}

fn module_names(result: &ModuleQueryResult) -> Vec<&str> {
    result
        .modules
        .iter()
        .map(|module| module.module_name.as_str())
        .collect()
}
