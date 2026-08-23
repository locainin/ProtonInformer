//! Exact module identity regression checks

use proton_informer_helper_protocol::WindowsModuleInfo;
use proton_informer_win_helper::module_identity::{find_basename_conflict, find_exact};

#[test]
fn same_content_or_same_name_does_not_substitute_for_an_exact_path() {
    let modules = vec![WindowsModuleInfo {
        module_name: "payload.dll".into(),
        windows_path: r"C:\other\payload.dll".into(),
    }];

    assert!(find_exact(&modules, r"C:\requested\payload.dll").is_none());
    assert!(find_basename_conflict(&modules, r"C:\requested\payload.dll").is_some());
}

#[test]
fn canonical_separator_and_case_differences_still_match_the_same_path() {
    let modules = vec![WindowsModuleInfo {
        module_name: "Payload.DLL".into(),
        windows_path: r"C:\Games\Payload.DLL".into(),
    }];

    assert!(find_exact(&modules, "c:/games/payload.dll").is_some());
}

#[test]
fn an_exact_path_is_not_reported_as_a_basename_conflict() {
    let modules = vec![WindowsModuleInfo {
        module_name: "Payload.DLL".into(),
        windows_path: r"C:\Games\Payload.DLL".into(),
    }];

    assert!(find_basename_conflict(&modules, r"c:\games\payload.dll").is_none());
}
