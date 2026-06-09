//! Helper and command discovery.

use proton_informer::helper;
use proton_informer::types::Architecture;

#[test]
fn unsupported_helper_architecture_has_no_candidate() {
    assert_eq!(helper::find_wine_helper(Architecture::Aarch64), None);
}

#[test]
fn known_shell_command_is_executable() {
    assert!(helper::command_exists("sh"));
}

#[test]
fn unknown_command_is_absent() {
    assert!(!helper::command_exists(
        "proton-informer-command-that-does-not-exist"
    ));
}
