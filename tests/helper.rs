//! Helper and command discovery

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use proton_informer::helper;
use proton_informer::types::Architecture;
use tempfile::tempdir;

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

#[test]
fn private_current_user_helper_path_is_trusted() {
    let directory = tempdir().expect("temporary directory");
    let helper_path = directory.path().join("helper.exe");
    fs::write(&helper_path, b"helper fixture").expect("helper fixture");
    fs::set_permissions(&helper_path, fs::Permissions::from_mode(0o755)).expect("helper mode");

    assert!(helper::helper_trust_error(&helper_path).is_none());
}

#[test]
fn group_writable_helper_file_is_rejected() {
    let directory = tempdir().expect("temporary directory");
    let helper_path = directory.path().join("helper.exe");
    fs::write(&helper_path, b"helper fixture").expect("helper fixture");
    fs::set_permissions(&helper_path, fs::Permissions::from_mode(0o775)).expect("helper mode");

    let error = helper::helper_trust_error(&helper_path).expect("unsafe helper file");

    assert!(error.contains("group-writable"));
}

#[test]
fn group_writable_helper_directory_is_rejected() {
    let directory = tempdir().expect("temporary directory");
    let helper_path = directory.path().join("helper.exe");
    fs::write(&helper_path, b"helper fixture").expect("helper fixture");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o770))
        .expect("directory mode");

    let error = helper::helper_trust_error(&helper_path).expect("unsafe helper directory");

    assert!(error.contains("helper directory is group-writable"));
}

#[test]
fn symlink_helper_file_is_rejected() {
    let directory = tempdir().expect("temporary directory");
    let real_helper = directory.path().join("real-helper.exe");
    let linked_helper = directory.path().join("helper.exe");
    fs::write(&real_helper, b"helper fixture").expect("helper fixture");
    symlink(&real_helper, &linked_helper).expect("helper symlink");

    let error = helper::helper_trust_error(&linked_helper).expect("symlink helper");

    assert!(error.contains("helper file is a symlink"));
}
