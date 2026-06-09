//! Managed run-state listing, validation, and cleanup checks.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::time::Duration;

use proton_informer::runs::{cleanup_in, list_in, parse_age};
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn listing_accepts_only_owner_only_uuid_directories() {
    let directory = tempdir().expect("temporary directory");
    let root = directory.path().join("state");
    let runs = root.join("runs");
    fs::create_dir_all(&runs).expect("runs directory");
    fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).expect("private runs directory");
    let valid = runs.join(Uuid::new_v4().to_string());
    fs::create_dir(&valid).expect("valid run");
    fs::set_permissions(&valid, fs::Permissions::from_mode(0o700)).expect("private run");
    fs::create_dir(runs.join("not-a-uuid")).expect("unexpected directory");
    symlink(&valid, runs.join(Uuid::new_v4().to_string())).expect("symlink fixture");

    let report = list_in(&root).expect("safe listing");

    assert_eq!(report.runs.len(), 1);
    assert_eq!(report.runs[0].path, valid);
    assert_eq!(report.warnings.len(), 2);
}

#[test]
fn cleanup_removes_valid_runs_without_following_symlinks() {
    let directory = tempdir().expect("temporary directory");
    let root = directory.path().join("state");
    let runs = root.join("runs");
    let outside = directory.path().join("outside");
    fs::create_dir_all(&runs).expect("runs directory");
    fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).expect("private runs directory");
    fs::create_dir(&outside).expect("outside directory");
    let valid = runs.join(Uuid::new_v4().to_string());
    fs::create_dir(&valid).expect("valid run");
    fs::set_permissions(&valid, fs::Permissions::from_mode(0o700)).expect("private run");
    let link = runs.join(Uuid::new_v4().to_string());
    symlink(&outside, &link).expect("symlink fixture");

    let report = cleanup_in(&root, None).expect("safe cleanup");

    assert_eq!(report.removed, 1);
    assert!(!valid.exists());
    assert!(link.exists());
    assert!(outside.exists());
}

#[test]
fn compact_age_parser_rejects_ambiguous_or_zero_values() {
    assert_eq!(
        parse_age("7d").expect("seven days"),
        Duration::from_hours(168)
    );
    assert!(parse_age("7").is_err());
    assert!(parse_age("0h").is_err());
    assert!(parse_age("1week").is_err());
}
