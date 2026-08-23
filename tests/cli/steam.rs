//! Steam discovery CLI behavior with isolated filesystem roots

use std::process::Command;

use serde_json::Value;
use tempfile::tempdir;

#[test]
fn steam_games_ignores_missing_roots_without_warnings() {
    let directory = tempdir().expect("temporary directory");
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer"))
        .env_clear()
        .env("HOME", directory.path())
        .env("XDG_DATA_HOME", directory.path().join("data"))
        .args(["--json", "steam-games"])
        .output()
        .expect("CLI should start");

    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).expect("Steam report JSON");
    assert_eq!(report["games"].as_array().expect("games array").len(), 0);
    assert_eq!(
        report["warnings"].as_array().expect("warnings array").len(),
        0
    );
}

#[test]
fn steam_games_ignores_non_manifest_files_in_a_library() {
    let directory = tempdir().expect("temporary directory");
    let steam_root = directory.path().join("steam");
    std::fs::create_dir_all(steam_root.join("steamapps")).expect("Steam app manifest directory");
    std::fs::write(steam_root.join("steamapps/readme.txt"), "not a manifest")
        .expect("non-manifest fixture");
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer"))
        .env_clear()
        .env("HOME", directory.path())
        .env("XDG_DATA_HOME", directory.path().join("data"))
        .env("STEAM_COMPAT_CLIENT_INSTALL_PATH", &steam_root)
        .args(["--json", "steam-games"])
        .output()
        .expect("CLI should start");

    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).expect("Steam report JSON");
    assert_eq!(report["games"].as_array().expect("games array").len(), 0);
    assert_eq!(
        report["warnings"].as_array().expect("warnings array").len(),
        0
    );
}

#[test]
fn doctor_reports_no_steam_libraries_for_an_empty_home() {
    let directory = tempdir().expect("temporary directory");
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer"))
        .env_clear()
        .env("HOME", directory.path())
        .env("XDG_DATA_HOME", directory.path().join("data"))
        .args(["--json", "doctor"])
        .output()
        .expect("CLI should start");

    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).expect("doctor report JSON");
    let check = report["checks"]
        .as_array()
        .expect("doctor checks")
        .iter()
        .find(|check| check["name"] == "steam_libraries")
        .expect("Steam library check");
    assert_eq!(check["status"], "failed");
}

#[test]
fn doctor_accepts_an_existing_compatibility_client_root() {
    let directory = tempdir().expect("temporary directory");
    let steam_root = directory.path().join("steam");
    std::fs::create_dir_all(&steam_root).expect("Steam root");
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer"))
        .env_clear()
        .env("HOME", directory.path())
        .env("XDG_DATA_HOME", directory.path().join("data"))
        .env("STEAM_COMPAT_CLIENT_INSTALL_PATH", &steam_root)
        .args(["--json", "doctor"])
        .output()
        .expect("CLI should start");

    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).expect("doctor report JSON");
    let check = report["checks"]
        .as_array()
        .expect("doctor checks")
        .iter()
        .find(|check| check["name"] == "steam_libraries")
        .expect("Steam library check");
    assert_eq!(check["status"], "passed");
}
