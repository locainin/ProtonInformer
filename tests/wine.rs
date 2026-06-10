//! Prefix-aware Wine path conversion

use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use proton_informer::wine::{unix_path_to_windows, windows_path_to_unix};
use tempfile::tempdir;

#[test]
fn c_drive_uses_prefix_mapping() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    let drive_c = prefix.join("drive_c");
    fs::create_dir_all(prefix.join("dosdevices")).expect("create dosdevices");
    fs::create_dir_all(&drive_c).expect("create drive c");
    symlink("../drive_c", prefix.join("dosdevices/c:")).expect("create c mapping");

    let converted =
        windows_path_to_unix(&prefix, r"C:\Games\Example.exe").expect("convert c drive");

    assert_eq!(converted, drive_c.join("Games/Example.exe"));
}

#[test]
fn configured_z_drive_maps_to_unix() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    fs::create_dir_all(prefix.join("dosdevices")).expect("create dosdevices");
    symlink("/", prefix.join("dosdevices/z:")).expect("create z mapping");

    let converted = windows_path_to_unix(&prefix, r"Z:\home\user\Mods\payload.dll")
        .expect("convert configured z drive");

    assert_eq!(converted, PathBuf::from("/home/user/Mods/payload.dll"));
}

#[test]
fn unix_conversion_prefers_specific_drive() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    let steamapps = directory.path().join("steamapps");
    let payload = steamapps.join("common/Game/mod.dll");
    fs::create_dir_all(prefix.join("dosdevices")).expect("create dosdevices");
    fs::create_dir_all(payload.parent().expect("payload parent")).expect("create payload parent");
    fs::write(&payload, b"MZ").expect("create payload");
    symlink("/", prefix.join("dosdevices/z:")).expect("create z mapping");
    symlink(&steamapps, prefix.join("dosdevices/s:")).expect("create s mapping");

    let converted = unix_path_to_windows(&prefix, &payload).expect("convert Unix path");

    assert_eq!(converted, r"s:\common\Game\mod.dll");
}
