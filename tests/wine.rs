//! Prefix-aware Wine path conversion

use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use proton_informer::Error;
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

#[test]
fn unix_conversion_rejects_a_backslash_inside_a_host_filename() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    let drive_root = directory.path().join("drive-root");
    let payload = drive_root.join("game").join("foo\\bar.dll");
    fs::create_dir_all(prefix.join("dosdevices")).expect("create dosdevices");
    fs::create_dir_all(payload.parent().expect("payload parent")).expect("create payload parent");
    fs::write(&payload, b"payload").expect("create payload");
    symlink(&drive_root, prefix.join("dosdevices/c:")).expect("create c mapping");

    let error = unix_path_to_windows(&prefix, &payload)
        .expect_err("a literal host backslash must not become a Windows separator");

    assert!(matches!(error, Error::PathConversion { .. }));
    assert!(error.to_string().contains("foo\\\\bar.dll"));
}

#[test]
fn unix_conversion_rejects_all_superscript_reserved_device_names() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    let drive_root = directory.path().join("drive-root");
    fs::create_dir_all(prefix.join("dosdevices")).expect("create dosdevices");
    fs::create_dir_all(&drive_root).expect("create drive root");
    symlink(&drive_root, prefix.join("dosdevices/c:")).expect("create c mapping");

    for name in [
        "COM¹",
        "COM¹.dll",
        "COM².dll",
        "COM³.dll",
        "LPT¹.dll",
        "LPT².dll",
        "LPT³.dll",
    ] {
        let path = drive_root.join(name);
        fs::write(&path, b"payload").expect("create reserved-name fixture");
        let error = unix_path_to_windows(&prefix, &path)
            .expect_err("superscript device names must not be converted");
        assert!(matches!(error, Error::PathConversion { .. }), "{name}");
    }
}

#[test]
fn accepted_unix_paths_round_trip_through_the_selected_drive() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    let drive_root = directory.path().join("drive-root");
    let payload = drive_root.join("game").join("payload.dll");
    fs::create_dir_all(prefix.join("dosdevices")).expect("create dosdevices");
    fs::create_dir_all(payload.parent().expect("payload parent")).expect("create payload parent");
    fs::write(&payload, b"payload").expect("create payload");
    symlink(&drive_root, prefix.join("dosdevices/c:")).expect("create c mapping");

    let windows = unix_path_to_windows(&prefix, &payload).expect("convert Unix path");
    let round_trip = windows_path_to_unix(&prefix, &windows).expect("convert Windows path");

    assert_eq!(
        round_trip,
        payload.canonicalize().expect("canonical payload")
    );
}

#[test]
fn windows_conversion_rejects_root_escape_and_parent_traversal() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    let drive_c = prefix.join("drive_c");
    fs::create_dir_all(prefix.join("dosdevices")).expect("create dosdevices");
    fs::create_dir_all(&drive_c).expect("create drive c");
    symlink("../drive_c", prefix.join("dosdevices/c:")).expect("create c mapping");

    for path in [r"C:\\foo.dll", r"C:\foo\..\foo.dll", r"C:\\\foo.dll"] {
        let error = windows_path_to_unix(&prefix, path).expect_err("reject unsafe Windows path");
        assert!(matches!(error, Error::PathConversion { .. }));
    }
}

#[test]
fn windows_conversion_accepts_mixed_separators_and_drive_root() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    let drive_c = prefix.join("drive_c");
    fs::create_dir_all(prefix.join("dosdevices")).expect("create dosdevices");
    fs::create_dir_all(&drive_c).expect("create drive c");
    symlink("../drive_c", prefix.join("dosdevices/c:")).expect("create c mapping");

    let root = windows_path_to_unix(&prefix, r"C:\").expect("convert drive root");
    let mixed =
        windows_path_to_unix(&prefix, r"C:/Games\Example.exe").expect("convert mixed separators");

    assert_eq!(root, drive_c);
    assert_eq!(mixed, drive_c.join("Games/Example.exe"));
}

#[test]
fn windows_conversion_rejects_win32_special_components() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    let drive_c = prefix.join("drive_c");
    fs::create_dir_all(prefix.join("dosdevices")).expect("create dosdevices");
    fs::create_dir_all(&drive_c).expect("create drive c");
    symlink("../drive_c", prefix.join("dosdevices/c:")).expect("create c mapping");

    for path in [
        r"C:\game\foo:bar.exe",
        r"C:\game\CON.exe",
        r"C:\game\foo?.exe",
        r"C:\game\foo.",
    ] {
        let error = windows_path_to_unix(&prefix, path)
            .expect_err("Win32-special components must not become Linux filenames");
        assert!(matches!(error, Error::PathConversion { .. }), "{path}");
    }
}

#[test]
fn unix_conversion_reports_missing_drive_mapping_as_a_specific_error() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    let payload = directory.path().join("payload.dll");
    fs::create_dir_all(prefix.join("dosdevices")).expect("create dosdevices");
    fs::write(&payload, b"payload").expect("write payload");

    let error = unix_path_to_windows(&prefix, &payload).expect_err("path is outside drives");

    assert!(matches!(error, Error::NoDriveMappingForPath { .. }));
}

#[test]
fn broken_unrelated_drive_does_not_poison_windows_conversion() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    let drive_c = prefix.join("drive_c");
    fs::create_dir_all(prefix.join("dosdevices")).expect("create dosdevices");
    fs::create_dir_all(&drive_c).expect("create drive c");
    symlink("../drive_c", prefix.join("dosdevices/c:")).expect("create c mapping");
    symlink("/missing-drive-target", prefix.join("dosdevices/d:"))
        .expect("create broken d mapping");

    let converted = windows_path_to_unix(&prefix, r"C:\game\payload.dll")
        .expect("valid requested drive must ignore unrelated broken mappings");

    assert_eq!(converted, drive_c.join("game/payload.dll"));
}

#[test]
fn broken_drive_mapping_is_not_reported_as_no_mapping_for_unrelated_unix_path() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    let drive_c = prefix.join("drive_c");
    let payload = directory.path().join("payload.dll");
    fs::create_dir_all(prefix.join("dosdevices")).expect("create dosdevices");
    fs::create_dir_all(&drive_c).expect("create drive c");
    fs::write(&payload, b"payload").expect("write payload");
    symlink("../drive_c", prefix.join("dosdevices/c:")).expect("create c mapping");
    symlink("/missing-drive-target", prefix.join("dosdevices/d:"))
        .expect("create broken d mapping");

    let error = unix_path_to_windows(&prefix, &payload)
        .expect_err("unmapped path with incomplete mapping inspection must fail");

    assert!(matches!(
        error,
        Error::DriveMappingInspectionIncomplete { .. }
    ));
}

#[test]
fn conflicting_case_variant_drive_mappings_are_rejected() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    let first_root = directory.path().join("first-drive");
    let second_root = directory.path().join("second-drive");
    fs::create_dir_all(prefix.join("dosdevices")).expect("create dosdevices");
    fs::create_dir_all(&first_root).expect("create first drive");
    fs::create_dir_all(&second_root).expect("create second drive");
    symlink(&first_root, prefix.join("dosdevices/c:")).expect("create lowercase c mapping");
    symlink(&second_root, prefix.join("dosdevices/C:")).expect("create uppercase c mapping");

    let error = windows_path_to_unix(&prefix, r"C:\game\payload.dll")
        .expect_err("conflicting case variants must not select by directory order");

    assert!(matches!(
        error,
        Error::AmbiguousDriveMapping { drive: 'c', .. }
    ));
}

#[test]
fn duplicate_drive_mappings_to_one_root_are_deduplicated() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    let drive_root = directory.path().join("drive-root");
    fs::create_dir_all(prefix.join("dosdevices")).expect("create dosdevices");
    fs::create_dir_all(&drive_root).expect("create drive root");
    symlink(&drive_root, prefix.join("dosdevices/c:")).expect("create lowercase c mapping");
    symlink(&drive_root, prefix.join("dosdevices/C:")).expect("create uppercase c mapping");

    let mappings = proton_informer::wine::drive_mappings(&prefix).expect("deduplicate mappings");

    assert_eq!(
        mappings,
        vec![('c', drive_root.canonicalize().expect("canonical root"))]
    );
}

#[test]
fn drive_mapping_inspection_ignores_non_drive_entries() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    let drive_root = directory.path().join("drive-root");
    fs::create_dir_all(prefix.join("dosdevices")).expect("create dosdevices");
    fs::create_dir_all(&drive_root).expect("create drive root");
    symlink(&drive_root, prefix.join("dosdevices/c:")).expect("create c mapping");
    symlink(&drive_root, prefix.join("dosdevices/1:")).expect("create invalid mapping name");

    let mappings = proton_informer::wine::drive_mappings(&prefix)
        .expect("invalid drive names must not poison valid mappings");

    assert_eq!(
        mappings,
        vec![('c', drive_root.canonicalize().expect("canonical root"))]
    );
}
