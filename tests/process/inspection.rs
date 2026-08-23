//! Live `/proc` inspection checks

use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use proton_informer::process::{self, EnvironmentStatus, TargetKind};
use tempfile::tempdir;

#[test]
fn current_process_has_complete_uid_identity() {
    let process = process::inspect(std::process::id()).expect("inspect current process");
    let uids = process.uids.expect("current process UIDs");

    assert_eq!(uids.real, uids.effective);
    assert_eq!(uids.effective, uids.filesystem);
    assert_eq!(process.owned_by_current_user, Some(true));
    assert!(process.start_time_ticks > 0);
    process::revalidate_identity(process.pid, process.start_time_ticks, uids.filesystem)
        .expect("current process identity should remain stable");
    let error =
        process::revalidate_identity(process.pid, process.start_time_ticks + 1, uids.filesystem)
            .expect_err("stale process identity must be rejected");
    assert!(matches!(
        error,
        proton_informer::Error::ProcessIdentityChanged { .. }
    ));

    let error =
        process::revalidate_identity(process.pid, process.start_time_ticks, uids.filesystem + 1)
            .expect_err("changed filesystem ownership must be rejected");
    assert!(matches!(
        error,
        proton_informer::Error::ProcessOwnershipChanged { .. }
    ));
}

#[test]
fn current_native_test_process_is_not_misclassified_as_wine() {
    let process = process::inspect(std::process::id()).expect("inspect current process");

    assert_eq!(process.target_kind, TargetKind::NativeLinux);
    assert_eq!(process.environment_status, EnvironmentStatus::Read);
}

#[test]
fn a_single_steam_app_id_is_runtime_evidence() {
    let mut child = Command::new("sleep")
        .arg("30")
        .env_remove("WINEPREFIX")
        .env_remove("STEAM_COMPAT_DATA_PATH")
        .env_remove("STEAM_COMPAT_CLIENT_INSTALL_PATH")
        .env_remove("STEAM_COMPAT_TOOL_PATHS")
        .env_remove("PROTONPATH")
        .env_remove("SteamAppId")
        .env_remove("SteamGameId")
        .env("STEAM_COMPAT_APP_ID", "123")
        .spawn()
        .expect("spawn AppID evidence fixture");

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut inspected = None;
    while Instant::now() < deadline {
        match process::inspect(child.id()) {
            Ok(candidate) if candidate.target_kind == TargetKind::WineProtonWindows => {
                inspected = Some(candidate);
                break;
            }
            Ok(_) | Err(proton_informer::Error::ProcessUnavailable(_)) => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("AppID evidence inspection failed: {error}"),
        }
    }
    child.kill().expect("stop AppID evidence fixture");
    child.wait().expect("reap AppID evidence fixture");

    let process = inspected.expect("AppID alone should classify as Wine/Proton evidence");
    assert_eq!(process.steam_app_id, Some(123));
}

#[test]
fn owned_process_scan_does_not_report_filtered_foreign_users_as_failures() {
    let report = process::list_owned_report();

    assert!(
        report
            .rejections
            .iter()
            .all(|failure| !failure.message.contains("another filesystem user"))
    );
    assert!(
        report
            .processes
            .iter()
            .all(|process| process.owned_by_current_user == Some(true))
    );
}

#[test]
fn legacy_process_list_keeps_the_current_process_visible() {
    let pid = std::process::id();

    assert!(
        process::list()
            .into_iter()
            .any(|process| process.pid == pid),
        "legacy process listing should include the current process"
    );
}

#[test]
fn owned_scan_uses_runtime_name_as_a_cheap_wine_indicator() {
    let directory = tempdir().expect("temporary directory");
    let sleep_path = std::env::split_paths(&std::env::var_os("PATH").expect("PATH"))
        .map(|path| path.join("sleep"))
        .find(|path| path.is_file())
        .expect("sleep executable in PATH");
    let wine_path = directory.path().join("wine");
    symlink(sleep_path, &wine_path).expect("create wine-name fixture");

    let mut child = Command::new(&wine_path)
        .arg("30")
        .spawn()
        .expect("spawn wine-name fixture");
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut inspected = None;
    while Instant::now() < deadline {
        if let Some(candidate) = process::list_owned_report()
            .processes
            .into_iter()
            .find(|candidate| candidate.pid == child.id())
        {
            inspected = Some(candidate);
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    child.kill().expect("stop wine-name fixture");
    child.wait().expect("reap wine-name fixture");

    assert_eq!(
        inspected
            .expect("wine-name process should appear in owned scan")
            .target_kind,
        TargetKind::WineProtonWindows
    );
}

#[test]
fn missing_process_is_rejected() {
    let error = process::inspect(u32::MAX).expect_err("missing process should fail");

    assert!(error.to_string().contains("does not exist"));
}

#[test]
fn invalid_selected_environment_values_are_not_decoded_lossily() {
    let mut child = Command::new("sleep")
        .arg("30")
        .env(
            "WINEPREFIX",
            OsString::from_vec(b"/tmp/proton-prefix\xff".to_vec()),
        )
        .spawn()
        .expect("spawn environment fixture");

    let error = process::inspect(child.id()).expect_err("invalid target identity must fail closed");
    child.kill().expect("stop environment fixture");
    child.wait().expect("reap environment fixture");

    assert!(matches!(
        &error,
        proton_informer::Error::InvalidProcessEnvironment { .. }
    ));
    assert_eq!(error.kind(), "invalid_process_environment");
    assert!(!error.to_string().contains('\u{fffd}'));
}

#[test]
fn invalid_utf8_guest_argument_keeps_exact_path_identity() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    fs::create_dir(&prefix).expect("create Wine prefix");
    let raw_name = OsString::from_vec(b"guest\xff.exe".to_vec());
    let guest = directory.path().join(&raw_name);
    write_minimal_pe_executable(&guest);

    let mut child = Command::new("sh")
        .args(["-c", "sleep 30 & wait", "sh"])
        .arg(&raw_name)
        .current_dir(directory.path())
        .env("WINEPREFIX", prefix.as_os_str())
        .spawn()
        .expect("spawn raw argv fixture");

    let inspected = inspect_until_guest_candidate(child.id());
    child.kill().expect("stop raw argv fixture");
    child.wait().expect("reap raw argv fixture");
    let guest_candidate = inspected
        .guest_executable
        .expect("raw guest executable should be resolved");

    assert_eq!(
        guest_candidate.path,
        guest.canonicalize().expect("canonical guest path")
    );
    assert_eq!(
        guest_candidate
            .path
            .file_name()
            .expect("guest filename")
            .as_bytes(),
        raw_name.as_bytes()
    );
}

#[test]
fn literal_backslashes_in_unix_argv_do_not_create_compatdata_identity() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    fs::create_dir(&prefix).expect("create Wine prefix");
    let argument = OsString::from_vec(
        format!(
            "{}/foo\\steamapps\\compatdata\\123",
            directory.path().display()
        )
        .into_bytes(),
    );

    let mut child = Command::new("sh")
        .args(["-c", "sleep 30 & wait", "sh"])
        .arg(&argument)
        .env("WINEPREFIX", prefix.as_os_str())
        .spawn()
        .expect("spawn literal-backslash fixture");
    let inspected = process::inspect(child.id());
    child.kill().expect("stop literal-backslash fixture");
    child.wait().expect("reap literal-backslash fixture");
    let process = inspected.expect("inspect literal-backslash fixture");

    assert_eq!(process.target_kind, TargetKind::WineProtonWindows);
    assert_eq!(process.compatdata_dir, None);
    assert_eq!(process.steam_app_id, None);
}

#[test]
fn conflicting_steam_environment_and_command_identity_is_rejected() {
    let directory = tempdir().expect("temporary directory");
    let environment_path = directory.path().join("steamapps/compatdata/111");
    let command_path = directory.path().join("steamapps/compatdata/222/game.exe");

    let mut child = Command::new("sh")
        .args(["-c", "sleep 30 & wait", "sh"])
        .arg(command_path.as_os_str())
        .env("STEAM_COMPAT_DATA_PATH", environment_path.as_os_str())
        .spawn()
        .expect("spawn conflicting Steam identity fixture");
    let error = inspect_until_steam_identity_conflict(child.id());
    child
        .kill()
        .expect("stop conflicting Steam identity fixture");
    child
        .wait()
        .expect("reap conflicting Steam identity fixture");

    assert!(matches!(
        error,
        proton_informer::Error::SteamIdentityConflict { .. }
    ));
}

#[test]
fn multiple_command_compatdata_paths_are_not_first_match_wins() {
    let directory = tempdir().expect("temporary directory");
    let first = directory
        .path()
        .join("steamapps/compatdata/111/launcher.exe");
    let second = directory.path().join("steamapps/compatdata/222/game.exe");

    let mut child = Command::new("sh")
        .args(["-c", "sleep 30 & wait", "sh"])
        .arg(first.as_os_str())
        .arg(second.as_os_str())
        .env("WINEPREFIX", directory.path().join("pfx").as_os_str())
        .spawn()
        .expect("spawn ambiguous Steam identity fixture");
    let error = process::inspect(child.id()).expect_err("ambiguous identity must fail closed");
    child.kill().expect("stop ambiguous Steam identity fixture");
    child.wait().expect("reap ambiguous Steam identity fixture");

    assert!(matches!(
        error,
        proton_informer::Error::SteamIdentityConflict { .. }
    ));
}

#[test]
fn wine_prefix_must_match_steam_compatdata_prefix() {
    let directory = tempdir().expect("temporary directory");
    let compatdata = directory.path().join("steamapps/compatdata/123");
    let matching_prefix = compatdata.join("pfx");
    let unrelated_prefix = directory.path().join("other-prefix");
    fs::create_dir_all(&matching_prefix).expect("create compatdata prefix");
    fs::create_dir_all(&unrelated_prefix).expect("create unrelated prefix");

    let mut child = Command::new("sh")
        .args(["-c", "sleep 30 & wait", "sh"])
        .env("STEAM_COMPAT_DATA_PATH", compatdata.as_os_str())
        .env("WINEPREFIX", unrelated_prefix.as_os_str())
        .env("STEAM_COMPAT_APP_ID", "123")
        .spawn()
        .expect("spawn mixed Proton identity fixture");
    let error = process::inspect(child.id()).expect_err("mixed prefixes must fail closed");
    child.kill().expect("stop mixed Proton identity fixture");
    child.wait().expect("reap mixed Proton identity fixture");

    assert!(matches!(
        error,
        proton_informer::Error::SteamIdentityConflict { .. }
    ));
    assert!(error.to_string().contains("WINEPREFIX"));
}

#[test]
fn nonexistent_explicit_wine_prefix_is_not_treated_as_missing_identity() {
    let directory = tempdir().expect("temporary directory");
    let missing_prefix = directory.path().join("missing-prefix");

    let mut child = Command::new("sh")
        .args(["-c", "sleep 30 & wait", "sh"])
        .env("WINEPREFIX", missing_prefix.as_os_str())
        .spawn()
        .expect("spawn missing-prefix fixture");
    let error = process::inspect(child.id()).expect_err("missing prefix must fail closed");
    child.kill().expect("stop missing-prefix fixture");
    child.wait().expect("reap missing-prefix fixture");

    assert!(matches!(error, proton_informer::Error::Io { .. }));
    assert!(error.to_string().contains("missing-prefix"));
}

#[test]
fn non_directory_compatdata_prefix_is_not_treated_as_missing_identity() {
    let directory = tempdir().expect("temporary directory");
    let compatdata = directory.path().join("steamapps/compatdata/123");
    let derived_prefix = compatdata.join("pfx");
    fs::create_dir_all(&compatdata).expect("create compatdata directory");
    fs::write(&derived_prefix, b"not a directory").expect("create invalid prefix fixture");

    let mut child = Command::new("sh")
        .args(["-c", "sleep 30 & wait", "sh"])
        .env("STEAM_COMPAT_DATA_PATH", compatdata.as_os_str())
        .spawn()
        .expect("spawn non-directory-prefix fixture");
    let error = process::inspect(child.id()).expect_err("non-directory prefix must fail closed");
    child.kill().expect("stop non-directory-prefix fixture");
    child.wait().expect("reap non-directory-prefix fixture");

    assert!(matches!(
        error,
        proton_informer::Error::SteamIdentityConflict { .. }
    ));
    assert!(error.to_string().contains("Wine prefix is not a directory"));
}

#[test]
fn proton_runtime_paths_must_be_absolute() {
    for (key, value) in [
        ("WINEPREFIX", "relative/pfx"),
        ("STEAM_COMPAT_DATA_PATH", "relative/compatdata"),
        ("PROTONPATH", "relative/proton"),
        ("STEAM_COMPAT_CLIENT_INSTALL_PATH", "relative/steam-client"),
        ("STEAM_COMPAT_TOOL_PATHS", "relative/tool"),
    ] {
        let mut child = Command::new("sh")
            .args(["-c", "sleep 30 & wait", "sh"])
            .env(key, value)
            .spawn()
            .expect("spawn relative Proton path fixture");
        let error = inspect_until_steam_identity_conflict(child.id());
        child.kill().expect("stop relative Proton path fixture");
        child.wait().expect("reap relative Proton path fixture");

        assert!(
            matches!(error, proton_informer::Error::SteamIdentityConflict { .. }),
            "{key}"
        );
    }
}

fn inspect_until_guest_candidate(pid: u32) -> proton_informer::process::ProcessInfo {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut last_command = Vec::new();

    loop {
        match process::inspect(pid) {
            Ok(inspected) if inspected.guest_executable.is_some() => return inspected,
            Ok(inspected) => last_command = inspected.command,
            Err(proton_informer::Error::ProcessUnavailable(_)) => {}
            Err(error) => panic!("raw argv process inspection failed: {error}"),
        }

        assert!(
            Instant::now() < deadline,
            "raw guest executable did not become visible; last command: {last_command:?}"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn inspect_until_steam_identity_conflict(pid: u32) -> proton_informer::Error {
    let deadline = Instant::now() + Duration::from_secs(2);

    loop {
        match process::inspect(pid) {
            Err(error @ proton_informer::Error::SteamIdentityConflict { .. }) => return error,
            Ok(_) | Err(proton_informer::Error::ProcessUnavailable(_)) => {
                assert!(
                    Instant::now() < deadline,
                    "Steam identity failure did not become visible"
                );
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("unexpected process inspection error: {error}"),
        }
    }
}

fn write_minimal_pe_executable(path: &Path) {
    let section_table = 0x188;
    let mut bytes = vec![0_u8; section_table + 3 * 40];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    bytes[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
    bytes[coff + 2..coff + 4].copy_from_slice(&3_u16.to_le_bytes());
    bytes[coff + 16..coff + 18].copy_from_slice(&0xf0_u16.to_le_bytes());
    bytes[coff + 18..coff + 20].copy_from_slice(&0x0022_u16.to_le_bytes());
    bytes[coff + 20..coff + 22].copy_from_slice(&0x20b_u16.to_le_bytes());

    // Keep one complete header for every declared section
    let names = [b".text\0\0\0", b".rdata\0\0", b".data\0\0\0"];
    for (index, name) in names.iter().enumerate() {
        let section = section_table + index * 40;
        bytes[section..section + 8].copy_from_slice(*name);
        bytes[section + 8..section + 12].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[section + 12..section + 16]
            .copy_from_slice(&(0x1000_u32 * (index as u32 + 1)).to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[section + 20..section + 24]
            .copy_from_slice(&(0x200_u32 * (index as u32 + 1)).to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0x6000_0020_u32.to_le_bytes());
    }

    fs::write(path, bytes).expect("PE executable fixture");
}
