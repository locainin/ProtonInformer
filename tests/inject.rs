//! One-command Steam process selection checks

use std::path::{Path, PathBuf};
use std::time::Duration;

use proton_informer::inject::{parse_wait_duration, select_steam_process};
use proton_informer::process::{
    ClassificationConfidence, EnvironmentStatus, GuestExecutableCandidate, GuestExecutableSource,
    ProcessInfo, TargetKind,
};
use proton_informer::types::Architecture;

fn process(pid: u32, app_id: u32, guest: &Path) -> ProcessInfo {
    ProcessInfo {
        classification_confidence: ClassificationConfidence::High,
        command: vec![guest.display().to_string()],
        compatdata_dir: Some(PathBuf::from("/steam/compatdata").join(app_id.to_string())),
        environment_status: EnvironmentStatus::Read,
        executable: None,
        guest_architecture: Some(Architecture::X86_64),
        guest_executable: Some(GuestExecutableCandidate {
            path: guest.to_path_buf(),
            source: GuestExecutableSource::AbsoluteUnixArgument,
        }),
        host_architecture: Architecture::X86_64,
        name: "Main".into(),
        owned_by_current_user: Some(true),
        pid,
        proton_dist: Some(PathBuf::from("/steam/proton")),
        steam_app_id: Some(app_id),
        steam_client_path: Some(PathBuf::from("/steam")),
        target_kind: TargetKind::WineProtonWindows,
        uids: None,
        wine_prefix: Some(PathBuf::from("/steam/pfx")),
    }
}

#[test]
fn app_id_selects_the_only_guest_executable_inside_the_game_directory() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let game = directory.path().join("game");
    std::fs::create_dir(&game).expect("game directory");
    let executable = game.join("BlackOps3.exe");
    std::fs::write(&executable, b"MZ").expect("guest executable");
    let outside = directory.path().join("steam.exe");
    std::fs::write(&outside, b"MZ").expect("outside executable");

    let selected = select_steam_process(
        311_210,
        None,
        &game,
        vec![
            process(100, 311_210, &outside),
            process(200, 311_210, &executable),
        ],
    )
    .expect("unique game process");

    assert_eq!(selected.pid, 200);
}

#[test]
fn app_id_never_guesses_when_multiple_game_processes_match() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let game = directory.path().join("game");
    std::fs::create_dir(&game).expect("game directory");
    let first = game.join("first.exe");
    let second = game.join("second.exe");
    std::fs::write(&first, b"MZ").expect("first executable");
    std::fs::write(&second, b"MZ").expect("second executable");

    let error = select_steam_process(
        311_210,
        None,
        &game,
        vec![
            process(100, 311_210, &first),
            process(200, 311_210, &second),
        ],
    )
    .expect_err("ambiguous targets must fail");

    assert!(error.to_string().contains("add --process or use --pid"));
}

#[test]
fn process_wait_duration_is_positive_and_bounded() {
    assert_eq!(
        parse_wait_duration("30s").expect("thirty second wait"),
        Duration::from_secs(30)
    );
    assert_eq!(
        parse_wait_duration("5m").expect("maximum wait"),
        Duration::from_mins(5)
    );
    assert!(parse_wait_duration("0s").is_err());
    assert!(parse_wait_duration("301s").is_err());
    assert!(parse_wait_duration("30").is_err());
}
