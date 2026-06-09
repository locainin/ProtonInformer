//! Strict target selection for the one-command injection workflow.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::process::{ClassificationConfidence, ProcessInfo, TargetKind};
use crate::steam;

const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(500);
const MAX_PROCESS_WAIT: Duration = Duration::from_mins(5);

/// Selects one running target from an explicit PID or Steam application.
///
/// # Errors
///
/// Returns an error when selectors conflict, Steam metadata is unavailable,
/// process evidence is unsafe, or more than one process remains.
pub fn select_target(
    pid: Option<u32>,
    app_id: Option<u32>,
    process_name: Option<&str>,
) -> Result<ProcessInfo> {
    match (pid, app_id) {
        (Some(pid), None) => select_explicit_pid(pid, process_name),
        (None, Some(app_id)) => select_steam_target(app_id, process_name),
        _ => Err(Error::InvalidInput(
            "select exactly one of --pid or --app-id".into(),
        )),
    }
}

/// Selects one target immediately or waits for an exact final Steam process.
///
/// # Errors
///
/// Returns an error for invalid wait combinations, unsafe process evidence,
/// ambiguity, or expiration before the named process becomes available.
pub fn select_target_with_wait(
    pid: Option<u32>,
    app_id: Option<u32>,
    process_name: Option<&str>,
    wait_for: Option<Duration>,
) -> Result<ProcessInfo> {
    let Some(wait_for) = wait_for else {
        return select_target(pid, app_id, process_name);
    };
    let (None, Some(app_id), Some(process_name)) = (pid, app_id, process_name) else {
        return Err(Error::InvalidInput(
            "--wait-for requires --app-id and --process without --pid".into(),
        ));
    };
    wait_for_steam_target(app_id, process_name, wait_for)
}

/// Parses and bounds process wait durations.
///
/// # Errors
///
/// Returns an error for malformed durations or waits longer than five minutes.
pub fn parse_wait_duration(value: &str) -> Result<Duration> {
    let duration = crate::duration::parse_compact(value, "wait duration")?;
    if duration > MAX_PROCESS_WAIT {
        return Err(Error::InvalidInput(
            "wait duration must not exceed 5m".into(),
        ));
    }
    Ok(duration)
}

/// Validates an explicit process instead of weakening normal load checks.
fn select_explicit_pid(pid: u32, process_name: Option<&str>) -> Result<ProcessInfo> {
    let target = crate::process::inspect(pid)?;
    validate_supported_target(&target)?;
    if let Some(expected_name) = process_name
        && !guest_basename_matches(&target, expected_name)
    {
        return Err(Error::InvalidInput(format!(
            "process {pid} does not identify guest executable {expected_name}"
        )));
    }
    Ok(target)
}

/// Finds the unique trusted guest executable inside one Steam game directory.
fn select_steam_target(app_id: u32, process_name: Option<&str>) -> Result<ProcessInfo> {
    let game_directory = steam_game_directory(app_id)?;
    select_steam_process(
        app_id,
        process_name,
        &game_directory,
        crate::process::list(),
    )
}

/// Waits at a bounded rate for one exact final executable.
fn wait_for_steam_target(
    app_id: u32,
    process_name: &str,
    wait_for: Duration,
) -> Result<ProcessInfo> {
    let game_directory = steam_game_directory(app_id)?;
    let deadline = Instant::now()
        .checked_add(wait_for)
        .ok_or_else(|| Error::InvalidInput("wait deadline overflowed".into()))?;

    loop {
        let mut candidates = trusted_steam_candidates(
            app_id,
            Some(process_name),
            &game_directory,
            crate::process::list(),
        );
        match candidates.len() {
            1 => return Ok(candidates.remove(0)),
            0 => {}
            count => return Err(ambiguous_target(app_id, &candidates, count)),
        }

        let now = Instant::now();
        if now >= deadline {
            return Err(Error::InvalidInput(format!(
                "timed out after {} seconds waiting for {process_name} in Steam AppID {app_id}",
                wait_for.as_secs()
            )));
        }
        // Never busy-poll procfs while waiting for a launcher handoff
        std::thread::sleep(PROCESS_POLL_INTERVAL.min(deadline.duration_since(now)));
    }
}

/// Resolves and canonicalizes one Steam game directory once per operation.
fn steam_game_directory(app_id: u32) -> Result<PathBuf> {
    let (game, warnings) = steam::find_game(app_id);
    let game = game.ok_or_else(|| {
        let warning_text = if warnings.is_empty() {
            String::new()
        } else {
            format!("; Steam discovery reported {} warning(s)", warnings.len())
        };
        Error::InvalidInput(format!("Steam AppID {app_id} was not found{warning_text}"))
    })?;
    if !game.game_dir_exists {
        return Err(Error::InvalidInput(format!(
            "Steam AppID {app_id} game directory does not exist: {}",
            game.game_dir.display()
        )));
    }
    let game_directory = game
        .game_dir
        .canonicalize()
        .map_err(|source| Error::io(&game.game_dir, source))?;
    Ok(game_directory)
}

/// Selects the unique trusted process from already collected process evidence.
///
/// This separate boundary keeps selection deterministic and directly testable.
///
/// # Errors
///
/// Returns an error when no trusted process remains or selection is ambiguous.
pub fn select_steam_process(
    app_id: u32,
    process_name: Option<&str>,
    game_directory: &Path,
    processes: Vec<ProcessInfo>,
) -> Result<ProcessInfo> {
    let mut candidates = trusted_steam_candidates(app_id, process_name, game_directory, processes);

    match candidates.len() {
        1 => Ok(candidates.remove(0)),
        0 => Err(Error::InvalidInput(format!(
            "no trusted running game process was found for Steam AppID {app_id}"
        ))),
        count => Err(ambiguous_target(app_id, &candidates, count)),
    }
}

/// Filters one process snapshot without performing filesystem discovery twice.
fn trusted_steam_candidates(
    app_id: u32,
    process_name: Option<&str>,
    game_directory: &Path,
    processes: Vec<ProcessInfo>,
) -> Vec<ProcessInfo> {
    let mut candidates: Vec<_> = processes
        .into_iter()
        .filter(|target| target.steam_app_id == Some(app_id))
        .filter(|target| validate_supported_target(target).is_ok())
        .filter(|target| guest_is_inside(target, game_directory))
        .filter(|target| {
            process_name.is_none_or(|expected| guest_basename_matches(target, expected))
        })
        .collect();
    candidates.sort_by_key(|target| target.pid);
    candidates
}

/// Builds one deterministic ambiguity error for immediate and waiting modes.
fn ambiguous_target(app_id: u32, candidates: &[ProcessInfo], count: usize) -> Error {
    let identities = candidates
        .iter()
        .map(|target| {
            let name = target
                .guest_executable
                .as_ref()
                .and_then(|guest| guest.path.file_name())
                .and_then(|name| name.to_str())
                .unwrap_or("<unknown>");
            format!("{}:{name}", target.pid)
        })
        .collect::<Vec<_>>()
        .join(", ");
    Error::InvalidInput(format!(
        "{count} trusted game processes matched Steam AppID {app_id}: {identities}; add --process \
         or use --pid"
    ))
}

/// Rejects wrappers, foreign processes, and weak Wine classification.
fn validate_supported_target(target: &ProcessInfo) -> Result<()> {
    if target.target_kind != TargetKind::WineProtonWindows {
        return Err(Error::Rejected(
            "target is not a Windows process hosted by Wine or Proton".into(),
        ));
    }
    if target.owned_by_current_user != Some(true) {
        return Err(Error::Rejected(
            "target ownership does not match the current user".into(),
        ));
    }
    if target.classification_confidence != ClassificationConfidence::High {
        return Err(Error::Rejected(
            "target Wine or Proton identity is not high confidence".into(),
        ));
    }
    if target.guest_executable.is_none() {
        return Err(Error::Rejected(
            "target guest executable path is unknown".into(),
        ));
    }
    Ok(())
}

/// Checks the canonical guest executable remains under the game directory.
fn guest_is_inside(target: &ProcessInfo, game_directory: &Path) -> bool {
    target
        .guest_executable
        .as_ref()
        .and_then(|guest| guest.path.canonicalize().ok())
        .is_some_and(|guest| guest.starts_with(game_directory))
}

/// Compares only the guest executable basename using Windows case rules.
fn guest_basename_matches(target: &ProcessInfo, expected: &str) -> bool {
    let expected = expected.rsplit(['\\', '/']).next().unwrap_or(expected);
    target
        .guest_executable
        .as_ref()
        .and_then(|guest| guest.path.file_name())
        .and_then(|name| name.to_str())
        .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
}
