//! Wine runtime evidence and guest executable resolution

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use super::model::{
    ClassificationConfidence, GuestExecutableCandidate, GuestExecutableSource, TargetKind,
};
use crate::binary::{self, BinaryFormat};
use crate::error::{Error, Result};
use crate::types::Architecture;
use crate::wine;

/// One independent indicator used during process classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EvidenceKind {
    CompatdataPath,
    GuestExecutableArgument,
    GuestProcessName,
    RuntimeIdentity,
    SteamCompatEnvironment,
    WineEnvironment,
}

/// Internal evidence set used to avoid classifying from `.exe` text alone
#[derive(Debug, Default)]
pub(super) struct ProcessEvidence {
    kinds: BTreeSet<EvidenceKind>,
}

impl ProcessEvidence {
    /// Reports whether one indicator was observed
    fn contains(&self, kind: EvidenceKind) -> bool {
        self.kinds.contains(&kind)
    }
}

/// Classifies a process and reports how strongly the available facts agree
pub(super) fn classify(evidence: &ProcessEvidence) -> (TargetKind, ClassificationConfidence) {
    let runtime_evidence = evidence.contains(EvidenceKind::RuntimeIdentity)
        || evidence.contains(EvidenceKind::WineEnvironment)
        || evidence.contains(EvidenceKind::SteamCompatEnvironment)
        || evidence.contains(EvidenceKind::CompatdataPath);

    if !runtime_evidence {
        return (TargetKind::NativeLinux, ClassificationConfidence::High);
    }

    let strong_count = [
        EvidenceKind::RuntimeIdentity,
        EvidenceKind::WineEnvironment,
        EvidenceKind::SteamCompatEnvironment,
        EvidenceKind::CompatdataPath,
    ]
    .into_iter()
    .filter(|kind| evidence.contains(*kind))
    .count();
    let guest_evidence = evidence.contains(EvidenceKind::GuestExecutableArgument)
        || evidence.contains(EvidenceKind::GuestProcessName);
    let confidence = if strong_count >= 2 {
        ClassificationConfidence::High
    } else if guest_evidence {
        ClassificationConfidence::Medium
    } else {
        ClassificationConfidence::Low
    };

    (TargetKind::WineProtonWindows, confidence)
}

/// Collects runtime evidence without treating a guest filename as proof alone
pub(super) fn collect(
    name: &str,
    executable: Option<&Path>,
    command: &[OsString],
    environment: &BTreeMap<String, String>,
    has_compatdata_path: bool,
) -> ProcessEvidence {
    let executable_name = executable
        .and_then(Path::file_name)
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let runtime_identity = is_wine_runtime_name(name) || is_wine_runtime_name(executable_name);
    let wine_environment = environment.contains_key("WINEPREFIX");
    let steam_compat_environment = environment.contains_key("STEAM_COMPAT_DATA_PATH")
        || environment.contains_key("STEAM_COMPAT_APP_ID");
    let guest_executable_argument = command
        .iter()
        .any(|argument| ends_with_ascii_case_insensitive(argument, b".exe"));
    let guest_process_name = name.to_ascii_lowercase().ends_with(".exe");

    let mut kinds = BTreeSet::new();
    for (present, kind) in [
        (has_compatdata_path, EvidenceKind::CompatdataPath),
        (
            guest_executable_argument,
            EvidenceKind::GuestExecutableArgument,
        ),
        (guest_process_name, EvidenceKind::GuestProcessName),
        (runtime_identity, EvidenceKind::RuntimeIdentity),
        (
            steam_compat_environment,
            EvidenceKind::SteamCompatEnvironment,
        ),
        (wine_environment, EvidenceKind::WineEnvironment),
    ] {
        if present {
            kinds.insert(kind);
        }
    }

    ProcessEvidence { kinds }
}

/// Collects every absolute Unix compatdata path found in command arguments
pub(super) fn command_compatdata_paths(command: &[OsString]) -> Result<Vec<PathBuf>> {
    command
        .iter()
        .map(|argument| host_compatdata_path(argument.as_os_str()))
        .collect::<Result<Vec<_>>>()
        .map(|paths| paths.into_iter().flatten().collect())
}

/// Finds an existing guest PE candidate and records how it was resolved
pub(super) fn find_guest_executable(
    command: &[OsString],
    prefix: Option<&Path>,
    working_directory: Option<&Path>,
) -> Result<Option<(GuestExecutableCandidate, Architecture)>> {
    let mut possible_paths = std::collections::BTreeMap::new();

    // Resolve every plausible executable argument before selecting anything
    for argument in command {
        if !ends_with_ascii_case_insensitive(argument, b".exe") {
            continue;
        }
        let display_argument = argument.to_string_lossy().into_owned();
        if looks_like_unsupported_windows_path(argument) {
            return Err(Error::PathConversion {
                path: display_argument,
                reason: "unsupported Windows path syntax; only drive-absolute paths are supported"
                    .into(),
            });
        }

        let unix_path = Path::new(argument);
        let (path, source) = if unix_path.is_absolute() {
            (
                unix_path.to_path_buf(),
                GuestExecutableSource::AbsoluteUnixArgument,
            )
        } else if is_windows_drive_path(argument) {
            let prefix = prefix.ok_or_else(|| Error::PathConversion {
                path: display_argument.clone(),
                reason: "Windows drive path requires a known Wine prefix".into(),
            })?;
            let windows_path = argument.to_str().ok_or_else(|| Error::PathConversion {
                path: display_argument.clone(),
                reason: "Windows path is not valid UTF-8 for the helper protocol".into(),
            })?;
            (
                wine::windows_path_to_unix(prefix, windows_path)?,
                GuestExecutableSource::WindowsDriveArgument,
            )
        } else {
            let working_directory = working_directory.ok_or_else(|| Error::PathConversion {
                path: display_argument.clone(),
                reason: "relative guest executable requires a known process working directory"
                    .into(),
            })?;
            (
                working_directory.join(unix_path),
                GuestExecutableSource::RelativeUnixArgument,
            )
        };

        let canonical = match path.canonicalize() {
            Ok(path) => path,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
            Err(source) => return Err(Error::io(&path, source)),
        };

        // Canonical paths deduplicate the same executable found through two
        // command-line spellings or two Wine drive mappings
        possible_paths.entry(canonical).or_insert(source);
    }

    let mut candidates = Vec::new();
    for (path, source) in possible_paths {
        let inspection = match binary::inspect(&path) {
            Ok(inspection) => inspection,
            Err(Error::InvalidBinary { .. }) => continue,
            Err(Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                continue;
            }
            Err(error) => return Err(error),
        };
        if inspection.format == BinaryFormat::PeExecutable {
            candidates.push((
                GuestExecutableCandidate { path, source },
                inspection.architecture,
            ));
        }
    }

    match candidates.as_slice() {
        [] => Ok(None),
        [candidate] => Ok(Some(candidate.clone())),
        _ => Err(Error::AmbiguousGuestExecutable {
            candidates: candidates
                .into_iter()
                .map(|(candidate, _)| candidate.path)
                .collect(),
        }),
    }
}

/// Resolves a guest executable for callers that do not need its architecture
///
/// # Errors
///
/// Returns path-conversion, inspection, or ambiguity failures without guessing
pub fn resolve_guest_executable(
    command: &[String],
    prefix: Option<&Path>,
    working_directory: Option<&Path>,
) -> Result<Option<GuestExecutableCandidate>> {
    let command = command
        .iter()
        .cloned()
        .map(OsString::from)
        .collect::<Vec<_>>();
    find_guest_executable(&command, prefix, working_directory)
        .map(|candidate| candidate.map(|(candidate, _)| candidate))
}

/// Recognizes only drive-absolute Windows arguments
fn is_windows_drive_path(value: &OsStr) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
}

/// Rejects Windows-looking forms that have no supported Linux-side resolver
fn looks_like_unsupported_windows_path(value: &OsStr) -> bool {
    let bytes = value.as_bytes();
    // A single-rooted Unix path keeps its exact Linux component spelling
    if bytes.starts_with(b"/") && !bytes.starts_with(b"//") {
        return false;
    }
    let is_drive_absolute = is_windows_drive_path(value);
    let has_windows_separator = bytes.iter().any(|byte| *byte == b'\\' || *byte == b':');
    (!is_drive_absolute && has_windows_separator) || bytes.starts_with(b"//")
}

/// Extracts an absolute host compatdata directory from one command argument
pub(super) fn host_compatdata_path(value: &OsStr) -> Result<Option<PathBuf>> {
    // Windows drive paths must first be resolved through a known prefix
    // Treating Z:/ as a Unix root would invent a host path
    let bytes = value.as_bytes();
    if !bytes.starts_with(b"/") {
        return Ok(None);
    }

    let marker = b"/steamapps/compatdata/";
    let Some(marker_start) = find_subslice(bytes, marker) else {
        return Ok(None);
    };
    let remainder = &bytes[marker_start + marker.len()..];
    let app_id_bytes = remainder
        .split(|byte| *byte == b'/')
        .next()
        .unwrap_or_default();
    let Ok(app_id_text) = std::str::from_utf8(app_id_bytes) else {
        return Err(Error::PathConversion {
            path: value.to_string_lossy().into_owned(),
            reason: "compatdata path contains invalid UTF-8".into(),
        });
    };
    let Ok(app_id) = app_id_text.parse::<u32>() else {
        return Ok(None);
    };
    let root = PathBuf::from(OsString::from_vec(bytes[..marker_start].to_vec()));
    Ok(Some(
        root.join("steamapps/compatdata").join(app_id.to_string()),
    ))
}

/// Finds one byte sequence without decoding the command argument
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Checks an ASCII suffix while preserving every other argument byte
fn ends_with_ascii_case_insensitive(value: &OsStr, suffix: &[u8]) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= suffix.len()
        && bytes[bytes.len() - suffix.len()..]
            .iter()
            .zip(suffix)
            .all(|(actual, expected)| actual.to_ascii_lowercase() == *expected)
}

/// Matches exact Wine runtime process names only
fn is_wine_runtime_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "wine" | "wine64" | "wine-preloader" | "wine64-preloader" | "wineserver" | "proton"
    )
}
