//! Wine runtime evidence and guest executable resolution

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::model::{
    ClassificationConfidence, GuestExecutableCandidate, GuestExecutableSource, TargetKind,
};
use crate::binary::{self, BinaryFormat};
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
    command: &[String],
    environment: &BTreeMap<String, String>,
) -> ProcessEvidence {
    let executable_name = executable
        .and_then(Path::file_name)
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let runtime_identity = is_wine_runtime_name(name) || is_wine_runtime_name(executable_name);
    let wine_environment = environment.contains_key("WINEPREFIX");
    let steam_compat_environment = environment.contains_key("STEAM_COMPAT_DATA_PATH")
        || environment.contains_key("STEAM_COMPAT_APP_ID");
    let compatdata_path = command
        .iter()
        .any(|argument| host_compatdata_path(argument).is_some());
    let guest_executable_argument = command
        .iter()
        .any(|argument| argument.to_ascii_lowercase().ends_with(".exe"));
    let guest_process_name = name.to_ascii_lowercase().ends_with(".exe");

    let mut kinds = BTreeSet::new();
    for (present, kind) in [
        (compatdata_path, EvidenceKind::CompatdataPath),
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

/// Finds an existing guest PE candidate and records how it was resolved
pub(super) fn find_guest_executable(
    command: &[String],
    prefix: Option<&Path>,
    working_directory: Option<&Path>,
) -> Option<GuestExecutableCandidate> {
    command.iter().find_map(|argument| {
        if !argument.to_ascii_lowercase().ends_with(".exe") {
            return None;
        }

        let unix_path = Path::new(argument);
        if unix_path.is_absolute() {
            return is_pe_executable(unix_path).then(|| GuestExecutableCandidate {
                path: unix_path.to_path_buf(),
                source: GuestExecutableSource::AbsoluteUnixArgument,
            });
        }

        if let Some(prefix) = prefix
            && let Some(path) = wine::windows_path_to_unix(prefix, argument)
                .ok()
                .filter(|path| is_pe_executable(path))
        {
            return Some(GuestExecutableCandidate {
                path,
                source: GuestExecutableSource::WindowsDriveArgument,
            });
        }

        working_directory
            .map(|directory| directory.join(unix_path))
            .filter(|path| is_pe_executable(path))
            .map(|path| GuestExecutableCandidate {
                path,
                source: GuestExecutableSource::RelativeUnixArgument,
            })
    })
}

/// Confirms one candidate is an actual PE executable rather than an `.exe` name
fn is_pe_executable(path: &Path) -> bool {
    binary::inspect(path).is_ok_and(|inspection| inspection.format == BinaryFormat::PeExecutable)
}

/// Extracts an absolute host compatdata directory from one command argument
pub(super) fn host_compatdata_path(value: &str) -> Option<PathBuf> {
    // Windows drive paths must first be resolved through a known prefix
    // Treating Z:/ as a Unix root would invent a host path
    if !value.starts_with('/') {
        return None;
    }

    let normalized = value.replace('\\', "/");
    let (root, remainder) = normalized.split_once("/steamapps/compatdata/")?;
    let app_id = remainder.split('/').next()?;
    app_id.parse::<u32>().ok()?;
    Some(PathBuf::from(format!(
        "{root}/steamapps/compatdata/{app_id}"
    )))
}

/// Extracts a Steam application identifier from an absolute host path
pub(super) fn steam_app_id_from_path(value: &str) -> Option<u32> {
    host_compatdata_path(value)?
        .file_name()?
        .to_str()?
        .parse()
        .ok()
}

/// Matches exact Wine runtime process names only
fn is_wine_runtime_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "wine" | "wine64" | "wine-preloader" | "wine64-preloader" | "wineserver" | "proton"
    )
}
