//! Prefix-aware Wine path conversion
//!
//! Wine prefixes define drive letters through symlinks in `dosdevices`
//! Conversion therefore uses the selected prefix's actual mappings instead of
//! assuming that a particular drive, including `Z:`, is configured

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

/// Converts an absolute Windows drive path through a prefix's configured drives
///
/// # Errors
///
/// Returns an error for invalid drive syntax, parent traversal, or a drive that
/// is absent from the selected prefix
pub fn windows_path_to_unix(prefix: &Path, windows_path: &str) -> Result<PathBuf> {
    let bytes = windows_path.as_bytes();
    if bytes.len() < 3 || bytes[1] != b':' || !bytes[0].is_ascii_alphabetic() {
        return Err(Error::PathConversion {
            path: windows_path.into(),
            reason: "expected an absolute drive path such as C:\\game\\file.dll".into(),
        });
    }

    let drive = (bytes[0] as char).to_ascii_lowercase();
    let separator = bytes[2];
    if separator != b'\\' && separator != b'/' {
        return Err(Error::PathConversion {
            path: windows_path.into(),
            reason: "drive-relative Windows paths are not supported".into(),
        });
    }

    // Normalize separators before checking the path as a host-relative value
    let relative = windows_path[3..].replace('\\', "/");
    let relative_path = Path::new(&relative);
    for component in relative_path.components() {
        match component {
            // An absolute RHS would discard the selected drive mapping in join
            Component::RootDir | Component::Prefix(_) => {
                return Err(Error::PathConversion {
                    path: windows_path.into(),
                    reason: "rooted path components are not allowed after the drive root".into(),
                });
            }
            // Parent traversal must never be normalized through a drive root
            Component::ParentDir => {
                return Err(Error::PathConversion {
                    path: windows_path.into(),
                    reason: "parent traversal is not allowed".into(),
                });
            }
            Component::CurDir => {}
            Component::Normal(component) => {
                let component = component.to_str().ok_or_else(|| Error::PathConversion {
                    path: windows_path.into(),
                    reason: "Windows path component is not valid UTF-8".into(),
                })?;
                validate_windows_component(Path::new(windows_path), component)?;
            }
        }
    }
    if !relative_path.is_relative() {
        return Err(Error::PathConversion {
            path: windows_path.into(),
            reason: "path after the drive root must remain relative".into(),
        });
    }

    let mapping = drive_mapping(prefix, drive)?;
    Ok(mapping.join(relative_path))
}

/// Converts an existing Unix path using the longest matching configured drive
///
/// # Errors
///
/// Returns an error when the path cannot be canonicalized, no configured drive
/// contains it, or it cannot be encoded for the helper protocol
pub fn unix_path_to_windows(prefix: &Path, unix_path: &Path) -> Result<String> {
    let absolute = unix_path
        .canonicalize()
        .map_err(|source| Error::io(unix_path, source))?;
    let report = inspect_drive_mappings(prefix)?;

    // A more specific mapping such as S:\steamapps is preferable to Z:\
    let Some((drive, root)) = report
        .mappings
        .iter()
        .filter(|(_, root)| absolute.starts_with(root))
        .max_by_key(|(_, root)| root.components().count())
    else {
        let relevant_ambiguity = report.ambiguities.iter().find(|ambiguity| {
            ambiguity
                .roots
                .iter()
                .any(|root| absolute.starts_with(root))
        });
        if let Some(ambiguity) = relevant_ambiguity {
            return Err(Error::AmbiguousDriveMapping {
                drive: ambiguity.drive,
                roots: ambiguity.roots.clone(),
            });
        }
        if let Some(failure) = report.failures.first() {
            return Err(Error::DriveMappingInspectionIncomplete {
                path: absolute.display().to_string(),
                details: failure.to_string(),
            });
        }
        return Err(Error::NoDriveMappingForPath {
            path: absolute.display().to_string(),
        });
    };

    let relative = absolute
        .strip_prefix(root)
        .map_err(|_| Error::PathConversion {
            path: absolute.display().to_string(),
            reason: "selected drive mapping does not contain the path".into(),
        })?;
    let mut suffix = String::new();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(Error::PathConversion {
                path: absolute.display().to_string(),
                reason: "canonical relative path contains an unsupported component".into(),
            });
        };
        let component = component.to_str().ok_or_else(|| Error::PathConversion {
            path: absolute.display().to_string(),
            reason: "path is not valid UTF-8 for the Windows helper protocol".into(),
        })?;
        validate_windows_component(&absolute, component)?;
        if !suffix.is_empty() {
            suffix.push('\\');
        }
        suffix.push_str(component);
    }

    if suffix.is_empty() {
        Ok(format!("{drive}:\\"))
    } else {
        Ok(format!("{drive}:\\{suffix}"))
    }
}

/// Returns every usable single-letter drive mapping from `dosdevices`
///
/// # Errors
///
/// Returns an error when the prefix's `dosdevices` directory cannot be read
pub fn drive_mappings(prefix: &Path) -> Result<Vec<(char, PathBuf)>> {
    let report = inspect_drive_mappings(prefix)?;
    if let Some(ambiguity) = report.ambiguities.first() {
        return Err(Error::AmbiguousDriveMapping {
            drive: ambiguity.drive,
            roots: ambiguity.roots.clone(),
        });
    }
    if let Some(failure) = report.failures.first() {
        return Err(Error::DriveMappingInspectionIncomplete {
            path: prefix.join("dosdevices").display().to_string(),
            details: failure.to_string(),
        });
    }
    Ok(report.mappings)
}

fn drive_mapping(prefix: &Path, drive: char) -> Result<PathBuf> {
    let report = inspect_drive_mappings(prefix)?;
    if let Some(ambiguity) = report
        .ambiguities
        .iter()
        .find(|ambiguity| ambiguity.drive == drive)
    {
        return Err(Error::AmbiguousDriveMapping {
            drive,
            roots: ambiguity.roots.clone(),
        });
    }
    if let Some(failure) = report
        .failures
        .iter()
        .find(|failure| failure.drive == drive)
    {
        return Err(Error::DriveMappingInspectionIncomplete {
            path: format!("{drive}:"),
            details: failure.to_string(),
        });
    }
    if let Some((_, root)) = report
        .mappings
        .into_iter()
        .find(|(mapped_drive, _)| *mapped_drive == drive)
    {
        return Ok(root);
    }

    Err(Error::PathConversion {
        path: format!("{drive}:"),
        reason: format!(
            "drive is not configured in {}",
            prefix.join("dosdevices").display()
        ),
    })
}

/// Canonicalized mappings and failures from unrelated mappings
pub(crate) struct DriveMappingReport {
    pub(crate) failures: Vec<DriveMappingFailure>,
    pub(crate) mappings: Vec<(char, PathBuf)>,
    pub(crate) ambiguities: Vec<DriveMappingAmbiguity>,
}

/// One mapping that could not be inspected without hiding its reason
pub(crate) struct DriveMappingFailure {
    pub(crate) drive: char,
    path: PathBuf,
    error: std::io::Error,
}

impl std::fmt::Display for DriveMappingFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.path.display(), self.error)
    }
}

/// One drive letter that resolves to more than one canonical root
pub(crate) struct DriveMappingAmbiguity {
    pub(crate) drive: char,
    pub(crate) roots: Vec<PathBuf>,
}

/// Inspects every mapping while keeping broken entries separate from valid ones
pub(crate) fn inspect_drive_mappings(prefix: &Path) -> Result<DriveMappingReport> {
    let dosdevices = prefix.join("dosdevices");
    let entries = fs::read_dir(&dosdevices).map_err(|source| Error::io(&dosdevices, source))?;
    let mut roots_by_drive: BTreeMap<char, Vec<PathBuf>> = BTreeMap::new();
    let mut failures = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|source| Error::io(&dosdevices, source))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(drive) = parse_drive_name(name) else {
            continue;
        };
        let path = entry.path();
        match path.canonicalize() {
            Ok(target) => roots_by_drive.entry(drive).or_default().push(target),
            Err(error) => failures.push(DriveMappingFailure { drive, path, error }),
        }
    }

    let mut mappings = Vec::new();
    let mut ambiguities = Vec::new();
    for (drive, roots) in roots_by_drive {
        if failures.iter().any(|failure| failure.drive == drive) {
            continue;
        }
        let unique_roots = roots.into_iter().collect::<BTreeSet<_>>();
        if unique_roots.len() == 1 {
            if let Some(root) = unique_roots.into_iter().next() {
                mappings.push((drive, root));
            }
        } else {
            ambiguities.push(DriveMappingAmbiguity {
                drive,
                roots: unique_roots.into_iter().collect(),
            });
        }
    }

    Ok(DriveMappingReport {
        failures,
        mappings,
        ambiguities,
    })
}

/// Parses only the single-letter drive names used by Wine dosdevices
fn parse_drive_name(name: &str) -> Option<char> {
    let bytes = name.as_bytes();
    (bytes.len() == 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic())
        .then(|| (bytes[0] as char).to_ascii_lowercase())
}

/// Rejects host names that Win32 would reinterpret rather than preserve
fn validate_windows_component(path: &Path, component: &str) -> Result<()> {
    if component.is_empty()
        || component
            .chars()
            .any(|character| character.is_ascii_control() || "\\/:*?\"<>|".contains(character))
        || component.ends_with(' ')
        || component.ends_with('.')
        || is_reserved_device_name(component)
    {
        return Err(Error::PathConversion {
            path: path.display().to_string(),
            reason: format!(
                "Unix component cannot be represented losslessly in Win32: {component:?}"
            ),
        });
    }
    Ok(())
}

/// Recognizes DOS device names that would not address an ordinary file
fn is_reserved_device_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    let uppercase = stem.to_ascii_uppercase();
    matches!(
        uppercase.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "COM¹"
            | "COM²"
            | "COM³"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
            | "LPT¹"
            | "LPT²"
            | "LPT³"
    )
}
