//! Prefix-aware Wine path conversion
//!
//! Wine prefixes define drive letters through symlinks in `dosdevices`
//! Conversion therefore uses the selected prefix's actual mappings instead of
//! assuming that a particular drive, including `Z:`, is configured

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

    // Reject parent traversal before joining user-controlled path components
    let relative = windows_path[3..].replace('\\', "/");
    let relative_path = Path::new(&relative);
    if relative_path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(Error::PathConversion {
            path: windows_path.into(),
            reason: "parent traversal is not allowed".into(),
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
    let mappings = drive_mappings(prefix)?;

    // A more specific mapping such as S:\steamapps is preferable to Z:\
    let (drive, root) = mappings
        .into_iter()
        .filter(|(_, root)| absolute.starts_with(root))
        .max_by_key(|(_, root)| root.components().count())
        .ok_or_else(|| Error::PathConversion {
            path: absolute.display().to_string(),
            reason: "no configured Wine drive contains this path".into(),
        })?;

    let relative = absolute
        .strip_prefix(&root)
        .map_err(|_| Error::PathConversion {
            path: absolute.display().to_string(),
            reason: "selected drive mapping does not contain the path".into(),
        })?;
    let suffix = relative
        .to_str()
        .ok_or_else(|| Error::PathConversion {
            path: absolute.display().to_string(),
            reason: "path is not valid UTF-8 for the Windows helper protocol".into(),
        })?
        .replace('/', "\\");

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
    let dosdevices = prefix.join("dosdevices");
    let entries = fs::read_dir(&dosdevices).map_err(|source| Error::io(&dosdevices, source))?;
    let mut mappings = Vec::new();

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let bytes = name.as_bytes();
        if bytes.len() != 2 || bytes[1] != b':' || !bytes[0].is_ascii_alphabetic() {
            continue;
        }

        // Canonicalization follows relative symlinks such as c: -> ../drive_c
        if let Ok(target) = entry.path().canonicalize() {
            mappings.push(((bytes[0] as char).to_ascii_lowercase(), target));
        }
    }

    mappings.sort_by_key(|(drive, _)| *drive);
    Ok(mappings)
}

fn drive_mapping(prefix: &Path, drive: char) -> Result<PathBuf> {
    drive_mappings(prefix)?
        .into_iter()
        .find_map(|(candidate, path)| (candidate == drive).then_some(path))
        .ok_or_else(|| Error::PathConversion {
            path: format!("{drive}:"),
            reason: format!(
                "drive is not configured in {}",
                prefix.join("dosdevices").display()
            ),
        })
}
