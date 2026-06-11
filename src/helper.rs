//! Discovery for replaceable backend helper executables

use std::env;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::binary::{self, BinaryFormat};
use crate::types::Architecture;

pub const HELPER_DIR_ENV: &str = "PROTON_INFORMER_HELPER_DIR";
const ROOT_UID: u32 = 0;

/// Finds the configured Wine helper without executing it
#[must_use]
pub fn find_wine_helper(architecture: Architecture) -> Option<PathBuf> {
    wine_helper_candidates(architecture)
        .into_iter()
        .find(|candidate| {
            helper_permissions_are_trusted(candidate)
                && binary::inspect(candidate).is_ok_and(|inspection| {
                    inspection.format == BinaryFormat::PeExecutable
                        && inspection.architecture == architecture
                })
        })
}

pub(crate) fn wine_helper_candidates(architecture: Architecture) -> Vec<PathBuf> {
    let Some(file_names) = helper_file_names(architecture) else {
        return Vec::new();
    };

    // Keep raw paths so symlink checks see the helper name that lookup found
    helper_directories(architecture)
        .into_iter()
        .flat_map(|directory| {
            file_names
                .iter()
                .map(move |file_name| directory.join(file_name))
        })
        .collect()
}

/// Returns the absolute helper-directory environment override
#[must_use]
pub fn helper_dir_env_override() -> Option<PathBuf> {
    env::var_os(HELPER_DIR_ENV)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

/// Reports whether one selected helper came from the environment override
#[must_use]
pub fn helper_uses_env_override(path: &Path) -> bool {
    helper_dir_env_override()
        .and_then(|directory| directory.canonicalize().ok())
        // Source reporting can follow the final trusted helper path safely
        .zip(path.canonicalize().ok())
        .is_some_and(|(directory, helper)| helper.starts_with(directory))
}

/// Checks whether an executable name is available through PATH
#[must_use]
pub fn command_exists(command: &str) -> bool {
    find_command(command).is_some()
}

/// Finds one executable command through `PATH`
#[must_use]
pub fn find_command(command: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;

    env::split_paths(&path)
        .map(|directory| directory.join(command))
        .find(|candidate| is_executable(candidate))
}

/// Checks the regular-file and Unix executable permission bits
#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.is_file()
        && path
            .metadata()
            .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
}

/// Uses the platform's regular-file behavior where Unix mode bits are absent
#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

fn helper_directories(architecture: Architecture) -> Vec<PathBuf> {
    let mut directories = Vec::new();

    if let Some(configured) = helper_dir_env_override() {
        directories.push(configured);
    }
    if let Ok(executable) = env::current_exe()
        && let Some(parent) = executable.parent()
    {
        directories.push(parent.join("helpers"));
        if let Some(target_root) = parent.parent() {
            let rust_target = match architecture {
                Architecture::X86 => "i686-pc-windows-gnu",
                Architecture::X86_64 => "x86_64-pc-windows-gnu",
                Architecture::Arm | Architecture::Aarch64 | Architecture::Unknown => {
                    return directories;
                }
            };
            directories.push(target_root.join(rust_target).join("release"));
            directories.push(target_root.join(rust_target).join("debug"));
        }
    }
    directories.push(Path::new("/usr/lib/proton-informer/helpers").to_path_buf());

    directories
}

const fn helper_file_names(architecture: Architecture) -> Option<&'static [&'static str]> {
    match architecture {
        Architecture::X86 => Some(&["proton-informer-win32-helper.exe"]),
        Architecture::X86_64 => Some(&["proton-informer-win-helper.exe"]),
        Architecture::Arm | Architecture::Aarch64 | Architecture::Unknown => None,
    }
}

/// Returns why a helper path cannot be trusted before execution
#[must_use]
pub fn helper_trust_error(path: &Path) -> Option<String> {
    let Some(current_uid) = current_uid() else {
        return Some("current user id could not be read from procfs".into());
    };
    // Do not follow helper symlinks before checking the selected file itself
    let file = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return Some(format!(
                "helper file cannot be inspected: {}: {error}",
                path.display()
            ));
        }
    };
    if file.file_type().is_symlink() {
        return Some(format!("helper file is a symlink: {}", path.display()));
    }
    if !file.is_file() {
        return Some(format!(
            "helper path is not a regular file: {}",
            path.display()
        ));
    }
    if !trusted_owner(file.uid(), current_uid) {
        return Some(format!(
            "helper file is not owned by the current user or root: {}",
            path.display()
        ));
    }
    // A writable helper can change between verification and execution
    if file.permissions().mode() & 0o022 != 0 {
        return Some(format!(
            "helper file is group-writable or world-writable: {}",
            path.display()
        ));
    }

    let Some(directory) = path.parent() else {
        return Some(format!(
            "helper path has no parent directory: {}",
            path.display()
        ));
    };
    // The parent controls replacement of the helper filename
    let directory_metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) => {
            return Some(format!(
                "helper directory cannot be inspected: {}: {error}",
                directory.display()
            ));
        }
    };
    if directory_metadata.file_type().is_symlink() {
        return Some(format!(
            "helper directory is a symlink: {}",
            directory.display()
        ));
    }
    if !directory_metadata.is_dir() {
        return Some(format!(
            "helper parent is not a real directory: {}",
            directory.display()
        ));
    }
    if !trusted_owner(directory_metadata.uid(), current_uid) {
        return Some(format!(
            "helper directory is not owned by the current user or root: {}",
            directory.display()
        ));
    }
    // Directory write access would allow swapping a trusted helper path
    if directory_metadata.permissions().mode() & 0o022 != 0 {
        return Some(format!(
            "helper directory is group-writable or world-writable: {}",
            directory.display()
        ));
    }

    None
}

/// Rejects helpers or containing directories with unsafe ownership or mode
pub(crate) fn helper_permissions_are_trusted(path: &Path) -> bool {
    helper_trust_error(path).is_none()
}

const fn trusted_owner(owner_uid: u32, current_uid: u32) -> bool {
    owner_uid == ROOT_UID || owner_uid == current_uid
}

fn current_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find(|line| line.starts_with("Uid:"))?
        .split_ascii_whitespace()
        .nth(2)?
        .parse()
        .ok()
}
