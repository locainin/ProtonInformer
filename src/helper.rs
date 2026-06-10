//! Discovery for replaceable backend helper executables.

use std::env;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::binary::{self, BinaryFormat};
use crate::types::Architecture;

pub const HELPER_DIR_ENV: &str = "PROTON_INFORMER_HELPER_DIR";

/// Finds the configured Wine helper without executing it.
#[must_use]
pub fn find_wine_helper(architecture: Architecture) -> Option<PathBuf> {
    let file_names: &[&str] = match architecture {
        Architecture::X86 => &["proton-informer-win32-helper.exe"],
        Architecture::X86_64 => &["proton-informer-win-helper.exe"],
        Architecture::Arm | Architecture::Aarch64 | Architecture::Unknown => return None,
    };

    helper_directories(architecture)
        .into_iter()
        .flat_map(|directory| {
            file_names
                .iter()
                .map(move |file_name| directory.join(file_name))
        })
        .filter_map(|candidate| candidate.canonicalize().ok())
        .find(|candidate| {
            helper_permissions_are_trusted(candidate)
                && binary::inspect(candidate).is_ok_and(|inspection| {
                    inspection.format == BinaryFormat::PeExecutable
                        && inspection.architecture == architecture
                })
        })
}

/// Returns the absolute helper-directory environment override.
#[must_use]
pub fn helper_dir_env_override() -> Option<PathBuf> {
    env::var_os(HELPER_DIR_ENV)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

/// Reports whether one selected helper came from the environment override.
#[must_use]
pub fn helper_uses_env_override(path: &Path) -> bool {
    helper_dir_env_override()
        .and_then(|directory| directory.canonicalize().ok())
        .is_some_and(|directory| path.starts_with(directory))
}

/// Checks whether an executable name is available through PATH.
#[must_use]
pub fn command_exists(command: &str) -> bool {
    find_command(command).is_some()
}

/// Finds one executable command through `PATH`.
#[must_use]
pub fn find_command(command: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;

    env::split_paths(&path)
        .map(|directory| directory.join(command))
        .find(|candidate| is_executable(candidate))
}

/// Checks the regular-file and Unix executable permission bits.
#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.is_file()
        && path
            .metadata()
            .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
}

/// Uses the platform's regular-file behavior where Unix mode bits are absent.
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

/// Rejects helpers or containing directories writable by group or other users.
pub(crate) fn helper_permissions_are_trusted(path: &Path) -> bool {
    let file_trusted = path
        .metadata()
        .is_ok_and(|metadata| metadata.permissions().mode() & 0o022 == 0);
    let directory_trusted = path
        .parent()
        .and_then(|directory| directory.metadata().ok())
        .is_some_and(|metadata| metadata.permissions().mode() & 0o022 == 0);
    file_trusted && directory_trusted
}
