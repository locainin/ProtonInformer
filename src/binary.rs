//! Binary-format inspection and payload validation
//!
//! Loader decisions must come from parsed headers rather than filenames. This
//! module reads each candidate with a strict size cap, identifies its object
//! format, and records the architecture needed by later policy checks

use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use goblin::Object;
use goblin::elf::header::{EM_386, EM_AARCH64, EM_ARM, EM_X86_64, ET_DYN, ET_EXEC};
use goblin::pe::header::{
    COFF_MACHINE_ARM, COFF_MACHINE_ARM64, COFF_MACHINE_X86, COFF_MACHINE_X86_64,
};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::types::Architecture;

// A mod payload should not need hundreds of megabytes of parser input. The cap
// bounds both memory usage and exposure to malformed binary structures
pub const MAX_INSPECTION_SIZE: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryFormat {
    PeDll,
    PeExecutable,
    ElfSharedObject,
    ElfExecutable,
}

impl fmt::Display for BinaryFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::PeDll => "PE DLL",
            Self::PeExecutable => "PE executable",
            Self::ElfSharedObject => "ELF shared object",
            Self::ElfExecutable => "ELF executable",
        };
        formatter.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryInspection {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub extension_warning: Option<String>,
}

impl BinaryInspection {
    /// Returns true only for formats that a loader backend may consume
    #[must_use]
    pub const fn is_loadable_payload(&self) -> bool {
        matches!(
            self.format,
            BinaryFormat::PeDll | BinaryFormat::ElfSharedObject
        )
    }
}

/// Parses a regular file without trusting its extension
///
/// # Errors
///
/// Returns an error for inaccessible, empty, oversized, malformed, or
/// unsupported files
pub fn inspect(path: &Path) -> Result<BinaryInspection> {
    let metadata = fs::metadata(path).map_err(|source| Error::io(path, source))?;

    // Device files and directories are rejected before any read is attempted
    if !metadata.is_file() {
        return Err(Error::InvalidBinary {
            path: path.to_path_buf(),
            reason: "selected path is not a regular file".into(),
        });
    }

    let size_bytes = metadata.len();
    if size_bytes == 0 {
        return Err(Error::EmptyPayload(path.to_path_buf()));
    }
    if size_bytes > MAX_INSPECTION_SIZE {
        return Err(Error::PayloadTooLarge {
            path: path.to_path_buf(),
            limit_bytes: MAX_INSPECTION_SIZE,
        });
    }

    // The reader itself is capped because metadata can become stale before
    // the file is opened or while another process is replacing it
    let bytes = read_capped(path)?;
    let size_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if size_bytes == 0 {
        return Err(Error::EmptyPayload(path.to_path_buf()));
    }

    // Parsed headers decide which loader world applies. Extensions are only
    // compared afterward to produce a warning for confusing filenames
    let (format, architecture) = match Object::parse(&bytes) {
        Ok(Object::PE(pe)) => {
            let format = if pe.is_lib {
                BinaryFormat::PeDll
            } else {
                BinaryFormat::PeExecutable
            };
            (format, architecture_from_pe(pe.header.coff_header.machine))
        }
        Ok(Object::Elf(elf)) => (
            classify_elf(elf.header.e_type, elf.interpreter.is_some(), path)?,
            architecture_from_elf(elf.header.e_machine),
        ),
        Ok(other) => {
            return Err(Error::InvalidBinary {
                path: path.to_path_buf(),
                reason: format!("unsupported object format: {other:?}"),
            });
        }
        Err(source) => {
            return Err(Error::InvalidBinary {
                path: path.to_path_buf(),
                reason: source.to_string(),
            });
        }
    };

    Ok(BinaryInspection {
        path: path.to_path_buf(),
        size_bytes,
        format,
        architecture,
        extension_warning: extension_warning(path, format),
    })
}

/// Reads at most one byte beyond the accepted payload limit
fn read_capped(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path).map_err(|source| Error::io(path, source))?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_INSPECTION_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| Error::io(path, source))?;

    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_INSPECTION_SIZE {
        return Err(Error::PayloadTooLarge {
            path: path.to_path_buf(),
            limit_bytes: MAX_INSPECTION_SIZE,
        });
    }

    Ok(bytes)
}

/// Distinguishes position-independent executables from true shared objects
fn classify_elf(object_type: u16, has_interpreter: bool, path: &Path) -> Result<BinaryFormat> {
    match object_type {
        ET_EXEC => Ok(BinaryFormat::ElfExecutable),
        // Modern PIE executables use ET_DYN but still name a program loader
        ET_DYN if has_interpreter => Ok(BinaryFormat::ElfExecutable),
        ET_DYN => Ok(BinaryFormat::ElfSharedObject),
        other => Err(Error::InvalidBinary {
            path: path.to_path_buf(),
            reason: format!("unsupported ELF object type {other}"),
        }),
    }
}

const fn architecture_from_pe(machine: u16) -> Architecture {
    match machine {
        COFF_MACHINE_X86 => Architecture::X86,
        COFF_MACHINE_X86_64 => Architecture::X86_64,
        COFF_MACHINE_ARM => Architecture::Arm,
        COFF_MACHINE_ARM64 => Architecture::Aarch64,
        _ => Architecture::Unknown,
    }
}

const fn architecture_from_elf(machine: u16) -> Architecture {
    match machine {
        EM_386 => Architecture::X86,
        EM_X86_64 => Architecture::X86_64,
        EM_ARM => Architecture::Arm,
        EM_AARCH64 => Architecture::Aarch64,
        _ => Architecture::Unknown,
    }
}

fn extension_warning(path: &Path, format: BinaryFormat) -> Option<String> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase);

    let expected = match format {
        BinaryFormat::PeDll => Some("dll"),
        BinaryFormat::ElfSharedObject => Some("so"),
        BinaryFormat::PeExecutable => Some("exe"),
        // Native executable names routinely omit extensions, but a misleading
        // module extension should still be called out
        BinaryFormat::ElfExecutable => None,
    };

    match (extension.as_deref(), expected) {
        (Some(actual), Some(expected)) if actual != expected => Some(format!(
            "extension .{actual} does not match detected {format}"
        )),
        (None, Some(_)) => Some(format!(
            "file has no extension; detected format is {format}"
        )),
        (Some(actual), None) => Some(format!(
            "extension .{actual} is unusual for detected {format}"
        )),
        _ => None,
    }
}
