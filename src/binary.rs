//! Bounded PE-format inspection and payload validation
//!
//! Loader decisions come from the small set of PE headers needed by policy
//! File identity and hashing stay separate from format inspection

use std::fmt;
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::types::Architecture;

// The payload size policy remains bounded even though inspection no longer
// allocates the whole file
pub const MAX_INSPECTION_SIZE: u64 = 256 * 1024 * 1024;

const DOS_HEADER_SIZE: usize = 64;
const PE_SIGNATURE_COFF_SIZE: usize = 24;
const SECTION_HEADER_SIZE: u64 = 40;
const MAX_SECTION_COUNT: u16 = 96;
const IMAGE_FILE_DLL: u16 = 0x2000;
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_MACHINE_ARM: u16 = 0x01c0;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const PE32_MAGIC: u16 = 0x010b;
const PE32_PLUS_MAGIC: u16 = 0x020b;
const PE32_MIN_OPTIONAL_HEADER_SIZE: u16 = 96;
const PE32_PLUS_MIN_OPTIONAL_HEADER_SIZE: u16 = 112;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryFormat {
    PeDll,
    PeExecutable,
}

impl fmt::Display for BinaryFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::PeDll => "PE DLL",
            Self::PeExecutable => "PE executable",
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
    /// Returns true only for the Windows PE DLL backend
    #[must_use]
    pub const fn is_loadable_payload(&self) -> bool {
        matches!(self.format, BinaryFormat::PeDll)
    }
}

/// Inspects a regular PE file without trusting its extension
///
/// # Errors
///
/// Returns an error for inaccessible, empty, oversized, malformed, or
/// unsupported files
pub fn inspect(path: &Path) -> Result<BinaryInspection> {
    let metadata = fs::metadata(path).map_err(|source| Error::io(path, source))?;

    // Device files and directories are rejected before any header read
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

    // Only DOS, PE, COFF, and optional-header fields are read
    let file = File::open(path).map_err(|source| Error::io(path, source))?;
    let (format, architecture) = parse_pe_headers(&file, size_bytes, path)?;

    // Detect a replacement during the bounded read before returning identity
    let final_size = file
        .metadata()
        .map_err(|source| Error::io(path, source))?
        .len();
    if final_size != size_bytes {
        return Err(Error::InvalidBinary {
            path: path.to_path_buf(),
            reason: format!(
                "file changed during header inspection: expected {size_bytes} bytes, found {final_size}"
            ),
        });
    }

    Ok(BinaryInspection {
        path: path.to_path_buf(),
        size_bytes,
        format,
        architecture,
        extension_warning: extension_warning(path, format),
    })
}

/// Parses only the bounded header fields needed by loader policy
fn parse_pe_headers(
    file: &File,
    size_bytes: u64,
    path: &Path,
) -> Result<(BinaryFormat, Architecture)> {
    if size_bytes < DOS_HEADER_SIZE as u64 {
        return Err(invalid_binary(path, "file is shorter than the DOS header"));
    }

    let mut dos_header = [0_u8; DOS_HEADER_SIZE];
    read_exact_at(file, 0, &mut dos_header, path, "DOS header")?;
    if dos_header.get(..2) != Some(b"MZ") {
        return Err(invalid_binary(path, "payload does not have an MZ header"));
    }

    let pe_offset = u64::from(u32::from_le_bytes(
        dos_header[0x3c..0x40]
            .try_into()
            .map_err(|_| invalid_binary(path, "invalid DOS header"))?,
    ));
    let pe_header_end = pe_offset
        .checked_add(PE_SIGNATURE_COFF_SIZE as u64)
        .ok_or_else(|| invalid_binary(path, "PE header offset overflowed"))?;
    if pe_header_end > size_bytes {
        return Err(invalid_binary(path, "file ends before the PE header"));
    }

    let mut pe_header = [0_u8; PE_SIGNATURE_COFF_SIZE];
    read_exact_at(file, pe_offset, &mut pe_header, path, "PE header")?;
    if pe_header.get(..4) != Some(b"PE\0\0") {
        return Err(invalid_binary(path, "payload does not have a PE signature"));
    }

    let machine = u16::from_le_bytes([pe_header[4], pe_header[5]]);
    let section_count = u16::from_le_bytes([pe_header[6], pe_header[7]]);
    let optional_header_size = u16::from_le_bytes([pe_header[20], pe_header[21]]);
    let characteristics = u16::from_le_bytes([pe_header[22], pe_header[23]]);
    if !(1..=MAX_SECTION_COUNT).contains(&section_count) {
        return Err(invalid_binary(
            path,
            "PE section count is outside the supported structural limit",
        ));
    }
    if characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
        return Err(invalid_binary(
            path,
            "PE header is not marked as an executable image",
        ));
    }

    let optional_magic = validate_optional_header_and_sections(
        file,
        size_bytes,
        path,
        pe_header_end,
        optional_header_size,
        section_count,
    )?;

    let architecture = architecture_from_pe(machine);
    let expected_magic = match architecture {
        Architecture::X86 | Architecture::Arm => PE32_MAGIC,
        Architecture::X86_64 | Architecture::Aarch64 => PE32_PLUS_MAGIC,
        Architecture::Unknown => return Err(invalid_binary(path, "PE architecture is unknown")),
    };
    if optional_magic != expected_magic {
        return Err(invalid_binary(
            path,
            "PE optional-header magic does not match the machine architecture",
        ));
    }

    let format = if characteristics & IMAGE_FILE_DLL != 0 {
        BinaryFormat::PeDll
    } else {
        BinaryFormat::PeExecutable
    };
    Ok((format, architecture))
}

/// Validates optional-header size and the declared section-table range
fn validate_optional_header_and_sections(
    file: &File,
    size_bytes: u64,
    path: &Path,
    optional_header_offset: u64,
    optional_header_size: u16,
    section_count: u16,
) -> Result<u16> {
    let optional_header_end = optional_header_offset
        .checked_add(u64::from(optional_header_size))
        .ok_or_else(|| invalid_binary(path, "optional-header offset overflowed"))?;
    if optional_header_end > size_bytes {
        return Err(invalid_binary(path, "file ends before the optional header"));
    }

    let mut optional_magic_bytes = [0_u8; 2];
    read_exact_at(
        file,
        optional_header_offset,
        &mut optional_magic_bytes,
        path,
        "PE optional header",
    )?;
    let optional_magic = u16::from_le_bytes(optional_magic_bytes);
    let minimum_optional_header_size = match optional_magic {
        PE32_MAGIC => PE32_MIN_OPTIONAL_HEADER_SIZE,
        PE32_PLUS_MAGIC => PE32_PLUS_MIN_OPTIONAL_HEADER_SIZE,
        _ => {
            return Err(invalid_binary(
                path,
                "PE optional-header magic is not PE32 or PE32+",
            ));
        }
    };
    if optional_header_size < minimum_optional_header_size {
        return Err(invalid_binary(
            path,
            "PE optional header is shorter than its mandatory fields",
        ));
    }

    // The section table follows the declared optional header exactly
    let section_table_size = u64::from(section_count)
        .checked_mul(SECTION_HEADER_SIZE)
        .ok_or_else(|| invalid_binary(path, "PE section table size overflowed"))?;
    let section_table_end = optional_header_end
        .checked_add(section_table_size)
        .ok_or_else(|| invalid_binary(path, "PE section table offset overflowed"))?;
    if section_table_end > size_bytes {
        return Err(invalid_binary(
            path,
            "file ends before the declared PE section table",
        ));
    }

    Ok(optional_magic)
}

/// Reads one addressed header range without allocating file-sized memory
fn read_exact_at(
    file: &File,
    offset: u64,
    buffer: &mut [u8],
    path: &Path,
    label: &str,
) -> Result<()> {
    let mut file = file;
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| Error::io(path, source))?;
    file.read_exact(buffer).map_err(|source| {
        if source.kind() == ErrorKind::UnexpectedEof {
            invalid_binary(path, format!("file ends while reading {label}"))
        } else {
            Error::io(path, source)
        }
    })
}

fn invalid_binary(path: &Path, reason: impl Into<String>) -> Error {
    Error::InvalidBinary {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

const fn architecture_from_pe(machine: u16) -> Architecture {
    match machine {
        IMAGE_FILE_MACHINE_I386 => Architecture::X86,
        IMAGE_FILE_MACHINE_AMD64 => Architecture::X86_64,
        IMAGE_FILE_MACHINE_ARM => Architecture::Arm,
        IMAGE_FILE_MACHINE_ARM64 => Architecture::Aarch64,
        _ => Architecture::Unknown,
    }
}

fn extension_warning(path: &Path, format: BinaryFormat) -> Option<String> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase);

    let expected = match format {
        BinaryFormat::PeDll => "dll",
        BinaryFormat::PeExecutable => "exe",
    };

    match extension.as_deref() {
        Some(actual) if actual != expected => Some(format!(
            "extension .{actual} does not match detected {format}"
        )),
        None => Some(format!(
            "file has no extension; detected format is {format}"
        )),
        _ => None,
    }
}
