//! Bounded PE import-table parsing for dependency preflight.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::HelperFailure;

const IMAGE_DIRECTORY_ENTRY_IMPORT: u64 = 1;
const IMPORT_DESCRIPTOR_BYTES: usize = 20;
const MAX_IMPORTS: usize = 4_096;
const MAX_IMPORT_NAME_BYTES: usize = 260;
const SECTION_HEADER_BYTES: usize = 40;

/// One PE section mapping from virtual address to file offset.
struct Section {
    raw_offset: u32,
    raw_size: u32,
    virtual_address: u32,
    virtual_size: u32,
}

/// Returns imported DLL basenames without loading the whole payload into RAM.
pub fn dll_names(path: &Path) -> Result<Vec<String>, HelperFailure> {
    let mut file = File::open(path)
        .map_err(|source| HelperFailure::io("unable to open PE imports", source))?;
    let mut dos = [0_u8; 64];
    file.read_exact(&mut dos)
        .map_err(|source| HelperFailure::io("unable to read PE DOS header", source))?;
    if dos.get(..2) != Some(b"MZ") {
        return Err(HelperFailure::Validation(
            "payload does not have an MZ header".into(),
        ));
    }
    let pe_offset =
        u64::from(u32::from_le_bytes(dos[0x3c..0x40].try_into().map_err(
            |_| HelperFailure::Validation("invalid DOS header".into()),
        )?));
    file.seek(SeekFrom::Start(pe_offset))
        .map_err(|source| HelperFailure::io("unable to seek to PE header", source))?;
    let mut coff = [0_u8; 24];
    file.read_exact(&mut coff)
        .map_err(|source| HelperFailure::io("unable to read PE header", source))?;
    if coff.get(..4) != Some(b"PE\0\0") {
        return Err(HelperFailure::Validation(
            "payload does not have a PE signature".into(),
        ));
    }

    let section_count = usize::from(u16::from_le_bytes([coff[6], coff[7]]));
    let optional_size = usize::from(u16::from_le_bytes([coff[20], coff[21]]));
    let optional_offset = pe_offset
        .checked_add(24)
        .ok_or_else(|| HelperFailure::Validation("optional header offset overflow".into()))?;
    let mut optional = vec![0_u8; optional_size];
    file.read_exact(&mut optional)
        .map_err(|source| HelperFailure::io("unable to read PE optional header", source))?;
    let magic = read_u16(&optional, 0)?;
    let data_directory_offset = match magic {
        0x010b => 96_usize,
        0x020b => 112_usize,
        _ => {
            return Err(HelperFailure::Validation(format!(
                "unsupported PE optional header magic {magic:#06x}"
            )));
        }
    };
    let import_entry = data_directory_offset
        .checked_add(
            usize::try_from(IMAGE_DIRECTORY_ENTRY_IMPORT * 8)
                .map_err(|_| HelperFailure::Validation("import directory overflow".into()))?,
        )
        .ok_or_else(|| HelperFailure::Validation("import directory offset overflow".into()))?;
    let import_rva = read_u32(&optional, import_entry)?;
    let import_size = read_u32(&optional, import_entry + 4)?;
    if import_rva == 0 || import_size == 0 {
        return Ok(Vec::new());
    }

    let section_offset = optional_offset
        .checked_add(
            u64::try_from(optional_size)
                .map_err(|_| HelperFailure::Validation("optional header size overflow".into()))?,
        )
        .ok_or_else(|| HelperFailure::Validation("section table offset overflow".into()))?;
    file.seek(SeekFrom::Start(section_offset))
        .map_err(|source| HelperFailure::io("unable to seek to section table", source))?;
    let sections = read_sections(&mut file, section_count)?;
    let import_offset = rva_to_offset(import_rva, &sections)?;
    file.seek(SeekFrom::Start(u64::from(import_offset)))
        .map_err(|source| HelperFailure::io("unable to seek to import table", source))?;

    let descriptor_limit = usize::try_from(import_size)
        .unwrap_or(usize::MAX)
        .checked_div(IMPORT_DESCRIPTOR_BYTES)
        .unwrap_or(0)
        .min(MAX_IMPORTS);
    let mut descriptors = Vec::new();
    for _ in 0..descriptor_limit {
        let mut descriptor = [0_u8; IMPORT_DESCRIPTOR_BYTES];
        file.read_exact(&mut descriptor)
            .map_err(|source| HelperFailure::io("unable to read import descriptor", source))?;
        if descriptor.iter().all(|byte| *byte == 0) {
            break;
        }
        descriptors.push(u32::from_le_bytes(descriptor[12..16].try_into().map_err(
            |_| HelperFailure::Validation("invalid import descriptor".into()),
        )?));
    }

    let mut imports = Vec::with_capacity(descriptors.len());
    for name_rva in descriptors {
        let name_offset = rva_to_offset(name_rva, &sections)?;
        file.seek(SeekFrom::Start(u64::from(name_offset)))
            .map_err(|source| HelperFailure::io("unable to seek to import name", source))?;
        imports.push(read_c_string(&mut file)?);
    }
    imports.sort_unstable_by_key(|name| name.to_ascii_lowercase());
    imports.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    Ok(imports)
}

/// Reads section mappings with a strict count from the validated COFF header.
fn read_sections(file: &mut File, count: usize) -> Result<Vec<Section>, HelperFailure> {
    let mut sections = Vec::with_capacity(count);
    for _ in 0..count {
        let mut header = [0_u8; SECTION_HEADER_BYTES];
        file.read_exact(&mut header)
            .map_err(|source| HelperFailure::io("unable to read section header", source))?;
        sections.push(Section {
            virtual_size: u32::from_le_bytes(
                header[8..12]
                    .try_into()
                    .map_err(|_| HelperFailure::Validation("invalid section header".into()))?,
            ),
            virtual_address: u32::from_le_bytes(
                header[12..16]
                    .try_into()
                    .map_err(|_| HelperFailure::Validation("invalid section header".into()))?,
            ),
            raw_size: u32::from_le_bytes(
                header[16..20]
                    .try_into()
                    .map_err(|_| HelperFailure::Validation("invalid section header".into()))?,
            ),
            raw_offset: u32::from_le_bytes(
                header[20..24]
                    .try_into()
                    .map_err(|_| HelperFailure::Validation("invalid section header".into()))?,
            ),
        });
    }
    Ok(sections)
}

/// Converts one image-relative address into a checked file offset.
fn rva_to_offset(rva: u32, sections: &[Section]) -> Result<u32, HelperFailure> {
    sections
        .iter()
        .find_map(|section| {
            let span = section.virtual_size.max(section.raw_size);
            let end = section.virtual_address.checked_add(span)?;
            if rva < section.virtual_address || rva >= end {
                return None;
            }
            section
                .raw_offset
                .checked_add(rva - section.virtual_address)
        })
        .ok_or_else(|| {
            HelperFailure::Validation(format!(
                "PE import RVA {rva:#010x} is outside file-backed sections"
            ))
        })
}

/// Reads one bounded ASCII import name.
fn read_c_string(file: &mut File) -> Result<String, HelperFailure> {
    let mut bytes = Vec::with_capacity(32);
    for _ in 0..MAX_IMPORT_NAME_BYTES {
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte)
            .map_err(|source| HelperFailure::io("unable to read import name", source))?;
        if byte[0] == 0 {
            return String::from_utf8(bytes).map_err(|error| {
                HelperFailure::Validation(format!("import name is not UTF-8: {error}"))
            });
        }
        if !byte[0].is_ascii() {
            return Err(HelperFailure::Validation(
                "import name contains non-ASCII bytes".into(),
            ));
        }
        bytes.push(byte[0]);
    }
    Err(HelperFailure::Validation(
        "import name exceeds the 260-byte limit".into(),
    ))
}

/// Reads one little-endian word from a bounded optional header.
fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, HelperFailure> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| HelperFailure::Validation("PE offset overflow".into()))?;
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or_else(|| HelperFailure::Validation("PE header is truncated".into()))?
            .try_into()
            .map_err(|_| HelperFailure::Validation("PE header is truncated".into()))?,
    ))
}

/// Reads one little-endian double word from a bounded optional header.
fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, HelperFailure> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| HelperFailure::Validation("PE offset overflow".into()))?;
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or_else(|| HelperFailure::Validation("PE header is truncated".into()))?
            .try_into()
            .map_err(|_| HelperFailure::Validation("PE header is truncated".into()))?,
    ))
}
