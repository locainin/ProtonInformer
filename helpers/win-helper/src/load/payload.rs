//! Payload path, identity, hash, and PE header validation

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use proton_informer_helper_protocol::{
    HelperPayload, MAX_PAYLOAD_SIZE_BYTES, ProtocolArchitecture,
};
use sha2::{Digest, Sha256};

use crate::error::HelperFailure;

const HEX: &[u8; 16] = b"0123456789abcdef";
const IMAGE_FILE_DLL: u16 = 0x2000;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const PE32_MAGIC: u16 = 0x010b;
const PE32_PLUS_MAGIC: u16 = 0x020b;

/// Accepts absolute drive or UNC paths without relative parent components
pub(super) fn is_absolute_windows_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    let drive_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    let unc = bytes.len() >= 5
        && matches!(bytes[0], b'\\' | b'/')
        && matches!(bytes[1], b'\\' | b'/')
        && !matches!(bytes[2], b'\\' | b'/');
    (drive_absolute || unc)
        && !path.contains('\0')
        && !path.split(['\\', '/']).any(|component| component == "..")
}

/// Confirms the helper sees the same immutable payload facts as the controller
pub(super) fn validate_payload(
    payload: &HelperPayload,
    canonical_path: &str,
    expected_architecture: ProtocolArchitecture,
) -> Result<(), HelperFailure> {
    let path = Path::new(canonical_path);
    let metadata = path
        .metadata()
        .map_err(|source| HelperFailure::io("unable to inspect payload", source))?;
    if !metadata.is_file() || metadata.len() != payload.size_bytes {
        return Err(HelperFailure::PayloadChanged(format!(
            "payload size changed: expected {}, found {}",
            payload.size_bytes,
            metadata.len()
        )));
    }
    if payload.size_bytes > MAX_PAYLOAD_SIZE_BYTES {
        return Err(HelperFailure::Validation(format!(
            "payload exceeds the {MAX_PAYLOAD_SIZE_BYTES}-byte limit"
        )));
    }
    let actual_hash = sha256_file(path, payload.size_bytes)?;
    if actual_hash != payload.sha256 {
        return Err(HelperFailure::PayloadChanged(
            "payload SHA-256 changed after controller validation".into(),
        ));
    }
    validate_pe_dll(path, expected_architecture)?;
    Ok(())
}

/// Reads only the DOS and COFF headers needed to prove PE DLL identity
fn validate_pe_dll(
    path: &Path,
    expected_architecture: ProtocolArchitecture,
) -> Result<(), HelperFailure> {
    let mut file = File::open(path)
        .map_err(|source| HelperFailure::io("unable to open payload headers", source))?;
    let mut dos_header = [0_u8; 64];
    file.read_exact(&mut dos_header)
        .map_err(|source| HelperFailure::io("unable to read DOS header", source))?;
    if dos_header.get(..2) != Some(b"MZ") {
        return Err(HelperFailure::Validation(
            "payload does not have an MZ header".into(),
        ));
    }
    let pe_offset = u64::from(u32::from_le_bytes(
        dos_header[0x3c..0x40]
            .try_into()
            .map_err(|_| HelperFailure::Validation("invalid DOS header".into()))?,
    ));
    file.seek(SeekFrom::Start(pe_offset))
        .map_err(|source| HelperFailure::io("unable to seek to PE header", source))?;
    let mut pe_header = [0_u8; 24];
    file.read_exact(&mut pe_header)
        .map_err(|source| HelperFailure::io("unable to read PE header", source))?;
    if pe_header.get(..4) != Some(b"PE\0\0") {
        return Err(HelperFailure::Validation(
            "payload does not have a PE signature".into(),
        ));
    }

    let machine = u16::from_le_bytes([pe_header[4], pe_header[5]]);
    let section_count = u16::from_le_bytes([pe_header[6], pe_header[7]]);
    let optional_header_size = u16::from_le_bytes([pe_header[20], pe_header[21]]);
    let characteristics = u16::from_le_bytes([pe_header[22], pe_header[23]]);
    if section_count == 0 || optional_header_size < 2 {
        return Err(HelperFailure::Validation(
            "payload PE header has no sections or optional header".into(),
        ));
    }
    if characteristics & IMAGE_FILE_DLL == 0 {
        return Err(HelperFailure::Validation(
            "payload PE header is not marked as a DLL".into(),
        ));
    }
    let architecture = match machine {
        IMAGE_FILE_MACHINE_AMD64 => ProtocolArchitecture::X86_64,
        IMAGE_FILE_MACHINE_I386 => ProtocolArchitecture::X86,
        _ => ProtocolArchitecture::Unknown,
    };
    if architecture != expected_architecture {
        return Err(HelperFailure::ArchitectureMismatch(format!(
            "payload architecture {architecture:?} does not match target {expected_architecture:?}"
        )));
    }
    let mut optional_magic = [0_u8; 2];
    file.read_exact(&mut optional_magic)
        .map_err(|source| HelperFailure::io("unable to read PE optional header", source))?;
    let optional_magic = u16::from_le_bytes(optional_magic);
    let expected_magic = match architecture {
        ProtocolArchitecture::X86 => PE32_MAGIC,
        ProtocolArchitecture::X86_64 => PE32_PLUS_MAGIC,
        ProtocolArchitecture::Arm
        | ProtocolArchitecture::Aarch64
        | ProtocolArchitecture::Unknown => {
            return Err(HelperFailure::Validation(
                "payload architecture is unsupported".into(),
            ));
        }
    };
    if optional_magic != expected_magic {
        return Err(HelperFailure::Validation(format!(
            "payload optional-header magic {optional_magic:#06x} does not match architecture"
        )));
    }
    Ok(())
}

/// Hashes exactly one expected payload length with bounded memory
pub(super) fn sha256_file(path: &Path, expected_size: u64) -> Result<String, HelperFailure> {
    let mut file =
        File::open(path).map_err(|source| HelperFailure::io("unable to open payload", source))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    let mut total_bytes = 0_u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| HelperFailure::io("unable to read payload", source))?;
        if count == 0 {
            break;
        }
        total_bytes = total_bytes
            .checked_add(u64::try_from(count).map_err(|_| {
                HelperFailure::Validation("payload read count does not fit u64".into())
            })?)
            .ok_or_else(|| HelperFailure::Validation("payload size overflowed u64".into()))?;
        if total_bytes > expected_size {
            return Err(HelperFailure::PayloadChanged(
                "payload grew while it was being hashed".into(),
            ));
        }
        hasher.update(&buffer[..count]);
    }
    if total_bytes != expected_size {
        return Err(HelperFailure::PayloadChanged(
            "payload shrank while it was being hashed".into(),
        ));
    }

    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(encoded)
}
