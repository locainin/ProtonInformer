//! Public bounded PE inspection behavior

use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};

use proton_informer::binary::{self, BinaryFormat, MAX_INSPECTION_SIZE};
use proton_informer::types::Architecture;
use tempfile::tempdir;

#[test]
fn pe_dll_headers_determine_format_and_architecture() {
    let directory = tempdir().expect("temporary directory");
    let payload = directory.path().join("payload.bin");
    write_minimal_pe(&payload, true);

    let inspection = binary::inspect(&payload).expect("inspect PE DLL");

    assert_eq!(inspection.format, BinaryFormat::PeDll);
    assert_eq!(inspection.architecture, Architecture::X86_64);
    assert!(inspection.extension_warning.is_some());
    assert!(inspection.is_loadable_payload());
}

#[test]
fn pe_dll_with_a_matching_extension_has_no_warning() {
    let directory = tempdir().expect("temporary directory");
    let payload = directory.path().join("payload.dll");
    write_minimal_pe(&payload, true);

    let inspection = binary::inspect(&payload).expect("inspect PE DLL");

    assert_eq!(inspection.extension_warning, None);
}

#[test]
fn pe_dll_without_an_extension_reports_a_warning() {
    let directory = tempdir().expect("temporary directory");
    let payload = directory.path().join("payload");
    write_minimal_pe(&payload, true);

    let inspection = binary::inspect(&payload).expect("inspect extensionless PE DLL");

    assert_eq!(
        inspection.extension_warning.as_deref(),
        Some("file has no extension; detected format is PE DLL")
    );
}

#[test]
fn pe_executable_is_not_a_loadable_payload_even_with_a_dll_extension() {
    let directory = tempdir().expect("temporary directory");
    let executable = directory.path().join("launcher.dll");
    write_minimal_pe(&executable, false);

    let inspection = binary::inspect(&executable).expect("inspect PE executable");

    assert_eq!(inspection.format, BinaryFormat::PeExecutable);
    assert_eq!(inspection.architecture, Architecture::X86_64);
    assert!(!inspection.is_loadable_payload());
    assert!(inspection.extension_warning.is_some());
}

#[test]
fn arm_pe_dll_headers_remain_visible_without_an_implicit_supported_backend() {
    let directory = tempdir().expect("temporary directory");
    let payload = directory.path().join("arm.dll");
    write_minimal_pe_arch(&payload, true, 0x01c0, 0x010b);

    let inspection = binary::inspect(&payload).expect("inspect ARM PE DLL");

    assert_eq!(inspection.format, BinaryFormat::PeDll);
    assert_eq!(inspection.architecture, Architecture::Arm);
    assert!(inspection.is_loadable_payload());
}

#[test]
fn native_elf_files_are_outside_the_payload_inspection_scope() {
    let current = std::env::current_exe().expect("current executable path");

    let error = binary::inspect(&current).expect_err("native ELF must not be a PE payload");

    assert!(error.to_string().contains("malformed binary"));
}

#[test]
fn large_sparse_pe_files_are_inspected_from_headers_only() {
    let directory = tempdir().expect("temporary directory");
    let payload = directory.path().join("large.dll");
    write_minimal_pe(&payload, true);
    OpenOptions::new()
        .write(true)
        .open(&payload)
        .expect("open sparse fixture")
        .set_len(32 * 1024 * 1024)
        .expect("extend sparse fixture");

    let inspection = binary::inspect(&payload).expect("bounded header inspection");

    assert_eq!(inspection.format, BinaryFormat::PeDll);
    assert_eq!(inspection.size_bytes, 32 * 1024 * 1024);
}

#[test]
fn oversized_payload_is_rejected_before_header_reads() {
    let directory = tempdir().expect("temporary directory");
    let payload = directory.path().join("oversized.dll");
    let file = File::create(&payload).expect("create sparse fixture");
    file.set_len(MAX_INSPECTION_SIZE + 1)
        .expect("size sparse fixture");

    let error = binary::inspect(&payload).expect_err("reject oversized payload");

    assert!(error.to_string().contains("inspection limit"));
}

#[test]
fn text_payload_is_rejected() {
    let directory = tempdir().expect("temporary directory");
    let payload = directory.path().join("payload.dll");
    fs::write(&payload, b"not a binary").expect("write fixture");

    let error = binary::inspect(&payload).expect_err("reject text payload");

    assert!(error.to_string().contains("malformed binary"));
}

#[test]
fn pe_header_offset_is_checked_against_file_structure_not_an_arbitrary_limit() {
    let directory = tempdir().expect("temporary directory");
    let payload = directory.path().join("distant-header.dll");
    write_minimal_pe_arch_at(&payload, true, 0x8664, 0x020b, 32 * 1024 * 1024);

    let inspection = binary::inspect(&payload).expect("inspect distant PE header");

    assert_eq!(inspection.format, BinaryFormat::PeDll);
    assert_eq!(inspection.architecture, Architecture::X86_64);
}

#[test]
fn pe_with_missing_section_table_is_rejected() {
    let directory = tempdir().expect("temporary directory");
    let payload = directory.path().join("missing-sections.dll");
    write_minimal_pe(&payload, true);
    OpenOptions::new()
        .write(true)
        .open(&payload)
        .expect("open PE fixture")
        .set_len(0x188)
        .expect("truncate section table");

    let error = binary::inspect(&payload).expect_err("missing section table must be rejected");

    assert!(error.to_string().contains("section table"));
}

#[test]
fn pe_header_boundary_is_inclusive_for_the_dos_header() {
    let directory = tempdir().expect("temporary directory");
    let payload = directory.path().join("dos-header.dll");
    let mut bytes = vec![0_u8; 64];
    bytes[0..2].copy_from_slice(b"MZ");
    fs::write(&payload, bytes).expect("write DOS-header fixture");

    let error = binary::inspect(&payload).expect_err("incomplete PE header must be rejected");

    assert!(error.to_string().contains("PE signature"));
}

#[test]
fn a_pe_header_ending_at_file_end_reaches_optional_header_validation() {
    let directory = tempdir().expect("temporary directory");
    let payload = directory.path().join("header-at-end.dll");
    let pe_offset = 0x80_usize;
    let mut bytes = vec![0_u8; pe_offset + 24];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
    bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
    bytes[pe_offset + 4..pe_offset + 6].copy_from_slice(&0x8664_u16.to_le_bytes());
    bytes[pe_offset + 6..pe_offset + 8].copy_from_slice(&1_u16.to_le_bytes());
    bytes[pe_offset + 22..pe_offset + 24].copy_from_slice(&0x2002_u16.to_le_bytes());
    fs::write(&payload, bytes).expect("write boundary fixture");

    let error = binary::inspect(&payload).expect_err("missing optional header must be rejected");

    assert!(error.to_string().contains("PE optional header"));
}

#[test]
fn the_minimum_pe32_plus_optional_header_size_is_accepted() {
    let directory = tempdir().expect("temporary directory");
    let payload = directory.path().join("minimum-optional-header.dll");
    write_minimal_pe(&payload, true);
    let mut file = OpenOptions::new()
        .write(true)
        .open(&payload)
        .expect("open PE fixture");
    file.seek(SeekFrom::Start(0x80 + 20))
        .expect("seek to optional-header size");
    file.write_all(&0x70_u16.to_le_bytes())
        .expect("write minimum optional-header size");

    let inspection = binary::inspect(&payload).expect("minimum PE32+ optional header");

    assert_eq!(inspection.format, BinaryFormat::PeDll);
}

#[test]
fn pe_without_the_executable_image_characteristic_is_rejected() {
    let directory = tempdir().expect("temporary directory");
    let payload = directory.path().join("non-executable.dll");
    write_minimal_pe(&payload, true);
    let mut file = OpenOptions::new()
        .write(true)
        .open(&payload)
        .expect("open PE fixture");
    file.seek(SeekFrom::Start(0x80 + 22))
        .expect("seek to PE characteristics");
    file.write_all(&0x2000_u16.to_le_bytes())
        .expect("remove executable-image characteristic");

    let error = binary::inspect(&payload).expect_err("non-executable image must be rejected");

    assert!(
        error
            .to_string()
            .contains("not marked as an executable image")
    );
}

fn write_minimal_pe(path: &std::path::Path, is_dll: bool) {
    write_minimal_pe_arch_at(path, is_dll, 0x8664, 0x020b, 0x80);
}

fn write_minimal_pe_arch(path: &std::path::Path, is_dll: bool, machine: u16, optional_magic: u16) {
    write_minimal_pe_arch_at(path, is_dll, machine, optional_magic, 0x80);
}

fn write_minimal_pe_arch_at(
    path: &std::path::Path,
    is_dll: bool,
    machine: u16,
    optional_magic: u16,
    pe_offset: u64,
) {
    let optional_header_size = 0xf0_u64;
    let section_table = pe_offset + 24 + optional_header_size;
    let file_size = section_table + 3 * 40;
    let mut file = File::create(path).expect("PE fixture file");
    file.set_len(file_size).expect("size PE fixture");

    let mut dos = [0_u8; 64];
    dos[0..2].copy_from_slice(b"MZ");
    dos[0x3c..0x40].copy_from_slice(
        &u32::try_from(pe_offset)
            .expect("PE fixture offset fits DOS field")
            .to_le_bytes(),
    );
    file.seek(SeekFrom::Start(0)).expect("seek to DOS header");
    file.write_all(&dos).expect("write DOS header");

    let mut pe_header = [0_u8; 24];
    pe_header[0..4].copy_from_slice(b"PE\0\0");
    pe_header[4..6].copy_from_slice(&machine.to_le_bytes());
    pe_header[6..8].copy_from_slice(&3_u16.to_le_bytes());
    pe_header[20..22].copy_from_slice(&0xf0_u16.to_le_bytes());
    let characteristics = if is_dll { 0x2022_u16 } else { 0x0022_u16 };
    pe_header[22..24].copy_from_slice(&characteristics.to_le_bytes());
    file.seek(SeekFrom::Start(pe_offset))
        .expect("seek to PE header");
    file.write_all(&pe_header).expect("write PE header");

    let mut optional = [0_u8; 0xf0];
    optional[0..2].copy_from_slice(&optional_magic.to_le_bytes());
    optional[16..20].copy_from_slice(&0x1000_u32.to_le_bytes());
    optional[24..32].copy_from_slice(&0x1_4000_0000_u64.to_le_bytes());
    optional[32..36].copy_from_slice(&0x1000_u32.to_le_bytes());
    optional[36..40].copy_from_slice(&0x200_u32.to_le_bytes());
    optional[56..60].copy_from_slice(&0x1000_u32.to_le_bytes());
    optional[60..64].copy_from_slice(&0x200_u32.to_le_bytes());
    optional[68..70].copy_from_slice(&3_u16.to_le_bytes());
    optional[92..96].copy_from_slice(&16_u32.to_le_bytes());
    file.write_all(&optional).expect("write optional header");

    // Keep one complete header for every declared section
    let names = [b".text\0\0\0", b".rdata\0\0", b".data\0\0\0"];
    for (index, name) in names.iter().enumerate() {
        let mut section_header = [0_u8; 40];
        section_header[0..8].copy_from_slice(*name);
        section_header[8..12].copy_from_slice(&0x1000_u32.to_le_bytes());
        section_header[12..16].copy_from_slice(&(0x1000_u32 * (index as u32 + 1)).to_le_bytes());
        section_header[16..20].copy_from_slice(&0x200_u32.to_le_bytes());
        section_header[20..24].copy_from_slice(&(0x200_u32 * (index as u32 + 1)).to_le_bytes());
        section_header[36..40].copy_from_slice(&0x6000_0020_u32.to_le_bytes());
        file.write_all(&section_header)
            .expect("write section header");
    }
}
