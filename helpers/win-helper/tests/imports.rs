//! PE import parser boundary checks.

use std::fs;

use proton_informer_win_helper::imports::dll_names;
use tempfile::tempdir;

const PE_OFFSET: usize = 0x80;
const OPTIONAL_SIZE: usize = 240;
const RAW_OFFSET: usize = 0x200;
const SECTION_RVA: u32 = 0x1000;

/// Builds one minimal PE32+ image with a single import descriptor.
fn pe_fixture(import_rva: u32, import_size: u32, name_rva: u32, raw_size: u32) -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x500];

    // DOS header points to the fixed PE header used by this fixture
    bytes[0..2].copy_from_slice(b"MZ");
    write_u32(
        &mut bytes,
        0x3c,
        u32::try_from(PE_OFFSET).expect("PE offset"),
    );

    // COFF identifies one x86_64 section and a normal PE32+ optional header
    bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
    write_u16(&mut bytes, PE_OFFSET + 4, 0x8664);
    write_u16(&mut bytes, PE_OFFSET + 6, 1);
    write_u16(
        &mut bytes,
        PE_OFFSET + 20,
        u16::try_from(OPTIONAL_SIZE).expect("optional size"),
    );
    let optional = PE_OFFSET + 24;
    write_u16(&mut bytes, optional, 0x020b);

    // The second data-directory entry is the import directory
    write_u32(&mut bytes, optional + 120, import_rva);
    write_u32(&mut bytes, optional + 124, import_size);

    // One section maps the selected RVA range to raw file bytes
    let section = optional + OPTIONAL_SIZE;
    write_u32(&mut bytes, section + 8, 0x300);
    write_u32(&mut bytes, section + 12, SECTION_RVA);
    write_u32(&mut bytes, section + 16, raw_size);
    write_u32(
        &mut bytes,
        section + 20,
        u32::try_from(RAW_OFFSET).expect("raw offset"),
    );

    // The descriptor and name bytes may intentionally lie outside raw_size
    let descriptor =
        RAW_OFFSET + usize::try_from(import_rva - SECTION_RVA).expect("descriptor relative offset");
    write_u32(&mut bytes, descriptor + 12, name_rva);
    let name = RAW_OFFSET + usize::try_from(name_rva - SECTION_RVA).expect("name relative offset");
    bytes[name..name + 12].copy_from_slice(b"fixture.dll\0");
    bytes
}

/// Writes one temporary fixture and invokes the public bounded parser.
fn parse_fixture(bytes: &[u8]) -> Result<Vec<String>, String> {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("fixture.dll");
    fs::write(&path, bytes).expect("PE fixture");
    dll_names(&path).map_err(|error| error.to_string())
}

/// Writes one little-endian word into a fixed fixture offset.
fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

/// Writes one little-endian double word into a fixed fixture offset.
fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn parser_reads_one_import_from_raw_section_data() {
    let imports = parse_fixture(&pe_fixture(SECTION_RVA, 40, SECTION_RVA + 0x40, 0x200))
        .expect("valid import table");

    assert_eq!(imports, ["fixture.dll"]);
}

#[test]
fn parser_rejects_import_directory_in_virtual_only_section_tail() {
    let error = parse_fixture(&pe_fixture(
        SECTION_RVA + 0x40,
        40,
        SECTION_RVA + 0x80,
        0x20,
    ))
    .expect_err("virtual-only import directory must fail");

    assert!(error.contains("outside raw file-backed section data"));
}

#[test]
fn parser_rejects_import_directory_larger_than_raw_section_remainder() {
    let error = parse_fixture(&pe_fixture(SECTION_RVA, 40, SECTION_RVA + 0x40, 30))
        .expect_err("oversized import directory must fail");

    assert!(error.contains("exceeds file-backed section data"));
}

#[test]
fn parser_rejects_import_name_crossing_raw_section_boundary() {
    let error = parse_fixture(&pe_fixture(SECTION_RVA, 40, SECTION_RVA + 0x48, 0x50))
        .expect_err("name crossing raw section must fail");

    assert!(error.contains("import name exceeds file-backed section data"));
}

#[test]
fn parser_rejects_descriptor_table_without_null_terminator() {
    let mut fixture = pe_fixture(SECTION_RVA, 40, SECTION_RVA + 0x40, 0x200);
    fixture[RAW_OFFSET + 20] = 1;

    let error = parse_fixture(&fixture).expect_err("unterminated descriptor table must fail");

    assert!(error.contains("no null terminator"));
}

#[test]
fn parser_rejects_import_names_with_path_components() {
    let mut fixture = pe_fixture(SECTION_RVA, 40, SECTION_RVA + 0x40, 0x200);
    let name = RAW_OFFSET + 0x40;
    fixture[name..name + 12].copy_from_slice(b"..\\evil.dll\0");

    let error = parse_fixture(&fixture).expect_err("path-shaped import name must fail");

    assert!(error.contains("safe DLL basename"));
}
