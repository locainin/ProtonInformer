//! Guest executable resolution invariants

use std::fs;
use std::path::Path;

use proton_informer::Error;
use proton_informer::process::{self, GuestExecutableSource};
use tempfile::tempdir;

#[test]
fn guest_resolution_rejects_multiple_valid_pe_executables() {
    let directory = tempdir().expect("temporary directory");
    let launcher = directory.path().join("launcher.exe");
    let target = directory.path().join("target.exe");
    write_minimal_pe_executable(&launcher);
    write_minimal_pe_executable(&target);

    let error = process::resolve_guest_executable(
        &[launcher.display().to_string(), target.display().to_string()],
        None,
        None,
    )
    .expect_err("multiple PE executable arguments must be ambiguous");

    assert!(matches!(error, Error::AmbiguousGuestExecutable { .. }));
    assert!(error.to_string().contains("launcher.exe"));
    assert!(error.to_string().contains("target.exe"));
}

#[test]
fn guest_resolution_deduplicates_canonical_paths_before_selection() {
    let directory = tempdir().expect("temporary directory");
    let executable = directory.path().join("target.exe");
    write_minimal_pe_executable(&executable);

    let candidate = process::resolve_guest_executable(
        &[executable.display().to_string(), "target.exe".into()],
        None,
        Some(directory.path()),
    )
    .expect("deduplicated executable")
    .expect("one executable candidate");

    assert_eq!(
        candidate.path,
        executable.canonicalize().expect("canonical path")
    );
    assert_eq!(
        candidate.source,
        GuestExecutableSource::AbsoluteUnixArgument
    );
}

#[test]
fn guest_resolution_reports_unresolved_when_no_argument_is_a_pe_executable() {
    let directory = tempdir().expect("temporary directory");

    let result =
        process::resolve_guest_executable(&["missing.exe".into()], None, Some(directory.path()))
            .expect("missing candidate is not an operational error");

    assert!(result.is_none());
}

#[test]
fn guest_resolution_rejects_unsupported_windows_path_forms() {
    let directory = tempdir().expect("temporary directory");
    for argument in [
        r"C:target.exe",
        r"\target.exe",
        r"\\server\target.exe",
        r"//server/target.exe",
        r"folder\target.exe",
    ] {
        let error =
            process::resolve_guest_executable(&[argument.into()], None, Some(directory.path()))
                .expect_err("unsupported Windows syntax must not become a Unix-relative path");

        assert!(matches!(error, Error::PathConversion { .. }), "{argument}");
    }
}

#[test]
fn guest_resolution_propagates_drive_conversion_failures() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    fs::create_dir_all(prefix.join("dosdevices")).expect("create dosdevices");

    let error = process::resolve_guest_executable(
        &[r"C:\target.exe".into()],
        Some(&prefix),
        Some(directory.path()),
    )
    .expect_err("a broken requested drive must remain a target-resolution error");

    assert!(matches!(error, Error::PathConversion { .. }));
}

#[test]
fn guest_resolution_accepts_drive_absolute_pe_paths() {
    let directory = tempdir().expect("temporary directory");
    let prefix = directory.path().join("pfx");
    let drive_c = prefix.join("drive_c");
    let executable = drive_c.join("target.exe");
    fs::create_dir_all(prefix.join("dosdevices")).expect("create dosdevices");
    fs::create_dir_all(&drive_c).expect("create drive C");
    std::os::unix::fs::symlink("../drive_c", prefix.join("dosdevices/c:"))
        .expect("create C drive mapping");
    write_minimal_pe_executable(&executable);

    let candidate =
        process::resolve_guest_executable(&[r"C:\target.exe".into()], Some(&prefix), None)
            .expect("drive-absolute guest path")
            .expect("drive-absolute PE candidate");

    assert_eq!(
        candidate.source,
        GuestExecutableSource::WindowsDriveArgument
    );
    assert_eq!(
        candidate.path,
        executable.canonicalize().expect("canonical executable")
    );
}

fn write_minimal_pe_executable(path: &Path) {
    let section_table = 0x188;
    let mut bytes = vec![0_u8; section_table + 3 * 40];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    bytes[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
    bytes[coff + 2..coff + 4].copy_from_slice(&3_u16.to_le_bytes());
    bytes[coff + 16..coff + 18].copy_from_slice(&0xf0_u16.to_le_bytes());
    bytes[coff + 18..coff + 20].copy_from_slice(&0x0022_u16.to_le_bytes());
    bytes[coff + 20..coff + 22].copy_from_slice(&0x20b_u16.to_le_bytes());

    // Keep one complete header for every declared section
    let names = [b".text\0\0\0", b".rdata\0\0", b".data\0\0\0"];
    for (index, name) in names.iter().enumerate() {
        let section_index = u32::try_from(index).expect("fixture section index fits in u32");
        let section = section_table + index * 40;
        bytes[section..section + 8].copy_from_slice(*name);
        bytes[section + 8..section + 12].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[section + 12..section + 16]
            .copy_from_slice(&(0x1000_u32 * (section_index + 1)).to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[section + 20..section + 24]
            .copy_from_slice(&(0x200_u32 * (section_index + 1)).to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0x6000_0020_u32.to_le_bytes());
    }

    fs::write(path, bytes).expect("PE executable fixture");
}
