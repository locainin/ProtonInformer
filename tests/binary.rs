//! Public binary inspection behavior.

use std::fs::{self, File};
use std::path::PathBuf;

use proton_informer::binary::{self, BinaryFormat, MAX_INSPECTION_SIZE};
use proton_informer::types::Architecture;
use tempfile::tempdir;

#[test]
fn current_pie_binary_is_an_executable() {
    let current = std::env::current_exe().expect("current executable path");
    let inspection = binary::inspect(&current).expect("inspect test binary");

    assert_eq!(inspection.format, BinaryFormat::ElfExecutable);
    assert_eq!(inspection.architecture, Architecture::host());
}

#[test]
fn misleading_extension_does_not_override_headers() {
    let current = std::env::current_exe().expect("current executable path");
    let directory = tempdir().expect("temporary directory");
    let disguised = directory.path().join("payload.dll");
    fs::copy(current, &disguised).expect("copy fixture");

    let inspection = binary::inspect(&disguised).expect("inspect fixture");

    assert_eq!(inspection.format, BinaryFormat::ElfExecutable);
    assert!(inspection.extension_warning.is_some());
}

#[test]
fn loaded_shared_object_is_accepted() {
    let maps = fs::read_to_string("/proc/self/maps").expect("read process maps");
    let inspection = maps
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .map(PathBuf::from)
        .filter(|path| {
            path.is_absolute()
                && path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains(".so"))
        })
        .filter_map(|path| binary::inspect(&path).ok())
        .find(|inspection| inspection.format == BinaryFormat::ElfSharedObject)
        .expect("find loaded shared object");

    assert_eq!(inspection.format, BinaryFormat::ElfSharedObject);
}

#[test]
fn oversized_payload_is_rejected() {
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
