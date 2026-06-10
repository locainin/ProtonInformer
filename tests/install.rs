//! Helper release-manifest verification checks

use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use proton_informer::install::{verify_sha256_manifest, verify_static};
use proton_informer::types::Architecture;
use tempfile::tempdir;

#[test]
fn matching_adjacent_sha256_manifest_is_accepted() {
    let directory = tempdir().expect("temporary directory");
    let helper = directory.path().join("helper.exe");
    fs::write(&helper, b"helper fixture").expect("helper fixture");
    fs::write(
        directory.path().join("helper.exe.sha256"),
        "8c1859d39257afd0a8e866cc881934777761c5c11a7e7ad481401050f12a3b93  helper.exe\n",
    )
    .expect("hash manifest");

    let hash = verify_sha256_manifest(&helper).expect("matching manifest");

    assert_eq!(
        hash,
        "8c1859d39257afd0a8e866cc881934777761c5c11a7e7ad481401050f12a3b93"
    );
}

#[test]
fn mismatched_adjacent_sha256_manifest_is_rejected() {
    let directory = tempdir().expect("temporary directory");
    let helper = directory.path().join("helper.exe");
    fs::write(&helper, b"helper fixture").expect("helper fixture");
    fs::write(
        directory.path().join("helper.exe.sha256"),
        format!("{}  helper.exe\n", "0".repeat(64)),
    )
    .expect("hash manifest");

    let error = verify_sha256_manifest(&helper).expect_err("mismatch must fail");

    assert!(error.to_string().contains("does not match"));
}

#[test]
fn manifest_lookup_preserves_non_utf8_helper_paths() {
    let directory = tempdir().expect("temporary directory");
    let helper = directory
        .path()
        .join(PathBuf::from(std::ffi::OsString::from_vec(vec![
            b'h', b'e', b'l', b'p', b'e', b'r', 0xff,
        ])));
    fs::write(&helper, b"helper fixture").expect("helper fixture");
    let mut manifest_name = helper.as_os_str().to_os_string();
    manifest_name.push(".sha256");
    fs::write(
        PathBuf::from(manifest_name),
        "8c1859d39257afd0a8e866cc881934777761c5c11a7e7ad481401050f12a3b93  helper\n",
    )
    .expect("hash manifest");

    let hash = verify_sha256_manifest(&helper).expect("non-UTF-8 manifest lookup");

    assert_eq!(
        hash,
        "8c1859d39257afd0a8e866cc881934777761c5c11a7e7ad481401050f12a3b93"
    );
}

#[test]
fn unsupported_architecture_is_rejected_before_helper_discovery() {
    let error = verify_static(Architecture::Aarch64)
        .expect_err("unsupported helper architecture must fail");

    assert!(error.to_string().contains("no supported Windows helper"));
}
