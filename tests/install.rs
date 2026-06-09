//! Helper release-manifest verification checks.

use std::fs;

use proton_informer::install::verify_sha256_manifest;
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
