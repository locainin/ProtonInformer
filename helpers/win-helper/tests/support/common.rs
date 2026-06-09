//! Shared black-box helper process utilities

use std::path::Path;
use std::process::Command;

use proton_informer_helper_protocol::{HelperRequest, HelperResponse};

/// Runs one request through the compiled helper executable
///
/// # Panics
///
/// Panics when the fixture cannot be written, the helper cannot start, or the
/// helper violates its process or JSON response contract
#[must_use]
pub fn run_request(request: &HelperRequest, path: &Path) -> HelperResponse {
    // Persist the same request file shape used by the Linux controller
    std::fs::write(
        path,
        serde_json::to_vec_pretty(request).expect("request JSON"),
    )
    .expect("request fixture");

    // Invoke the final executable boundary instead of calling helper internals
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer-win-helper"))
        .args(["--request-json", path.to_str().expect("UTF-8 fixture path")])
        .output()
        .expect("helper should start");

    // Request failures use protocol JSON while process execution still succeeds
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).expect("protocol response")
}
