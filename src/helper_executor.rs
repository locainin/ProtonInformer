//! Bounded execution of typed helper invocations.

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wait_timeout::ChildExt;

use crate::error::{Error, Result};
use crate::helper_runtime::HelperInvocation;

const MAX_HELPER_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAX_HELPER_PROCESS_TIME_MS: u64 = 310_000;

/// Captured helper process result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperExecutionOutput {
    /// Process exit code when the platform reported one.
    pub exit_code: Option<i32>,
    /// Bounded standard error text.
    pub stderr: String,
    /// Bounded standard output text.
    pub stdout: String,
}

/// Executes one invocation without a shell and with a hard timeout.
///
/// # Errors
///
/// Returns an error for state-file failures, process launch failures, timeout,
/// output larger than one MiB, or invalid UTF-8 output.
pub fn execute(invocation: &HelperInvocation, timeout_ms: u64) -> Result<HelperExecutionOutput> {
    if !(1..=MAX_HELPER_PROCESS_TIME_MS).contains(&timeout_ms) {
        return Err(Error::InvalidInput(
            "helper process timeout must be between 1 and 310000 ms".into(),
        ));
    }

    let directory = std::env::temp_dir().join(format!("proton-informer-helper-{}", Uuid::new_v4()));
    fs::create_dir(&directory).map_err(|source| Error::io(&directory, source))?;
    let result = (|| {
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|source| Error::io(&directory, source))?;
        let stdout_path = directory.join("stdout");
        let stderr_path = directory.join("stderr");
        let stdout = private_output_file(&stdout_path)?;
        let stderr = private_output_file(&stderr_path)?;
        run_process(
            invocation,
            timeout_ms,
            stdout,
            stderr,
            &stdout_path,
            &stderr_path,
        )
    })();
    let _ = fs::remove_dir_all(&directory);
    result
}

/// Executes one invocation using an existing owner-only run directory.
///
/// # Errors
///
/// Returns the same bounded process and output failures as [`execute`].
pub fn execute_in_directory(
    invocation: &HelperInvocation,
    timeout_ms: u64,
    directory: &std::path::Path,
    keep_output_files: bool,
) -> Result<HelperExecutionOutput> {
    if !(1..=MAX_HELPER_PROCESS_TIME_MS).contains(&timeout_ms) {
        return Err(Error::InvalidInput(
            "helper process timeout must be between 1 and 310000 ms".into(),
        ));
    }
    let stdout_path = directory.join("helper.stdout");
    let stderr_path = directory.join("helper.stderr");
    let mut stdout_created = false;
    let mut stderr_created = false;
    let result = (|| {
        let stdout = private_output_file(&stdout_path)?;
        stdout_created = true;
        let stderr = private_output_file(&stderr_path)?;
        stderr_created = true;
        run_process(
            invocation,
            timeout_ms,
            stdout,
            stderr,
            &stdout_path,
            &stderr_path,
        )
    })();
    if !keep_output_files {
        if stdout_created {
            let _ = fs::remove_file(&stdout_path);
        }
        if stderr_created {
            let _ = fs::remove_file(&stderr_path);
        }
    }
    result
}

/// Runs one child after all output destinations are ready.
fn run_process(
    invocation: &HelperInvocation,
    timeout_ms: u64,
    stdout: File,
    stderr: File,
    stdout_path: &std::path::Path,
    stderr_path: &std::path::Path,
) -> Result<HelperExecutionOutput> {
    let mut command = Command::new(&invocation.program);
    command
        .env_clear()
        .args(&invocation.arguments)
        .envs(&invocation.environment)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    let mut child = command
        .spawn()
        .map_err(|source| Error::io(&invocation.program, source))?;
    let status = child
        .wait_timeout(Duration::from_millis(timeout_ms))
        .map_err(|source| Error::io(&invocation.program, source))?;
    let Some(status) = status else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Error::HelperTimeout { timeout_ms });
    };

    let stdout = read_bounded_text(stdout_path)?;
    let stderr = read_bounded_text(stderr_path)?;
    Ok(HelperExecutionOutput {
        exit_code: status.code(),
        stderr,
        stdout,
    })
}

/// Creates one owner-only output file without replacing existing data.
fn private_output_file(path: &std::path::Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| Error::io(path, source))
}

/// Reads helper output only after enforcing a strict size limit.
fn read_bounded_text(path: &std::path::Path) -> Result<String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|source| Error::io(path, source))?
        .take(MAX_HELPER_OUTPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| Error::io(path, source))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_HELPER_OUTPUT_BYTES {
        return Err(Error::HelperExecution(format!(
            "{} exceeded the {}-byte output limit",
            path.display(),
            MAX_HELPER_OUTPUT_BYTES
        )));
    }
    String::from_utf8(bytes)
        .map_err(|error| Error::HelperExecution(format!("helper output is not UTF-8: {error}")))
}
