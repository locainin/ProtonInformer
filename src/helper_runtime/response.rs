//! Shared helper response parsing for controller-side helper calls

use proton_informer_helper_protocol::HelperResponse;

use crate::error::{Error, Result};
use crate::helper_executor::HelperExecutionOutput;

/// Parses one protocol response after detecting empty helper output
///
/// # Errors
///
/// Returns an error when the helper produced no JSON or emitted malformed JSON
pub(super) fn parse_helper_response(output: &HelperExecutionOutput) -> Result<HelperResponse> {
    if output.stdout.trim().is_empty() {
        let stderr = output.stderr.trim();
        let detail = if stderr.is_empty() {
            "stderr was empty".to_owned()
        } else {
            format!("stderr: {stderr}")
        };
        return Err(Error::HelperExecution(format!(
            "helper produced no protocol output; exit {:?}; {detail}",
            output.exit_code
        )));
    }
    serde_json::from_str(&output.stdout).map_err(Error::from)
}
