//! Typed helper runtime selection, secure request files, and dry-run planning

mod invocation;
mod model;
mod planning;
mod query;
mod response;
mod state;

pub use invocation::{diagnostic_invocation, helper_architecture_supported, select_runtime};
pub use model::{HelperInvocation, HelperRuntime, LoadDryRunPlan, PayloadPathMode};
pub use planning::plan_load_dry_run;
pub use query::query_modules;
pub(crate) use state::state_directory;
pub use state::{create_request_directory, prepare_payload_for_request};

/// Parses one helper protocol response from captured process output
pub(crate) fn parse_helper_response(
    output: &crate::helper_executor::HelperExecutionOutput,
) -> crate::Result<proton_informer_helper_protocol::HelperResponse> {
    response::parse_helper_response(output)
}

/// Builds a diagnostic command for the exact helper that passed verification
pub(crate) fn diagnostic_invocation_with_helper(
    target: &crate::process::ProcessInfo,
    helper_path: &std::path::Path,
    flag: &str,
) -> crate::Result<HelperInvocation> {
    invocation::diagnostic_invocation_with_helper(target, helper_path, flag)
}
