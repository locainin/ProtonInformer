//! Typed helper runtime selection, secure request files, and dry-run planning.

mod invocation;
mod model;
mod planning;
mod query;
mod state;

pub use invocation::{diagnostic_invocation, helper_architecture_supported, select_runtime};
pub use model::{HelperInvocation, HelperRuntime, LoadDryRunPlan};
pub use planning::plan_load_dry_run;
pub use query::query_modules;
pub use state::create_request_directory;
pub(crate) use state::state_directory;

/// Builds a diagnostic command for the exact helper that passed verification.
pub(crate) fn diagnostic_invocation_with_helper(
    target: &crate::process::ProcessInfo,
    helper_path: &std::path::Path,
    flag: &str,
) -> crate::Result<HelperInvocation> {
    invocation::diagnostic_invocation_with_helper(target, helper_path, flag)
}
