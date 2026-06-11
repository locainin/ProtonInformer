//! Readiness checks for Steam, Wine, helpers, `/proc`, and state storage
//!
//! The root module keeps the public API stable while the check groups live in
//! smaller files by responsibility

mod live;
mod model;
mod static_checks;

pub use model::{CapabilityReadiness, CheckStatus, DoctorCheck, DoctorReport};

use crate::error::Result;

/// Runs local checks without attaching to or changing a target process
#[must_use]
pub fn run() -> DoctorReport {
    static_checks::run()
}

/// Runs static checks plus live helper diagnostics in one target runtime
///
/// # Errors
///
/// Returns an error when the target cannot be inspected or is not a Wine or
/// Proton process owned by the current user
pub fn run_for_process(pid: u32) -> Result<DoctorReport> {
    live::run_for_process(pid)
}
