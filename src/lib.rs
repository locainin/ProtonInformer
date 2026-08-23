//! Core inspection and planning library for `ProtonInformer`
//!
//! Modules expose typed data for the CLI and other clients. Remote loading is
//! delegated to the Windows helper after controller-side validation

#![forbid(unsafe_code)]
#![deny(warnings)]
#![warn(clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::doc_paragraphs_missing_punctuation,
    reason = "existing API documentation uses concise comment-style sentences"
)]

pub mod binary;
pub mod cli;
pub mod decision {
    //! Public planning decision matrix

    mod model;
    mod override_plan;
    mod running;

    pub use model::{Backend, LoadPlan, OverridePlacement, OverridePlan, RequirementCheck};
    pub use override_plan::plan_override;
    pub use running::plan_running;
}

pub mod doctor {
    //! Readiness checks for Steam, Wine, helpers, `/proc`, and state storage
    //!
    //! Public entry points stay here while each check group lives in a focused file

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
}

pub mod duration {
    //! Compact duration parsing shared by bounded CLI operations

    mod compact;

    pub use compact::parse_compact;
}
pub mod error;
pub mod helper;
pub mod helper_executor;
pub mod helper_protocol;
pub mod helper_runtime;
pub mod inject;
pub mod install;
pub mod load;
pub mod modules;
pub mod process {
    //! Linux process discovery with Wine and Proton runtime evidence
    //!
    //! Public models remain stable here while `/proc` reading and classification
    //! logic stay in focused internal modules

    mod evidence;
    mod model;
    mod procfs;

    pub use evidence::resolve_guest_executable;
    pub use model::{
        ClassificationConfidence, EnvironmentStatus, GuestExecutableCandidate,
        GuestExecutableSource, ProcessEvidenceFailure, ProcessInfo, ProcessInspectionFailure,
        ProcessListReport, ProcessUids, TargetKind,
    };
    pub use procfs::{inspect, list, list_owned_report, list_report, revalidate_identity};
}
pub mod runs;
pub mod steam;
pub mod types;
pub mod wine;

pub use error::{Error, Result};
