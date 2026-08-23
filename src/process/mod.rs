//! Linux process discovery with Wine and Proton runtime evidence
//!
//! Public models remain stable here while /proc reading and classification
//! logic stay in focused internal modules

mod evidence;
mod model;
mod procfs;

pub use evidence::resolve_guest_executable;
pub use model::{
    ClassificationConfidence, EnvironmentStatus, GuestExecutableCandidate, GuestExecutableSource,
    ProcessEvidenceFailure, ProcessInfo, ProcessInspectionFailure, ProcessListReport, ProcessUids,
    TargetKind,
};
pub use procfs::{inspect, list, list_owned_report, list_report, revalidate_identity};
