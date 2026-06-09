//! Linux process discovery with Wine and Proton runtime evidence.
//!
//! Public models remain stable here while `/proc` reading and classification
//! logic stay in focused internal modules.

mod evidence;
mod model;
mod procfs;

pub use model::{
    ClassificationConfidence, EnvironmentStatus, GuestExecutableCandidate, GuestExecutableSource,
    ProcessInfo, ProcessUids, TargetKind,
};
pub use procfs::{inspect, list};
