//! Versioned JSON contract shared by the Linux controller and Windows helper

#![forbid(unsafe_code)]
#![deny(warnings)]
#![warn(clippy::pedantic, clippy::nursery)]

mod architecture;
mod constants;
mod operation;
mod payload;
mod request;
mod response;
mod result;
mod target;
mod validation;
mod version;

pub use architecture::ProtocolArchitecture;
pub use constants::{MAX_PAYLOAD_SIZE_BYTES, MAX_REQUEST_SIZE_BYTES, SCHEMA_VERSION};
pub use operation::{HelperCapability, HelperOperation};
pub use payload::HelperPayload;
pub use request::{HelperOptions, HelperRequest};
pub use response::{HelperError, HelperResponse};
pub use result::{
    HelperResult, LoadLibraryResult, ModuleQueryResult, ProcessQueryResult, SelfTestCheck,
    SelfTestResult, WindowsModuleInfo, WindowsProcessInfo,
};
pub use target::{HelperTarget, TargetSelector};
pub use validation::ProtocolValidationError;
pub use version::HelperVersion;
