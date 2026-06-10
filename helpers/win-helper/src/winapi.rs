//! Unsafe Windows API boundary
//!
//! Raw handles and pointers are confined to this module tree. Public functions
//! return owned Rust values and convert Windows failures immediately

mod common;
mod dependencies;
mod loader;
mod modules;
mod payload;
mod processes;

pub use dependencies::dependency_visible;
pub use loader::load_library;
pub use modules::modules;
pub use payload::{LockedPayload, lock_payload};
pub use processes::{current_process_id, processes};
