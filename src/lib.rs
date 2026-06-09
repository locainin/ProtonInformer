//! Core inspection and planning library for `ProtonInformer`.
//!
//! Modules expose typed data for the CLI and other clients. Remote loading is
//! delegated to the Windows helper after controller-side validation.

#![forbid(unsafe_code)]
#![deny(warnings)]
#![warn(clippy::pedantic, clippy::nursery)]

pub mod binary;
pub mod cli;
pub mod decision;
pub mod doctor;
pub mod error;
pub mod helper;
pub mod helper_executor;
pub mod helper_protocol;
pub mod helper_runtime;
pub mod inject;
pub mod install;
pub mod load;
pub mod process;
pub mod steam;
pub mod types;
pub mod wine;

pub use error::{Error, Result};
