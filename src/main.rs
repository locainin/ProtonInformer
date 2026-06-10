//! Minimal executable entry point for `ProtonInformer`

#![forbid(unsafe_code)]
#![deny(warnings)]
#![warn(clippy::pedantic, clippy::nursery)]

use std::process::ExitCode;

fn main() -> ExitCode {
    proton_informer::cli::launch()
}
