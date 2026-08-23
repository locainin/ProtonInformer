//! Windows-side helper command and protocol implementation

#![deny(warnings)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::doc_paragraphs_missing_punctuation,
    reason = "existing helper documentation uses concise comment-style sentences"
)]

mod args;
pub mod error;
pub mod imports;
mod load;
pub mod module_identity;
mod modules;
mod process;
mod protocol;
mod self_test;
mod windows_path;

#[cfg(windows)]
mod winapi;

use std::process::ExitCode;

use error::HelperFailure;

/// Parses process arguments and returns one helper exit status
#[must_use]
pub fn main_entry() -> ExitCode {
    match args::parse().and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// Executes one validated helper command
fn run(command: args::Command) -> Result<(), HelperFailure> {
    match command {
        args::Command::Help => {
            println!("{}", args::usage());
            Ok(())
        }
        args::Command::Request(path) => protocol::run_request_file(&path),
        args::Command::SelfTest => protocol::write_json(&self_test::run()?),
        args::Command::Version => protocol::write_json(&protocol::version()),
    }
}
