//! Windows-side helper entry point.

#![deny(warnings)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::pedantic, clippy::nursery)]

mod args;
mod error;
mod load;
mod modules;
mod process;
mod protocol;
mod self_test;

#[cfg(windows)]
mod winapi;

use std::process::ExitCode;

use error::HelperFailure;

fn main() -> ExitCode {
    match args::parse().and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// Executes one validated helper command.
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
