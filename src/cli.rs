//! Command-line orchestration kept separate from the executable entry point

mod args;
mod commands;
mod output;

use std::ffi::OsString;
use std::process::ExitCode;

use clap::{Parser, error::ErrorKind};

use self::args::Cli;

/// Parses process arguments, runs one command, and returns its exit status
#[must_use]
pub fn launch() -> ExitCode {
    launch_from(std::env::args_os())
}

/// Runs the CLI from an explicit argument source
///
/// Keeping parsing here allows tests and other clients to exercise the same
/// command boundary without adding logic to `main.rs`
fn launch_from<I, T>(arguments: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let collected: Vec<OsString> = arguments.into_iter().map(Into::into).collect();
    let json_requested = collected.iter().any(|argument| argument == "--json");
    let cli = match Cli::try_parse_from(collected) {
        Ok(cli) => cli,
        Err(error) => {
            let informational = matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            );
            if informational {
                if let Err(print_error) = error.print() {
                    eprintln!("Error: {print_error}");
                }
                return ExitCode::SUCCESS;
            }
            if json_requested {
                output::print_error("cli_parse", &error.to_string(), None, None);
            } else if let Err(print_error) = error.print() {
                eprintln!("Error: {print_error}");
            }
            return ExitCode::from(2);
        }
    };
    let json = cli.json;

    match commands::run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if json {
                output::print_error(
                    error.kind(),
                    &error.to_string(),
                    error.windows_error(),
                    error.windows_error_hint(),
                );
            } else {
                eprintln!("Error: {error}");
                if let Some(hint) = error.windows_error_hint() {
                    eprintln!("Likely cause: {hint}");
                }
            }
            ExitCode::FAILURE
        }
    }
}
