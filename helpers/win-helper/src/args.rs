//! Command parser for the helper's narrow interface

use std::path::PathBuf;

use crate::error::HelperFailure;

/// Supported helper command
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Print the supported command syntax
    Help,
    /// Read one request from a JSON file
    Request(PathBuf),
    /// Run non-mutating environment checks
    SelfTest,
    /// Print helper identity and capabilities
    Version,
}

/// Parses process arguments without accepting free-form operation fields
pub fn parse() -> Result<Command, HelperFailure> {
    parse_from(std::env::args_os().skip(1))
}

/// Parses an explicit argument iterator
fn parse_from<I>(arguments: I) -> Result<Command, HelperFailure>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut arguments = arguments.into_iter();
    let flag = arguments
        .next()
        .ok_or_else(|| HelperFailure::usage("missing command"))?;
    let flag = flag
        .to_str()
        .ok_or_else(|| HelperFailure::usage("command is not valid Unicode"))?;

    let command = match flag {
        "-h" | "--help" => Command::Help,
        "--version-json" => Command::Version,
        "--self-test-json" => Command::SelfTest,
        "--request-json" => {
            let path = arguments
                .next()
                .ok_or_else(|| HelperFailure::usage("--request-json requires a path"))?;
            Command::Request(PathBuf::from(path))
        }
        _ => return Err(HelperFailure::usage("unknown command")),
    };

    if arguments.next().is_some() {
        return Err(HelperFailure::usage("unexpected extra argument"));
    }
    Ok(command)
}

/// Returns the helper's command syntax
pub const fn usage() -> &'static str {
    concat!(
        "Usage: proton-informer-win-helper <COMMAND>\n\n",
        "Commands:\n",
        "  --request-json <PATH>  Execute one typed JSON request\n",
        "  --self-test-json       Run non-mutating helper checks\n",
        "  --version-json         Print helper identity and capabilities\n",
        "  -h, --help             Print this help",
    )
}
