use serde::Serialize;

use crate::error::{Error, Result};

/// Machine-readable error response
#[derive(Debug, Serialize)]
struct ErrorEnvelope<'a> {
    error: ErrorBody<'a>,
    ok: bool,
}

/// Stable error category and user-facing detail
#[derive(Debug, Serialize)]
struct ErrorBody<'a> {
    kind: &'static str,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    windows_error: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    windows_error_hint: Option<&'static str>,
}

/// Writes a serialized value to standard output
pub(in crate::cli) fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let output = serde_json::to_string_pretty(value).map_err(Error::from)?;
    println!("{output}");
    Ok(())
}

/// Writes a structured error to standard error
pub(in crate::cli) fn print_error(
    kind: &'static str,
    message: &str,
    windows_error: Option<u32>,
    windows_error_hint: Option<&'static str>,
) {
    let envelope = ErrorEnvelope {
        error: ErrorBody {
            kind,
            message,
            windows_error,
            windows_error_hint,
        },
        ok: false,
    };

    // Keep diagnostics visible if the error envelope changes later
    match serde_json::to_string_pretty(&envelope) {
        Ok(output) => eprintln!("{output}"),
        Err(_) => eprintln!("Error: {message}"),
    }
}
