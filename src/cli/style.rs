use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};

static COLOR_ENABLED: AtomicBool = AtomicBool::new(false);

pub(super) fn configure(text_output: bool) {
    // Avoid ANSI escapes in JSON, pipes, dumb terminals, and NO_COLOR sessions
    let color_allowed = text_output
        && std::io::stdout().is_terminal()
        && std::io::stderr().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var_os("TERM").is_none_or(|term| term != "dumb");
    COLOR_ENABLED.store(color_allowed, Ordering::Relaxed);
}

pub(super) fn error_label() -> &'static str {
    colorize("Error:", "\x1b[1;31m")
}

pub(super) fn hint_label() -> &'static str {
    colorize("Likely cause:", "\x1b[1;33m")
}

pub(super) fn success_word(value: &'static str) -> &'static str {
    colorize(value, "\x1b[1;32m")
}

pub(super) fn warning_word(value: &'static str) -> &'static str {
    colorize(value, "\x1b[1;33m")
}

fn colorize(value: &'static str, color: &'static str) -> &'static str {
    if !COLOR_ENABLED.load(Ordering::Relaxed) {
        return value;
    }

    // Return static strings so labels can be formatted without allocation
    match (color, value) {
        ("\x1b[1;31m", "Error:") => "\x1b[1;31mError:\x1b[0m",
        ("\x1b[1;33m", "Likely cause:") => "\x1b[1;33mLikely cause:\x1b[0m",
        ("\x1b[1;32m", "Loaded") => "\x1b[1;32mLoaded\x1b[0m",
        ("\x1b[1;32m", "Verified") => "\x1b[1;32mVerified\x1b[0m",
        ("\x1b[1;33m", "Already loaded") => "\x1b[1;33mAlready loaded\x1b[0m",
        ("\x1b[1;33m", "Warning") => "\x1b[1;33mWarning\x1b[0m",
        _ => value,
    }
}
