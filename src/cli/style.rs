use crate::doctor::{CapabilityReadiness, CheckStatus};

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

pub(super) fn failure_word(value: &'static str) -> &'static str {
    colorize(value, "\x1b[1;31m")
}

pub(super) fn readiness(value: CapabilityReadiness) -> &'static str {
    match value {
        CapabilityReadiness::Ready => success_word("Ready"),
        CapabilityReadiness::Unavailable => failure_word("Unavailable"),
    }
}

pub(super) fn status(value: CheckStatus) -> &'static str {
    match value {
        CheckStatus::Passed => success_word("Passed"),
        CheckStatus::Warning => warning_word("Warning"),
        CheckStatus::Failed => failure_word("Failed"),
    }
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
        ("\x1b[1;31m", "Failed") => "\x1b[1;31mFailed\x1b[0m",
        ("\x1b[1;31m", "Unavailable") => "\x1b[1;31mUnavailable\x1b[0m",
        ("\x1b[1;31m", "Verified") => "\x1b[1;31mVerified\x1b[0m",
        ("\x1b[1;33m", "Likely cause:") => "\x1b[1;33mLikely cause:\x1b[0m",
        ("\x1b[1;33m", "no") => "\x1b[1;33mno\x1b[0m",
        ("\x1b[1;33m", "Warning") => "\x1b[1;33mWarning\x1b[0m",
        ("\x1b[1;32m", "Loaded") => "\x1b[1;32mLoaded\x1b[0m",
        ("\x1b[1;32m", "Passed") => "\x1b[1;32mPassed\x1b[0m",
        ("\x1b[1;32m", "Ready") => "\x1b[1;32mReady\x1b[0m",
        ("\x1b[1;32m", "Verified") => "\x1b[1;32mVerified\x1b[0m",
        ("\x1b[1;32m", "yes") => "\x1b[1;32myes\x1b[0m",
        ("\x1b[1;33m", "Already loaded") => "\x1b[1;33mAlready loaded\x1b[0m",
        _ => value,
    }
}
