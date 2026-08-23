//! Shared value types used across inspection, discovery, and planning

use std::fmt;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

/// Processor architecture reported by parsed binary headers or explicit input
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    /// 32-bit Intel or AMD architecture
    X86,
    /// 64-bit Intel or AMD architecture
    X86_64,
    /// 32-bit ARM architecture
    Arm,
    /// 64-bit ARM architecture
    Aarch64,
    /// Architecture could not be established from trusted input
    Unknown,
}

impl fmt::Display for Architecture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keep user-facing output stable and independent from Rust target names
        let value = match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm => "arm",
            Self::Aarch64 => "aarch64",
            Self::Unknown => "unknown",
        };
        formatter.write_str(value)
    }
}
