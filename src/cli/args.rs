use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::types::Architecture;

/// Parsed top-level command-line input
#[derive(Debug, Parser)]
#[command(
    name = "proton-informer",
    version,
    about = "Load Windows PE DLLs into Wine and Proton processes from Linux"
)]
pub(super) struct Cli {
    /// Emit machine-readable success and error output
    #[arg(long, global = true)]
    pub(super) json: bool,

    /// Print extra target and runtime diagnostics in text output
    #[arg(long, global = true)]
    pub(super) debug: bool,

    /// Operation selected by the caller
    #[command(subcommand)]
    pub(super) command: Command,
}

/// Supported CLI operations
#[derive(Debug, Subcommand)]
pub(super) enum Command {
    /// Remove safe controller-managed run state
    Cleanup {
        /// Remove only runs at least this old, using s, m, h, or d
        #[arg(long)]
        older_than: Option<String>,

        /// Inspect the fallback state directory inside this Wine prefix
        #[arg(long)]
        prefix: Option<PathBuf>,
    },

    /// Check local Steam, Wine, helper, process, and state readiness
    Doctor {
        /// Wine or Proton process used for live helper diagnostics
        #[arg(long)]
        pid: Option<u32>,
    },

    /// Inspect a payload from its binary headers
    Inspect {
        /// Payload file to inspect
        payload: PathBuf,
    },

    /// Discover a Wine or Proton target and load one validated PE DLL
    Inject {
        /// Payload DLL to validate and load
        #[arg(long)]
        payload: PathBuf,

        /// Exact Linux process identifier
        #[arg(long, required_unless_present = "app_id", conflicts_with = "app_id")]
        pid: Option<u32>,

        /// Steam application identifier used for game and process discovery
        #[arg(long, required_unless_present = "pid", conflicts_with = "pid")]
        app_id: Option<u32>,

        /// Guest executable basename used to disambiguate an `AppID`
        #[arg(long)]
        process: Option<String>,

        /// Wait for the named final game process, using s, m, h, or d
        #[arg(
            long,
            value_name = "DURATION",
            requires = "app_id",
            requires = "process",
            conflicts_with = "pid"
        )]
        wait_for: Option<String>,

        /// Generate request artifacts without running the helper
        #[arg(long, conflicts_with = "yes")]
        dry_run: bool,

        /// Execute the validated helper request for real
        #[arg(long, conflicts_with = "dry_run")]
        yes: bool,

        /// Retain bounded helper stdout and stderr in the private run directory
        #[arg(long)]
        keep_run_files: bool,

        /// Load the less-isolated original payload path instead of a private staged copy
        #[arg(long)]
        original_payload_path: bool,

        /// Maximum helper operation time in milliseconds
        #[arg(
            long,
            default_value_t = 10_000,
            value_parser = clap::value_parser!(u64).range(1..=300_000)
        )]
        timeout_ms: u64,
    },

    /// Prepare or execute a helper-backed load for a running Wine process
    Load {
        /// Payload DLL to validate and load
        #[arg(long)]
        payload: PathBuf,

        /// Target Linux process identifier used to discover the Wine runtime
        #[arg(long)]
        pid: u32,

        /// Explicit guest architecture when process inspection cannot prove it
        #[arg(long, value_enum)]
        target_arch: Option<Architecture>,

        /// Generate request artifacts and print the invocation without running it
        #[arg(long, required_unless_present = "yes", conflicts_with = "yes")]
        dry_run: bool,

        /// Execute the validated helper request for real
        #[arg(long, required_unless_present = "dry_run", conflicts_with = "dry_run")]
        yes: bool,

        /// Retain bounded helper stdout and stderr in the private run directory
        #[arg(long)]
        keep_run_files: bool,

        /// Load the less-isolated original payload path instead of a private staged copy
        #[arg(long)]
        original_payload_path: bool,

        /// Maximum helper operation time in milliseconds
        #[arg(
            long,
            default_value_t = 10_000,
            value_parser = clap::value_parser!(u64).range(1..=300_000)
        )]
        timeout_ms: u64,
    },

    /// List modules loaded by one exact Wine or Proton process
    Modules {
        /// Exact Linux process identifier
        #[arg(long, required_unless_present = "app_id", conflicts_with = "app_id")]
        pid: Option<u32>,

        /// Steam application identifier used for game and process discovery
        #[arg(long, required_unless_present = "pid", conflicts_with = "pid")]
        app_id: Option<u32>,

        /// Guest executable basename used to disambiguate an `AppID`
        #[arg(long)]
        process: Option<String>,

        /// Case-insensitive module basename substring
        #[arg(long, value_parser = non_empty_string)]
        filter: Option<String>,

        /// Case-insensitive module basename or path substring
        #[arg(long, value_parser = non_empty_string)]
        contains: Option<String>,
    },

    /// Plan a startup DLL override for an app or explicit Wine prefix
    OverridePlan {
        /// Payload DLL to validate
        #[arg(long)]
        payload: PathBuf,

        /// DLL base name used by `WINEDLLOVERRIDES`
        #[arg(long)]
        dll_name: String,

        /// Steam application identifier
        #[arg(long, required_unless_present = "prefix", conflicts_with = "prefix")]
        app_id: Option<u32>,

        /// Existing Wine prefix
        #[arg(long, required_unless_present = "app_id", conflicts_with = "app_id")]
        prefix: Option<PathBuf>,
    },

    /// Validate a payload and select a backend for a running process
    Plan {
        /// Windows PE payload DLL
        #[arg(long)]
        payload: PathBuf,

        /// Target process identifier
        #[arg(long)]
        pid: u32,

        /// Explicit guest architecture when process inspection cannot prove it
        #[arg(long, value_enum)]
        target_arch: Option<Architecture>,

        /// Plan the less-isolated original payload path instead of a private staged copy
        #[arg(long)]
        original_payload_path: bool,
    },

    /// List readable Linux, Wine, and Proton processes
    Processes {
        /// Show only targets supported by the Wine backend
        #[arg(long)]
        wine_only: bool,
    },

    /// List safe controller-managed run state
    Runs {
        /// Inspect the fallback state directory inside this Wine prefix
        #[arg(long)]
        prefix: Option<PathBuf>,
    },

    /// Discover games and existing Proton prefixes from Steam metadata
    SteamGames,

    /// Verify helper permissions, checksum, version, schema, and architecture
    VerifyInstall {
        /// Verify only the helper for this architecture without a live probe
        #[arg(long, value_enum, conflicts_with = "pid")]
        arch: Option<Architecture>,

        /// Also run a version and schema probe in this Wine or Proton process
        #[arg(long, conflicts_with = "arch")]
        pid: Option<u32>,
    },
}

/// Rejects blank filters while keeping absent filters as the show-all default
fn non_empty_string(value: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        Err("filter value cannot be empty".into())
    } else {
        Ok(value.to_owned())
    }
}
