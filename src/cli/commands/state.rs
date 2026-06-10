use std::path::Path;

use crate::error::Result;
use crate::runs;

use crate::cli::output;

/// Lists safe managed run-state directories
pub(super) fn run_runs(prefix: Option<&Path>, json: bool) -> Result<()> {
    let report = prefix.map_or_else(runs::list, runs::list_for_prefix)?;
    if json {
        output::error::print_json(&report)
    } else {
        output::state::print_runs(&report);
        Ok(())
    }
}

/// Removes all or age-filtered managed run-state directories
pub(super) fn run_cleanup(
    older_than: Option<&str>,
    prefix: Option<&Path>,
    json: bool,
) -> Result<()> {
    let threshold = older_than.map(runs::parse_age).transpose()?;
    let report = prefix.map_or_else(
        || runs::cleanup(threshold),
        |prefix| runs::cleanup_for_prefix(prefix, threshold),
    )?;
    if json {
        output::error::print_json(&report)
    } else {
        output::state::print_cleanup(&report);
        Ok(())
    }
}
