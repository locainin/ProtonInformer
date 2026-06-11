use crate::runs::{CleanupReport, RunStateReport};

use crate::cli::style;

/// Writes managed run-state directories and retained warnings
pub(in crate::cli) fn print_runs(report: &RunStateReport) {
    println!("Run State");
    println!("  Root: {}", report.root.display());
    for run in &report.runs {
        println!(
            "  {}  age={}s  {}",
            run.request_id,
            run.age_seconds,
            run.path.display()
        );
    }
    for warning in &report.warnings {
        eprintln!("{}: {warning}", style::warning_word("Warning"));
    }
}

/// Writes one cleanup summary and every skipped-entry warning
pub(in crate::cli) fn print_cleanup(report: &CleanupReport) {
    println!("Run Cleanup");
    println!("  Root:    {}", report.root.display());
    println!("  Removed: {}", report.removed);
    for warning in &report.warnings {
        eprintln!("{}: {warning}", style::warning_word("Warning"));
    }
}
