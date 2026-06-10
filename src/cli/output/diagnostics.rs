use crate::doctor::DoctorReport;
use crate::install::InstallVerification;

/// Writes readiness by capability rather than one broad Wine status
pub(in crate::cli) fn print_doctor(report: DoctorReport) {
    println!("Process planning: {:?}", report.process_planning);
    println!("Steam discovery: {:?}", report.steam_discovery);
    println!("Wine helper x86: {:?}", report.wine_helper_x86);
    println!("Wine helper x86_64: {:?}", report.wine_helper_x86_64);
    for check in report.checks {
        println!("  [{:?}] {}: {}", check.status, check.name, check.detail);
    }
}

/// Writes every verified helper installation identity
pub(in crate::cli) fn print_install_verifications(reports: &[InstallVerification]) {
    for (index, report) in reports.iter().enumerate() {
        if index != 0 {
            println!();
        }
        println!("Helper Installation");
        println!("  Path:             {}", report.helper_path.display());
        println!("  Source:           {}", report.helper_source);
        println!("  Architecture:     {}", report.architecture);
        println!(
            "  Version:          {}",
            report.version.as_deref().unwrap_or("<not probed>")
        );
        println!(
            "  Schema:           {}",
            report
                .schema_version
                .map_or_else(|| "<not probed>".into(), |version| version.to_string())
        );
        println!("  SHA-256:          {}", report.helper_sha256);
        println!("  Static verified:  yes");
        println!("  Runtime verified: {}", report.runtime_verified);
        for warning in &report.warnings {
            println!("  Warning:          {warning}");
        }
    }
}
