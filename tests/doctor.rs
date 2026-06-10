//! Capability-specific doctor reporting

use proton_informer::doctor::{self, CapabilityReadiness};

#[test]
fn process_planning_is_independent_from_steam_and_helpers() {
    let report = doctor::run();

    assert_eq!(report.process_planning, CapabilityReadiness::Ready);
    assert!(report.checks.iter().any(|check| check.name == "proc_self"));
}
