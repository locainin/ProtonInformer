//! Shared type behavior.

use proton_informer::types::Architecture;

#[test]
fn host_architecture_has_stable_display_text() {
    assert!(!Architecture::host().to_string().is_empty());
}
