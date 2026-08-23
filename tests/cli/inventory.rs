use std::process::Command;

use proton_informer::process::{
    ClassificationConfidence, EnvironmentStatus, ProcessEvidenceFailure, ProcessInfo, TargetKind,
};
use serde_json::Value;
use serde_json::json;

#[test]
fn processes_json_keeps_the_documented_top_level_array_contract() {
    let output = Command::new(env!("CARGO_BIN_EXE_proton-informer"))
        .args(["--json", "processes"])
        .output()
        .expect("CLI should start");
    let stdout = String::from_utf8(output.stdout).expect("process JSON should be UTF-8");

    assert!(output.status.success());
    let value: Value = serde_json::from_str(&stdout).expect("process JSON should be valid");
    assert!(value.is_array());
}

#[test]
fn process_json_row_contract_documents_the_intentional_legacy_field_change() {
    let process = ProcessInfo {
        classification_confidence: ClassificationConfidence::High,
        command: Vec::new(),
        compatdata_dir: None,
        environment_status: EnvironmentStatus::NotInspected,
        evidence_failures: vec![ProcessEvidenceFailure {
            kind: "permission_denied".into(),
            message: "optional procfs evidence was unavailable".into(),
        }],
        executable: None,
        guest_architecture: None,
        guest_executable: None,
        name: "native-process".into(),
        owned_by_current_user: Some(true),
        pid: 123,
        start_time_ticks: 0,
        proton_dist: None,
        steam_app_id: None,
        steam_client_path: None,
        target_kind: TargetKind::NativeLinux,
        uids: None,
        wine_prefix: None,
    };
    let row = serde_json::to_value(process).expect("process row should serialize");

    assert_eq!(row["environment_status"], json!("not_inspected"));
    assert_eq!(row["start_time_ticks"], json!(0));
    assert!(row.get("evidence_failures").is_some());
    assert!(row.get("host_architecture").is_none());
}
