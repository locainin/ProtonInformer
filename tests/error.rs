//! Stable error categories.

use proton_informer::Error;

#[test]
fn invalid_input_has_stable_json_kind() {
    let error = Error::InvalidInput("fixture".into());

    assert_eq!(error.kind(), "invalid_input");
}
