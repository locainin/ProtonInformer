//! Compact duration parser coverage

use std::time::Duration;

use proton_informer::duration::parse_compact;

#[test]
fn compact_duration_accepts_supported_units() {
    assert_eq!(
        parse_compact("15s", "timeout").expect("seconds duration"),
        Duration::from_secs(15)
    );
    assert_eq!(
        parse_compact("2m", "timeout").expect("minutes duration"),
        Duration::from_mins(2)
    );
    assert_eq!(
        parse_compact("3h", "timeout").expect("hours duration"),
        Duration::from_hours(3)
    );
    assert_eq!(
        parse_compact("1d", "timeout").expect("days duration"),
        Duration::from_hours(24)
    );
}

#[test]
fn compact_duration_rejects_ambiguous_or_invalid_values() {
    assert!(parse_compact("15", "timeout").is_err());
    assert!(parse_compact("0s", "timeout").is_err());
    assert!(parse_compact("s", "timeout").is_err());
    assert!(parse_compact("1 week", "timeout").is_err());
    assert!(parse_compact("1w", "timeout").is_err());
}

#[test]
fn compact_duration_rejects_overflow_before_constructing_duration() {
    let value = format!("{}d", u64::MAX);

    let error = parse_compact(&value, "timeout").expect_err("overflow must be rejected");

    assert!(error.to_string().contains("exceeds the supported range"));
}
