//! Parser for positive compact durations such as `30s` and `5m`

use std::time::Duration;

use crate::error::{Error, Result};

const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 60 * SECONDS_PER_MINUTE;
const SECONDS_PER_DAY: u64 = 24 * SECONDS_PER_HOUR;

struct CompactDuration<'a> {
    amount: u64,
    field: &'a str,
    unit: &'a str,
}

/// Parses a positive duration using seconds, minutes, hours, or days
///
/// # Errors
///
/// Returns an error for missing, zero, overflowing, or unknown units
pub fn parse_compact(value: &str, field: &str) -> Result<Duration> {
    // Whitespace is tolerated around the value but not between amount and unit
    let value = value.trim();
    let parsed = parse_parts(value, field)?;
    let multiplier = unit_multiplier(parsed.unit, parsed.field)?;

    // checked_mul keeps very large values from wrapping into a smaller duration
    let seconds = parsed.amount.checked_mul(multiplier).ok_or_else(|| {
        Error::InvalidInput(format!("{} exceeds the supported range", parsed.field))
    })?;
    Ok(Duration::from_secs(seconds))
}

fn parse_parts<'a>(value: &'a str, field: &'a str) -> Result<CompactDuration<'a>> {
    let (amount, unit) = split_amount_and_unit(value, field)?;
    let amount = parse_amount(amount, field)?;

    Ok(CompactDuration {
        amount,
        field,
        unit,
    })
}

fn split_amount_and_unit<'a>(value: &'a str, field: &str) -> Result<(&'a str, &'a str)> {
    // The first non-digit starts the unit; missing units are rejected as ambiguous
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .ok_or_else(|| Error::InvalidInput(format!("{field} requires a unit: s, m, h, or d")))?;
    Ok(value.split_at(split))
}

fn parse_amount(amount: &str, field: &str) -> Result<u64> {
    let amount = amount
        .parse::<u64>()
        .map_err(|_| Error::InvalidInput(format!("{field} must start with a positive integer")))?;

    // Zero-duration waits and cleanup ages are usually caller mistakes
    if amount == 0 {
        return Err(Error::InvalidInput(format!(
            "{field} must be greater than zero"
        )));
    }

    Ok(amount)
}

fn unit_multiplier(unit: &str, field: &str) -> Result<u64> {
    match unit {
        "s" => Ok(1),
        "m" => Ok(SECONDS_PER_MINUTE),
        "h" => Ok(SECONDS_PER_HOUR),
        "d" => Ok(SECONDS_PER_DAY),
        _ => Err(Error::InvalidInput(format!(
            "{field} unit must be s, m, h, or d"
        ))),
    }
}
