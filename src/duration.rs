//! Compact duration parsing shared by bounded CLI operations.

use std::time::Duration;

use crate::error::{Error, Result};

/// Parses a positive duration using seconds, minutes, hours, or days.
///
/// # Errors
///
/// Returns an error for missing, zero, overflowing, or unknown units.
pub fn parse_compact(value: &str, field: &str) -> Result<Duration> {
    let value = value.trim();
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .ok_or_else(|| Error::InvalidInput(format!("{field} requires a unit: s, m, h, or d")))?;
    let (amount, unit) = value.split_at(split);
    let amount = amount
        .parse::<u64>()
        .map_err(|_| Error::InvalidInput(format!("{field} must start with a positive integer")))?;
    if amount == 0 {
        return Err(Error::InvalidInput(format!(
            "{field} must be greater than zero"
        )));
    }
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => {
            return Err(Error::InvalidInput(format!(
                "{field} unit must be s, m, h, or d"
            )));
        }
    };
    let seconds = amount
        .checked_mul(multiplier)
        .ok_or_else(|| Error::InvalidInput(format!("{field} exceeds the supported range")))?;
    Ok(Duration::from_secs(seconds))
}
