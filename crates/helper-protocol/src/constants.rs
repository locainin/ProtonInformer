/// Current helper protocol schema.
pub const SCHEMA_VERSION: u32 = 2;

/// Largest payload accepted by controller and helper validation.
pub const MAX_PAYLOAD_SIZE_BYTES: u64 = 256 * 1024 * 1024;

/// Largest helper request document accepted from disk.
pub const MAX_REQUEST_SIZE_BYTES: u64 = 1024 * 1024;
