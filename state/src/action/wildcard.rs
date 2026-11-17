//! Wildcard keys for token limits.
//!
//! Token limit actions can carry wildcard keys so a single action covers
//! "any mint" and/or "any destination". A wildcard key is a 32-byte key of
//! all `0xFF` bytes, reserved here to mean any key. A wildcard mint grants
//! unlimited token spend within its destination scope. Its amount and recurring
//! ledger fields are ignored.
//!
//! Exact-mint limits still apply; other mints remain unlimited. A wildcard
//! destination with an exact mint tracks amounts normally in that mint's base
//! units. No amounts are pooled across different mints.

/// The wildcard key: 32 `0xFF` bytes.
pub const WILDCARD: [u8; 32] = [0xFF; 32];

/// Returns true when `key` is the wildcard key. A fixed-slice compare
/// keeps the hot path allocation-free and branch-light.
#[inline(always)]
pub fn is_wildcard(key: &[u8]) -> bool {
    key.len() == 32 && key == WILDCARD
}

/// True when the action field covers the input field: an exact match, or
/// the action field is the wildcard (covering any input).
#[inline(always)]
pub fn covers_field(action_field: &[u8], input_field: &[u8]) -> bool {
    action_field == input_field || is_wildcard(action_field)
}
