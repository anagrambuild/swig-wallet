//! Wildcard keys for token limits.
//!
//! Token limit actions can carry wildcard keys so a single action covers
//! "any mint" and/or "any destination". A wildcard key is a 32-byte key of
//! all `0xFF` bytes, reserved here to mean any key. Wildcards let a role trade any token program-native asset
//! (up to a spend limit) without enumerating every mint, as long as the
//! interacting programs are scoped through program permissions.
//!
//! Every applicable scope is charged: exact and wildcard limits compose
//! restrictively, including both one-shot and recurring ledgers. Amounts
//! are shared raw token base units, not prices or decimal-normalized values.

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
