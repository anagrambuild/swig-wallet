//! Wildcard keys for token limits.
//!
//! An all-`0xFF` mint or destination in a token limit action covers any mint
//! or destination. A wildcard mint grants unlimited spend within its
//! destination scope and its amount fields are ignored. A wildcard destination
//! with an exact mint behaves like a normal destination limit and tracks
//! amounts in that mint's base units.

/// Wildcard key: 32 `0xFF` bytes.
pub const WILDCARD: [u8; 32] = [0xFF; 32];

/// Returns true when `key` is the wildcard key.
#[inline(always)]
pub fn is_wildcard(key: &[u8]) -> bool {
    key == WILDCARD
}

/// True when `action_field` matches `input_field` or is the wildcard.
#[inline(always)]
pub fn covers_field(action_field: &[u8], input_field: &[u8]) -> bool {
    action_field == input_field || is_wildcard(action_field)
}
