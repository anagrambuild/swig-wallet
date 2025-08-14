//! Recurring token destination limit action type.
//!
//! This module defines the TokenRecurringDestinationLimit action type which
//! enforces recurring limits on token operations to specific destinations
//! within the Swig wallet system. The limit resets after a specified time
//! window.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, SwigAuthenticateError, SwigStateError, Transmutable, TransmutableMut};

/// Represents a recurring limit on token operations to a specific destination.
///
/// This struct tracks and enforces a maximum amount of tokens that can be
/// sent to a specific destination token account within a specified time window.
/// The limit resets automatically after the window expires.
///
/// The matching key is a combination of [token_mint + destination] (64 bytes
/// total) to allow for precise control over token transfers to specific
/// destinations.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct TokenRecurringDestinationLimit {
    /// The token mint pubkey (32 bytes)
    pub token_mint: [u8; 32],
    /// The destination token account pubkey (32 bytes)
    pub destination: [u8; 32],
    /// The amount that resets each window (in token base units)
    pub recurring_amount: u64,
    /// The time window in slots after which the limit resets
    pub window: u64,
    /// The last slot when the limit was reset
    pub last_reset: u64,
    /// The current remaining amount that can be used (in token base units)
    pub current_amount: u64,
}

impl TokenRecurringDestinationLimit {
    /// Processes a token operation to this destination and updates the
    /// remaining limit.
    ///
    /// If the time window has expired, the limit is reset before processing
    /// the operation.
    ///
    /// # Arguments
    /// * `token_diff` - The amount of tokens to be sent in the operation
    /// * `current_slot` - The current slot number
    ///
    /// # Returns
    /// * `Ok(())` - If the operation is within limits
    /// * `Err(ProgramError)` - If the operation would exceed the limit
    pub fn run(&mut self, token_diff: u64, current_slot: u64) -> Result<(), ProgramError> {
        // Reset the limit if the time window has expired and the operation would fit in
        // a fresh window
        if current_slot - self.last_reset > self.window && token_diff <= self.recurring_amount {
            self.current_amount = self.recurring_amount;
            self.last_reset = current_slot;
        }

        // Check if the operation exceeds the current available amount
        if token_diff > self.current_amount {
            return Err(
                SwigAuthenticateError::PermissionDeniedRecurringTokenDestinationLimitExceeded
                    .into(),
            );
        }

        // Deduct the amount from the current limit
        self.current_amount -= token_diff;
        Ok(())
    }

    /// Checks if this destination limit matches the provided token mint and
    /// destination.
    ///
    /// # Arguments
    /// * `combined_key` - The combined key [token_mint + destination] (64
    ///   bytes)
    ///
    /// # Returns
    /// * `bool` - True if the token mint and destination match
    pub fn matches_destination(&self, combined_key: &[u8; 64]) -> bool {
        let token_mint: [u8; 32] = combined_key[0..32].try_into().unwrap_or([0; 32]);
        let destination: [u8; 32] = combined_key[32..64].try_into().unwrap_or([0; 32]);

        self.token_mint == token_mint && self.destination == destination
    }
}

impl Transmutable for TokenRecurringDestinationLimit {
    /// Size of the TokenRecurringDestinationLimit struct in bytes (32 + 32 + 8
    /// + 8 + 8 + 8 = 96)
    const LEN: usize = core::mem::size_of::<TokenRecurringDestinationLimit>();
}

impl TransmutableMut for TokenRecurringDestinationLimit {}

impl IntoBytes for TokenRecurringDestinationLimit {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> Actionable<'a> for TokenRecurringDestinationLimit {
    /// This action represents the TokenRecurringDestinationLimit permission
    /// type
    const TYPE: Permission = Permission::TokenRecurringDestinationLimit;
    /// Multiple recurring destination limits can exist per role (for different
    /// token mint + destination combinations)
    const REPEATABLE: bool = true;

    /// Checks if this action matches the provided combined key data.
    fn match_data(&self, data: &[u8]) -> bool {
        if data.len() >= 64 {
            let combined_key: [u8; 64] = data[0..64].try_into().unwrap_or([0; 64]);
            self.matches_destination(&combined_key)
        } else {
            false
        }
    }

    fn valid_layout(data: &'a [u8]) -> Result<bool, ProgramError> {
        if data.len() != Self::LEN {
            return Ok(false);
        }

        // Validate that the struct fields are properly aligned and contain valid data
        let token_mint = &data[0..32];
        let destination = &data[32..64];
        let recurring_amount = u64::from_le_bytes(
            data[64..72]
                .try_into()
                .map_err(|_| SwigStateError::InvalidActionData)?,
        );
        let window = u64::from_le_bytes(
            data[72..80]
                .try_into()
                .map_err(|_| SwigStateError::InvalidActionData)?,
        );
        let _last_reset = u64::from_le_bytes(
            data[80..88]
                .try_into()
                .map_err(|_| SwigStateError::InvalidActionData)?,
        );
        let current_amount = u64::from_le_bytes(
            data[88..96]
                .try_into()
                .map_err(|_| SwigStateError::InvalidActionData)?,
        );

        // Validate that the token_mint is a valid pubkey (32 bytes, all zeros is valid)
        if token_mint.len() != 32 {
            return Ok(false);
        }

        // Validate that the destination is a valid pubkey (32 bytes, all zeros is
        // valid)
        if destination.len() != 32 {
            return Ok(false);
        }

        // Validate that window is not zero (would cause division by zero)
        if window == 0 {
            return Ok(false);
        }

        // Validate that current_amount doesn't exceed recurring_amount
        if current_amount > recurring_amount {
            return Ok(false);
        }

        Ok(true)
    }
}
