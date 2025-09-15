//! Recurring token limit action type.
//!
//! This module defines the TokenRecurringLimit action type which enforces
//! recurring limits on token operations within the Swig wallet system.
//! Each limit is specific to a particular token mint and resets after
//! a specified time window.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Represents a recurring limit on token operations for a specific token mint.
///
/// This struct tracks and enforces a maximum amount of tokens that can be
/// used in operations within a specified time window. The limit is specific
/// to a particular token mint and resets automatically after the window
/// expires.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct TokenRecurringLimit {
    /// The mint address of the token this limit applies to
    pub token_mint: [u8; 32],
    /// The time window in slots after which the limit resets
    pub window: u64,
    /// The amount that resets each window
    pub limit: u64,
    /// The current remaining amount that can be used
    pub current: u64,
    /// The last slot when the limit was reset
    pub last_reset: u64,
}

impl TokenRecurringLimit {
    /// Processes a token operation and updates the remaining limit.
    ///
    /// If the time window has expired, the limit is reset before processing
    /// the operation.
    ///
    /// # Arguments
    /// * `amount` - The amount of tokens to be used in the operation
    /// * `current_slot` - The current slot number
    ///
    /// # Returns
    /// * `Ok(())` - If the operation is within limits
    /// * `Err(ProgramError)` - If the operation would exceed the limit
    pub fn run(&mut self, amount: u64, current_slot: u64) -> Result<(), ProgramError> {
        if current_slot.saturating_sub(self.last_reset) > self.window && amount <= self.limit {
            self.current = self.limit;
            // reset the last reset to the start of the current window
            self.last_reset = (current_slot / self.window) * self.window;
        }
        if amount > self.current {
            return Err(ProgramError::InsufficientFunds);
        }
        self.current = self.current.saturating_sub(amount);
        Ok(())
    }
}

impl Transmutable for TokenRecurringLimit {
    /// Size of the TokenRecurringLimit struct in bytes
    const LEN: usize = 64;
}

impl TransmutableMut for TokenRecurringLimit {}

impl IntoBytes for TokenRecurringLimit {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> Actionable<'a> for TokenRecurringLimit {
    /// This action represents the TokenRecurringLimit permission type
    const TYPE: Permission = Permission::TokenRecurringLimit;
    /// Multiple recurring token limits can exist per role (one per token mint)
    const REPEATABLE: bool = true;

    /// Checks if this token limit matches the provided token mint.
    ///
    /// # Arguments
    /// * `data` - The token mint to check against (first 32 bytes)
    fn match_data(&self, data: &[u8]) -> bool {
        data[0..32] == self.token_mint
    }

    fn valid_layout(data: &'a [u8]) -> Result<bool, ProgramError> {
        // current amount needs to be equal to limit
        let current = &data[48..56];
        let limit = &data[40..48];
        // last reset needs to be 0
        let last_reset = &data[56..64];
        Ok(current == limit && last_reset == &[0u8; 8] && data.len() == Self::LEN)
    }
}
