//! Token limit action type.
//!
//! This module defines the TokenLimit action type which enforces limits on
//! token operations within the Swig wallet system. Each limit is specific
//! to a particular token mint.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut};

/// Represents a limit on token operations for a specific token mint.
///
/// This struct tracks and enforces a maximum amount of tokens that can be
/// used in operations. The limit is specific to a particular token mint
/// and is decreased as operations are performed.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct TokenLimit {
    /// The mint address of the token this limit applies to
    pub token_mint: [u8; 32],
    /// The remaining amount of tokens that can be used
    pub current_amount: u64,
}

impl TokenLimit {
    /// Processes a token operation and updates the remaining limit.
    ///
    /// # Arguments
    /// * `amount` - The amount of tokens to be used in the operation
    ///
    /// # Returns
    /// * `Ok(())` - If the operation is within limits
    /// * `Err(ProgramError)` - If the operation would exceed the limit
    pub fn run(&mut self, amount: u64) -> Result<(), ProgramError> {
        if amount > self.current_amount {
            return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
        }
        self.current_amount -= amount;
        Ok(())
    }
}

impl Transmutable for TokenLimit {
    /// Size of the TokenLimit struct in bytes (32 bytes for mint + 8 bytes for
    /// amount)
    const LEN: usize = 40;
}

impl TransmutableMut for TokenLimit {}

impl IntoBytes for TokenLimit {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

impl<'a> Actionable<'a> for TokenLimit {
    /// This action represents the TokenLimit permission type
    const TYPE: Permission = Permission::TokenLimit;
    /// Multiple token limits can exist per role (one per token mint)
    const REPEATABLE: bool = true;

    /// Checks if this token limit matches the provided token mint.
    ///
    /// # Arguments
    /// * `data` - The token mint to check against (first 32 bytes)
    fn match_data(&self, data: &[u8]) -> bool {
        data[0..32] == self.token_mint
    }
}
