//! Token destination limit action type.
//!
//! This module defines the TokenDestinationLimit action type which enforces
//! limits on token operations to specific destinations within the Swig
//! wallet system. Each limit is specific to both a token mint and a
//! destination.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, SwigAuthenticateError, SwigStateError, Transmutable, TransmutableMut};

/// Represents a limit on token operations to a specific destination for a
/// specific token mint.
///
/// This struct tracks and enforces a maximum amount of tokens that can be
/// sent to a specific destination token account for a particular token mint.
/// The limit is decreased as operations are performed.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct TokenDestinationLimit {
    /// The mint address of the token this limit applies to (32 bytes)
    pub token_mint: [u8; 32],
    /// The destination token account pubkey (32 bytes)
    pub destination: [u8; 32],
    /// The remaining amount of tokens that can be sent to this destination
    pub amount: u64,
}

impl TokenDestinationLimit {
    /// Processes a token operation to this destination and updates the
    /// remaining limit.
    ///
    /// # Arguments
    /// * `token_diff` - The amount of tokens to be sent in the operation
    ///
    /// # Returns
    /// * `Ok(())` - If the operation is within limits
    /// * `Err(ProgramError)` - If the operation would exceed the limit
    pub fn run(&mut self, token_diff: u64) -> Result<(), ProgramError> {
        if token_diff > self.amount {
            return Err(
                SwigAuthenticateError::PermissionDeniedTokenDestinationLimitExceeded.into(),
            );
        }
        self.amount -= token_diff;
        Ok(())
    }

    /// Checks if this destination limit matches the provided token mint and
    /// destination.
    ///
    /// # Arguments
    /// * `token_mint` - The token mint to check against
    /// * `destination` - The destination token account to check against
    ///
    /// # Returns
    /// * `bool` - True if both the mint and destination match
    pub fn matches_mint_and_destination(
        &self,
        token_mint: &[u8; 32],
        destination: &[u8; 32],
    ) -> bool {
        self.token_mint == *token_mint && self.destination == *destination
    }
}

impl Transmutable for TokenDestinationLimit {
    /// Size of the TokenDestinationLimit struct in bytes (32 + 32 + 8 = 72)
    const LEN: usize = core::mem::size_of::<TokenDestinationLimit>();
}

impl TransmutableMut for TokenDestinationLimit {}

impl IntoBytes for TokenDestinationLimit {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> Actionable<'a> for TokenDestinationLimit {
    /// This action represents the TokenDestinationLimit permission type
    const TYPE: Permission = Permission::TokenDestinationLimit;
    /// Multiple token destination limits can exist per role (for different
    /// mint/destination combinations)
    const REPEATABLE: bool = true;

    /// Checks if this action matches the provided token mint and destination
    /// data.
    ///
    /// Expected data format: [token_mint (32 bytes), destination (32 bytes)]
    fn match_data(&self, data: &[u8]) -> bool {
        if data.len() >= 64 {
            let token_mint: [u8; 32] = data[0..32].try_into().unwrap_or([0; 32]);
            let destination: [u8; 32] = data[32..64].try_into().unwrap_or([0; 32]);
            self.matches_mint_and_destination(&token_mint, &destination)
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
        let amount = u64::from_le_bytes(
            data[64..72]
                .try_into()
                .map_err(|_| SwigStateError::InvalidActionData)?,
        );

        // Validate that the token mint is a valid pubkey (32 bytes, all zeros is valid)
        if token_mint.len() != 32 {
            return Ok(false);
        }

        // Validate that the destination is a valid pubkey (32 bytes, all zeros is
        // valid)
        if destination.len() != 32 {
            return Ok(false);
        }

        // Amount can be any valid u64 value, including 0
        let _ = amount; // Suppress unused variable warning

        Ok(true)
    }
}
