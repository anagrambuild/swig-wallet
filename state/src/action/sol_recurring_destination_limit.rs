//! Recurring SOL destination limit action type.
//!
//! This module defines the SolRecurringDestinationLimit action type which
//! enforces recurring limits on SOL token operations to specific destinations
//! within the Swig wallet system. The limit resets after a specified time
//! window.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, SwigAuthenticateError, SwigStateError, Transmutable, TransmutableMut};

/// Represents a recurring limit on SOL token operations to a specific
/// destination.
///
/// This struct tracks and enforces a maximum amount of SOL that can be
/// sent to a specific destination pubkey within a specified time window. The
/// limit resets automatically after the window expires.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct SolRecurringDestinationLimit {
    /// The destination pubkey (32 bytes)
    pub destination: [u8; 32],
    /// The amount that resets each window (in lamports)
    pub recurring_amount: u64,
    /// The time window in slots after which the limit resets
    pub window: u64,
    /// The last slot when the limit was reset
    pub last_reset: u64,
    /// The current remaining amount that can be used (in lamports)
    pub current_amount: u64,
}

impl SolRecurringDestinationLimit {
    /// Processes a SOL operation to this destination and updates the remaining
    /// limit.
    ///
    /// If the time window has expired, the limit is reset before processing
    /// the operation.
    ///
    /// # Arguments
    /// * `lamport_diff` - The amount of lamports to be sent in the operation
    /// * `current_slot` - The current slot number
    ///
    /// # Returns
    /// * `Ok(())` - If the operation is within limits
    /// * `Err(ProgramError)` - If the operation would exceed the limit
    pub fn run(&mut self, lamport_diff: u64, current_slot: u64) -> Result<(), ProgramError> {
        // Reset the limit if the time window has expired and the operation would fit in
        // a fresh window
        if current_slot - self.last_reset > self.window && lamport_diff <= self.recurring_amount {
            self.current_amount = self.recurring_amount;
            self.last_reset = current_slot;
        }

        // Check if the operation exceeds the current available amount
        if lamport_diff > self.current_amount {
            return Err(
                SwigAuthenticateError::PermissionDeniedSolDestinationRecurringLimitExceeded.into(),
            );
        }

        // Deduct the amount from the current limit
        self.current_amount -= lamport_diff;
        Ok(())
    }

    /// Checks if this destination limit matches the provided destination.
    ///
    /// # Arguments
    /// * `destination` - The destination pubkey to check against
    ///
    /// # Returns
    /// * `bool` - True if the destinations match
    pub fn matches_destination(&self, destination: &[u8; 32]) -> bool {
        self.destination == *destination
    }
}

impl Transmutable for SolRecurringDestinationLimit {
    /// Size of the SolRecurringDestinationLimit struct in bytes (32 + 8 + 8 + 8
    /// + 8 = 64)
    const LEN: usize = core::mem::size_of::<SolRecurringDestinationLimit>();
}

impl TransmutableMut for SolRecurringDestinationLimit {}

impl IntoBytes for SolRecurringDestinationLimit {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> Actionable<'a> for SolRecurringDestinationLimit {
    /// This action represents the SolRecurringDestinationLimit permission type
    const TYPE: Permission = Permission::SolRecurringDestinationLimit;
    /// Multiple recurring destination limits can exist per role (for different
    /// destinations)
    const REPEATABLE: bool = true;

    /// Checks if this action matches the provided destination data.
    fn match_data(&self, data: &[u8]) -> bool {
        if data.len() >= 32 {
            let destination: [u8; 32] = data[0..32].try_into().unwrap_or([0; 32]);
            self.matches_destination(&destination)
        } else {
            false
        }
    }

    fn valid_layout(data: &'a [u8]) -> Result<bool, ProgramError> {
        if data.len() != Self::LEN {
            return Ok(false);
        }

        // Validate that the struct fields are properly aligned and contain valid data
        let destination = &data[0..32];
        let recurring_amount = u64::from_le_bytes(
            data[32..40]
                .try_into()
                .map_err(|_| SwigStateError::InvalidActionData)?,
        );
        let window = u64::from_le_bytes(
            data[40..48]
                .try_into()
                .map_err(|_| SwigStateError::InvalidActionData)?,
        );
        let _last_reset = u64::from_le_bytes(
            data[48..56]
                .try_into()
                .map_err(|_| SwigStateError::InvalidActionData)?,
        );
        let current_amount = u64::from_le_bytes(
            data[56..64]
                .try_into()
                .map_err(|_| SwigStateError::InvalidActionData)?,
        );

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
