//! Recurring SOL token limit action type.
//!
//! This module defines the SolRecurringLimit action type which enforces
//! recurring limits on SOL token operations within the Swig wallet system.
//! The limit resets after a specified time window.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Represents a recurring limit on SOL token operations.
///
/// This struct tracks and enforces a maximum amount of SOL that can be
/// used in operations within a specified time window. The limit resets
/// automatically after the window expires.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct SolRecurringLimit {
    /// The amount that resets each window (in lamports)
    pub recurring_amount: u64,
    /// The time window in slots after which the limit resets
    pub window: u64,
    /// The last slot when the limit was reset
    pub last_reset: u64,
    /// The current remaining amount that can be used (in lamports)
    pub current_amount: u64,
}

impl SolRecurringLimit {
    /// Processes a SOL operation and updates the remaining limit.
    ///
    /// If the time window has expired, the limit is reset before processing
    /// the operation.
    ///
    /// # Arguments
    /// * `lamport_diff` - The amount of lamports to be used in the operation
    /// * `current_slot` - The current slot number
    ///
    /// # Returns
    /// * `Ok(())` - If the operation is within limits
    /// * `Err(ProgramError)` - If the operation would exceed the limit
    pub fn run(&mut self, lamport_diff: u64, current_slot: u64) -> Result<(), ProgramError> {
        if current_slot.saturating_sub(self.last_reset) > self.window
            && lamport_diff <= self.recurring_amount
        {
            self.current_amount = self.recurring_amount;
            self.last_reset = current_slot;
        }
        if lamport_diff > self.current_amount {
            return Err(ProgramError::InsufficientFunds);
        }
        self.current_amount = self.current_amount.saturating_sub(lamport_diff);
        Ok(())
    }
}

impl Transmutable for SolRecurringLimit {
    /// Size of the SolRecurringLimit struct in bytes
    const LEN: usize = core::mem::size_of::<SolRecurringLimit>();
}

impl IntoBytes for SolRecurringLimit {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl TransmutableMut for SolRecurringLimit {}

impl<'a> Actionable<'a> for SolRecurringLimit {
    /// This action represents the SolRecurringLimit permission type
    const TYPE: Permission = Permission::SolRecurringLimit;
    /// Only one recurring SOL limit can exist per role
    const REPEATABLE: bool = false;

    fn valid_layout(data: &'a [u8]) -> Result<bool, ProgramError> {
        // current amount needs to be equal to recurring amount
        let current_amount = &data[24..32];
        let recurring_amount = &data[0..8];
        // last reset needs to be 0
        let last_reset = &data[16..24];
        Ok(
            current_amount == recurring_amount
                && last_reset == &[0u8; 8]
                && data.len() == Self::LEN,
        )
    }
}
