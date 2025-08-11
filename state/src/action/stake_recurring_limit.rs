//! Recurring stake limit action type.
//!
//! This module defines the StakeRecurringLimit action type which enforces
//! recurring limits on staking operations within the Swig wallet system.
//! The limit resets after a specified time window and applies to both
//! staking and unstaking operations.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Represents a recurring limit on staking operations.
///
/// This struct tracks and enforces a maximum amount that can be staked or
/// unstaked within a specified time window. The limit resets automatically
/// after the window expires.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct StakeRecurringLimit {
    /// The amount that resets each window (in lamports)
    pub recurring_amount: u64,
    /// The time window in slots after which the limit resets
    pub window: u64,
    /// The last slot when the limit was reset
    pub last_reset: u64,
    /// The current remaining amount that can be used (in lamports)
    pub current_amount: u64,
}

impl StakeRecurringLimit {
    /// Processes a staking operation and updates the remaining limit.
    ///
    /// This method handles both staking (increasing) and unstaking (decreasing)
    /// operations. If the time window has expired, the limit is reset before
    /// processing the operation.
    ///
    /// # Arguments
    /// * `stake_amount_diff` - The absolute change in stake amount
    /// * `current_slot` - The current slot number
    ///
    /// # Returns
    /// * `Ok(())` - If the operation is within limits
    /// * `Err(ProgramError)` - If the operation would exceed the limit
    pub fn run(&mut self, stake_amount_diff: u64, current_slot: u64) -> Result<(), ProgramError> {
        if current_slot.saturating_sub(self.last_reset) > self.window
            && stake_amount_diff <= self.recurring_amount
        {
            self.current_amount = self.recurring_amount;
            self.last_reset = current_slot;
        }
        if stake_amount_diff > self.current_amount {
            return Err(ProgramError::InsufficientFunds);
        }
        self.current_amount = self.current_amount.saturating_sub(stake_amount_diff);
        Ok(())
    }
}

impl Transmutable for StakeRecurringLimit {
    /// Size of the StakeRecurringLimit struct in bytes
    const LEN: usize = core::mem::size_of::<StakeRecurringLimit>();
}

impl IntoBytes for StakeRecurringLimit {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl TransmutableMut for StakeRecurringLimit {}

impl<'a> Actionable<'a> for StakeRecurringLimit {
    /// This action represents the StakeRecurringLimit permission type
    const TYPE: Permission = Permission::StakeRecurringLimit;
    /// Only one recurring stake limit can exist per role
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
