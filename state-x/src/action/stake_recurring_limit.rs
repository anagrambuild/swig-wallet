use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct StakeRecurringLimit {
    pub recurring_amount: u64,
    pub window: u64,
    pub last_reset: u64,
    pub current_amount: u64,
}

impl StakeRecurringLimit {
    /// Runs the recurring stake limit check against the provided change in
    /// stake amount. This handles both staking (increasing) and unstaking
    /// (decreasing) operations. The stake_amount_diff should be the
    /// absolute difference between the new and old stake amounts.
    pub fn run(&mut self, stake_amount_diff: u64, current_slot: u64) -> Result<(), ProgramError> {
        if current_slot - self.last_reset > self.window
            && stake_amount_diff <= self.recurring_amount
        {
            self.current_amount = self.recurring_amount;
            self.last_reset = current_slot;
        }
        if stake_amount_diff > self.current_amount {
            return Err(ProgramError::InsufficientFunds);
        }
        self.current_amount -= stake_amount_diff;
        Ok(())
    }
}

impl Transmutable for StakeRecurringLimit {
    const LEN: usize = core::mem::size_of::<StakeRecurringLimit>();
}

impl IntoBytes for StakeRecurringLimit {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl TransmutableMut for StakeRecurringLimit {}

impl<'a> Actionable<'a> for StakeRecurringLimit {
    const TYPE: Permission = Permission::StakeRecurringLimit;
    const REPEATABLE: bool = false;
}
