use no_padding::NoPadding;
use pinocchio::{msg, program_error::ProgramError};

use super::{Actionable, Permission};
use crate::{IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut};

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct StakeLimit {
    pub amount: u64,
}

impl StakeLimit {
    /// Runs the stake limit check against the provided change in stake amount.
    /// This handles both staking (increasing) and unstaking (decreasing)
    /// operations. The stake_amount_diff should be the absolute difference
    /// between the new and old stake amounts.
    pub fn run(&mut self, stake_amount_diff: u64) -> Result<(), ProgramError> {
        if stake_amount_diff > self.amount {
            return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
        }
        self.amount -= stake_amount_diff;
        Ok(())
    }
}

impl Transmutable for StakeLimit {
    const LEN: usize = core::mem::size_of::<StakeLimit>();
}

impl TransmutableMut for StakeLimit {}

impl IntoBytes for StakeLimit {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> Actionable<'a> for StakeLimit {
    const TYPE: Permission = Permission::StakeLimit;
    const REPEATABLE: bool = false;
}
