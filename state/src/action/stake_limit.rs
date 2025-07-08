//! Stake limit action type.
//!
//! This module defines the StakeLimit action type which enforces limits on
//! staking operations within the Swig wallet system. The limit applies to
//! both staking and unstaking operations.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut};

/// Represents a limit on staking operations.
///
/// This struct tracks and enforces a maximum amount that can be staked or
/// unstaked. The limit is decreased as operations are performed, regardless
/// of whether they are staking or unstaking operations.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct StakeLimit {
    /// The remaining amount that can be staked or unstaked (in lamports)
    pub amount: u64,
}

impl StakeLimit {
    /// Processes a staking operation and updates the remaining limit.
    ///
    /// This method handles both staking (increasing) and unstaking (decreasing)
    /// operations. The stake_amount_diff should be the absolute difference
    /// between the new and old stake amounts.
    ///
    /// # Arguments
    /// * `stake_amount_diff` - The absolute change in stake amount
    ///
    /// # Returns
    /// * `Ok(())` - If the operation is within limits
    /// * `Err(ProgramError)` - If the operation would exceed the limit
    pub fn run(&mut self, stake_amount_diff: u64) -> Result<(), ProgramError> {
        if stake_amount_diff > self.amount {
            return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
        }
        self.amount -= stake_amount_diff;
        Ok(())
    }
}

impl Transmutable for StakeLimit {
    /// Size of the StakeLimit struct in bytes
    const LEN: usize = core::mem::size_of::<StakeLimit>();
}

impl TransmutableMut for StakeLimit {}

impl IntoBytes for StakeLimit {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> Actionable<'a> for StakeLimit {
    /// This action represents the StakeLimit permission type
    const TYPE: Permission = Permission::StakeLimit;
    /// Only one stake limit can exist per role
    const REPEATABLE: bool = false;
}
