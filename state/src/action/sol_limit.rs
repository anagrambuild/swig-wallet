//! SOL token limit action type.
//!
//! This module defines the SolLimit action type which enforces limits on
//! SOL token operations within the Swig wallet system.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut};

/// Represents a limit on SOL token operations.
///
/// This struct tracks and enforces a maximum amount of SOL that can be
/// used in operations. The limit is decreased as operations are performed.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct SolLimit {
    /// The remaining amount of SOL that can be used (in lamports)
    pub amount: u64,
}

impl SolLimit {
    /// Processes a SOL operation and updates the remaining limit.
    ///
    /// # Arguments
    /// * `lamport_diff` - The amount of lamports to be used in the operation
    ///
    /// # Returns
    /// * `Ok(())` - If the operation is within limits
    /// * `Err(ProgramError)` - If the operation would exceed the limit
    pub fn run(&mut self, lamport_diff: u64) -> Result<(), ProgramError> {
        if lamport_diff > self.amount {
            return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
        }
        self.amount -= lamport_diff;
        Ok(())
    }
}

impl Transmutable for SolLimit {
    /// Size of the SolLimit struct in bytes
    const LEN: usize = core::mem::size_of::<SolLimit>();
}

impl TransmutableMut for SolLimit {}

impl IntoBytes for SolLimit {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> Actionable<'a> for SolLimit {
    /// This action represents the SolLimit permission type
    const TYPE: Permission = Permission::SolLimit;
    /// Only one SOL limit can exist per role
    const REPEATABLE: bool = false;
}
