//! SOL destination limit action type.
//!
//! This module defines the SolDestinationLimit action type which enforces
//! limits on SOL token operations to specific destinations within the Swig
//! wallet system.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut};

/// Represents a limit on SOL token operations to a specific destination.
///
/// This struct tracks and enforces a maximum amount of SOL that can be
/// sent to a specific destination pubkey. The limit is decreased as operations
/// are performed.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct SolDestinationLimit {
    /// The destination pubkey (32 bytes)
    pub destination: [u8; 32],
    /// The remaining amount of SOL that can be sent to this destination (in
    /// lamports)
    pub amount: u64,
}

impl SolDestinationLimit {
    /// Processes a SOL operation to this destination and updates the remaining
    /// limit.
    ///
    /// # Arguments
    /// * `lamport_diff` - The amount of lamports to be sent in the operation
    ///
    /// # Returns
    /// * `Ok(())` - If the operation is within limits
    /// * `Err(ProgramError)` - If the operation would exceed the limit
    pub fn run(&mut self, lamport_diff: u64) -> Result<(), ProgramError> {
        if lamport_diff > self.amount {
            return Err(SwigAuthenticateError::PermissionDeniedSolDestinationLimitExceeded.into());
        }
        self.amount -= lamport_diff;
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

impl Transmutable for SolDestinationLimit {
    /// Size of the SolDestinationLimit struct in bytes (32 + 8 = 40)
    const LEN: usize = core::mem::size_of::<SolDestinationLimit>();
}

impl TransmutableMut for SolDestinationLimit {}

impl IntoBytes for SolDestinationLimit {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> Actionable<'a> for SolDestinationLimit {
    /// This action represents the SolDestinationLimit permission type
    const TYPE: Permission = Permission::SolDestinationLimit;
    /// Multiple destination limits can exist per role (for different
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
}
