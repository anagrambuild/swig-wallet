//! Unrestricted staking action type.
//!
//! This module defines the StakeAll action type which grants unrestricted
//! permissions for staking operations within the Swig wallet system.

use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Represents unrestricted staking permissions.
///
/// This is a marker struct that grants full access to all staking operations.
/// It contains no data since its mere presence indicates complete staking
/// access.
pub struct StakeAll;

impl Transmutable for StakeAll {
    const LEN: usize = 0; // Since this is just a marker with no data
}

impl TransmutableMut for StakeAll {}

impl IntoBytes for StakeAll {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(&[])
    }
}

impl<'a> Actionable<'a> for StakeAll {
    /// This action represents the StakeAll permission type
    const TYPE: Permission = Permission::StakeAll;
    /// Only one instance of unrestricted staking permissions can exist per role
    const REPEATABLE: bool = false;

    /// Always returns true since this represents unrestricted staking access.
    fn match_data(&self, _data: &[u8]) -> bool {
        true
    }
}
