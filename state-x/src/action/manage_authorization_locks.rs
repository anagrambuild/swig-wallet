//! Manage authorization locks action type.
//!
//! This module defines the ManageAuthorizationLocks action type which grants
//! permission to add and remove authorization locks within the Swig wallet
//! system.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Represents permission to manage authorization locks.
///
/// This action grants the authority to add and remove authorization locks
/// for any token mint. It's a powerful permission that should be granted
/// carefully as it allows control over payment preauthorization limits.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct ManageAuthorizationLocks {}

impl Transmutable for ManageAuthorizationLocks {
    /// Size of the ManageAuthorizationLocks struct in bytes (empty struct)
    const LEN: usize = 1; // Minimum size for empty struct
}

impl TransmutableMut for ManageAuthorizationLocks {}

impl IntoBytes for ManageAuthorizationLocks {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

impl<'a> Actionable<'a> for ManageAuthorizationLocks {
    /// This action represents the ManageAuthorizationLocks permission type
    const TYPE: Permission = Permission::ManageAuthorizationLocks;
    /// Only one ManageAuthorizationLocks permission per role is needed
    const REPEATABLE: bool = false;

    /// No specific data matching required for this permission.
    ///
    /// # Arguments
    /// * `_data` - Unused data parameter
    fn match_data(&self, _data: &[u8]) -> bool {
        true // This permission applies globally, no specific data matching
    }
}
