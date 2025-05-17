//! Sub-account action type.
//!
//! This module defines the SubAccount action type which manages permissions
//! for sub-accounts within the Swig wallet system. Sub-accounts allow for
//! delegated access with specific permissions.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Represents permission to manage a sub-account.
///
/// This struct tracks a sub-account's identifier and manages permissions
/// related to that sub-account. The sub-account field is initially zeroed
/// and is populated when the sub-account is created.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct SubAccount {
    /// The sub-account's identifier (zeroed until sub-account creation)
    pub sub_account: [u8; 32],
}

impl Transmutable for SubAccount {
    /// Size of the SubAccount struct in bytes (32 bytes for sub_account)
    const LEN: usize = 32;
}

impl TransmutableMut for SubAccount {}

impl IntoBytes for SubAccount {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> Actionable<'a> for SubAccount {
    /// This action represents the SubAccount permission type
    const TYPE: Permission = Permission::SubAccount;
    /// Multiple sub-account permissions can exist per role
    const REPEATABLE: bool = true;

    /// Always returns true as matching is handled elsewhere
    fn match_data(&self, data: &[u8]) -> bool {
        true
    }

    /// Validates that the data has the correct length and is zeroed.
    ///
    /// # Arguments
    /// * `data` - The data to validate
    ///
    /// # Returns
    /// * `Ok(true)` - If the data is valid (32 bytes, all zero)
    /// * `Ok(false)` - If the data is invalid
    fn valid_layout(data: &'a [u8]) -> Result<bool, ProgramError> {
        Ok(data.len() == Self::LEN && data[0..32] == [0u8; 32])
    }
}
