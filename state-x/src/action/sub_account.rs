//! Sub-account action type.
//!
//! This module defines the SubAccount action type which manages permissions
//! for sub-accounts within the Swig wallet system. Sub-accounts allow for
//! delegated access with specific permissions.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;
use swig_assertions::sol_assert_bytes_eq;

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

    /// Checks if this sub-account permission matches the provided data.
    ///
    /// For sub-account creation, matches against empty data (since sub_account is initially zeroed).
    /// For toggle/withdraw operations, matches against the actual sub-account pubkey.
    ///
    /// # Arguments
    /// * `data` - The data to match against (empty for creation, pubkey for operations)
    ///
    /// # Returns
    /// * `true` if the data matches this sub-account permission
    /// * `false` if the data doesn't match
    fn match_data(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            // For sub-account creation, match against zeroed sub_account field
            sol_assert_bytes_eq(&self.sub_account, &[0u8; 32], 32);
            self.sub_account == [0u8; 32]
        } else if data.len() == 32 {
            // For other operations, match against the actual sub-account pubkey
            sol_assert_bytes_eq(&self.sub_account, data, 32)
        } else {
            false
        }
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
