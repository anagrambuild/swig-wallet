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
/// This struct tracks a sub-account's metadata and manages permissions
/// related to that sub-account. The sub-account field is initially zeroed
/// and is populated when the sub-account is created.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct SubAccount {
    /// The sub-account's identifier (zeroed until sub-account creation)
    pub sub_account: [u8; 32],
    /// PDA bump seed
    pub bump: u8,
    /// Whether the sub-account is enabled
    pub enabled: bool,
    /// Index of this sub-account (0-254). Enables multiple sub-accounts per role.
    /// Index 0 uses legacy PDA derivation for backwards compatibility.
    /// Indices 1-254 use new derivation with index in seeds.
    pub sub_account_index: u8,
    _padding: u8,
    /// ID of the role associated with this sub-account
    pub role_id: u32,
    /// ID of the parent Swig account
    pub swig_id: [u8; 32],
}

impl Transmutable for SubAccount {
    /// Size of the SubAccount struct in bytes
    /// 32 (sub_account) + 1 (bump) + 1 (enabled) + 2 (padding) + 4 (role_id) +
    /// 32 (swig_id) = 72
    const LEN: usize = 72;
}

impl TransmutableMut for SubAccount {}

impl IntoBytes for SubAccount {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl SubAccount {
    /// Creates a new SubAccount action with default values.
    ///
    /// # Arguments
    /// * `sub_account` - The sub-account's public key (32 bytes, initially
    ///   zeroed)
    ///
    /// # Returns
    /// A new SubAccount instance with default values
    pub fn new(sub_account: [u8; 32], sub_account_index: u8) -> Self {
        Self {
            sub_account,
            bump: 0,
            enabled: false,
            sub_account_index,
            _padding: 0,
            role_id: 0,
            swig_id: [0; 32],
        }
    }

    /// Creates a new SubAccount action for initial creation (with zeroed
    /// sub_account).
    ///
    /// # Arguments
    /// * `sub_account_index` - The index for this sub-account (0-254)
    ///
    /// # Returns
    /// A new SubAccount instance suitable for role creation
    pub fn new_for_creation(sub_account_index: u8) -> Self {
        Self::new([0; 32], sub_account_index)
    }
}

impl<'a> Actionable<'a> for SubAccount {
    /// This action represents the SubAccount permission type
    const TYPE: Permission = Permission::SubAccount;
    /// Multiple sub-account permissions can exist per role
    const REPEATABLE: bool = true;

    /// Checks if this sub-account permission matches the provided data.
    ///
    /// For sub-account creation, matches against empty data (since sub_account
    /// is initially zeroed). For toggle/withdraw operations, matches
    /// against the actual sub-account pubkey.
    ///
    /// # Arguments
    /// * `data` - The data to match against (empty for creation, pubkey for
    ///   operations)
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

    /// Validates that the data has the correct length and the sub_account field
    /// is zeroed.
    ///
    /// # Arguments
    /// * `data` - The data to validate
    ///
    /// # Returns
    /// * `Ok(true)` - If the data is valid (correct size, sub_account field
    ///   zeroed)
    /// * `Ok(false)` - If the data is invalid
    fn valid_layout(data: &'a [u8]) -> Result<bool, ProgramError> {
        if data.len() == Self::LEN {
            // Check that the sub_account field (first 32 bytes) is zeroed
            Ok(data[0..32] == [0u8; 32])
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sub_account_new_size() {
        // Test that the SubAccount struct has the correct size (72 bytes)
        assert_eq!(SubAccount::LEN, 72);
        assert_eq!(core::mem::size_of::<SubAccount>(), 72);

        // Test that new() works correctly
        let sub_account = SubAccount::new([1u8; 32], 0);
        assert_eq!(sub_account.sub_account, [1u8; 32]);
        assert_eq!(sub_account.bump, 0);
        assert_eq!(sub_account.enabled, false);
        assert_eq!(sub_account.sub_account_index, 0);
        assert_eq!(sub_account.role_id, 0);
        assert_eq!(sub_account.swig_id, [0u8; 32]);

        // Test that new_for_creation() works correctly
        let sub_account = SubAccount::new_for_creation(0);
        assert_eq!(sub_account.sub_account, [0u8; 32]);
        assert_eq!(sub_account.bump, 0);
        assert_eq!(sub_account.enabled, false);
        assert_eq!(sub_account.sub_account_index, 0);
        assert_eq!(sub_account.role_id, 0);
        assert_eq!(sub_account.swig_id, [0u8; 32]);

        // Test serialization
        let bytes = sub_account.into_bytes().unwrap();
        assert_eq!(bytes.len(), 72);
    }

    #[test]
    fn test_sub_account_no_reserved_lamports() {
        // Verify that the old reserved_lamports field is no longer part of the struct
        let sub_account = SubAccount::new_for_creation(0);
        let bytes = sub_account.into_bytes().unwrap();

        // The struct should be 72 bytes, not the old 80 bytes
        assert_eq!(bytes.len(), 72);

        // Verify struct layout:
        // 32 (sub_account) + 1 (bump) + 1 (enabled) + 1 (sub_account_index) + 1 (padding) + 4 (role_id) + 32
        // (swig_id) = 72
        let expected_size = 32 + 1 + 1 + 1 + 1 + 4 + 32;
        assert_eq!(expected_size, 72);
        assert_eq!(SubAccount::LEN, expected_size);
    }

    #[test]
    fn test_sub_account_valid_layout() {
        // Test the valid_layout function with correct size
        let sub_account = SubAccount::new_for_creation(0);
        let bytes = sub_account.into_bytes().unwrap();

        // Should return true for correct size with zeroed sub_account
        assert!(SubAccount::valid_layout(bytes).unwrap());

        // Should return false for incorrect size
        let too_short = &bytes[..71];
        assert!(!SubAccount::valid_layout(too_short).unwrap());

        let too_long = &[bytes, &[0u8; 1]].concat();
        assert!(!SubAccount::valid_layout(&too_long).unwrap());

        // Should return false for non-zeroed sub_account field
        let mut non_zero_data = bytes.to_vec();
        non_zero_data[0] = 1; // Make first byte of sub_account non-zero
        assert!(!SubAccount::valid_layout(&non_zero_data).unwrap());
    }
}
