//! Action module for the state crate.
//!
//! This module defines the core action system used by the Swig wallet for
//! permission management and operation control. It includes various types of
//! actions such as limits on token operations, program interactions, and
//! stake management.

pub mod all;
pub mod all_but_manage_authority;
pub mod manage_authority;
pub mod program;
pub mod program_all;
pub mod program_curated;
pub mod program_scope;
pub mod sol_destination_limit;
pub mod sol_limit;
pub mod sol_recurring_destination_limit;
pub mod sol_recurring_limit;
pub mod stake_all;
pub mod stake_limit;
pub mod stake_recurring_limit;
pub mod sub_account;
pub mod token_destination_limit;
pub mod token_limit;
pub mod token_recurring_destination_limit;
pub mod token_recurring_limit;
use all::All;
use all_but_manage_authority::AllButManageAuthority;
use manage_authority::ManageAuthority;
use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;
use program::Program;
use program_all::ProgramAll;
use program_curated::ProgramCurated;
use program_scope::ProgramScope;
use sol_destination_limit::SolDestinationLimit;
use sol_limit::SolLimit;
use sol_recurring_destination_limit::SolRecurringDestinationLimit;
use sol_recurring_limit::SolRecurringLimit;
use stake_all::StakeAll;
use stake_limit::StakeLimit;
use stake_recurring_limit::StakeRecurringLimit;
use sub_account::SubAccount;
use token_destination_limit::TokenDestinationLimit;
use token_limit::TokenLimit;
use token_recurring_destination_limit::TokenRecurringDestinationLimit;
use token_recurring_limit::TokenRecurringLimit;

use crate::{IntoBytes, SwigStateError, Transmutable, TransmutableMut};

/// Represents an action in the Swig wallet system.
///
/// Actions define what operations can be performed and under what conditions.
/// Each action has a type, length, and boundary information for storage.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct Action {
    /// The type of action (maps to Permission enum)
    action_type: u16,
    /// Length of the action data in bytes
    length: u16,
    /// Boundary marker for action data
    boundary: u32,
}

impl IntoBytes for Action {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

impl Transmutable for Action {
    const LEN: usize = core::mem::size_of::<Action>();
}

impl Action {
    /// Creates a new action for client-side use.
    pub fn client_new(_type: Permission, length: u16) -> Self {
        Self {
            action_type: _type as u16,
            length,
            boundary: 0,
        }
    }

    /// Creates a new action with boundary information.
    pub fn new(_type: Permission, length: u16, boundary: u32) -> Self {
        Self {
            action_type: _type as u16,
            length,
            boundary,
        }
    }

    /// Returns the permission type of this action.
    pub fn permission(&self) -> Result<Permission, ProgramError> {
        Permission::try_from(self.action_type)
    }

    /// Returns the length of the action data.
    pub fn length(&self) -> u16 {
        self.length
    }

    /// Returns the boundary marker for this action.
    pub fn boundary(&self) -> u32 {
        self.boundary
    }
}

/// Represents different types of permissions in the system.
///
/// Each permission type corresponds to a different kind of action that can
/// be performed within the Swig wallet system.
#[derive(Default, Debug, PartialEq, Copy, Clone)]
#[repr(u16)]
pub enum Permission {
    /// No permission granted
    #[default]
    None,
    /// Permission to perform SOL token operations with limits
    SolLimit = 1,
    /// Permission to perform recurring SOL token operations with limits
    SolRecurringLimit = 2,
    /// Permission to interact with programs
    Program = 3,
    /// Permission to interact with program scopes
    ProgramScope = 4,
    /// Permission to perform token operations with limits
    TokenLimit = 5,
    /// Permission to perform recurring token operations with limits
    TokenRecurringLimit = 6,
    /// Permission to perform all operations
    All = 7,
    /// Permission to manage authority settings
    ManageAuthority = 8,
    /// Permission to manage sub-accounts
    SubAccount = 9,
    /// Permission to perform stake operations with limits
    StakeLimit = 10,
    /// Permission to perform recurring stake operations with limits
    StakeRecurringLimit = 11,
    /// Permission to perform all stake operations
    StakeAll = 12,
    /// Permission to interact with any program (unrestricted CPI)
    ProgramAll = 13,
    /// Permission to interact with curated programs only
    ProgramCurated = 14,
    /// Permission to perform all operations except authority/subaccount
    /// management
    AllButManageAuthority = 15,
    /// Permission to perform SOL token operations with limits to specific
    /// destinations
    SolDestinationLimit = 16,
    /// Permission to perform recurring SOL token operations with limits to
    /// specific destinations
    SolRecurringDestinationLimit = 17,
    /// Permission to perform token operations with limits to specific
    /// destinations
    TokenDestinationLimit = 18,
    /// Permission to perform recurring token operations with limits to specific
    /// destinations
    TokenRecurringDestinationLimit = 19,
}

impl TryFrom<u16> for Permission {
    type Error = ProgramError;

    #[inline(always)]
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            // SAFETY: `value` is guaranteed to be in the range of the enum variants.
            0..=19 => Ok(unsafe { core::mem::transmute::<u16, Permission>(value) }),
            _ => Err(SwigStateError::PermissionLoadError.into()),
        }
    }
}

impl TryFrom<&[u8]> for Permission {
    type Error = ProgramError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let type_bytes = value
            .try_into()
            .map_err(|_| SwigStateError::PermissionLoadError)?;
        Permission::try_from(u16::from_le_bytes(type_bytes))
    }
}

/// Trait for types that can be used as action data.
///
/// This trait defines the interface for action-specific data structures,
/// including their type information and validation rules.
pub trait Actionable<'a>: Transmutable + TransmutableMut {
    /// The permission type associated with this action
    const TYPE: Permission;
    /// Whether multiple instances of this action are allowed
    const REPEATABLE: bool;

    /// Checks if this action matches the provided data.
    fn match_data(&self, _data: &[u8]) -> bool {
        false
    }

    /// Validates the layout of the action data.
    fn valid_layout(data: &'a [u8]) -> Result<bool, ProgramError> {
        Ok(data.len() == Self::LEN)
    }
}

/// Helper struct for loading and validating actions.
pub struct ActionLoader;

impl ActionLoader {
    /// Validates the layout of action data based on its permission type.
    pub fn validate_layout(permission: Permission, data: &[u8]) -> Result<bool, ProgramError> {
        match permission {
            Permission::SolLimit => SolLimit::valid_layout(data),
            Permission::SolRecurringLimit => SolRecurringLimit::valid_layout(data),
            Permission::SolDestinationLimit => SolDestinationLimit::valid_layout(data),
            Permission::SolRecurringDestinationLimit => {
                SolRecurringDestinationLimit::valid_layout(data)
            },
            Permission::Program => Program::valid_layout(data),
            Permission::ProgramScope => ProgramScope::valid_layout(data),
            Permission::TokenLimit => TokenLimit::valid_layout(data),
            Permission::TokenRecurringLimit => TokenRecurringLimit::valid_layout(data),
            Permission::All => All::valid_layout(data),
            Permission::ManageAuthority => ManageAuthority::valid_layout(data),
            Permission::SubAccount => SubAccount::valid_layout(data),
            Permission::StakeLimit => StakeLimit::valid_layout(data),
            Permission::StakeRecurringLimit => StakeRecurringLimit::valid_layout(data),
            Permission::StakeAll => StakeAll::valid_layout(data),
            Permission::ProgramAll => ProgramAll::valid_layout(data),
            Permission::ProgramCurated => ProgramCurated::valid_layout(data),
            Permission::AllButManageAuthority => AllButManageAuthority::valid_layout(data),
            Permission::TokenDestinationLimit => TokenDestinationLimit::valid_layout(data),
            Permission::TokenRecurringDestinationLimit => {
                TokenRecurringDestinationLimit::valid_layout(data)
            },
            _ => Ok(false),
        }
    }

    /// Finds an action of a specific type in the provided bytes.
    pub fn find_action<'a, T: Actionable<'a>>(
        bytes: &'a [u8],
    ) -> Result<Option<&'a T>, ProgramError> {
        let mut cursor = 0;

        while cursor < bytes.len() {
            let action = unsafe { Action::load_unchecked(&bytes[cursor..cursor + Action::LEN])? };
            if action.permission() == Ok(T::TYPE) {
                return Ok(Some(unsafe {
                    T::load_unchecked(&bytes[cursor..cursor + action.length() as usize])?
                }));
            }
            cursor = action.boundary() as usize;
        }
        Ok(None)
    }
}

// Permission mask utilities for efficient permission checking

/// Type alias for permission mask, using u64 to support up to 64 permissions.
pub type PermissionMask = u64;

/// Maximum valid permission index (TokenRecurringDestinationLimit = 19).
const MAX_PERMISSION_INDEX: u16 = Permission::TokenRecurringDestinationLimit as u16;

/// Converts a permission to its corresponding bit in the mask.
#[inline(always)]
fn permission_bit(permission: Permission) -> PermissionMask {
    1u64 << (permission as u16)
}

/// Converts an index to a Permission enum variant if valid.
#[inline(always)]
fn permission_from_index(index: u16) -> Option<Permission> {
    if index <= MAX_PERMISSION_INDEX {
        // SAFETY: `index` is guaranteed to be within the range of the enum variants.
        Some(unsafe { core::mem::transmute::<u16, Permission>(index) })
    } else {
        None
    }
}

/// Converts an iterator of permissions into a permission mask.
///
/// Each permission sets its corresponding bit in the mask.
pub fn permissions_to_mask<I>(permissions: I) -> PermissionMask
where
    I: IntoIterator<Item = Permission>,
{
    permissions
        .into_iter()
        .fold(0u64, |mask, permission| mask | permission_bit(permission))
}

/// Converts a permission mask back into a vector of permissions.
///
/// Only valid permission bits (within the enum range) are included.
pub fn mask_to_permissions(mask: PermissionMask) -> Vec<Permission> {
    let mut permissions = Vec::new();
    let mut remaining = mask;

    while remaining != 0 {
        let index = remaining.trailing_zeros() as u16;
        if let Some(permission) = permission_from_index(index) {
            permissions.push(permission);
        }
        remaining &= !(1u64 << index);
    }

    permissions
}

/// Checks if all requested permissions are present in the allowed mask.
///
/// Returns `true` if all bits set in `requested` are also set in `allowed`.
#[inline(always)]
pub fn check_permissions(allowed: PermissionMask, requested: PermissionMask) -> bool {
    (requested & allowed) == requested
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sort_permissions(perms: &mut Vec<Permission>) {
        perms.sort_by_key(|p| *p as u16);
    }

    #[test]
    fn empty_permissions_to_mask_is_zero() {
        let mask = permissions_to_mask(core::iter::empty());
        assert_eq!(mask, 0);
    }

    #[test]
    fn single_permission_sets_correct_bit() {
        let mask = permissions_to_mask([Permission::Program]);
        assert_eq!(mask, 1u64 << (Permission::Program as u16));
    }

    #[test]
    fn multiple_permissions_set_combined_bits() {
        let mask = permissions_to_mask([
            Permission::Program,
            Permission::TokenLimit,
            Permission::StakeAll,
        ]);
        let expected = (1u64 << (Permission::Program as u16))
            | (1u64 << (Permission::TokenLimit as u16))
            | (1u64 << (Permission::StakeAll as u16));
        assert_eq!(mask, expected);
    }

    #[test]
    fn none_permission_sets_bit_zero() {
        let mask = permissions_to_mask([Permission::None]);
        assert_eq!(mask, 1u64 << (Permission::None as u16));
        let mut perms = mask_to_permissions(mask);
        assert!(perms.contains(&Permission::None));
    }

    #[test]
    fn mask_to_permissions_ignores_out_of_range_bits() {
        // Set a very high bit, beyond defined enum range
        let mask = 1u64 << 63;
        let perms = mask_to_permissions(mask);
        assert!(perms.is_empty());
    }

    #[test]
    fn mask_to_permissions_includes_highest_defined_permission() {
        let highest = Permission::TokenRecurringDestinationLimit as u16;
        let mask = 1u64 << highest;
        let perms = mask_to_permissions(mask);
        assert_eq!(perms.len(), 1);
        assert_eq!(perms[0], Permission::TokenRecurringDestinationLimit);
    }

    #[test]
    fn round_trip_permissions_to_mask_and_back() {
        let original = vec![
            Permission::Program,
            Permission::TokenLimit,
            Permission::StakeRecurringLimit,
            Permission::ProgramCurated,
        ];
        let mask = permissions_to_mask(original.clone());
        let mut round_tripped = mask_to_permissions(mask);

        let mut expected = original.clone();
        sort_permissions(&mut round_tripped);
        sort_permissions(&mut expected);
        assert_eq!(round_tripped, expected);
    }

    #[test]
    fn round_trip_mask_to_permissions_and_back() {
        let mask = (1u64 << (Permission::All as u16))
            | (1u64 << (Permission::ProgramScope as u16))
            | (1u64 << (Permission::SolRecurringDestinationLimit as u16));
        println!("mask: {:?}", mask);
        let perms = mask_to_permissions(mask);
        println!("perms: {:?}", perms);
        let rebuilt_mask = permissions_to_mask(perms);
        println!("rebuilt_mask: {:?}", rebuilt_mask);
        assert_eq!(rebuilt_mask, mask);
    }

    #[test]
    fn check_permissions_validates_subset() {
        let allowed = permissions_to_mask([
            Permission::Program,
            Permission::SolLimit,
            Permission::TokenLimit,
        ]);

        assert!(check_permissions(
            allowed,
            permissions_to_mask([Permission::Program, Permission::TokenLimit])
        ));
        assert!(!check_permissions(
            allowed,
            permissions_to_mask([
                Permission::Program,
                Permission::TokenLimit,
                Permission::StakeRecurringLimit
            ])
        ));
        assert!(check_permissions(
            allowed,
            permissions_to_mask([Permission::Program, Permission::TokenLimit,])
        ));
        assert!(check_permissions(
            allowed,
            permissions_to_mask([
                Permission::Program,
                Permission::TokenLimit,
                Permission::SolLimit,
            ])
        ));
        assert!(!check_permissions(
            allowed,
            permissions_to_mask([
                Permission::Program,
                Permission::TokenLimit,
                Permission::StakeAll,
                Permission::StakeRecurringLimit,
                Permission::ProgramCurated,
                Permission::None,
                Permission::All
            ])
        ));
    }
}
