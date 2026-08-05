//! Action module for the state crate.
//!
//! This module defines the core action system used by the Swig wallet for
//! permission management and operation control. It includes various types of
//! actions such as limits on token operations, program interactions, and
//! stake management.

extern crate alloc;

pub mod all;
pub mod all_but_manage_authority;
pub mod close_swig_authority;
pub mod manage_authority;
pub mod program;
pub mod program_all;
pub mod program_curated;
pub mod program_scope;
pub mod replace_authority;
pub mod sol_destination_limit;
pub mod sol_limit;
pub mod sol_recurring_destination_limit;
pub mod sol_recurring_limit;
pub mod stake_all;
pub mod stake_limit;
pub mod stake_recurring_limit;
pub mod sub_account;
pub mod sub_account_v2;
pub mod token_destination_limit;
pub mod token_limit;
pub mod token_recurring_destination_limit;
pub mod token_recurring_limit;
use all::All;
use all_but_manage_authority::AllButManageAuthority;
use close_swig_authority::CloseSwigAuthority;
use manage_authority::ManageAuthority;
use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;
use program::Program;
use program_all::ProgramAll;
use program_curated::ProgramCurated;
use program_scope::ProgramScope;
use replace_authority::ReplaceAuthority;
use sol_destination_limit::SolDestinationLimit;
use sol_limit::SolLimit;
use sol_recurring_destination_limit::SolRecurringDestinationLimit;
use sol_recurring_limit::SolRecurringLimit;
use stake_all::StakeAll;
use stake_limit::StakeLimit;
use stake_recurring_limit::StakeRecurringLimit;
use sub_account::SubAccount;
use sub_account_v2::{
    SubAccountV2All, SubAccountV2Create, SubAccountV2Sign, SubAccountV2Toggle, SubAccountV2Withdraw,
};
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
    /// Permission to close token accounts and the swig account
    CloseSwigAuthority = 20,
    /// Permission to replace a role's signer without changing its permissions
    ReplaceAuthority = 21,
    /// Permission to create V2 sub-accounts (non-repeatable marker)
    SubAccountV2Create = 22,
    /// Scoped umbrella permission for V2 sub-account runtime operations
    /// (sign/withdraw/toggle) on a single `subacc_id`
    SubAccountV2All = 23,
    /// Scoped permission to sign as a V2 sub-account for a single `subacc_id`
    SubAccountV2Sign = 24,
    /// Scoped permission to withdraw from a V2 sub-account for a single
    /// `subacc_id`
    SubAccountV2Withdraw = 25,
    /// Scoped permission to toggle a V2 sub-account for a single `subacc_id`
    SubAccountV2Toggle = 26,
}

impl TryFrom<u16> for Permission {
    type Error = ProgramError;

    #[inline(always)]
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            // SAFETY: `value` is guaranteed to be in the range of the enum variants.
            0..=26 => Ok(unsafe { core::mem::transmute::<u16, Permission>(value) }),
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

/// Returns a deduplication key for a V2 sub-account action, or `None` for any
/// non-V2 permission (which is intentionally not deduplicated).
///
/// The scoped permissions key on `(type, subacc_id)`; the create marker keys on
/// its type with a fixed id so a second marker collides.
fn v2_dedup_key(permission: Permission, data: &[u8]) -> Option<(u16, u32)> {
    match permission {
        Permission::SubAccountV2Create => Some((permission as u16, 0)),
        Permission::SubAccountV2All
        | Permission::SubAccountV2Sign
        | Permission::SubAccountV2Withdraw
        | Permission::SubAccountV2Toggle => {
            if data.len() >= 4 {
                let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                Some((permission as u16, id))
            } else {
                None
            }
        },
        _ => None,
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
            Permission::CloseSwigAuthority => CloseSwigAuthority::valid_layout(data),
            Permission::ReplaceAuthority => ReplaceAuthority::valid_layout(data),
            Permission::TokenDestinationLimit => TokenDestinationLimit::valid_layout(data),
            Permission::TokenRecurringDestinationLimit => {
                TokenRecurringDestinationLimit::valid_layout(data)
            },
            Permission::SubAccountV2Create => SubAccountV2Create::valid_layout(data),
            Permission::SubAccountV2All => SubAccountV2All::valid_layout(data),
            Permission::SubAccountV2Sign => SubAccountV2Sign::valid_layout(data),
            Permission::SubAccountV2Withdraw => SubAccountV2Withdraw::valid_layout(data),
            Permission::SubAccountV2Toggle => SubAccountV2Toggle::valid_layout(data),
            _ => Ok(false),
        }
    }

    /// Rejects duplicate V2 sub-account scoped actions within a role's full
    /// action buffer.
    ///
    /// A role may hold at most one scoped V2 action per `(permission type,
    /// subacc_id)` and at most one `SubAccountV2Create` marker. Only the five V2
    /// permission types are deduplicated here; all other actions (including V1
    /// `SubAccount` and repeatable destination limits) are left untouched to
    /// preserve existing behavior.
    ///
    /// `actions_data` is walked sequentially by `[header][data]`, matching how
    /// `calculate_num_actions` reads the same buffer.
    pub fn reject_duplicate_v2_scoped(actions_data: &[u8]) -> Result<(), ProgramError> {
        // Single forward pass collecting one packed `(type, subacc_id)` key per
        // V2 action, then sort + adjacent-compare. Roles are capped at 255
        // actions by `calculate_num_actions`, so this vector stays small.
        let mut keys: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
        let mut cursor = 0;
        while cursor + Action::LEN <= actions_data.len() {
            let header =
                unsafe { Action::load_unchecked(&actions_data[cursor..cursor + Action::LEN])? };
            let data_start = cursor + Action::LEN;
            let data_end = data_start
                .checked_add(header.length() as usize)
                .ok_or(ProgramError::InvalidInstructionData)?;
            if data_end > actions_data.len() {
                return Err(ProgramError::InvalidInstructionData);
            }

            if let Some((ty, id)) =
                v2_dedup_key(header.permission()?, &actions_data[data_start..data_end])
            {
                keys.push(((ty as u64) << 32) | id as u64);
            }

            cursor = data_end;
        }

        keys.sort_unstable();
        for pair in keys.windows(2) {
            if pair[0] == pair[1] {
                return Err(SwigStateError::DuplicateV2SubAccountAction.into());
            }
        }
        Ok(())
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
