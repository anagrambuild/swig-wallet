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

macro_rules! non_repeatable_permission_mask {
    ($($action:ty),+ $(,)?) => {
        0u32 $(| ((!<$action>::REPEATABLE as u32) << <$action>::TYPE as u32))+
    };
}

const NON_REPEATABLE_PERMISSION_MASK: u32 = non_repeatable_permission_mask!(
    SolLimit,
    SolRecurringLimit,
    Program,
    ProgramScope,
    TokenLimit,
    TokenRecurringLimit,
    All,
    ManageAuthority,
    SubAccount,
    StakeLimit,
    StakeRecurringLimit,
    StakeAll,
    ProgramAll,
    ProgramCurated,
    AllButManageAuthority,
    SolDestinationLimit,
    SolRecurringDestinationLimit,
    TokenDestinationLimit,
    TokenRecurringDestinationLimit,
    CloseSwigAuthority,
    ReplaceAuthority,
    SubAccountV2Create,
    SubAccountV2All,
    SubAccountV2Sign,
    SubAccountV2Withdraw,
    SubAccountV2Toggle,
);

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

/// Returns a validation key for a V2 sub-account action, or `None` for any
/// non-V2 permission (which is intentionally not validated here).
///
/// The scoped permissions key on `(type, subacc_id)`; the create marker keys on
/// its type with a fixed id so a second marker collides.
fn v2_validation_key(permission: Permission, data: &[u8]) -> Option<(u16, u32)> {
    match permission {
        Permission::SubAccountV2Create => Some((permission as u16, 0)),
        Permission::SubAccountV2All
        | Permission::SubAccountV2Sign
        | Permission::SubAccountV2Withdraw
        | Permission::SubAccountV2Toggle => {
            if data.len() == SubAccountV2All::LEN {
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
    /// Rejects duplicate permission types that are declared non-repeatable.
    #[inline(always)]
    pub fn validate_non_repeatable_actions(actions_data: &[u8]) -> Result<(), ProgramError> {
        let mut non_repeatable_permissions = 0u32;
        let mut cursor = 0;
        while cursor < actions_data.len() {
            if cursor + Action::LEN > actions_data.len() {
                return Err(ProgramError::InvalidInstructionData);
            }
            let header = unsafe {
                Action::load_unchecked(actions_data.get_unchecked(cursor..cursor + Action::LEN))?
            };
            cursor += Action::LEN + header.length() as usize;
            if cursor > actions_data.len() {
                return Err(ProgramError::InvalidInstructionData);
            }

            let permission = header.action_type as u32;
            if permission > Permission::SubAccountV2Toggle as u32 {
                return Err(SwigStateError::PermissionLoadError.into());
            }
            let permission_bit = 1u32 << permission;
            if NON_REPEATABLE_PERMISSION_MASK & permission_bit != 0 {
                if non_repeatable_permissions & permission_bit != 0 {
                    return Err(SwigStateError::DuplicateNonRepeatableAction.into());
                }
                non_repeatable_permissions |= permission_bit;
            }
        }
        Ok(())
    }

    /// Validates a stored role, with a straight-line path for the common
    /// two-action case.
    #[inline(always)]
    pub fn validate_stored_non_repeatable_actions(
        actions_data: &[u8],
        num_actions: u16,
    ) -> Result<(), ProgramError> {
        if num_actions != 2 {
            return Self::validate_non_repeatable_actions(actions_data);
        }
        if actions_data.len() < Action::LEN * 2 {
            return Err(ProgramError::InvalidInstructionData);
        }

        let first = unsafe { Action::load_unchecked(actions_data.get_unchecked(..Action::LEN))? };
        let second_start = Action::LEN + first.length() as usize;
        if second_start + Action::LEN > actions_data.len() {
            return Err(ProgramError::InvalidInstructionData);
        }
        let second = unsafe {
            Action::load_unchecked(
                actions_data.get_unchecked(second_start..second_start + Action::LEN),
            )?
        };
        if second_start + Action::LEN + second.length() as usize != actions_data.len() {
            return Err(ProgramError::InvalidInstructionData);
        }

        let first_permission = first.action_type as u32;
        let second_permission = second.action_type as u32;
        if first_permission > Permission::SubAccountV2Toggle as u32
            || second_permission > Permission::SubAccountV2Toggle as u32
        {
            return Err(SwigStateError::PermissionLoadError.into());
        }
        if first_permission == second_permission
            && NON_REPEATABLE_PERMISSION_MASK & (1u32 << first_permission) != 0
        {
            return Err(SwigStateError::DuplicateNonRepeatableAction.into());
        }
        Ok(())
    }

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

    /// Validates constraints that require a role's full action buffer.
    ///
    /// Non-repeatable permission types may appear at most once. Repeatable
    /// permissions retain their action-specific matching semantics.
    ///
    /// Each scoped action must target an existing sub-account id (strictly less
    /// than `sub_account_counter`). A role may also hold at most one scoped V2
    /// action per `(permission type, subacc_id)` and at most one
    /// `SubAccountV2Create` marker. Other action types are left untouched.
    ///
    /// `actions_data` is walked sequentially by `[header][data]`, matching how
    /// `calculate_num_actions` reads the same buffer.
    pub fn validate_v2_actions(
        actions_data: &[u8],
        sub_account_counter: u32,
    ) -> Result<(), ProgramError> {
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

            let permission = header.permission()?;
            if let Some((ty, id)) =
                v2_validation_key(permission, &actions_data[data_start..data_end])
            {
                if permission != Permission::SubAccountV2Create && id >= sub_account_counter {
                    return Err(SwigStateError::SubAccountV2PermissionTargetDoesNotExist.into());
                }
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
        Self::validate_non_repeatable_actions(actions_data)
    }

    /// Finds an action of a specific type in the provided bytes.
    pub fn find_action<'a, T: Actionable<'a>>(
        bytes: &'a [u8],
    ) -> Result<Option<&'a T>, ProgramError> {
        let mut cursor = 0;

        while cursor < bytes.len() {
            let data_start = cursor
                .checked_add(Action::LEN)
                .ok_or(ProgramError::InvalidAccountData)?;
            let header = bytes
                .get(cursor..data_start)
                .ok_or(ProgramError::InvalidAccountData)?;
            let action = unsafe { Action::load_unchecked(header)? };
            let data_end = data_start
                .checked_add(action.length() as usize)
                .ok_or(ProgramError::InvalidAccountData)?;
            let action_data = bytes
                .get(data_start..data_end)
                .ok_or(ProgramError::InvalidAccountData)?;

            // Actions are contiguous, so the boundary must be the exact start
            // of the next header. This also guarantees forward progress.
            if action.boundary() as usize != data_end {
                return Err(ProgramError::InvalidAccountData);
            }

            if action.permission()? == T::TYPE {
                return Ok(Some(unsafe { T::load_unchecked(action_data)? }));
            }
            cursor = data_end;
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(8))]
    struct AlignedBytes<const N: usize>([u8; N]);

    fn write_header<const N: usize>(bytes: &mut AlignedBytes<N>, offset: usize, action: &Action) {
        bytes.0[offset..offset + Action::LEN]
            .copy_from_slice(action.into_bytes().expect("serialize action header"));
    }

    #[test]
    fn find_action_rejects_truncated_header() {
        let bytes = AlignedBytes([0; Action::LEN - 1]);

        for len in 1..Action::LEN {
            assert!(matches!(
                ActionLoader::find_action::<All>(&bytes.0[..len]),
                Err(ProgramError::InvalidAccountData)
            ));
        }
    }

    #[test]
    fn find_action_loads_data_after_header() {
        const DATA_END: usize = Action::LEN + SolLimit::LEN;
        let mut bytes = AlignedBytes([0; DATA_END]);
        let amount = 42_u64;
        let header = Action::new(Permission::SolLimit, SolLimit::LEN as u16, DATA_END as u32);
        write_header(&mut bytes, 0, &header);
        bytes.0[Action::LEN..DATA_END].copy_from_slice(&amount.to_le_bytes());

        let action = ActionLoader::find_action::<SolLimit>(&bytes.0)
            .expect("valid action data")
            .expect("SolLimit action");

        assert_eq!(action.amount, amount);
    }

    #[test]
    fn find_action_rejects_truncated_data() {
        let mut bytes = AlignedBytes([0; Action::LEN]);
        let header = Action::new(
            Permission::SolLimit,
            SolLimit::LEN as u16,
            (Action::LEN + SolLimit::LEN) as u32,
        );
        write_header(&mut bytes, 0, &header);

        assert!(matches!(
            ActionLoader::find_action::<SolLimit>(&bytes.0),
            Err(ProgramError::InvalidAccountData)
        ));
    }

    #[test]
    fn find_action_rejects_non_advancing_boundary() {
        let mut bytes = AlignedBytes([0; Action::LEN]);
        let header = Action::new(Permission::All, All::LEN as u16, 0);
        write_header(&mut bytes, 0, &header);

        assert!(matches!(
            ActionLoader::find_action::<All>(&bytes.0),
            Err(ProgramError::InvalidAccountData)
        ));
    }

    #[test]
    fn find_action_rejects_boundary_inside_action_data() {
        const DATA_END: usize = Action::LEN + Program::LEN;
        let mut bytes = AlignedBytes([0; DATA_END]);
        let program_header =
            Action::new(Permission::Program, Program::LEN as u16, Action::LEN as u32);
        write_header(&mut bytes, 0, &program_header);

        let embedded_all = Action::new(Permission::All, All::LEN as u16, DATA_END as u32);
        write_header(&mut bytes, Action::LEN, &embedded_all);

        assert!(matches!(
            ActionLoader::find_action::<All>(&bytes.0),
            Err(ProgramError::InvalidAccountData)
        ));
    }

    #[test]
    fn find_action_follows_valid_boundaries() {
        const FIRST_END: usize = Action::LEN + SolLimit::LEN;
        const SECOND_END: usize = FIRST_END + Action::LEN;
        let mut bytes = AlignedBytes([0; SECOND_END]);
        let sol_limit = Action::new(Permission::SolLimit, SolLimit::LEN as u16, FIRST_END as u32);
        write_header(&mut bytes, 0, &sol_limit);
        bytes.0[Action::LEN..FIRST_END].copy_from_slice(&42_u64.to_le_bytes());

        let all = Action::new(Permission::All, All::LEN as u16, SECOND_END as u32);
        write_header(&mut bytes, FIRST_END, &all);

        assert!(ActionLoader::find_action::<All>(&bytes.0)
            .expect("valid action data")
            .is_some());
    }
}
