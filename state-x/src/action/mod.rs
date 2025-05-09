pub mod all;
pub mod manage_authority;
pub mod program;
pub mod program_scope;
pub mod sol_limit;
pub mod sol_recurring_limit;
pub mod stake_all;
pub mod stake_limit;
pub mod stake_recurring_limit;
pub mod sub_account;
pub mod token_limit;
pub mod token_recurring_limit;
use all::All;
use manage_authority::ManageAuthority;
use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;
use program::Program;
use program_scope::ProgramScope;
use sol_limit::SolLimit;
use sol_recurring_limit::SolRecurringLimit;
use sub_account::SubAccount;
use stake_all::StakeAll;
use stake_limit::StakeLimit;
use stake_recurring_limit::StakeRecurringLimit;

use token_limit::TokenLimit;
use token_recurring_limit::TokenRecurringLimit;

use crate::{IntoBytes, SwigStateError, Transmutable, TransmutableMut};

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct Action {
    action_type: u16,
    length: u16,
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
    pub fn client_new(_type: Permission, length: u16) -> Self {
        Self {
            action_type: _type as u16,
            length,
            boundary: 0,
        }
    }
    pub fn new(_type: Permission, length: u16, boundary: u32) -> Self {
        Self {
            action_type: _type as u16,
            length,
            boundary,
        }
    }

    pub fn permission(&self) -> Result<Permission, ProgramError> {
        Permission::try_from(self.action_type)
    }

    pub fn length(&self) -> u16 {
        self.length
    }

    pub fn boundary(&self) -> u32 {
        self.boundary
    }
}

#[derive(Default, Debug, PartialEq, Copy, Clone)]
#[repr(u16)]
pub enum Permission {
    #[default]
    None,
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
}

impl TryFrom<u16> for Permission {
    type Error = ProgramError;

    #[inline(always)]
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            // SAFETY: `value` is guaranteed to be in the range of the enum variants.
            0..=14 => Ok(unsafe { core::mem::transmute::<u16, Permission>(value) }),
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

/// Trait for representing action data.
pub trait Actionable<'a>: Transmutable + TransmutableMut {
    const TYPE: Permission;
    const REPEATABLE: bool;

    fn match_data(&self, _data: &[u8]) -> bool {
        false
    }

    fn valid_layout(data: &'a [u8]) -> Result<bool, ProgramError> {
        Ok(data.len() == Self::LEN)
    }
}

pub struct ActionLoader;

impl ActionLoader {
    pub fn validate_layout(permission: Permission, data: &[u8]) -> Result<bool, ProgramError> {
        match permission {
            Permission::SolLimit => SolLimit::valid_layout(data),
            Permission::SolRecurringLimit => SolRecurringLimit::valid_layout(data),
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
            _ => Ok(false),
        }
    }

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
            cursor += action.boundary() as usize;
        }
        Ok(None)
    }
}
