pub mod all;
pub mod manage_authority;
pub mod program;
pub mod sol_limit;
pub mod sol_recurring_limit;
pub mod sub_account;
pub mod token_limit;
pub mod token_recurring_limit;
use all::All;
use manage_authority::ManageAuthority;
use pinocchio::{msg, program_error::ProgramError};
use program::Program;
use sol_limit::SolLimit;
use sol_recurring_limit::SolRecurringLimit;
use token_limit::TokenLimit;
use token_recurring_limit::TokenRecurringLimit;

use crate::{IntoBytes, Transmutable, TransmutableMut};

static_assertions::const_assert!(core::mem::size_of::<Action>() % 8 == 0);
#[repr(C)]
#[derive(Debug)]
pub struct Action {
    /// Data section.
    ///  * [0] type
    ///  * [1] length 
    ///  * [2..3] boundary 
    data: [u16; 4],
}

impl<'a> IntoBytes<'a> for Action {
    fn into_bytes(&'a self) -> Result<&'a [u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self.data.as_ptr() as *const u8, 8) })
    }
}

impl Transmutable for Action {
    const LEN: usize = core::mem::size_of::<Action>();
}

impl Action {
    pub fn client_new(_type: Permission, length: u16) -> Self {
        Self {
            data: [_type as u16, length, 0, 0],
        }
    }
    pub fn new(_type: Permission, length: u16, boundary: u32) -> Self {
        Self {
            data: [
                _type as u16,
                length,
                (boundary >> 16) as u16,
                (boundary & 0xFFFF) as u16,
            ],
        }
    }

    pub fn permission(&self) -> Result<Permission, ProgramError> {
        Permission::try_from(self.data[0])
    }

    pub fn length(&self) -> u16 {
        self.data[1]
    }

    pub fn boundary(&self) -> u32 {
        (self.data[2] as u32) << 16 | self.data[3] as u32
    }
}

#[derive(Default, PartialEq, Copy, Clone)]
#[repr(u16)]
pub enum Permission {
    #[default]
    None,
    SolLimit,
    SolRecurringLimit,
    Program,
    TokenLimit,
    TokenRecurringLimit,
    All,
    ManageAuthority,
    SubAccount,
}

impl TryFrom<u16> for Permission {
    type Error = ProgramError;

    #[inline(always)]
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            // SAFETY: `value` is guaranteed to be in the range of the enum variants.
            0..=10 => Ok(unsafe { core::mem::transmute::<u16, Permission>(value) }),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

impl TryFrom<&[u8]> for Permission {
    type Error = ProgramError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let type_bytes = value
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        Permission::try_from(u16::from_le_bytes(type_bytes))
    }
}

/// Trait for representing action data.
pub trait Actionable<'a>: Transmutable + TransmutableMut {
    const TYPE: Permission;
    const REPEATABLE: bool;

    fn validate(&mut self);

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
            Permission::TokenLimit => TokenLimit::valid_layout(data),
            Permission::TokenRecurringLimit => TokenRecurringLimit::valid_layout(data),
            Permission::All => All::valid_layout(data),
            Permission::ManageAuthority => ManageAuthority::valid_layout(data),
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
