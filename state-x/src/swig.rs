extern crate alloc;

use alloc::boxed::Box;
use pinocchio::{msg, program_error::ProgramError};

use crate::{
    action::{Action, ActionLoader, Permission},
    authority::{Authority, AuthorityType},
    role::{Position, Role},
    FromBytes, IntoBytes, Transmutable, TransmutableMut,
};

pub struct SwigBuilder<'a> {
    pub account_buffer: &'a mut [u8],
    pub swig: &'a mut Swig,
}

impl<'a> SwigBuilder<'a> {
    pub fn create(account_buffer: &'a mut [u8], swig: Swig) -> Result<Self, ProgramError> {
        let (swig_bytes, roles_bytes) = account_buffer.split_at_mut(Swig::LEN);
        let bytes = swig.into_bytes()?;
        swig_bytes[0..].copy_from_slice(bytes);
        let builder = Self {
            account_buffer: roles_bytes,
            swig: unsafe { Swig::load_mut_unchecked(swig_bytes)? },
        };
        Ok(builder)
    }

    pub fn new_from_bytes(account_buffer: &'a mut [u8]) -> Result<Self, ProgramError> {
        let (swig_bytes, roles_bytes) = account_buffer.split_at_mut(Swig::LEN);
        let swig = unsafe { Swig::load_mut_unchecked(swig_bytes)? };
        let builder = Self {
            account_buffer: roles_bytes,
            swig,
        };
        Ok(builder)
    }

    pub fn add_role<T: Authority<'a>>(
        &mut self,
        authority: &'a T,
        num_actions: u8,
        actions_data: &'a [u8],
    ) -> Result<(), ProgramError> {
        // check number of roles and iterate to last boundary
        let mut cursor = 0;
        // iterate and transmute each position to get boundary if not the last then jump to next boundary
        for _i in 0..self.swig.roles {
            let position = unsafe {
                Position::load_unchecked(&self.account_buffer[cursor..cursor + Position::LEN])
                    .unwrap()
            };
            cursor += position.boundary() as usize;
        }
        let size = T::LEN + num_actions as usize * Action::LEN + actions_data.len();
        let boundary = cursor + size;
        // add role to the end of the buffer
        let new_position = Position::new(
            T::TYPE,
            self.swig.role_counter,
            size as u16,
            boundary as u32,
        );
        self.account_buffer[cursor..cursor + Position::LEN]
            .copy_from_slice(new_position.into_bytes()?);
        cursor += Position::LEN;
        self.account_buffer[cursor..cursor + T::LEN].copy_from_slice(authority.into_bytes()?);
        cursor += T::LEN;
        let mut action_cursor = 0;
        for _i in 0..num_actions {
            let (header, data) = actions_data.split_at(action_cursor + Action::LEN);
            let action_header = unsafe { Action::load_unchecked(header)? };
            action_cursor += Action::LEN;
            let action_slice = &data[0..action_header.length() as usize];
            action_cursor += action_header.length() as usize;
            if ActionLoader::validate_layout(action_header.permission()?, action_slice)? {
                self.account_buffer[cursor..cursor + Action::LEN].copy_from_slice(header);
                // change boundary to the new boundary
                self.account_buffer[cursor + 2..cursor + 6].copy_from_slice(
                    &((cursor + Action::LEN + action_header.length() as usize) as u32)
                        .to_le_bytes(),
                );
                cursor += Action::LEN;
                self.account_buffer[cursor..cursor + action_header.length() as usize]
                    .copy_from_slice(action_slice);
                cursor += action_header.length() as usize;
            } else {
                return Err(ProgramError::InvalidAccountData);
            }
        }
        self.swig.roles += 1;
        self.swig.role_counter += 1;
        Ok(())
    }
}

static_assertions::const_assert!(core::mem::size_of::<Swig>() % 8 == 0);
#[repr(C)]
pub struct Swig {
    pub discriminator: u8,
    pub bump: u8,
    pub id: [u8; 32],
    pub roles: u16,
    pub role_counter: u32, // ensure unique ids up to 2^32
    _padding: [u16; 4],
}

impl Swig {
    pub fn new(id: [u8; 32], bump: u8) -> Self {
        Self {
            discriminator: 0,
            id,
            bump,
            roles: 0,
            role_counter: 0,
            _padding: [0; 4],
        }
    }
}

impl Transmutable for Swig {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl TransmutableMut for Swig {}

impl<'a> IntoBytes<'a> for Swig {
    fn into_bytes(&'a self) -> Result<&'a [u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

pub struct SwigWithRoles<'a> {
    pub state: &'a Swig,

    roles: &'a [u8],
}

impl<'a> SwigWithRoles<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ProgramError> {
        if bytes.len() < Swig::LEN {
            return Err(ProgramError::InvalidAccountData);
        }

        let state = unsafe { Swig::load_unchecked(&bytes[..Swig::LEN])? };
        let roles = &bytes[Swig::LEN..];

        Ok(SwigWithRoles { state, roles })
    }

    pub fn get<T: Authority<'a> + 'a>(&'a self, id: u32) -> Option<Role<T>> {
        let mut cursor = 0;

        while (cursor + Position::LEN) <= self.roles.len() {
            let offset = cursor + Position::LEN;
            let position =
                unsafe { Position::load_unchecked(&self.roles[cursor..offset]).unwrap() };

            match position.authority_type() {
                Ok(t) if t == T::TYPE && position.id() == id => {
                    let end = offset + position.length() as usize;

                    match Role::<T>::from_bytes(&self.roles[cursor..end]) {
                        Ok(role) => return Some(role),
                        Err(_) => return None,
                    }
                },
                Ok(AuthorityType::None) => return None,
                _ => cursor = offset + position.boundary() as usize,
            }
        }

        None
    }
}
