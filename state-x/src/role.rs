use pinocchio::program_error::ProgramError;

use crate::{
    action::{Action, Actionable},
    authority::{Authority, AuthorityType},
    FromBytes, FromBytesMut, Transmutable,
};

pub struct Role<'a, T: Authority<'a>> {
    pub position: &'a Position,

    /// Authority specific data.
    ///
    /// TODO: is the length known at compile time by the authority?
    pub authority: &'a T,

    /// Actions associated with this authority.
    actions: &'a [u8],
}

impl<'a, T: Authority<'a>> FromBytes<'a> for Role<'a, T> {
    fn from_bytes(bytes: &'a [u8]) -> Result<Self, ProgramError> {
        // The role must be at least `Position::LEN` bytes.
        if bytes.len() < Position::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let position = unsafe { Position::load_unchecked(&bytes[..Position::LEN])? };
        let authority = unsafe { T::load_unchecked(&bytes[Position::LEN..])? };
        let actions = &bytes[Position::LEN + authority.length()..];

        Ok(Role {
            position,
            authority,
            actions,
        })
    }
}

pub struct RoleMut<'a, T: Authority<'a>> {
    pub position: &'a Position,

    /// Authority specific data.
    ///
    /// TODO: is the length known at compile time by the authority?
    pub authority: &'a mut T,

    /// Actions associated with this authority.
    actions: &'a mut [u8],
}

/*
impl<'a, T: Authority<'a>> RoleMut<'a, T> {
    pub fn validate(&mut self) {
        let mut cursor = 0;

        while (cursor + Action::LEN) <= self.actions.len() {
            let offset = cursor + Action::LEN;
            let action: &Action = unsafe {
                // TODO: Fix the unwrap.
                Action::load_unchecked(&self.actions[cursor..offset]).unwrap()
            };
            let end = offset + action.length() as usize;

            let action = Actionable::from_bytes(&self.actions[offset..end]);
            // TODO: conditionally validate the action.
            action.validate();
        }
    }
}
*/
impl<'a, T: Authority<'a>> FromBytesMut<'a> for RoleMut<'a, T> {
    fn from_bytes_mut(bytes: &'a mut [u8]) -> Result<Self, ProgramError> {
        // The role must be at least `Position::LEN` bytes.
        if bytes.len() < Position::LEN {
            return Err(ProgramError::InvalidAccountData);
        }

        let (position, remaining) = bytes.split_at_mut(Position::LEN);
        let position = unsafe { Position::load_unchecked(position)? };

        let (authority, actions) = remaining.split_at_mut(T::LEN);
        let authority = unsafe { T::load_mut_unchecked(authority)? };

        Ok(RoleMut {
            position,
            authority,
            actions,
        })
    }
}

#[repr(C)]
pub struct Position {
    /// Data section.
    ///   0. authority type
    ///   1. ID
    ///   2. length
    ///   3. boundary
    data: [u16; 4],
}

impl Transmutable for Position {
    const LEN: usize = core::mem::size_of::<Position>();
}

impl Position {
    pub fn authority_type(&self) -> Result<AuthorityType, ProgramError> {
        AuthorityType::try_from(self.data[0])
    }

    pub fn id(&self) -> u16 {
        self.data[1]
    }

    pub fn length(&self) -> u16 {
        self.data[2]
    }

    pub fn boundary(&self) -> u16 {
        self.data[3]
    }
}
