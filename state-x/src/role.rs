use core::mem::{self, MaybeUninit};

use pinocchio::program_error::ProgramError;

use crate::{
    action::{Action, Actionable, Permission},
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

impl<'a, T: Authority<'a>> Role<'a, T> {
    pub fn get<U: Actionable<'a>>(&'a self) -> Option<&U> {
        let mut cursor = 0;

        while (cursor + Action::LEN) <= self.actions.len() {
            let offset = cursor + Action::LEN;
            let action = unsafe { Action::load_unchecked(&self.actions[cursor..offset]).unwrap() };

            match action.permission() {
                Ok(t) if t == U::TYPE => {
                    let end = offset + action.length() as usize;
                    return unsafe { U::load_unchecked(&self.actions[offset..end]).ok() };
                },
                Ok(Permission::None) => {
                    return None;
                },
                _ => cursor = offset + action.boundary() as usize,
            }
        }

        None
    }
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
    _actions: &'a mut [u8],
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
            _actions: actions,
        })
    }
}

static_assertions::const_assert!(mem::size_of::<Position>() % 8 == 0);

#[repr(C)]
pub struct Position {
    /// Data section.
    ///   - `[0]` authority type (u16)
    ///   - `[1]` length (u16)
    ///   - `[2..3]` ID (u32)
    ///   - `[4..5]` boundary (u32)
    ///   - `[6..7]` padding (u32)
    data: [u16; 8],
}

impl Transmutable for Position {
    const LEN: usize = core::mem::size_of::<Position>();
}

impl Position {
    pub fn new(authority_type: AuthorityType, id: u32, length: u16, boundary: u32) -> Self {
        let mut data: MaybeUninit<[u16; 8]> = MaybeUninit::uninit();
        let ptr = data.as_mut_ptr();

        unsafe {
            *(*ptr).get_unchecked_mut(0) = authority_type as u16;
            *(*ptr).get_unchecked_mut(1) = length;

            let raw = ptr as *mut u8;
            (raw.add(4) as *mut [u8; 4]).write(id.to_le_bytes());
            (raw.add(8) as *mut [u8; 4]).write(boundary.to_le_bytes());
            // Make sure the padding is zeroed out.
            (raw.add(12) as *mut [u8; 4]).write([0; 4]);
        }

        Self {
            data: unsafe { data.assume_init() },
        }
    }

    pub fn authority_type(&self) -> Result<AuthorityType, ProgramError> {
        AuthorityType::try_from(self.data[0])
    }

    pub fn length(&self) -> u16 {
        self.data[1]
    }

    pub fn id(&self) -> u32 {
        // SAFETY: The `data` is guaranteed to be aligned and have the correct size.
        u32::from_le_bytes(unsafe { *(self.data.as_ptr().add(2) as *const [u8; 4]) })
    }

    pub fn boundary(&self) -> u32 {
        // SAFETY: The `data` is guaranteed to be aligned and have the correct size.
        u32::from_le_bytes(unsafe { *(self.data.as_ptr().add(4) as *const [u8; 4]) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_position() {
        let position = Position::new(AuthorityType::Ed25519, 12345, 100, 54321);

        // Check expected values.
        assert_eq!(position.authority_type().unwrap(), AuthorityType::Ed25519);
        assert_eq!(position.length(), 100);
        assert_eq!(position.id(), 12345);
        assert_eq!(position.boundary(), 54321);

        let bytes = position.as_bytes();
        assert_eq!(bytes.len(), Position::LEN);
        assert_eq!(bytes[12..16], [0; 4]);
    }

    #[test]
    fn test_position_edge_cases() {
        // Test max values
        let max_position = Position::new(AuthorityType::Ed25519, u32::MAX, u16::MAX, u32::MAX);
        let bytes = max_position.as_bytes();
        let loaded = unsafe { Position::load_unchecked(bytes) }.unwrap();
        assert_eq!(loaded.id(), u32::MAX);
        assert_eq!(loaded.length(), u16::MAX);
        assert_eq!(loaded.boundary(), u32::MAX);

        // Test zero values
        let zero_position = Position::new(AuthorityType::Ed25519, 0, 0, 0);
        let bytes = zero_position.as_bytes();
        let loaded = unsafe { Position::load_unchecked(bytes) }.unwrap();
        assert_eq!(loaded.id(), 0);
        assert_eq!(loaded.length(), 0);
        assert_eq!(loaded.boundary(), 0);
    }

    #[test]
    fn test_position_invalid_authority_type() {
        let position = Position::new(AuthorityType::Ed25519, 0, 0, 0);
        let mut bytes = position.as_bytes().to_vec();

        // Set authority type to 0 (None) which should be invalid
        let bytes_as_u16: &mut [u16] = unsafe {
            core::slice::from_raw_parts_mut(bytes.as_mut_ptr() as *mut u16, Position::LEN / 2)
        };
        bytes_as_u16[0] = 0;

        let loaded = unsafe { Position::load_unchecked(&bytes) }.unwrap();
        assert!(
            loaded.authority_type().is_err(),
            "Authority type None (0) should be invalid"
        );
    }
}
