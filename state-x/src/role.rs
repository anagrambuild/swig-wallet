use core::mem;

use pinocchio::program_error::ProgramError;

use crate::{
    action::{Action, Actionable},
    authority::{Authority, AuthorityType},
    FromBytes, FromBytesMut, IntoBytes, Transmutable,
};

// pub struct Role<'a, T: Authority<'a>> {
//     pub position: &'a Position,

//     /// Authority specific data.
//     ///
//     /// TODO: is the length known at compile time by the authority?
//     pub authority: &'a T,

//     /// Actions associated with this authority.
//     actions: &'a [u8],
// }

// impl<'a, T: Authority<'a>> FromBytes<'a> for Role<'a, T> {
//     fn from_bytes(bytes: &'a [u8]) -> Result<Self, ProgramError> {
//         // The role must be at least `Position::LEN` bytes.
//         if bytes.len() < Position::LEN {
//             return Err(ProgramError::InvalidAccountData);
//         }
//         let (position, remaining) = bytes.split_at(Position::LEN);
//         let (authority, actions) = remaining.split_at(T::LEN);
//         Ok(Role {
//             position: unsafe { Position::load_unchecked(position)? },
//             authority: unsafe { T::load_unchecked(authority)? },
//             actions,
//         })
//     }
// }

// pub struct RoleMut<'a, T: Authority<'a>> {
//     pub position: &'a Position,

//     /// Authority specific data.
//     ///
//     /// TODO: is the length known at compile time by the authority?
//     pub authority: &'a mut T,

//     /// Actions associated with this authority.
//     actions: &'a mut [u8],
// }

// impl<'a, T: Authority<'a>> FromBytesMut<'a> for RoleMut<'a, T> {
//     fn from_bytes_mut(bytes: &'a mut [u8]) -> Result<Self, ProgramError> {
//         // The role must be at least `Position::LEN` bytes.
//         if bytes.len() < Position::LEN {
//             return Err(ProgramError::InvalidAccountData);
//         }

//         let (position, remaining) = bytes.split_at_mut(Position::LEN);
//         let position = unsafe { Position::load_unchecked(position)? };

//         let (authority, actions) = remaining.split_at_mut(T::LEN);
//         let authority = unsafe { T::load_mut_unchecked(authority)? };

//         Ok(RoleMut {
//             position,
//             authority,
//             actions,
//         })
//     }
// }
// impl<'a, T: Authority<'a>> RoleMut<'a, T> {
//     pub fn get_mut_action<A: Actionable<'a>>(
//         &mut self,
//         match_data: &[u8],
//     ) -> Result<Option<&mut A>, ProgramError> {
//         let num_actions = self.position.num_actions();
//         let mut cursor = 0;
//         for i in 0..num_actions {
//             let action =
//                 unsafe { Action::load_unchecked(&self.actions[cursor..cursor + Action::LEN])? };
//             cursor += Action::LEN;
//             if action.permission()? == A::TYPE {
//                 let action_obj =
//                     unsafe { A::load_mut_unchecked(&mut self.actions[cursor..cursor + A::LEN])? };

//                 return Ok(Some(action_obj));
//             }
//         }
//         Ok(None)
//     }
// }

static_assertions::const_assert!(mem::size_of::<Position>() % 8 == 0);
#[repr(C)]
#[derive(Debug)]
pub struct Position {
    /// Data section.
    ///   0. authority type u16
    ///   1..2. ID u32
    ///   3. authority length u16
    ///   4. num_actions u16
    ///   5..6. boundary u32
    ///   7. padding u16
    data: [u16; 8],
}

pub struct RolePosition<'a> {
    pub offset: usize,
    pub position: &'a Position,
}

impl<'a> RolePosition<'a> {
    pub fn new(offset: usize, position: &'a Position) -> Self {
        Self { offset, position }
    }
}

impl<'a> IntoBytes<'a> for Position {
    fn into_bytes(&'a self) -> Result<&'a [u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

impl Transmutable for Position {
    const LEN: usize = core::mem::size_of::<Position>();
}

impl Position {
    pub fn new(
        authority_type: AuthorityType,
        id: u32,
        length: u16,
        num_actions: u16,
        boundary: u32,
    ) -> Self {
        Self {
            data: [
                authority_type as u16,
                (id >> 16) as u16,
                (id & 0xFFFF) as u16,
                length,
                num_actions,
                (boundary >> 16) as u16,
                (boundary & 0xFFFF) as u16,
                0,
            ],
        }
    }

    pub fn authority_type(&self) -> Result<AuthorityType, ProgramError> {
        AuthorityType::try_from(self.data[0])
    }

    pub fn id(&self) -> u32 {
        (self.data[1] as u32) << 16 | self.data[2] as u32
    }

    pub fn authority_length(&self) -> u16 {
        self.data[3]
    }

    pub fn num_actions(&self) -> u16 {
        self.data[4]
    }

    pub fn boundary(&self) -> u32 {
        (self.data[5] as u32) << 16 | self.data[6] as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_position_to_bytes() {
        let position = Position::new(AuthorityType::Ed25519, 12345, 100, 5, 54321);
        let bytes = position.into_bytes().unwrap();

        assert_eq!(bytes.len(), Position::LEN);

        // Check raw bytes match expected values
        let bytes_as_u16: &[u16] =
            unsafe { core::slice::from_raw_parts(bytes.as_ptr() as *const u16, Position::LEN / 2) };
        assert_eq!(bytes_as_u16[0], AuthorityType::Ed25519 as u16);
        assert_eq!(bytes_as_u16[1], (12345 >> 16) as u16);
        assert_eq!(bytes_as_u16[2], (12345 & 0xFFFF) as u16);
        assert_eq!(bytes_as_u16[3], 100);
        assert_eq!(bytes_as_u16[4], 5);
        assert_eq!(bytes_as_u16[5], (54321 >> 16) as u16);
        assert_eq!(bytes_as_u16[6], (54321 & 0xFFFF) as u16);
        assert_eq!(bytes_as_u16[7], 0); // padding
    }

    #[test]
    fn test_position_from_bytes() {
        let original = Position::new(AuthorityType::Ed25519, 12345, 100, 5, 54321);
        let bytes = original.into_bytes().unwrap();

        let loaded = unsafe { Position::load_unchecked(bytes) }.unwrap();
        assert_eq!(loaded.authority_type().unwrap(), AuthorityType::Ed25519);
        assert_eq!(loaded.id(), 12345);
        assert_eq!(loaded.authority_length(), 100);
        assert_eq!(loaded.num_actions(), 5);
        assert_eq!(loaded.boundary(), 54321);
    }

    #[test]
    fn test_position_edge_cases() {
        // Test max values
        let max_position = Position::new(
            AuthorityType::Ed25519,
            u32::MAX,
            u16::MAX,
            u16::MAX,
            u32::MAX,
        );
        let bytes = max_position.into_bytes().unwrap();
        let loaded = unsafe { Position::load_unchecked(bytes) }.unwrap();
        assert_eq!(loaded.id(), u32::MAX);
        assert_eq!(loaded.authority_length(), u16::MAX);
        assert_eq!(loaded.num_actions(), u16::MAX);
        assert_eq!(loaded.boundary(), u32::MAX);

        // Test zero values
        let zero_position = Position::new(AuthorityType::Ed25519, 0, 0, 0, 0);
        let bytes = zero_position.into_bytes().unwrap();
        let loaded = unsafe { Position::load_unchecked(bytes) }.unwrap();
        assert_eq!(loaded.id(), 0);
        assert_eq!(loaded.authority_length(), 0);
        assert_eq!(loaded.num_actions(), 0);
        assert_eq!(loaded.boundary(), 0);
    }

    #[test]
    fn test_invalid_authority_type() {
        let position = Position::new(AuthorityType::Ed25519, 0, 0, 0, 0);
        let mut bytes = position.into_bytes().unwrap().to_vec();

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
