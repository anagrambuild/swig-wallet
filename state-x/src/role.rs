use core::mem;

use pinocchio::program_error::ProgramError;

use crate::{
    action::{Action, Actionable},
    authority::{ AuthorityInfo, AuthorityType}, IntoBytes, Transmutable, TransmutableMut,
};

static_assertions::const_assert!(mem::size_of::<Position>() % 8 == 0);
#[repr(C)]
#[derive(Debug)]
pub struct Position {
    pub authority_type: u16,
    pub authority_length: u16,
    pub num_actions: u16,
    padding: u16,
    pub id: u32,
    pub boundary: u32,
}

pub struct Role<'a> {
    pub position: &'a Position,
    pub authority: &'a dyn AuthorityInfo,
    pub actions: &'a [u8],
}

impl<'a> Role<'a> {
    pub fn get_action<A: Actionable<'a>>(
        &'a self,
        match_data: &[u8],
    ) -> Result<Option<&'a A>, ProgramError> {
        let mut cursor = 0;
        if self.actions.len() < Action::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        while cursor < self.actions.len() {
            let action = unsafe {
                Action::load_unchecked(self.actions.get_unchecked(cursor..cursor + Action::LEN))?
            };
            cursor += Action::LEN;
            if action.permission()? == A::TYPE {
                let action_obj = unsafe {
                    A::load_unchecked(&self.actions.get_unchecked(cursor..cursor + A::LEN))?
                };
                if !A::REPEATABLE || action_obj.match_data(match_data) {
                    return Ok(Some(action_obj));
                }
            }

            cursor = action.boundary() as usize;
        }
        Ok(None)
    }
}

pub struct RoleMut<'a> {
    pub position: &'a Position,
    pub authority: &'a dyn AuthorityInfo,
    pub num_actions: u8,
    pub actions: &'a mut [u8],
}

impl<'a> RoleMut<'a> {
    pub fn get_action_mut<A: Actionable<'a>>(
        actions_data: &'a mut [u8],
        match_data: &[u8],
    ) -> Result<Option<&'a mut A>, ProgramError> {
        let mut cursor = 0;
        let end_pos = actions_data.len();
        let mut found_offset = None;
        {
            while cursor < end_pos {
                let action = unsafe {
                    Action::load_unchecked(
                        actions_data.get_unchecked(cursor..cursor + Action::LEN),
                    )?
                };
                cursor += Action::LEN;
                if action.permission()? == A::TYPE {
                    let action_obj = unsafe {
                        A::load_unchecked(&actions_data.get_unchecked(cursor..cursor + A::LEN))?
                    };
                    if !A::REPEATABLE || action_obj.match_data(match_data) {
                        found_offset = Some(cursor);
                        break;
                    }
                }
                cursor = action.boundary() as usize;
            }
        }

        if let Some(offset) = found_offset {
            let action_obj =
                unsafe { A::load_mut_unchecked(&mut actions_data[offset..offset + A::LEN])? };
            Ok(Some(action_obj))
        } else {
            Ok(None)
        }
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

impl TransmutableMut for Position {}

impl Position {
    pub fn new(
        authority_type: AuthorityType,
        id: u32,
        length: u16,
        num_actions: u16,
        boundary: u32,
    ) -> Self {
        Self {
            authority_type: authority_type as u16,
            authority_length: length,
            num_actions,
            padding: 0,
            id,
            boundary,
        }
    }

    pub fn authority_type(&self) -> Result<AuthorityType, ProgramError> {
        AuthorityType::try_from(self.authority_type)
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn authority_length(&self) -> u16 {
        self.authority_length
    }

    pub fn num_actions(&self) -> u16 {
        self.num_actions
    }

    pub fn boundary(&self) -> u32 {
        self.boundary
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
        assert_eq!(bytes_as_u16[1], 100); // authority_length
        assert_eq!(bytes_as_u16[2], 5); // num_actions
        assert_eq!(bytes_as_u16[3], 0); // padding

        // Read u32 values directly
        let bytes_as_u32: &[u32] =
            unsafe { core::slice::from_raw_parts(bytes.as_ptr() as *const u32, Position::LEN / 4) };
        assert_eq!(bytes_as_u32[2], 12345); // id
        assert_eq!(bytes_as_u32[3], 54321); // boundary
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
