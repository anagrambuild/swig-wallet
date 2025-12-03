//! Role management module for the Swig wallet system.
//!
//! This module provides functionality for managing roles and their associated
//! permissions through positions, actions, and authorities. It implements the
//! core role-based access control (RBAC) system.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use crate::{
    action::{Action, Actionable},
    authority::{AuthorityInfo, AuthorityType},
    IntoBytes, Transmutable, TransmutableMut,
};

/// Represents a position in the role system with associated metadata.
///
/// A position defines the structure of a role by specifying its authority type,
/// size information, and boundaries for actions.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct Position {
    /// The type of authority associated with this position
    pub authority_type: u16,
    /// Length of the authority data
    pub authority_length: u16,
    /// Number of actions associated with this position
    pub num_actions: u16,
    padding: u16,
    /// Unique identifier for this position
    pub id: u32,
    /// Boundary marker for position data
    pub boundary: u32,
}

/// Represents a role with immutable access to its components.
///
/// A role combines a position with its authority information and associated
/// actions.
pub struct Role<'a> {
    /// The position defining this role's structure
    pub position: &'a Position,
    /// The authority information for this role
    pub authority: &'a dyn AuthorityInfo,
    /// Raw bytes containing the role's actions
    pub actions: &'a [u8],
}

impl<'a> Role<'a> {
    /// Retrieves a specific action from the role's action list.
    ///
    /// Searches through the role's actions to find one matching the given type
    /// and data.
    pub fn get_action<A: Actionable<'a>>(
        &'a self,
        match_data: &[u8],
    ) -> Result<Option<&'a A>, ProgramError> {
        let mut cursor = 0;
        if self.actions.len() < Action::LEN && self.position.id() != 0 {
            return Err(ProgramError::InvalidAccountData);
        }
        while cursor < self.actions.len() {
            let action = unsafe {
                Action::load_unchecked(self.actions.get_unchecked(cursor..cursor + Action::LEN))?
            };
            cursor += Action::LEN;
            if action.permission()? == A::TYPE {
                let action_obj = unsafe {
                    A::load_unchecked(self.actions.get_unchecked(cursor..cursor + A::LEN))?
                };
                if !A::REPEATABLE || action_obj.match_data(match_data) {
                    return Ok(Some(action_obj));
                }
            }

            cursor = action.boundary() as usize;
        }
        Ok(None)
    }

    /// Retrieves all actions associated with this role.
    pub fn get_all_actions(&'a self) -> Result<Vec<&Action>, ProgramError> {
        let mut actions = Vec::new();
        let mut cursor = 0;
        while cursor < self.actions.len() {
            let action = unsafe {
                Action::load_unchecked(self.actions.get_unchecked(cursor..cursor + Action::LEN))?
            };
            actions.push(action);
            cursor = action.boundary() as usize;
        }
        Ok(actions)
    }

    /// Retrieves all actions of a specific type from the role's action list.
    ///
    /// This method is useful for repeatable actions where multiple instances
    /// of the same action type can exist (e.g., multiple destination limits).
    pub fn get_all_actions_of_type<A: Actionable<'a>>(
        &'a self,
    ) -> Result<Vec<&'a A>, ProgramError> {
        let mut actions = Vec::new();
        let mut cursor = 0;
        if self.actions.len() < Action::LEN && self.position.id() != 0 {
            return Err(ProgramError::InvalidAccountData);
        }
        while cursor < self.actions.len() {
            let action = unsafe {
                Action::load_unchecked(self.actions.get_unchecked(cursor..cursor + Action::LEN))?
            };
            cursor += Action::LEN;
            if action.permission()? == A::TYPE {
                let action_obj = unsafe {
                    A::load_unchecked(self.actions.get_unchecked(cursor..cursor + A::LEN))?
                };
                actions.push(action_obj);
            }
            cursor = action.boundary() as usize;
        }
        Ok(actions)
    }

    /// Returns the authority type associated with this role.
    pub fn authority_type(&self) -> Result<AuthorityType, ProgramError> {
        self.position.authority_type()
    }
}

/// Represents a role with mutable access to its components.
///
/// Similar to `Role`, but provides mutable access to the authority and actions.
pub struct RoleMut<'a> {
    /// The position defining this role's structure
    pub position: &'a Position,
    /// Mutable reference to the authority information
    pub authority: &'a mut dyn AuthorityInfo,
    /// Number of actions in this role
    pub num_actions: u8,
    /// Mutable reference to the raw action bytes
    pub actions: &'a mut [u8],
}

impl<'a> RoleMut<'a> {
    /// Retrieves a specific action from the role's action list.
    ///
    /// Similar to `Role::get_action` but for mutable roles.
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
                    A::load_unchecked(self.actions.get_unchecked(cursor..cursor + A::LEN))?
                };
                if !A::REPEATABLE || action_obj.match_data(match_data) {
                    return Ok(Some(action_obj));
                }
            }
            cursor = action.boundary() as usize;
        }
        Ok(None)
    }

    /// Retrieves a mutable reference to a specific action.
    ///
    /// This is a static method that works directly with action data.
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
                        A::load_unchecked(actions_data.get_unchecked(cursor..cursor + A::LEN))?
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

impl IntoBytes for Position {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
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
    /// Creates a new Position with the specified parameters.
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

    /// Returns the authority type of this position.
    pub fn authority_type(&self) -> Result<AuthorityType, ProgramError> {
        AuthorityType::try_from(self.authority_type)
    }

    /// Returns the unique identifier of this position.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Returns the length of the authority data.
    pub fn authority_length(&self) -> u16 {
        self.authority_length
    }

    /// Returns the number of actions associated with this position.
    pub fn num_actions(&self) -> u16 {
        self.num_actions
    }

    /// Returns the boundary marker for this position.
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
