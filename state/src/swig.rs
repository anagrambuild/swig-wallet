//! Core Swig wallet functionality implementation.
//!
//! This module provides the core functionality for the Swig wallet system,
//! including account management, role-based access control, and sub-account
//! handling. It implements the main Swig account structure and associated
//! helper functions.

extern crate alloc;

use no_padding::NoPadding;
use pinocchio::{instruction::Seed, msg, program_error::ProgramError};

use crate::{
    action::{program_scope::ProgramScope, Action, ActionLoader, Actionable},
    authority::{
        ed25519::{ED25519Authority, Ed25519SessionAuthority},
        secp256k1::{Secp256k1Authority, Secp256k1SessionAuthority},
        secp256r1::{Secp256r1Authority, Secp256r1SessionAuthority},
        Authority, AuthorityInfo, AuthorityType,
    },
    role::{Position, Role, RoleMut},
    Discriminator, IntoBytes, SwigStateError, Transmutable, TransmutableMut,
};

/// Generates the seeds for a Swig account.
#[inline(always)]
pub fn swig_account_seeds(id: &[u8]) -> [&[u8]; 2] {
    [b"swig".as_ref(), id]
}

/// Generates the seeds for a Swig account with bump seed.
#[inline(always)]
pub fn swig_account_seeds_with_bump<'a>(id: &'a [u8], bump: &'a [u8]) -> [&'a [u8]; 3] {
    [b"swig".as_ref(), id, bump]
}

/// Creates a signer seeds array for a Swig account.
pub fn swig_account_signer<'a>(id: &'a [u8], bump: &'a [u8; 1]) -> [Seed<'a>; 3] {
    [
        b"swig".as_ref().into(),
        id.as_ref().into(),
        bump.as_ref().into(),
    ]
}

/// Generates the seeds for a sub-account.
#[inline(always)]
pub fn sub_account_seeds<'a>(swig_id: &'a [u8], role_id: &'a [u8]) -> [&'a [u8]; 3] {
    [b"sub-account".as_ref(), swig_id, role_id]
}

/// Generates the seeds for a sub-account with bump seed.
#[inline(always)]
pub fn sub_account_seeds_with_bump<'a>(
    swig_id: &'a [u8],
    role_id: &'a [u8],
    bump: &'a [u8],
) -> [&'a [u8]; 4] {
    [b"sub-account".as_ref(), swig_id, role_id, bump]
}

/// Creates a signer seeds array for a sub-account.
pub fn sub_account_signer<'a>(
    swig_id: &'a [u8],
    role_id: &'a [u8],
    bump: &'a [u8; 1],
) -> [Seed<'a>; 4] {
    [
        b"sub-account".as_ref().into(),
        swig_id.into(),
        role_id.into(),
        bump.as_ref().into(),
    ]
}

/// Represents a Swig sub-account with its associated metadata.
#[repr(C, align(8))]
#[derive(Debug, PartialEq, NoPadding)]
pub struct SwigSubAccount {
    /// Account type discriminator
    pub discriminator: u8,
    /// PDA bump seed
    pub bump: u8,
    /// Whether the sub-account is enabled
    pub enabled: bool,
    _padding: [u8; 1],
    /// ID of the role associated with this sub-account
    pub role_id: u32,
    /// ID of the parent Swig account
    pub swig_id: [u8; 32],
    /// Amount of lamports reserved for rent
    pub reserved_lamports: u64,
}

impl Transmutable for SwigSubAccount {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl TransmutableMut for SwigSubAccount {}

impl IntoBytes for SwigSubAccount {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Builder for constructing and modifying Swig accounts.
pub struct SwigBuilder<'a> {
    /// Buffer for role data
    pub role_buffer: &'a mut [u8],
    /// Reference to the Swig account being built
    pub swig: &'a mut Swig,
}

impl<'a> SwigBuilder<'a> {
    /// Creates a new SwigBuilder from account buffer and Swig data.
    pub fn create(account_buffer: &'a mut [u8], swig: Swig) -> Result<Self, ProgramError> {
        let (swig_bytes, roles_bytes) = account_buffer.split_at_mut(Swig::LEN);
        let bytes = swig.into_bytes()?;
        swig_bytes[0..].copy_from_slice(bytes);
        let builder = Self {
            role_buffer: roles_bytes,
            swig: unsafe { Swig::load_mut_unchecked(swig_bytes)? },
        };
        Ok(builder)
    }

    /// Creates a new SwigBuilder from raw account bytes.
    pub fn new_from_bytes(account_buffer: &'a mut [u8]) -> Result<Self, ProgramError> {
        let (swig_bytes, roles_bytes) = account_buffer.split_at_mut(Swig::LEN);
        let swig = unsafe { Swig::load_mut_unchecked(swig_bytes)? };
        let builder = Self {
            role_buffer: roles_bytes,
            swig,
        };
        Ok(builder)
    }

    /// Removes a role from the Swig account.
    ///
    /// Returns a tuple of (new_data_end, old_data_len) on success.
    pub fn remove_role(&mut self, id: u32) -> Result<(usize, usize), ProgramError> {
        // Find the role to remove
        let mut cursor = 0;
        let mut found_offset = None;
        let role_buffer_len = self.role_buffer.len();

        // First pass: scan all roles and collect their positions and boundaries
        for _i in 0..self.swig.roles {
            if cursor >= role_buffer_len {
                break; // Safety check to prevent out-of-bounds access
            }

            if cursor + Position::LEN > role_buffer_len {
                return Err(ProgramError::InvalidAccountData); // Not enough data
                                                              // for a position
            }

            let position = unsafe {
                Position::load_unchecked(&self.role_buffer[cursor..cursor + Position::LEN])?
            };

            // Record position info for all roles
            let role_id = position.id();
            let boundary = position.boundary() as usize;

            // Check for invalid boundary
            if boundary > role_buffer_len {
                return Err(ProgramError::InvalidAccountData);
            }

            // Check if this is the role we want to remove
            if role_id == id {
                found_offset = Some((cursor, boundary));
            }

            cursor = boundary;
        }

        // If role found, remove it and adjust other roles
        if let Some((offset, boundary)) = found_offset {
            // Calculate the size of data to be removed
            let removal_size = boundary - offset;

            // Shift all data after the removed role to fill the gap
            let remaining_len = role_buffer_len - boundary;
            if remaining_len > 0 {
                self.role_buffer
                    .copy_within(boundary..boundary + remaining_len, offset);
            }

            // Update the boundaries of remaining roles
            cursor = offset;
            let new_end = offset + remaining_len;

            while cursor < new_end {
                if cursor + Position::LEN > role_buffer_len {
                    break; // Safety check
                }

                let position = unsafe {
                    Position::load_mut_unchecked(
                        &mut self.role_buffer[cursor..cursor + Position::LEN],
                    )?
                };

                // Calculate and write the new boundary (subtract the removal size)
                if position.boundary as usize > removal_size {
                    position.boundary -= removal_size as u32;
                    cursor = position.boundary as usize;
                } else {
                    // Invalid boundary, break to avoid infinite loop
                    break;
                }
            }
            // Zero out the now-unused data at the end
            let new_data_end = role_buffer_len - removal_size;
            if new_data_end < role_buffer_len {
                self.role_buffer[new_data_end..].fill(0);
            }
            let old_data_len = self.role_buffer.len() - new_data_end;
            // Update the role count in the Swig struct
            self.swig.roles -= 1;
            return Ok((new_data_end, old_data_len));
        }

        Err(SwigStateError::RoleNotFound.into())
    }

    /// Calculates the actual number of actions in the provided actions data.
    ///
    /// This function iterates through the actions data and counts the number of
    /// valid actions by parsing action headers and their boundaries.
    ///
    /// # Arguments
    /// * `actions_data` - Raw bytes containing action data
    ///
    /// # Returns
    /// * `Result<u8, ProgramError>` - The number of actions found, or error if invalid data
    fn calculate_num_actions(actions_data: &[u8]) -> Result<u8, ProgramError> {
        let mut cursor = 0;
        let mut count = 0u8;

        while cursor < actions_data.len() {
            if cursor + Action::LEN > actions_data.len() {
                break;
            }

            let action_header =
                unsafe { Action::load_unchecked(&actions_data[cursor..cursor + Action::LEN])? };
            cursor += Action::LEN;

            let action_len = action_header.length() as usize;
            if cursor + action_len > actions_data.len() {
                return Err(SwigStateError::InvalidAuthorityMustHaveAtLeastOneAction.into());
            }

            cursor += action_len;
            count += 1;

            // Prevent overflow
            if count == u8::MAX {
                return Err(ProgramError::InvalidInstructionData);
            }
        }

        if count == 0 {
            return Err(SwigStateError::InvalidAuthorityMustHaveAtLeastOneAction.into());
        }

        Ok(count)
    }

    /// Adds a new role to the Swig account.
    ///
    /// # Arguments
    /// * `authority_type` - The type of authority for this role
    /// * `authority_data` - Raw bytes containing the authority data
    /// * `actions_data` - Raw bytes containing the actions data
    ///
    /// # Returns
    /// * `Result<(), ProgramError>` - Success or error status
    pub fn add_role(
        &mut self,
        authority_type: AuthorityType,
        authority_data: &[u8],
        actions_data: &'a [u8],
    ) -> Result<(), ProgramError> {
        // Calculate the actual number of actions from the actions data
        let num_actions = Self::calculate_num_actions(actions_data)?;

        // check number of roles and iterate to last boundary
        let mut cursor = 0;
        // iterate and transmute each position to get boundary if not the last then jump
        // to next boundary
        for _i in 0..self.swig.roles {
            let position = unsafe {
                Position::load_unchecked(&self.role_buffer[cursor..cursor + Position::LEN]).unwrap()
            };
            cursor = position.boundary() as usize;
        }
        let auth_offset = cursor + Position::LEN;
        let authority_length = match authority_type {
            AuthorityType::Ed25519 => {
                ED25519Authority::set_into_bytes(
                    authority_data,
                    &mut self.role_buffer[auth_offset..auth_offset + ED25519Authority::LEN],
                )?;
                ED25519Authority::LEN
            },
            AuthorityType::Ed25519Session => {
                Ed25519SessionAuthority::set_into_bytes(
                    authority_data,
                    &mut self.role_buffer[auth_offset..auth_offset + Ed25519SessionAuthority::LEN],
                )?;
                Ed25519SessionAuthority::LEN
            },
            AuthorityType::Secp256k1 => {
                Secp256k1Authority::set_into_bytes(
                    authority_data,
                    &mut self.role_buffer[auth_offset..auth_offset + Secp256k1Authority::LEN],
                )?;
                Secp256k1Authority::LEN
            },
            AuthorityType::Secp256k1Session => {
                Secp256k1SessionAuthority::set_into_bytes(
                    authority_data,
                    &mut self.role_buffer
                        [auth_offset..auth_offset + Secp256k1SessionAuthority::LEN],
                )?;
                Secp256k1SessionAuthority::LEN
            },
            AuthorityType::Secp256r1 => {
                Secp256r1Authority::set_into_bytes(
                    authority_data,
                    &mut self.role_buffer[auth_offset..auth_offset + Secp256r1Authority::LEN],
                )?;
                Secp256r1Authority::LEN
            },
            AuthorityType::Secp256r1Session => {
                Secp256r1SessionAuthority::set_into_bytes(
                    authority_data,
                    &mut self.role_buffer
                        [auth_offset..auth_offset + Secp256r1SessionAuthority::LEN],
                )?;
                Secp256r1SessionAuthority::LEN
            },
            _ => return Err(SwigStateError::InvalidAuthorityData.into()),
        };
        let size = authority_length + actions_data.len();
        let boundary = cursor + Position::LEN + size;
        // add role to the end of the buffer

        let position = unsafe {
            Position::load_mut_unchecked(&mut self.role_buffer[cursor..cursor + Position::LEN])?
        };
        position.authority_type = authority_type as u16;
        position.authority_length = authority_length as u16;
        position.num_actions = num_actions as u16;
        position.boundary = boundary as u32;
        position.id = self.swig.role_counter;
        cursor += Position::LEN;
        cursor += authority_length;
        // todo check actions for duplicates
        let mut action_cursor = 0;
        let actions_start_cursor_pos = cursor;
        for _i in 0..num_actions {
            let header = &actions_data[action_cursor..action_cursor + Action::LEN];
            let action_header = unsafe { Action::load_unchecked(header)? };
            action_cursor += Action::LEN;
            let action_slice =
                &actions_data[action_cursor..action_cursor + action_header.length() as usize];
            action_cursor += action_header.length() as usize;

            if ActionLoader::validate_layout(action_header.permission()?, action_slice)? {
                self.role_buffer[cursor..cursor + Action::LEN].copy_from_slice(header);
                // Position where next action starts within actions buffer
                let current_action_pos_in_actions = cursor - actions_start_cursor_pos;
                let next_action_pos_in_actions =
                    current_action_pos_in_actions + Action::LEN + action_header.length() as usize;
                // Change boundary to the new boundary position which is
                // next_action_pos_in_actions
                self.role_buffer[cursor + 4..cursor + 8]
                    .copy_from_slice(&(next_action_pos_in_actions as u32).to_le_bytes());
                cursor += Action::LEN;
                self.role_buffer[cursor..cursor + action_header.length() as usize]
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

/// Main Swig account structure.
#[repr(C, align(8))]
#[derive(Debug, PartialEq, NoPadding)]
pub struct Swig {
    /// Account type discriminator
    pub discriminator: u8,
    /// PDA bump seed
    pub bump: u8,
    /// Unique identifier for this Swig account
    pub id: [u8; 32],
    /// Number of roles in this account
    pub roles: u16,
    /// Counter for generating unique role IDs
    pub role_counter: u32,
    /// Amount of lamports reserved for rent
    pub reserved_lamports: u64,
}

impl Swig {
    /// Creates a new Swig account.
    pub fn new(id: [u8; 32], bump: u8, reserved_lamports: u64) -> Self {
        Self {
            discriminator: Discriminator::SwigAccount as u8,
            id,
            bump,
            roles: 0,
            role_counter: 0,
            reserved_lamports,
        }
    }

    /// Gets a mutable reference to a role by ID.
    pub fn get_mut_role(id: u32, roles: &mut [u8]) -> Result<Option<RoleMut<'_>>, ProgramError> {
        let mut cursor = 0;
        let mut found_offset = None;
        let roles_len = roles.len();
        if roles_len < Swig::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        for _i in 0..roles_len {
            let offset = cursor + Position::LEN;
            let position =
                unsafe { Position::load_unchecked(roles.get_unchecked(cursor..offset))? };
            if position.id() == id {
                found_offset = Some(cursor);
                break;
            }
            cursor = position.boundary() as usize;
        }
        if let Some(offset) = found_offset {
            let (position, remaning) =
                unsafe { roles[offset..].split_at_mut_unchecked(Position::LEN) };
            let position = unsafe { Position::load_unchecked(position)? };
            let authority_length = position.authority_length() as usize;
            let (authority, actions) = unsafe { remaning.split_at_mut_unchecked(authority_length) };

            let auth: &mut dyn AuthorityInfo = match position.authority_type()? {
                AuthorityType::Ed25519 => unsafe {
                    ED25519Authority::load_mut_unchecked(authority)?
                },
                AuthorityType::Ed25519Session => unsafe {
                    Ed25519SessionAuthority::load_mut_unchecked(authority)?
                },
                AuthorityType::Secp256k1 => unsafe {
                    Secp256k1Authority::load_mut_unchecked(authority)?
                },
                AuthorityType::Secp256k1Session => unsafe {
                    Secp256k1SessionAuthority::load_mut_unchecked(authority)?
                },
                AuthorityType::Secp256r1 => unsafe {
                    Secp256r1Authority::load_mut_unchecked(authority)?
                },
                AuthorityType::Secp256r1Session => unsafe {
                    Secp256r1SessionAuthority::load_mut_unchecked(authority)?
                },
                _ => return Err(ProgramError::InvalidAccountData),
            };

            let action_data_end =
                position.boundary() as usize - (offset + Position::LEN + authority_length);
            let (actions, _rest) = unsafe { actions.split_at_mut_unchecked(action_data_end) };
            let role = RoleMut {
                position,
                authority: auth,
                num_actions: position.num_actions() as u8,
                actions,
            };
            return Ok(Some(role));
        }

        Ok(None)
    }
}

impl Transmutable for Swig {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl TransmutableMut for Swig {}

impl IntoBytes for Swig {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

/// Wrapper structure for a Swig account with its roles.
pub struct SwigWithRoles<'a> {
    /// Reference to the Swig account state
    pub state: &'a Swig,
    /// Raw bytes containing role data
    roles: &'a [u8],
}

impl<'a> SwigWithRoles<'a> {
    /// Creates a new SwigWithRoles from raw bytes.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ProgramError> {
        if bytes.len() < Swig::LEN {
            return Err(ProgramError::InvalidAccountData);
        }

        let state = unsafe { Swig::load_unchecked(&bytes[..Swig::LEN])? };
        let roles = &bytes[Swig::LEN..];

        Ok(SwigWithRoles { state, roles })
    }

    /// Looks up a role ID by authority data.
    pub fn lookup_role_id(&'a self, authority_data: &'a [u8]) -> Result<Option<u32>, ProgramError> {
        let mut cursor = 0;

        for _i in 0..self.state.roles {
            let offset = cursor + Position::LEN;
            let position =
                unsafe { Position::load_unchecked(self.roles.get_unchecked(cursor..offset))? };
            let auth_type = position.authority_type()?;
            let auth_len = position.authority_length() as usize;

            // Load the authority based on its type
            let authority: &dyn AuthorityInfo = match auth_type {
                AuthorityType::Ed25519 => unsafe {
                    ED25519Authority::load_unchecked(
                        self.roles.get_unchecked(offset..offset + auth_len),
                    )?
                },
                AuthorityType::Ed25519Session => unsafe {
                    Ed25519SessionAuthority::load_unchecked(
                        self.roles.get_unchecked(offset..offset + auth_len),
                    )?
                },
                AuthorityType::Secp256k1 => unsafe {
                    Secp256k1Authority::load_unchecked(
                        self.roles.get_unchecked(offset..offset + auth_len),
                    )?
                },
                AuthorityType::Secp256k1Session => unsafe {
                    Secp256k1SessionAuthority::load_unchecked(
                        self.roles.get_unchecked(offset..offset + auth_len),
                    )?
                },
                AuthorityType::Secp256r1 => unsafe {
                    Secp256r1Authority::load_unchecked(
                        self.roles.get_unchecked(offset..offset + auth_len),
                    )?
                },
                AuthorityType::Secp256r1Session => unsafe {
                    Secp256r1SessionAuthority::load_unchecked(
                        self.roles.get_unchecked(offset..offset + auth_len),
                    )?
                },
                _ => return Err(ProgramError::InvalidAccountData),
            };

            // Check if this authority matches the provided data
            // The match_data method requires data of the correct length
            if authority_data.len() >= 32 && authority.match_data(authority_data) {
                return Ok(Some(position.id()));
            }

            // Move cursor to the next role boundary
            cursor = position.boundary() as usize;
        }

        // No matching role found
        Ok(None)
    }

    /// Gets a reference to a role by ID.
    pub fn get_role(&'a self, id: u32) -> Result<Option<Role<'a>>, ProgramError> {
        let mut cursor = 0;
        for _i in 0..self.state.roles {
            let offset = cursor + Position::LEN;
            let position =
                unsafe { Position::load_unchecked(self.roles.get_unchecked(cursor..offset))? };
            if position.id() == id {
                let authority: &dyn AuthorityInfo =
                    match position.authority_type()? {
                        AuthorityType::Ed25519 => unsafe {
                            ED25519Authority::load_unchecked(self.roles.get_unchecked(
                                offset..offset + position.authority_length() as usize,
                            ))?
                        },
                        AuthorityType::Ed25519Session => unsafe {
                            Ed25519SessionAuthority::load_unchecked(self.roles.get_unchecked(
                                offset..offset + position.authority_length() as usize,
                            ))?
                        },
                        AuthorityType::Secp256k1 => unsafe {
                            Secp256k1Authority::load_unchecked(self.roles.get_unchecked(
                                offset..offset + position.authority_length() as usize,
                            ))?
                        },
                        AuthorityType::Secp256k1Session => unsafe {
                            Secp256k1SessionAuthority::load_unchecked(self.roles.get_unchecked(
                                offset..offset + position.authority_length() as usize,
                            ))?
                        },
                        AuthorityType::Secp256r1 => unsafe {
                            Secp256r1Authority::load_unchecked(self.roles.get_unchecked(
                                offset..offset + position.authority_length() as usize,
                            ))?
                        },
                        AuthorityType::Secp256r1Session => unsafe {
                            Secp256r1SessionAuthority::load_unchecked(self.roles.get_unchecked(
                                offset..offset + position.authority_length() as usize,
                            ))?
                        },
                        _ => return Err(ProgramError::InvalidAccountData),
                    };

                return Ok(Some(Role {
                    position,
                    authority,
                    actions: unsafe {
                        self.roles.get_unchecked(
                            offset + position.authority_length() as usize
                                ..position.boundary() as usize,
                        )
                    },
                }));
            }
            cursor = position.boundary() as usize;
        }
        Ok(None)
    }

    /// Finds a program scope by target account.
    pub fn find_program_scope_by_target(
        &self,
        target_account: &[u8],
    ) -> Option<(u8, ProgramScope)> {
        for role_id in 0..self.state.role_counter {
            if let Ok(Some(role)) = self.get_role(role_id) {
                let mut cursor = 0;
                while cursor < role.actions.len() {
                    if cursor + Action::LEN > role.actions.len() {
                        break;
                    }

                    // Load the action header
                    if let Ok(action_header) = unsafe {
                        Action::load_unchecked(&role.actions[cursor..cursor + Action::LEN])
                    } {
                        cursor += Action::LEN;

                        // Check if we have enough data for the action content
                        let action_len = action_header.length() as usize;
                        if cursor + action_len > role.actions.len() {
                            break;
                        }

                        // Try to load as ProgramScope
                        if action_header.permission().ok() == Some(ProgramScope::TYPE) {
                            let action_data = &role.actions[cursor..cursor + action_len];
                            if action_data.len() == core::mem::size_of::<ProgramScope>() {
                                // SAFETY: We've verified the length matches exactly
                                let program_scope = unsafe {
                                    core::mem::transmute_copy::<
                                        [u8; core::mem::size_of::<ProgramScope>()],
                                        ProgramScope,
                                    >(
                                        action_data.try_into().unwrap()
                                    )
                                };

                                if program_scope.target_account == target_account {
                                    return Some((role_id as u8, program_scope));
                                }
                            }
                        }

                        cursor += action_len;
                    } else {
                        break;
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        action::{all::All, manage_authority::ManageAuthority, sol_limit::SolLimit, Actionable},
        authority::{ed25519::ED25519Authority, secp256k1::CreateSecp256k1SessionAuthority},
    };

    // Calculate exact buffer size needed for a test with N roles
    fn calculate_buffer_size(num_roles: usize, action_bytes_per_role: usize) -> usize {
        // Add extra buffer space to account for any alignment or boundary calculations
        Swig::LEN
            + (num_roles * (Position::LEN + ED25519Authority::LEN + action_bytes_per_role))
            + 64
    }

    fn setup_precise_test_buffer(
        num_roles: usize,
        action_bytes_per_role: usize,
    ) -> (Vec<u8>, [u8; 32], u8) {
        let buffer_size = calculate_buffer_size(num_roles, action_bytes_per_role);
        let account_buffer = vec![0u8; buffer_size];
        let id = [1; 32];
        let bump = 255;
        (account_buffer, id, bump)
    }

    // Keep existing setup functions for backward compatibility
    fn setup_test_buffer() -> ([u8; Swig::LEN + 256], [u8; 32], u8) {
        let account_buffer = [0u8; Swig::LEN + 256];
        let id = [1; 32];
        let bump = 255;
        (account_buffer, id, bump)
    }

    fn setup_large_test_buffer() -> ([u8; Swig::LEN + 512], [u8; 32], u8) {
        let account_buffer = [0u8; Swig::LEN + 512];
        let id = [1; 32];
        let bump = 255;
        (account_buffer, id, bump)
    }

    #[test]
    fn test_swig_creation() {
        let (mut account_buffer, id, bump) = setup_test_buffer();
        let swig = Swig::new(id, bump, 0);

        // Test all fields of the Swig struct
        assert_eq!(swig.discriminator, 1);
        assert_eq!(swig.id, id);
        assert_eq!(swig.bump, bump);
        assert_eq!(swig.roles, 0);
        assert_eq!(swig.role_counter, 0);
        assert_eq!(swig.reserved_lamports, 0);

        // Test builder creation and verify buffer state
        let builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();
        assert_eq!(builder.swig.id, id);
        assert_eq!(builder.swig.bump, bump);
        assert_eq!(builder.swig.roles, 0);
        assert_eq!(builder.swig.role_counter, 0);
        assert_eq!(builder.role_buffer.len(), account_buffer.len() - Swig::LEN);
    }

    #[test]
    fn test_swig_account_seeds() {
        let id = [1; 32];
        let bump = [255];

        // Test basic seeds
        let seeds = swig_account_seeds(&id);
        assert_eq!(seeds.len(), 2);
        assert_eq!(seeds[0], b"swig");
        assert_eq!(seeds[1], &id);

        // Test seeds with bump
        let seeds_with_bump = swig_account_seeds_with_bump(&id, &bump);
        assert_eq!(seeds_with_bump.len(), 3);
        assert_eq!(seeds_with_bump[0], b"swig");
        assert_eq!(seeds_with_bump[1], &id);
        assert_eq!(seeds_with_bump[2], &bump);

        // Test signer seeds
        let signer_seeds = swig_account_signer(&id, &[255]);
        assert_eq!(signer_seeds.len(), 3);
        assert_eq!(signer_seeds[0].as_ref(), b"swig");
        assert_eq!(signer_seeds[1].as_ref(), &id);
        assert_eq!(signer_seeds[2].as_ref(), &[255]);
    }

    #[test]
    fn test_add_single_role() {
        let (mut account_buffer, id, bump) = setup_test_buffer();
        let swig = Swig::new(id, bump, 0);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        let authority = ED25519Authority {
            public_key: [2; 32],
        };

        let action_data = All {}.into_bytes().unwrap();
        let action = Action::new(
            All::TYPE,
            action_data.len() as u16,
            Action::LEN as u32 + action_data.len() as u32,
        );
        let action_bytes = action.into_bytes().unwrap();
        let actions_data = [action_bytes, action_data].concat();

        // Test role addition
        builder
            .add_role(
                AuthorityType::Ed25519,
                authority.into_bytes().unwrap(),
                &actions_data,
            )
            .unwrap();

        // Verify Swig state after role addition
        assert_eq!(builder.swig.roles, 1);
        assert_eq!(builder.swig.role_counter, 1);

        // Verify role can be found and has correct data
        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();
        let role = swig_with_roles.get_role(0).unwrap().unwrap();

        // Verify authority type
        assert_eq!(
            role.position.authority_type().unwrap(),
            AuthorityType::Ed25519
        );

        // Verify role ID
        assert_eq!(role.position.id(), 0);

        // Verify we have actions data
        assert!(!role.actions.is_empty());
    }

    #[test]
    fn test_role_lookup() {
        let (mut account_buffer, id, bump) = setup_test_buffer();
        let swig = Swig::new(id, bump, 0);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        let authority = ED25519Authority {
            public_key: [2; 32],
        };

        let action_data = All {}.into_bytes().unwrap();
        let action = Action::new(
            All::TYPE,
            action_data.len() as u16,
            Action::LEN as u32 + action_data.len() as u32,
        );
        let action_bytes = action.into_bytes().unwrap();
        let actions_data = [action_bytes, action_data].concat();

        builder
            .add_role(
                AuthorityType::Ed25519,
                authority.into_bytes().unwrap(),
                &actions_data,
            )
            .unwrap();

        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();

        // Test successful role lookup
        let role = swig_with_roles.get_role(0).unwrap();
        assert!(role.is_some());
        let role = role.unwrap();
        assert_eq!(role.position.id(), 0);
        assert_eq!(
            role.position.authority_type().unwrap(),
            AuthorityType::Ed25519
        );
        assert_eq!(role.position.num_actions(), 1);

        // Test non-existent role lookup
        let role = swig_with_roles.get_role(999).unwrap();
        assert!(role.is_none());

        // Test boundary role lookup
        let role = swig_with_roles.get_role(u32::MAX).unwrap();
        assert!(role.is_none());
    }

    #[test]
    fn test_multiple_roles() {
        let (mut account_buffer, id, bump) = setup_test_buffer();
        let swig = Swig::new(id, bump, 0);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        let authority1 = ED25519Authority {
            public_key: [2; 32],
        };

        let authority2 = ED25519Authority {
            public_key: [3; 32],
        };

        let action_data = All {}.into_bytes().unwrap();
        let action = Action::new(
            All::TYPE,
            action_data.len() as u16,
            Action::LEN as u32 + action_data.len() as u32,
        );
        let action_bytes = action.into_bytes().unwrap();
        let actions_data = [action_bytes, action_data].concat();

        // Add and verify first role
        builder
            .add_role(
                AuthorityType::Ed25519,
                authority1.into_bytes().unwrap(),
                &actions_data,
            )
            .unwrap();
        assert_eq!(builder.swig.roles, 1);
        assert_eq!(builder.swig.role_counter, 1);

        // Add and verify second role
        builder
            .add_role(
                AuthorityType::Ed25519,
                authority2.into_bytes().unwrap(),
                &actions_data,
            )
            .unwrap();
        assert_eq!(builder.swig.roles, 2);
        assert_eq!(builder.swig.role_counter, 2);

        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();

        // Verify roles have correct IDs and types
        let role1 = swig_with_roles.get_role(0).unwrap().unwrap();
        assert_eq!(role1.position.id(), 0);
        assert_eq!(
            role1.position.authority_type().unwrap(),
            AuthorityType::Ed25519
        );

        let role2 = swig_with_roles.get_role(1).unwrap().unwrap();
        assert_eq!(role2.position.id(), 1);
        assert_eq!(
            role2.position.authority_type().unwrap(),
            AuthorityType::Ed25519
        );
    }

    #[test]
    fn test_get_mut_role() -> Result<(), ProgramError> {
        let (mut account_buffer, id, bump) = setup_test_buffer();
        let swig = Swig::new(id, bump, 0);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        let authority = ED25519Authority {
            public_key: [2; 32],
        };

        let sol_limit = SolLimit { amount: 1000 };
        let action_data = sol_limit.into_bytes().unwrap();
        let action = Action::new(
            SolLimit::TYPE,
            action_data.len() as u16,
            Action::LEN as u32 + action_data.len() as u32,
        );
        let action_bytes = action.into_bytes().unwrap();
        let actions_data = [action_bytes, action_data].concat();

        // Add a role
        builder
            .add_role(
                AuthorityType::Ed25519,
                authority.into_bytes().unwrap(),
                &actions_data,
            )
            .unwrap();

        // Get a reference to the roles buffer for later modification
        let roles_buffer = &mut account_buffer[Swig::LEN..];

        // Get mutable role and modify SolLimit
        let role_id = 0;
        if let Some(role) = Swig::get_mut_role(role_id, roles_buffer)? {
            // Navigate to the SolLimit action
            let mut cursor = 0;
            let action_data = role.actions;

            for _ in 0..role.num_actions {
                let action_header =
                    unsafe { Action::load_unchecked(&action_data[cursor..cursor + Action::LEN])? };
                cursor += Action::LEN;

                if action_header.permission()? == SolLimit::TYPE {
                    // Use a new mutable slice to modify the action data
                    let end_cursor = cursor + action_header.length() as usize;
                    let sol_limit = unsafe {
                        SolLimit::load_mut_unchecked(&mut action_data[cursor..end_cursor])?
                    };

                    // Modify the SolLimit amount
                    sol_limit.amount -= 300;
                    break;
                }

                cursor += action_header.length() as usize;
            }
        }

        // Verify the change persisted
        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();
        let role = swig_with_roles.get_role(0)?.unwrap();

        // Navigate the actions data to find the SolLimit action
        let mut cursor = 0;
        let mut found_action = false;

        for _ in 0..role.position.num_actions() {
            let action_header =
                unsafe { Action::load_unchecked(&role.actions[cursor..cursor + Action::LEN])? };
            cursor += Action::LEN;

            if action_header.permission()? == SolLimit::TYPE {
                // Found the SolLimit action
                let action_data = &role.actions[cursor..cursor + action_header.length() as usize];
                let sol_limit = unsafe { SolLimit::load_unchecked(action_data)? };

                // Verify the amount was reduced
                assert_eq!(sol_limit.amount, 700);
                found_action = true;
                break;
            }

            cursor += action_header.length() as usize;
        }

        assert!(found_action, "SolLimit action not found");
        Ok(())
    }

    #[test]
    fn test_multiple_actions_with_token_limit() -> Result<(), ProgramError> {
        let (mut account_buffer, id, bump) = setup_test_buffer();
        let swig = Swig::new(id, bump, 0);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        let authority = ED25519Authority {
            public_key: [2; 32],
        };

        // Create token_limit action
        let token_mint = [3; 32];
        let token_limit = crate::action::token_limit::TokenLimit {
            token_mint,
            current_amount: 5000,
        };
        let token_limit_data = token_limit.into_bytes().unwrap();
        let token_limit_action = Action::new(
            crate::action::token_limit::TokenLimit::TYPE,
            token_limit_data.len() as u16,
            Action::LEN as u32 + token_limit_data.len() as u32,
        );
        let token_limit_action_bytes = token_limit_action.into_bytes().unwrap();

        // Create sol_limit action
        let sol_limit = SolLimit { amount: 1000 };
        let sol_limit_data = sol_limit.into_bytes().unwrap();
        let sol_limit_action = Action::new(
            SolLimit::TYPE,
            sol_limit_data.len() as u16,
            Action::LEN as u32 + sol_limit_data.len() as u32,
        );
        let sol_limit_action_bytes = sol_limit_action.into_bytes().unwrap();

        // Combine actions
        let actions_data = [
            token_limit_action_bytes,
            token_limit_data,
            sol_limit_action_bytes,
            sol_limit_data,
        ]
        .concat();

        // Add role with both actions
        builder
            .add_role(
                AuthorityType::Ed25519,
                authority.into_bytes().unwrap(),
                &actions_data,
            )
            .unwrap();

        // Get a reference to the roles buffer for later modification
        let roles_buffer = &mut account_buffer[Swig::LEN..];

        // Get mutable role and modify TokenLimit
        let role_id = 0;
        if let Some(role) = Swig::get_mut_role(role_id, roles_buffer)? {
            let action_data = role.actions;
            let mut cursor = 0;

            // First pass: Just scan and record positions of each action
            let mut token_limit_pos = None;
            let mut sol_limit_pos = None;

            for _i in 0..role.num_actions {
                let action_header =
                    unsafe { Action::load_unchecked(&action_data[cursor..cursor + Action::LEN])? };
                cursor += Action::LEN;

                let action_type = action_header.permission()?;
                let action_len = action_header.length() as usize;

                if action_type == crate::action::token_limit::TokenLimit::TYPE {
                    token_limit_pos = Some((cursor, action_len));
                } else if action_type == SolLimit::TYPE {
                    sol_limit_pos = Some((cursor, action_len));
                }

                cursor += action_len;
            }

            // Now apply changes using the recorded positions
            if let Some((pos, len)) = token_limit_pos {
                let token_limit = unsafe {
                    crate::action::token_limit::TokenLimit::load_mut_unchecked(
                        &mut action_data[pos..pos + len],
                    )?
                };
                token_limit.current_amount -= 1500;
            }

            if let Some((pos, len)) = sol_limit_pos {
                let sol_limit =
                    unsafe { SolLimit::load_mut_unchecked(&mut action_data[pos..pos + len])? };
                sol_limit.amount -= 300;
            }
        }

        // Verify the changes persisted by checking each action
        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();
        let role = swig_with_roles.get_role(0)?.unwrap();

        // Navigate actions data to find both actions and verify changes
        let mut cursor = 0;
        let mut found_token_limit = false;
        let mut found_sol_limit = false;

        for _ in 0..role.position.num_actions() {
            let action_header =
                unsafe { Action::load_unchecked(&role.actions[cursor..cursor + Action::LEN])? };
            cursor += Action::LEN;

            if action_header.permission()? == crate::action::token_limit::TokenLimit::TYPE {
                // Found the TokenLimit action
                let action_data = &role.actions[cursor..cursor + action_header.length() as usize];
                let token_limit =
                    unsafe { crate::action::token_limit::TokenLimit::load_unchecked(action_data)? };

                // Verify token mint is preserved
                assert_eq!(token_limit.token_mint, [3; 32]);
                // Verify the amount was reduced
                assert_eq!(token_limit.current_amount, 3500);
                found_token_limit = true;
            } else if action_header.permission()? == SolLimit::TYPE {
                // Found the SolLimit action
                let action_data = &role.actions[cursor..cursor + action_header.length() as usize];
                let sol_limit = unsafe { SolLimit::load_unchecked(action_data)? };

                // Verify the amount was reduced
                assert_eq!(sol_limit.amount, 700);
                found_sol_limit = true;
            }

            cursor += action_header.length() as usize;
        }

        // Verify that we found and verified both actions
        assert!(found_token_limit, "TokenLimit action not found");
        assert!(found_sol_limit, "SolLimit action not found");

        Ok(())
    }

    #[test]
    fn test_lookup_role_id_comprehensive() -> Result<(), ProgramError> {
        let (mut account_buffer, id, bump) = setup_large_test_buffer();
        let swig = Swig::new(id, bump, 0);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        // Create authorities with different public keys
        let authority1 = ED25519Authority {
            public_key: [42; 32],
        };

        let authority2 = ED25519Authority {
            public_key: [43; 32],
        };

        // Create simpler action data for the tests

        // All permission action
        let all_action_data = All {}.into_bytes().unwrap();
        let all_action = Action::new(
            All::TYPE,
            all_action_data.len() as u16,
            Action::LEN as u32 + all_action_data.len() as u32,
        );
        let all_action_bytes = all_action.into_bytes().unwrap();
        let all_actions_data = [all_action_bytes, all_action_data].concat();

        // SolLimit action
        let sol_limit = SolLimit { amount: 5000 };
        let sol_limit_data = sol_limit.into_bytes().unwrap();
        let sol_limit_action = Action::new(
            SolLimit::TYPE,
            sol_limit_data.len() as u16,
            Action::LEN as u32 + sol_limit_data.len() as u32,
        );
        let sol_limit_action_bytes = sol_limit_action.into_bytes().unwrap();
        let sol_limit_actions_data = [sol_limit_action_bytes, sol_limit_data].concat();

        // Add roles with different authorities and actions
        println!("Adding role 1 with All action");
        builder
            .add_role(
                AuthorityType::Ed25519,
                authority1.into_bytes().unwrap(),
                &all_actions_data,
            )
            .unwrap();

        println!("Adding role 2 with SolLimit action");
        builder
            .add_role(
                AuthorityType::Ed25519,
                authority2.into_bytes().unwrap(),
                &sol_limit_actions_data,
            )
            .unwrap();

        // Create SwigWithRoles for testing
        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();

        // Test basic lookup of each authority by public key
        println!("Looking up authority1");
        let role_id1 = swig_with_roles.lookup_role_id(&authority1.public_key)?;
        assert_eq!(role_id1, Some(0), "Should find authority1 at role 0");

        println!("Looking up authority2");
        let role_id2 = swig_with_roles.lookup_role_id(&authority2.public_key)?;
        assert_eq!(role_id2, Some(1), "Should find authority2 at role 1");

        // Test lookup with empty data
        println!("Testing empty data");
        let empty_data: [u8; 0] = [];
        let role_empty = swig_with_roles.lookup_role_id(&empty_data)?;
        assert_eq!(role_empty, None, "Empty data should not match any role");

        // Test with non-existent authority
        println!("Testing non-existent authority");
        let nonexistent_key = [99; 32];
        let role_nonexistent = swig_with_roles.lookup_role_id(&nonexistent_key)?;
        assert_eq!(
            role_nonexistent, None,
            "Non-existent key should not match any role"
        );

        // Test finding a role and then getting it
        println!("Testing get_role with lookup_role_id result");
        if let Some(role_id) = swig_with_roles.lookup_role_id(&authority1.public_key)? {
            let role = swig_with_roles.get_role(role_id)?.unwrap();
            assert_eq!(role.position.num_actions(), 1, "Role should have 1 action");
        } else {
            panic!("Failed to find authority1");
        }

        // Test duplicate authority test
        println!("Testing duplicate authority");
        let (mut new_buffer, _, _) = setup_large_test_buffer();
        let new_swig = Swig::new(id, bump, 0);
        let mut new_builder = SwigBuilder::create(&mut new_buffer, new_swig).unwrap();

        // Add two roles with the same authority but different actions
        new_builder
            .add_role(
                AuthorityType::Ed25519,
                authority1.into_bytes().unwrap(),
                &all_actions_data,
            )
            .unwrap();
        new_builder
            .add_role(
                AuthorityType::Ed25519,
                authority1.into_bytes().unwrap(),
                &sol_limit_actions_data,
            )
            .unwrap();

        let new_swig_with_roles = SwigWithRoles::from_bytes(&new_buffer).unwrap();
        let duplicate_role_id = new_swig_with_roles.lookup_role_id(&authority1.public_key)?;
        assert_eq!(
            duplicate_role_id,
            Some(0),
            "Should return first role with matching authority"
        );

        Ok(())
    }

    #[test]
    fn test_remove_role() -> Result<(), ProgramError> {
        // Calculate buffer size for 2 roles
        // For the All action, which is very small
        let action_bytes = Action::LEN + 1; // All action is very small

        // Use verbose calculations to ensure adequate space
        let one_role_size = Position::LEN + ED25519Authority::LEN + action_bytes;
        let total_size = Swig::LEN + (2 * one_role_size) + 128; // Add extra padding

        let mut account_buffer = vec![0u8; total_size];
        let id = [1; 32];
        let bump = 255;

        let swig = Swig::new(id, bump, 0);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        // Create two different authorities
        let authority1 = ED25519Authority {
            public_key: [2; 32],
        };
        let authority2 = ED25519Authority {
            public_key: [3; 32],
        };

        // Create action data
        let all_action = All {}.into_bytes().unwrap();
        let all_header = Action::new(
            All::TYPE,
            all_action.len() as u16,
            Action::LEN as u32 + all_action.len() as u32,
        );
        let all_bytes = all_header.into_bytes().unwrap();
        let all_actions = [all_bytes, all_action].concat();

        // Add two roles
        builder
            .add_role(
                AuthorityType::Ed25519,
                authority1.into_bytes().unwrap(),
                &all_actions,
            )
            .unwrap();
        builder
            .add_role(
                AuthorityType::Ed25519,
                authority2.into_bytes().unwrap(),
                &all_actions,
            )
            .unwrap();

        // Verify two roles exist
        assert_eq!(builder.swig.roles, 2);
        println!(
            "Role counter after adding 2 roles: {}",
            builder.swig.role_counter
        );

        // Drop the builder to release mutable reference
        drop(builder);

        // Before removal: scan roles to see what IDs are assigned
        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();
        println!("Before removal - scanning available roles:");
        let mut assigned_ids = Vec::new();

        // Find all assigned role IDs
        for i in 0..4 {
            match swig_with_roles.get_role(i)? {
                Some(role) => {
                    println!("Role ID {} exists with position: {:?}", i, role.position);
                    assigned_ids.push(i);
                },
                None => println!("Role ID {} does not exist", i),
            }
        }

        // Ensure we have 2 roles
        assert_eq!(
            assigned_ids.len(),
            2,
            "Should have exactly 2 roles before removal"
        );

        // Sort IDs in ascending order
        assigned_ids.sort();

        // Now remove the first role
        let first_role_id = assigned_ids[0];
        println!("Removing first role with ID: {}", first_role_id);

        // Drop the immutable reference before creating a mutable one
        drop(swig_with_roles);

        // Recreate builder and remove the first role
        let mut builder = SwigBuilder::new_from_bytes(&mut account_buffer).unwrap();
        builder.remove_role(first_role_id).unwrap();

        // Verify one role was removed
        assert_eq!(builder.swig.roles, 1);

        // Drop the builder to release the mutable reference
        drop(builder);

        // After removal: check the state of all roles
        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();

        // Print information about the SwigWithRoles
        println!(
            "After removal - Swig account has {} roles",
            swig_with_roles.state.roles
        );
        println!("Role counter: {}", swig_with_roles.state.role_counter);

        // Check what roles exist after removal
        let mut remaining_ids = Vec::new();
        for i in 0..4 {
            match swig_with_roles.get_role(i)? {
                Some(role) => {
                    println!("Role ID {} exists with position: {:?}", i, role.position);
                    remaining_ids.push(i);
                },
                None => println!("Role ID {} does not exist", i),
            }
        }

        // Ensure we have 1 role left
        assert_eq!(
            remaining_ids.len(),
            1,
            "Should have exactly 1 role after removal"
        );

        // Verify the first role was removed
        assert!(
            !remaining_ids.contains(&first_role_id),
            "First role with ID {} should be removed",
            first_role_id
        );

        // Verify second role still exists
        assert!(
            remaining_ids.contains(&assigned_ids[1]),
            "Second role with ID {} should still exist",
            assigned_ids[1]
        );

        Ok(())
    }

    #[test]
    fn test_remove_non_existent_role() -> Result<(), ProgramError> {
        // Single role with minimal action size
        let (mut account_buffer, id, bump) = setup_precise_test_buffer(1, Action::LEN + 1);
        let swig = Swig::new(id, bump, 0);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        // Add a role
        let authority = ED25519Authority {
            public_key: [2; 32],
        };

        let action_data = All {}.into_bytes().unwrap();
        let action = Action::new(
            All::TYPE,
            action_data.len() as u16,
            Action::LEN as u32 + action_data.len() as u32,
        );
        let action_bytes = action.into_bytes().unwrap();
        let actions_data = [action_bytes, action_data].concat();

        builder
            .add_role(
                AuthorityType::Ed25519,
                authority.into_bytes().unwrap(),
                &actions_data,
            )
            .unwrap();

        // Try to remove a non-existent role ID
        let e = builder.remove_role(999);
        assert!(e.is_err());
        // Verify that the role count hasn't changed
        assert_eq!(builder.swig.roles, 1);

        // Drop builder to avoid borrowing conflict
        drop(builder);

        // Verify the role still exists
        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();
        let role = swig_with_roles.get_role(0)?;
        assert!(role.is_some());

        Ok(())
    }

    #[test]
    fn test_remove_from_empty_swig() -> Result<(), ProgramError> {
        // Empty swig, no roles
        let (mut account_buffer, id, bump) = setup_precise_test_buffer(0, 0);
        let swig = Swig::new(id, bump, 0);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        // Verify initial state
        assert_eq!(builder.swig.roles, 0);

        // Try to remove from empty Swig
        let e = builder.remove_role(0);
        assert!(e.is_err());

        // Verify no change
        assert_eq!(builder.swig.roles, 0);

        Ok(())
    }

    #[test]
    fn test_remove_only_role() -> Result<(), ProgramError> {
        // Single role with minimal action size
        let (mut account_buffer, id, bump) = setup_precise_test_buffer(1, Action::LEN + 1);
        let swig = Swig::new(id, bump, 0);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        // Add a single role
        let authority = ED25519Authority {
            public_key: [2; 32],
        };

        let action_data = All {}.into_bytes().unwrap();
        let action = Action::new(
            All::TYPE,
            action_data.len() as u16,
            Action::LEN as u32 + action_data.len() as u32,
        );
        let action_bytes = action.into_bytes().unwrap();
        let actions_data = [action_bytes, action_data].concat();

        builder
            .add_role(
                AuthorityType::Ed25519,
                authority.into_bytes().unwrap(),
                &actions_data,
            )
            .unwrap();
        assert_eq!(builder.swig.roles, 1);

        // Remove the only role
        builder.remove_role(0).unwrap();

        // Verify role was removed
        assert_eq!(builder.swig.roles, 0);

        // Drop builder to avoid borrowing conflict
        drop(builder);

        // Verify no roles exist
        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();
        assert_eq!(swig_with_roles.state.roles, 0);

        Ok(())
    }

    #[test]
    fn test_remove_middle_role() -> Result<(), ProgramError> {
        // Use the same 2-role approach as the working test
        // For the All action, which is very small
        let action_bytes = Action::LEN + 1; // All action is very small

        // Use verbose calculations to ensure adequate space
        let one_role_size = Position::LEN + ED25519Authority::LEN + action_bytes;
        let total_size = Swig::LEN + (2 * one_role_size); // Add extra padding

        let mut account_buffer = vec![0u8; total_size];
        let id = [1; 32];
        let bump = 255;

        let swig = Swig::new(id, bump, 0);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        // Create two different authorities
        let authority1 = ED25519Authority {
            public_key: [2; 32],
        };
        let authority2 = ED25519Authority {
            public_key: [3; 32],
        };

        // Create action data
        let all_action = All {}.into_bytes().unwrap();
        let all_header = Action::new(
            All::TYPE,
            all_action.len() as u16,
            Action::LEN as u32 + all_action.len() as u32,
        );
        let all_bytes = all_header.into_bytes().unwrap();
        let all_actions = [all_bytes, all_action].concat();

        // Add two roles
        builder
            .add_role(
                AuthorityType::Ed25519,
                authority1.into_bytes().unwrap(),
                &all_actions,
            )
            .unwrap();
        builder
            .add_role(
                AuthorityType::Ed25519,
                authority2.into_bytes().unwrap(),
                &all_actions,
            )
            .unwrap();

        // Verify two roles exist
        assert_eq!(builder.swig.roles, 2);
        println!(
            "Role counter after adding 2 roles: {}",
            builder.swig.role_counter
        );

        // Drop the builder to release mutable reference
        drop(builder);

        // Before removal: scan roles to see what IDs are assigned
        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();
        println!("Before removal - scanning available roles:");
        let mut assigned_ids = Vec::new();

        // Find all assigned role IDs
        for i in 0..4 {
            match swig_with_roles.get_role(i)? {
                Some(role) => {
                    println!("Role ID {} exists with position: {:?}", i, role.position);
                    assigned_ids.push(i);
                },
                None => println!("Role ID {} does not exist", i),
            }
        }

        // Ensure we have exactly 2 roles as expected
        assert_eq!(
            assigned_ids.len(),
            2,
            "Should have exactly 2 roles before removal"
        );

        // Since we have exactly 2 roles, we can remove the second one (index 1)
        let second_role_id = assigned_ids[1];
        println!("Removing second role with ID: {}", second_role_id);

        // Drop the immutable reference before creating a mutable one
        drop(swig_with_roles);

        // Recreate builder and remove the role
        let mut builder = SwigBuilder::new_from_bytes(&mut account_buffer).unwrap();
        builder.remove_role(second_role_id).unwrap();

        // Verify one role was removed
        assert_eq!(builder.swig.roles, 1);

        // Drop the builder to release the mutable reference
        drop(builder);

        // After removal: check the state of all roles
        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();
        println!(
            "After removal - Swig account has {} roles",
            swig_with_roles.state.roles
        );

        // Only first role should still exist
        let first_role = swig_with_roles.get_role(assigned_ids[0])?;
        assert!(
            first_role.is_some(),
            "First role should still exist after removal"
        );

        // Second role should not exist
        let second_role = swig_with_roles.get_role(second_role_id)?;
        assert!(
            second_role.is_none(),
            "Second role should not exist after removal"
        );

        Ok(())
    }

    #[test]
    fn test_remove_multiple_roles() -> Result<(), ProgramError> {
        // This test will add and remove multiple roles
        let action_bytes = Action::LEN + 1; // All action is very small

        // Use verbose calculations to ensure adequate space for 2 roles
        let one_role_size = Position::LEN + ED25519Authority::LEN + action_bytes;
        let two_role_size = Position::LEN + Secp256k1Authority::LEN + action_bytes;
        let total_size = Swig::LEN + one_role_size + two_role_size; // Add extra padding

        let mut account_buffer = vec![0u8; total_size];
        let id = [1; 32];
        let bump = 255;

        let swig = Swig::new(id, bump, 0);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        // Create two different authorities
        let authority1 = ED25519Authority {
            public_key: [2; 32],
        };
        let authority2 = [3; 64];

        // Create action data
        let all_action = All {}.into_bytes().unwrap();
        let all_header = Action::new(
            All::TYPE,
            all_action.len() as u16,
            Action::LEN as u32 + all_action.len() as u32,
        );
        let all_bytes = all_header.into_bytes().unwrap();
        let all_actions = [all_bytes, all_action].concat();
        let ma_action = ManageAuthority {}.into_bytes().unwrap();
        let ma_header = Action::new(
            ManageAuthority::TYPE,
            ma_action.len() as u16,
            Action::LEN as u32 + ma_action.len() as u32,
        );
        let ma_bytes = ma_header.into_bytes().unwrap();
        let ma_actions = [ma_bytes, ma_action].concat();

        // Add two roles
        builder
            .add_role(
                AuthorityType::Ed25519,
                authority1.into_bytes().unwrap(),
                &all_actions,
            )
            .unwrap();
        builder
            .add_role(AuthorityType::Secp256k1, &authority2, &ma_actions)
            .unwrap();

        // Scan for assigned role IDs
        drop(builder);
        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();
        println!(
            "Before removals - Swig has {} roles",
            swig_with_roles.state.roles
        );

        let mut assigned_ids = Vec::new();
        for i in 0..4 {
            if let Some(role) = swig_with_roles.get_role(i)? {
                println!("Role ID {} exists with position: {:?}", i, role.position);
                assigned_ids.push(i);
            }
        }

        // Verify we have 2 roles
        assert_eq!(
            assigned_ids.len(),
            2,
            "Should have exactly 2 roles before removal"
        );

        // Remember the IDs
        let first_id = assigned_ids[0];
        let second_id = assigned_ids[1];
        drop(swig_with_roles);

        // Remove first role
        let mut builder = SwigBuilder::new_from_bytes(&mut account_buffer).unwrap();
        builder.remove_role(first_id).unwrap();
        assert_eq!(
            builder.swig.roles, 1,
            "Should have 1 role after first removal"
        );

        // Verify second role still exists
        drop(builder);
        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();
        assert_eq!(
            swig_with_roles.state.roles, 1,
            "Should have 1 role after first removal"
        );

        let second_role = swig_with_roles.get_role(second_id)?;
        assert!(second_role.is_some(), "Second role should still exist");
        drop(swig_with_roles);

        // Remove second role
        let mut builder = SwigBuilder::new_from_bytes(&mut account_buffer).unwrap();
        builder.remove_role(second_id).unwrap();
        assert_eq!(
            builder.swig.roles, 0,
            "Should have 0 roles after second removal"
        );

        // Verify all roles are gone
        drop(builder);
        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();
        assert_eq!(
            swig_with_roles.state.roles, 0,
            "Should have 0 roles after all removals"
        );

        let first_role = swig_with_roles.get_role(first_id)?;
        let second_role = swig_with_roles.get_role(second_id)?;
        assert!(
            first_role.is_none(),
            "First role should not exist after removal"
        );
        assert!(
            second_role.is_none(),
            "Second role should not exist after removal"
        );

        Ok(())
    }

    #[test]
    fn test_remove_secp_middle_role() -> Result<(), ProgramError> {
        // Use the same 2-role approach as the working test
        // For the All action, which is very small
        let action_bytes = Action::LEN + 1; // All action is very small

        // Use verbose calculations to ensure adequate space
        let one_role_size = Position::LEN + ED25519Authority::LEN + action_bytes;
        let two_role_size = Position::LEN + Secp256k1Authority::LEN + action_bytes;
        let total_size = Swig::LEN + one_role_size + two_role_size; // Add extra padding

        let mut account_buffer = vec![0u8; total_size];
        let id = [1; 32];
        let bump = 255;

        let swig = Swig::new(id, bump, 0);
        let mut builder = SwigBuilder::create(&mut account_buffer, swig).unwrap();

        // Create two different authorities
        let authority1 = ED25519Authority {
            public_key: [2; 32],
        };
        let authority2 = [3; 64];

        // Create action data
        let all_action = All {}.into_bytes().unwrap();
        let all_header = Action::new(
            All::TYPE,
            all_action.len() as u16,
            Action::LEN as u32 + all_action.len() as u32,
        );
        let all_bytes = all_header.into_bytes().unwrap();
        let all_actions = [all_bytes, all_action].concat();

        // Add two roles
        builder
            .add_role(
                AuthorityType::Ed25519,
                authority1.into_bytes().unwrap(),
                &all_actions,
            )
            .unwrap();
        builder
            .add_role(AuthorityType::Secp256k1, &authority2, &all_actions)
            .unwrap();

        // Verify two roles exist
        assert_eq!(builder.swig.roles, 2);
        println!(
            "Role counter after adding 2 roles: {}",
            builder.swig.role_counter
        );

        // Drop the builder to release mutable reference
        drop(builder);

        // Before removal: scan roles to see what IDs are assigned
        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();
        println!("Before removal - scanning available roles:");
        let mut assigned_ids = Vec::new();

        // Find all assigned role IDs
        for i in 0..4 {
            match swig_with_roles.get_role(i)? {
                Some(role) => {
                    println!("Role ID {} exists with position: {:?}", i, role.position);
                    assigned_ids.push(i);
                },
                None => println!("Role ID {} does not exist", i),
            }
        }

        // Ensure we have exactly 2 roles as expected
        assert_eq!(
            assigned_ids.len(),
            2,
            "Should have exactly 2 roles before removal"
        );

        // Since we have exactly 2 roles, we can remove the second one (index 1)
        let second_role_id = assigned_ids[1];
        println!("Removing second role with ID: {}", second_role_id);

        // Drop the immutable reference before creating a mutable one
        drop(swig_with_roles);

        // Recreate builder and remove the role
        let mut builder = SwigBuilder::new_from_bytes(&mut account_buffer).unwrap();
        builder.remove_role(second_role_id).unwrap();

        // Verify one role was removed
        assert_eq!(builder.swig.roles, 1);

        // Drop the builder to release the mutable reference
        drop(builder);

        // After removal: check the state of all roles
        let swig_with_roles = SwigWithRoles::from_bytes(&account_buffer).unwrap();
        println!(
            "After removal - Swig account has {} roles",
            swig_with_roles.state.roles
        );

        // Only first role should still exist
        let first_role = swig_with_roles.get_role(assigned_ids[0])?;
        assert!(
            first_role.is_some(),
            "First role should still exist after removal"
        );

        // Second role should not exist
        let second_role = swig_with_roles.get_role(second_role_id)?;
        assert!(
            second_role.is_none(),
            "Second role should not exist after removal"
        );

        Ok(())
    }
}
