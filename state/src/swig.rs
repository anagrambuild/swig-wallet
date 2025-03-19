use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::bytes_of;
use bytemuck::{Pod, Zeroable};
use core::mem;
use core::slice;
use pinocchio::account_info;
use pinocchio::account_info::AccountInfo;
use std::marker::PhantomData;
use thiserror::Error;

use crate::action::Actionable;
use crate::authority::{AuthorityData, AuthorityDataMut};
use crate::role::{Role, RoleBuilder, RoleHeader, RoleMut};
use crate::util::ZeroCopy;
use crate::{authority::AuthorityType, Action, Discriminator};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SwigStateError {
    #[error("Invalid Swig alignment")]
    InvalidSwigAlignment,
    #[error("Realloc Error")]
    ReallocError,
    #[error("Invalid Role Header")]
    InvalidRoleHeader,
    #[error("Invalid Action")]
    InvalidAction,
    #[error("Invalid Role Size")]
    InvalidSwigAccountSize,
}

/// A trait for authorities that can authenticate operations
pub trait Authenticate {
    /// Authenticates an operation using this authority
    ///
    /// May mutate internal state (e.g., to advance nonces)
    fn authenticate(&mut self, data: &[u8]) -> bool;
}

/// Header for a Swig account, containing fixed-size metadata
#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(C)]
pub struct Swig {
    pub discriminator: u8,
    pub id: [u8; 32],
    pub bump: u8,
    _num_roles: u16,
}
impl ZeroCopy<'_, Swig> for Swig {}

impl Swig {
    pub const LEN: usize = std::mem::size_of::<Swig>();

    pub fn new(id: [u8; 32], bump: u8) -> Self {
        Self {
            discriminator: Discriminator::SwigAccount as u8,
            id,
            bump,
            _num_roles: 0,
        }
    }

    pub fn size(&self, data: &[u8]) -> Result<usize, SwigStateError> {
        let mut cursor = Swig::LEN;
        for i in 0..self._num_roles {
            let role_header = RoleHeader::load(&data[cursor..cursor + RoleHeader::LEN])
                .map_err(|_| SwigStateError::InvalidRoleHeader)?;
            cursor += RoleHeader::LEN;
            cursor += role_header.authority_size as usize;
            cursor += role_header.actions_size as usize;
        }
        Ok(cursor)
    }

    pub fn size_with_role<'a, A, R>(
        &self,
        data: &[u8],
        role: &RoleBuilder<'a, R, A>,
    ) -> Result<usize, SwigStateError>
    where
        R: AuthorityData<'a>,
        A: Actionable<'a>,
    {
        let mut cursor = self.size(data)?;
        cursor += role.size();
        Ok(cursor)
    }

    pub fn num_roles(&self) -> u16 {
        self._num_roles
    }

    pub fn get_last_role_offset(&self, data: &[u8]) -> Result<usize, SwigStateError> {
        let mut offset = Swig::LEN;
        for i in 0..self._num_roles {
            let role_header = RoleHeader::load(&data[offset..offset + RoleHeader::LEN])
                .map_err(|_| SwigStateError::InvalidRoleHeader)?;
            offset += RoleHeader::LEN;
            offset += role_header.authority_size as usize;
            offset += role_header.actions_size as usize;
        }
        Ok(offset)
    }

    // pub fn add_role<'a, R, A>(
    //     &mut self,
    //     role: RoleBuilder<'a, R, A>,
    //     data: &mut [u8],
    // ) -> Result<(), SwigStateError>
    // where
    //     R: AuthorityData<'a>,
    //     A: Actionable<'a>,
    // {
    //     let last_offset = self.get_last_role_offset(data)?;
    //     self._num_roles += 1;
    //     let role_bytes = role.into_bytes();
    //     let end = last_offset + role_bytes.len();
    //     if end + 1 > data.len() {
    //         return Err(SwigStateError::InvalidSwigAccountSize);
    //     }
    //     data[last_offset..end].copy_from_slice(&role_bytes);
    //     Ok(())
    // }

    pub fn get_role<'a, R: AuthorityData<'a>>(
        &self,
        index: u16,
        data: &'a [u8],
    ) -> Option<Role<'a, R>> {
        let mut cursor = Swig::LEN;

        for i in 0..self._num_roles {
            let role_header = RoleHeader::load(&data[cursor..cursor + RoleHeader::LEN]).ok()?;

            if i == index {
                if role_header.authority_type != R::TYPE {
                    return None;
                }
                cursor += RoleHeader::LEN;
                let (authority_data, actions_data) =
                    data.split_at(cursor + role_header.authority_size as usize);

                return Some(Role::new(
                    role_header.authority_size + role_header.actions_size as u32,
                    role_header.num_actions,
                    R::load_from_bytes(&authority_data),
                    &actions_data,
                ));
            } else {
                cursor += RoleHeader::LEN
                    + role_header.authority_size as usize
                    + role_header.actions_size as usize;
            }
        }
        None
    }

    pub fn get_role_mut<'a, R: AuthorityDataMut<'a>>(
        &self,
        index: u16,
        data: &'a mut [u8],
    ) -> Option<RoleMut<'a, R>> {
        let mut cursor = Swig::LEN;

        // First, find the correct role index and cursor position
        let mut target_cursor = None;

        for i in 0..self._num_roles {
            let role_header = RoleHeader::load(&data[cursor..cursor + RoleHeader::LEN]).ok()?;

            if i == index {
                if role_header.authority_type != R::TYPE {
                    return None;
                }
                target_cursor = Some((
                    cursor,
                    role_header.authority_size,
                    role_header.actions_size,
                    role_header.num_actions,
                ));
                break;
            } else {
                cursor += RoleHeader::LEN
                    + role_header.authority_size as usize
                    + role_header.actions_size as usize;
            }
        }

        // Now use the found cursor to create the role
        if let Some((cursor, authority_size, actions_size, num_actions)) = target_cursor {
            let authority_start = cursor + RoleHeader::LEN;
            let action_start = authority_start + authority_size as usize;

            // Split after authority, this gives us all role data after the authority
            let (authority_slice, remaining) = data.split_at_mut(action_start);

            return Some(RoleMut::new(
                authority_size + actions_size as u32,
                num_actions,
                R::load_from_bytes_mut(authority_slice),
                &mut remaining[0..actions_size as usize],
            ));
        }

        None
    }
}
