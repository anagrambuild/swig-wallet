use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};
use core::mem;
use core::slice;
use std::marker::PhantomData;

use crate::util::ZeroCopy;
use crate::{Action, AuthorityType, Discriminator};

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
    pub num_roles: u16,
}

impl ZeroCopy<'_, Swig> for Swig {}

impl Swig {
    pub const LEN: usize = std::mem::size_of::<Swig>();

    pub fn get_role<'a, R: RoleData<'a>>(&self, index: u16, data: &'a [u8]) -> Option<Role<'a, R>> {
        let mut cursor = Swig::LEN;

        for i in 0..self.num_roles {
            let role_header = RoleHeader::load(&data[cursor..cursor + RoleHeader::LEN]).ok()?;

            if i == index {
                if role_header.authority_type != R::TYPE {
                    return None;
                }
                cursor += RoleHeader::LEN;
                let (authority_data, actions_data) =
                    data.split_at(cursor + role_header.authority_size as usize);

                return Some(Role {
                    size: role_header.authority_size + role_header.actions_size as u32,
                    num_actions: role_header.num_actions,
                    authority: R::load_from_bytes(&authority_data),
                    actions_data: &actions_data,
                });
            } else {
                cursor += RoleHeader::LEN
                    + role_header.authority_size as usize
                    + role_header.actions_size as usize;
            }
        }
        None
    }

    pub fn get_role_mut<'a, R: RoleDataMut<'a>>(
        &self,
        index: u16,
        data: &'a mut [u8],
    ) -> Option<RoleMut<'a, R>> {
        let mut cursor = Swig::LEN;

        // First, find the correct role index and cursor position
        let mut target_cursor = None;

        for i in 0..self.num_roles {
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

            // Get just the authority portion from the first slice
            let authority_data = &mut authority_slice[authority_start..];

            // Take the part we need for actions from the remaining slice
            let actions_data = &mut remaining[0..actions_size as usize];

            return Some(RoleMut {
                size: authority_size + actions_size as u32,
                num_actions,
                data: R::load_from_bytes_mut(authority_data),
                actions_data,
            });
        }

        None
    }
}

pub trait ActionData {
    fn size(&self) -> usize;
    fn resource(&self) -> u8;
    fn action(&self) -> u8;
}

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(C)]
pub struct RoleHeader {
    pub authority_size: u32,
    pub actions_size: u16,
    pub num_actions: u8,
    pub authority_type: AuthorityType,
}

pub struct Role<'a, T: RoleData<'a>> {
    pub size: u32,
    pub num_actions: u8,
    pub authority: T,
    actions_data: &'a [u8],
}

pub struct RoleMut<'a, T: RoleDataMut<'a>> {
    pub size: u32,
    pub num_actions: u8,
    pub data: T,
    actions_data: &'a mut [u8],
}

impl<'a, T: RoleDataMut<'a>> RoleMut<'a, T> {
    fn find_permission<A: Actionable<'a>>(
        &mut self,
        match_data: Option<&'a [u8]>,
    ) -> Option<impl Actionable<'a>> {
        let mut cursor = 0;
        let mut target_cursor = None;
        for i in 0..self.num_actions {
            let action_type = PermissionType::from_u8(self.actions_data[cursor])?;
            let action_size: u16 = u16::from_le_bytes(
                self.actions_data[cursor + 1..cursor + 3]
                    .try_into()
                    .unwrap(),
            );
            cursor += 3;

            if action_type == A::TYPE {
                target_cursor = Some((cursor, action_size));
                break;
            }

            cursor += action_size as usize;
                
        }
        None
    }
}

impl ZeroCopy<'_, RoleHeader> for RoleHeader {}
impl RoleHeader {
    pub const LEN: usize = std::mem::size_of::<RoleHeader>();
}

pub trait Actionable<'a> {
    const TYPE: PermissionType;
    fn size(&self) -> usize;
    fn load_from_bytes_mut(data: &'a mut [u8]) -> Self;
}

pub trait RoleData<'a> {
    const TYPE: AuthorityType;
    fn size(&self) -> usize;
    fn load_from_bytes(data: &'a [u8]) -> Self;
}

pub trait RoleDataMut<'a>: RoleData<'a> {
    fn load_from_bytes_mut(data: &'a mut [u8]) -> Self;
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
#[repr(C)]
pub enum PermissionType {
    #[default]
    None,
    SolLimit,
    SolRecurringLimit,
    Program,
    TokenLimit,
    TokenRecurringLimit,
    TokensLimit,
    TokensRecurringLimit,
    All,
    ManageAuthority,
    SubAccount,
}

impl PermissionType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::SolLimit),
            2 => Some(Self::SolRecurringLimit),
            3 => Some(Self::Program),
            4 => Some(Self::TokenLimit),
            5 => Some(Self::TokenRecurringLimit),
            6 => Some(Self::TokensLimit),
            7 => Some(Self::TokensRecurringLimit),
            8 => Some(Self::All),
            9 => Some(Self::ManageAuthority),
            10 => Some(Self::SubAccount),
            _ => None,
        }
    }
}

unsafe impl Pod for PermissionType {}
unsafe impl Zeroable for PermissionType {}

// impl ActionHeader {
//     pub const LEN: usize = std::mem::size_of::<ActionHeader>();
// }

// pub struct Ed25519Role<'a> {
//     pub pubkey: [u8; 32],
// }

// pub struct Ed25519RoleMut<'a> {
//     pub pubkey: [u8; 32],
// }

// impl<'a> Role<'a> for Ed25519Role<'a> {
//     fn size(&self) -> usize {
//         self.actions.iter().map(|a| a.size()).sum::<usize>() + 32
//     }

//     fn load_from_bytes(data: &[u8]) -> Self {
//         let pubkey = data[0..32].try_into().unwrap();
//         let num_actions = data[32];

//         Self { pubkey, actions }
//     }
// }
