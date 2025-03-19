use std::marker::PhantomData;

use bytemuck::{bytes_of, Pod, Zeroable};

use crate::{
    action::{Action, Actionable, PermissionType},
    authority::{Authority, AuthorityData, AuthorityDataBuilder, AuthorityDataMut, AuthorityType},
    swig::SwigStateError,
    util::ZeroCopy,
};

pub struct RoleBuilder {}

impl RoleBuilder {
    pub fn create_role<'a>(
        authority: Authority<'a>,
        actions: Vec<Action<'a>>,
        data: &'a mut [u8],
    ) -> Result<(), SwigStateError>
    {
        let mut offset = 0;
        let header = RoleHeader {
            authority_size: authority.size() as u32,
            actions_size: actions.iter().map(|a| a.size()).sum::<usize>() as u16,
            num_actions: actions.len() as u8,
            authority_type: T::TYPE,
        };
        data[offset..RoleHeader::LEN].copy_from_slice(bytes_of(&header));
        offset += RoleHeader::LEN;
        data[offset..offset + header.authority_size as usize]
            .copy_from_slice(&mut authority.into_bytes());
        for action in actions {
            let size = action.size();
            data[offset..offset + size].copy_from_slice(&action.into_bytes());
            offset += size;
        }
        Ok(())
    }
}
// impl<'a, R: AuthorityData<'a>, A: Actionable<'a>> RoleBuilder<'a, R, A> {
//     pub fn new(authority: R, actions: Vec<A>) -> Self {
//         Self {
//             authority,
//             actions,
//             _phantom: PhantomData,
//         }
//     }

//     pub fn load_role_from_bytes(data: &'a [u8]) -> R {
//         R::load_from_bytes(data)
//     }

//     pub fn size(&self) -> usize {
//         RoleHeader::LEN
//             + self.authority.size()
//             + self.actions.iter().map(|a| a.size()).sum::<usize>()
//     }

//     // pub fn into_bytes(self) -> Vec<u8> {
//     //     let mut bytes = Vec::with_capacity(self.size());
//     //     let header = RoleHeader {
//     //         authority_size: self.authority.size() as u32,
//     //         actions_size: self.actions.iter().map(|a| a.size()).sum::<usize>() as u16,
//     //         num_actions: self.actions.len() as u8,
//     //         authority_type: R::TYPE,
//     //     };
//     //     bytes.extend_from_slice(bytes_of(&header));
//     //     bytes.extend_from_slice(self.authority.into_bytes().as_slice());
//     //     for action in self.actions {
//     //         bytes.extend_from_slice(action.into_bytes().as_slice());
//     //     }
//     //     bytes
//     // }
// }

pub struct Role<'a, T: AuthorityData<'a>> {
    pub size: u32,
    pub num_actions: u8,
    pub authority: T,
    actions_data: &'a [u8],
}

impl<'a, T: AuthorityData<'a>> Role<'a, T> {
    pub fn new(size: u32, num_actions: u8, authority: T, actions_data: &'a [u8]) -> Self {
        Self {
            size,
            num_actions,
            authority,
            actions_data,
        }
    }
}

pub struct RoleMut<'a, T: AuthorityDataMut<'a>> {
    pub size: u32,
    pub num_actions: u8,
    pub data: T,
    actions_data: &'a mut [u8],
}

impl<'a, T: AuthorityDataMut<'a>> RoleMut<'a, T> {
    pub fn new(size: u32, num_actions: u8, data: T, actions_data: &'a mut [u8]) -> Self {
        Self {
            size,
            num_actions,
            data,
            actions_data,
        }
    }

    pub fn get_permission_mut<A: Actionable<'a>>(&'a mut self) -> Option<A> {
        let mut cursor = 0;
        let mut target_cursor = None;
        for i in 0..self.num_actions {
            let action_type = PermissionType::from_u8(self.actions_data[cursor]);
            if action_type == PermissionType::None {
                return None;
            }
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
        if let Some((cursor, action_size)) = target_cursor {
            let action_data = A::load_from_bytes_mut(
                &mut self.actions_data[cursor..cursor + action_size as usize],
            )
            .ok()?;
            return Some(action_data);
        }
        None
    }
}

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(C)]
pub struct RoleHeader {
    pub authority_size: u32,
    pub actions_size: u16,
    pub num_actions: u8,
    pub authority_type: AuthorityType,
}

impl ZeroCopy<'_, RoleHeader> for RoleHeader {}
impl RoleHeader {
    pub const LEN: usize = std::mem::size_of::<RoleHeader>();
}
