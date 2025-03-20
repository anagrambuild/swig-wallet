use borsh::{BorshDeserialize, BorshSerialize};
use pinocchio::{instruction::Seed, program_error::ProgramError};

pub mod authority;

#[derive(Debug)]
#[repr(u8)] //starts at 100
pub enum SwigStateError {
    InvalidAuthority = 100,
    InvalidSessionData = 101,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct CreateV1 {
    pub id: [u8; 13],
    pub bump: u8,
    pub initial_authority: AuthorityType,
    pub start_slot: u64,
    pub end_slot: u64,
    pub authority_data: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct StartSessionV1 {
    pub role_id: u32,
    pub authority_payload: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug)]
#[repr(u8)]
pub enum Discriminator {
    SwigAccount,
}

pub struct IndexedRole<'a> {
    pub index: u8,
    pub role: &'a Role,
}

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub struct Swig {
    pub(crate) discriminator: u8,
    pub id: [u8; 13],
    pub bump: u8,
    pub roles: Vec<Role>,
}

#[inline(always)]
pub fn swig_account_seeds(id: &[u8]) -> [&[u8]; 2] {
    [b"swig".as_ref(), id]
}

#[inline(always)]
pub fn swig_account_seeds_with_bump<'a>(id: &'a [u8], bump: &'a [u8]) -> [&'a [u8]; 3] {
    [b"swig".as_ref(), id, bump]
}

pub fn swig_account_signer<'a>(id: &'a [u8], bump: &'a [u8; 1]) -> [Seed<'a>; 3] {
    [
        b"swig".as_ref().into(),
        id.as_ref().into(),
        bump.as_ref().into(),
    ]
}

impl Swig {
    pub fn raw_get_id(data: &[u8]) -> [u8; 13] {
        let mut id = [0u8; 13];
        id.copy_from_slice(&data[1..14]);
        id
    }

    pub fn raw_get_bump(data: &[u8]) -> u8 {
        data[14]
    }

    pub fn raw_get_role(data: &[u8], index: usize) -> Option<(usize, Role)> {
        let mut offset = 15;
        let size = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        if index >= size {
            return None;
        }
        offset += 4;
        for i in 0..size {
            let role_size = usize::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            if index == i {
                return Some((
                    offset,
                    Role::try_from_slice(&data[offset..offset + role_size])
                        .ok()
                        .unwrap(),
                ));
            }
            offset += role_size;
        }
        None
    }

    pub fn get_last_role_offset(data: &[u8]) -> usize {
        let mut offset = 15;
        let size = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        for _ in 0..size {
            let role_size = usize::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            offset += role_size;
        }
        offset
    }

    pub fn raw_add_role(data: &mut [u8], role: &Role) -> Result<(), borsh::io::Error> {
        let offset = 15;
        let last_offset = Self::get_last_role_offset(data);
        role.serialize(&mut &mut data[last_offset..])?;
        let mut size = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        size += 1;
        data[offset..offset + 4].copy_from_slice(&size.to_le_bytes());
        Ok(())
    }

    pub fn raw_lookup_role(data: &[u8], authority: &[u8]) -> Option<usize> {
        let offset = 15;
        let size = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        let mut offset = offset + 4;
        for i in 0..size {
            let role_size = usize::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            let data_size =
                u32::from_le_bytes(data[offset + 25..offset + 29].try_into().unwrap()) as usize;
            let authority_data = data[offset + 29..offset + 29 + data_size].to_vec();
            if authority_data == authority {
                return Some(i);
            }
            offset += role_size;
        }
        None
    }

    #[inline(always)]
    pub fn new(id: [u8; 13], bump: u8, roles: Vec<Role>) -> Self {
        Self {
            discriminator: Discriminator::SwigAccount as u8,
            id,
            bump,
            roles,
        }
    }
    pub fn size(&self) -> usize {
        1 + 13 + 1 + 4 + self.roles.iter().map(|role| role.size()).sum::<usize>()
    }

    pub fn lookup_role(&self, authority: &[u8]) -> Option<IndexedRole> {
        self.roles
            .iter()
            .enumerate()
            .find(|(_, role)| role.authority_data == authority)
            .map(|(i, role)| IndexedRole {
                index: i as u8,
                role,
            })
    }
}

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone, Copy)]
#[repr(u8)]
pub enum AuthorityType {
    Ed25519,
    Secp256k1,
    Ed25519Session,
    Secp256k1Session,
    R1PasskeySession,
    //---- zkp
}

unsafe impl bytemuck::Zeroable for AuthorityType {}
unsafe impl bytemuck::Pod for AuthorityType {}

impl AuthorityType {
    #[inline(always)]
    pub fn data_size(&self) -> usize {
        match self {
            AuthorityType::Ed25519 => 32,
            AuthorityType::Secp256k1 => 64,
            AuthorityType::Ed25519Session => 32 + 32 + 8 + 8,
            AuthorityType::Secp256k1Session => 64 + 32 + 8 + 8,
            _ => 0,
        }
    }
}

#[derive(BorshDeserialize, PartialEq, Debug, Clone)]
pub struct NewRole {
    pub(crate) size: u32,
    pub authority_type: AuthorityType,
    pub start_slot: u64,
    pub end_slot: u64,
    pub authority_data_len: usize,
    pub permissions_len: usize,
}

#[derive(BorshDeserialize, PartialEq, Debug, Clone)]
pub struct Role {
    pub(crate) size: usize,
    pub authority_type: AuthorityType,
    pub start_slot: u64,
    pub end_slot: u64,
    pub authority_data: Vec<u8>,
    pub actions: Vec<Action>,
}

impl borsh::ser::BorshSerialize for Role {
    fn serialize<__W: borsh::io::Write>(
        &self,
        writer: &mut __W,
    ) -> ::core::result::Result<(), borsh::io::Error> {
        borsh::BorshSerialize::serialize(&self.size(), writer)?;
        borsh::BorshSerialize::serialize(&self.authority_type, writer)?;
        borsh::BorshSerialize::serialize(&self.start_slot, writer)?;
        borsh::BorshSerialize::serialize(&self.end_slot, writer)?;
        borsh::BorshSerialize::serialize(&self.authority_data, writer)?;
        borsh::BorshSerialize::serialize(&self.actions, writer)?;
        Ok(())
    }
}

impl Role {
    pub fn new(
        authority_type: AuthorityType,
        authority_data: Vec<u8>,
        start_slot: u64,
        end_slot: u64,
        actions: Vec<Action>,
    ) -> Self {
        Self {
            size: 0,
            authority_type,
            authority_data,
            start_slot,
            end_slot,
            actions,
        }
    }

    pub fn new_with_size(
        authority_type: AuthorityType,
        authority_data: Vec<u8>,
        start_slot: u64,
        end_slot: u64,
        actions: Vec<Action>,
    ) -> Self {
        let mut se = Self {
            size: 0,
            authority_type,
            authority_data,
            start_slot,
            end_slot,
            actions,
        };
        se.size = se.size();
        se
    }

    pub fn size(&self) -> usize {
        8 + 1
            + 8
            + 8
            + 4
            + self.authority_data.len()
            + 4
            + self
                .actions
                .iter()
                .map(|action| action.size())
                .sum::<usize>()
    }
}

pub enum Resource {
    Tokens,
    Token,
    Sol,
    Roles,
}

pub enum SolActionType {
    None,
    All,
    Manage,
}

pub enum TokenActionType {
    None,
    All,
    Manage,
}

pub enum RoleActionType {
    None,
    All,
    Add,
    Replace,
}

pub struct Permission {
    pub size: u16,
    pub data_len: u16,
    pub resource: Resource,
    pub action: u8,
}
pub type SolPermission = (Permission, SolActionType, u64);
pub type TokensPermission = (Permission, TokenActionType, u64);
pub type TokenPermission = (Permission, TokenActionType, [u8; 32], u64);
pub type RolePermission = (Permission, RoleActionType, u8);

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone, Copy)]
pub enum TokenAction {
    All,
    Manage(u64),
    Temporal(u64, u64, u64),
}
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone, Copy)]
pub enum SolAction {
    All,
    Manage(u64),
    // Amount, Window, Last
    Temporal(u64, u64, u64),
}

impl SolAction {
    pub fn size(&self) -> usize {
        match self {
            SolAction::All => 1,
            SolAction::Manage(_) => 1 + 8,
            SolAction::Temporal(_, _, _) => 1 + 8 + 8 + 8,
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone, Copy)]
pub enum Action {
    All,
    ManageAuthority,
    Tokens { action: TokenAction },
    Token { key: [u8; 32], action: TokenAction },
    Sol { action: SolAction },
    Program { key: [u8; 32] },
}

impl TokenAction {
    pub fn size(&self) -> usize {
        match self {
            TokenAction::All => 1,
            TokenAction::Manage(_) => 1 + 8,
            TokenAction::Temporal(_, _, _) => 1 + 8 + 8 + 8,
        }
    }
}

impl Action {
    pub fn size(&self) -> usize {
        match self {
            Action::All => 1,
            Action::ManageAuthority => 1,
            Action::Token { action, .. } => 1 + 32 + action.size(),
            Action::Sol { action } => 1 + action.size(),
            Action::Program { .. } => 1 + 32,
            Action::Tokens { action } => 1 + action.size(),
        }
    }
}

#[cfg(test)]
mod tests {
    use borsh::BorshSerialize;

    use super::*;
    use crate::Role;

    #[test]
    fn test_raw_swig() {
        let swig = Swig::new([11u8; 13], 0, vec![]);
        let mut bytes = vec![];
        swig.serialize(&mut bytes).unwrap();
        let id = Swig::raw_get_id(&bytes);
        let bump = Swig::raw_get_bump(&bytes);

        assert_eq!(id, swig.id);
        assert_eq!(bump, swig.bump);
    }

    #[test]
    fn test_lookup_role() {
        let mut roles = vec![
            Role::new(
                AuthorityType::Ed25519,
                vec![0u8; 32],
                0,
                0,
                vec![Action::Token {
                    key: [4u8; 32],
                    action: TokenAction::Manage(100),
                }],
            ),
            Role::new(
                AuthorityType::Ed25519,
                vec![1u8; 32],
                0,
                0,
                vec![Action::All],
            ),
            Role::new(
                AuthorityType::Ed25519,
                vec![2u8; 32],
                0,
                0,
                vec![Action::All],
            ),
        ];
        roles[0].actions.push(Action::Token {
            key: [0u8; 32],
            action: TokenAction::Manage(100),
        });
        roles[1].actions.push(Action::Token {
            key: [1u8; 32],
            action: TokenAction::Manage(100),
        });
        roles[2].actions.push(Action::Token {
            key: [2u8; 32],
            action: TokenAction::Manage(100),
        });
        let swig = Swig::new([0u8; 13], 0, roles);
        let lookup = swig.lookup_role(&[0u8; 32]).unwrap();
        assert_eq!(lookup.index, 0);
        assert_eq!(lookup.role.actions.len(), 2);
        assert_eq!(
            lookup.role.actions[0],
            Action::Token {
                key: [4u8; 32],
                action: TokenAction::Manage(100),
            }
        );
    }

    #[test]
    fn test_raw_get_role() {
        let mut roles = vec![
            Role::new(
                AuthorityType::Ed25519,
                vec![0u8; 32],
                0,
                0,
                vec![Action::All],
            ),
            Role::new(
                AuthorityType::Ed25519,
                vec![1u8; 32],
                0,
                0,
                vec![Action::All],
            ),
            Role::new(
                AuthorityType::Ed25519,
                vec![2u8; 32],
                0,
                0,
                vec![Action::All],
            ),
        ];
        roles[0].actions.push(Action::Token {
            key: [0u8; 32],
            action: TokenAction::Manage(100),
        });
        roles[1].actions.push(Action::Token {
            key: [1u8; 32],
            action: TokenAction::Manage(100),
        });
        roles[2].actions.push(Action::Token {
            key: [2u8; 32],
            action: TokenAction::Manage(100),
        });
        let rolecopy = roles[0].clone();
        let swig = Swig::new([0u8; 13], 0, roles);

        let mut bytes = vec![];
        swig.serialize(&mut bytes).unwrap();
        let (i, role) = Swig::raw_get_role(&bytes, 0).unwrap();
        assert_eq!(role.size(), rolecopy.size());
        assert_eq!(role.authority_type, rolecopy.authority_type);
        assert_eq!(role.start_slot, rolecopy.start_slot);
        assert_eq!(role.end_slot, rolecopy.end_slot);
        assert_eq!(role.authority_data, rolecopy.authority_data);
        assert_eq!(role.actions, rolecopy.actions);
        assert_eq!(role.actions.len(), 2);
        assert_eq!(role.actions[0], Action::All);
        assert_eq!(role.actions.len(), 2);
    }
}
