// use bytemuck::{Pod, Zeroable};
// use pinocchio::{
//     account_info::AccountInfo, instruction::Seed, msg, program_error::ProgramError,
//     syscalls::sol_memcpy_,
// };
// use std::ops::Range;
// use thiserror::Error;

// use crate::{error::SwigError, util::ZeroCopy};

// #[derive(Error, Debug)]
// pub enum SwigStateError {
//     #[error("Deserialization Error")]
//     SwigDeserializationError,
//     #[error("Deserialization Error")]
//     AuthorityDeserializationError,
//     #[error("Max Authorities Reached")]
//     MaxAuthoritiesReached,
//     #[error("Max Authority Size Reached")]
//     MaxAuthoritySizeReached,
//     #[error("Invalid Authority Type")]
//     InvalidAuthorityType,
//     #[error("Invalid Authority Strategy")]
//     InvalidAuthorityStrategy,
//     #[error("Invalid Authority")]
//     InvalidAuthority,
//     #[error("Invalid Authority Index")]
//     InvalidAuthorityIndex,
//     #[error("Authority Not Found")]
//     AuthorityNotFound,
//     #[error("Insufficient Space")]
//     InsufficentSpace,
// }

// pub enum PolicyType {
//     None,
//     Owner,
//     TimeRange(u64, u64), // start, end if end == 0 then forever
//     RateLimit {
//         count: u32,
//         wait: u64
//     }, // debounce, cooldown
// }

// pub struct Role {
//     pub authority: Authority,
//     pub policy: Policy,
// }

// pub enum Authority {
//     None,
//     Ed25519([u8; 32]),
//     Secp256k1([u8; 64]),
// }

// pub struct Policy {
//     pub policy_type: PolicyType,
//     pub permissions: [Permissions],
// }

// pub enum Permissions {
//     None,
//     All,
//     Token([u8; 32], TokenAction),
//     Program([u8; 32]),
// }

// pub enum TokenAction {
//     None,
//     All,
//     Transfer(u64),
//     Burn(u64),
// }

// impl From<SwigStateError> for SwigError {
//     fn from(e: SwigStateError) -> Self {
//         SwigError::StateError(e.to_string()) //  possibly too inefficient
//     }
// }

// const MAX_AUTHORITIES: usize = 8;

use pinocchio::instruction::Seed;

// #[derive(Copy, Clone)]
// #[repr(C, align(8))]
// pub struct SwigAccount {
//     pub id: SwigId,
//     pub bump: [u8; 1],
// }



// impl SwigAccount {
//     pub const SIZE: usize = std::mem::size_of::<SwigAccount>();

//     #[inline(always)]
//     pub fn signer<'a>(&'a self) -> Vec<Seed<'a>> {
//         vec![
//             b"swig".as_ref().into(),
//             self.id.as_ref().into(),
//             self.bump.as_ref().into(),
//         ]
//     }

//     pub fn new(id: SwigId, bump: [u8; 1]) -> Self {
//         Self {
//             id,
//             bump,
//         }
//     }

//     pub fn create_with_authorities(
//         &mut self,
//         account_data: &mut [u8],
//         authorities: Vec<Authority>,
//     ) -> Result<(), SwigStateError> {
//         for authority in authorities.iter() {
//             self.add_authority(
//                 authority.authority_type(),
//                 authority.data(),
//                 &mut account_data[std::mem::size_of::<Self>()..],
//             )?;
//         }
//         self.write_to_account(account_data)?;
//         Ok(())
//     }

//     fn write_to_account(&self, account_data: &mut [u8]) -> Result<(), SwigStateError> {
//         if account_data.len() < std::mem::size_of::<Self>() {
//             return Err(SwigStateError::InsufficentSpace);
//         }
//         let bytes = self.as_bytes();
//         account_data[..std::mem::size_of::<Self>()].copy_from_slice(bytes);
//         Ok(())
//     }

//     pub fn next_empty_index(&self) -> Option<u8> {
//         (0..MAX_AUTHORITIES)
//             .find(|&i| self.authority_map[i] == AuthorityType::None)
//             .map(|i| i as u8)
//     }

//     fn get_authority_range(&self, index: u8) -> Option<Range<usize>> {
//         if (index as usize) < self.num_authorities as usize {
//             let start = self.authority_offsets[index as usize];
//             let end = start + self.authority_map[index as usize].size();
//             Some(start..end)
//         } else {
//             None
//         }
//     }

//     pub fn get_authority<'a>(
//         &self,
//         index: u8,
//         swig_account_data: &'a [u8],
//     ) -> Result<Authority<'a>, SwigStateError> {
//         let authority_type = self.authority_map[index as usize];
//         if authority_type == AuthorityType::None {
//             return Err(SwigStateError::AuthorityNotFound);
//         }
//         if let Some(range) = self.get_authority_range(index) {
//             let authority_data = &swig_account_data[range];
//             Authority::from_bytes(authority_type, authority_data)
//         } else {
//             Err(SwigStateError::AuthorityNotFound)
//         }
//     }

//     pub fn add_authority(
//         &mut self,
//         authority_type: AuthorityType,
//         authority_data: &[u8],
//         swig_account_data: &mut [u8],
//     ) -> Result<(), SwigStateError> {
//         let index = self
//             .next_empty_index()
//             .ok_or(SwigStateError::MaxAuthoritiesReached)?;
//         if authority_type == AuthorityType::None {
//             return Err(SwigStateError::InvalidAuthorityType);
//         }
//         if authority_data.len() != authority_type.size() {
//             return Err(SwigStateError::InvalidAuthorityType);
//         }

//         let insertion_offset = if self.num_authorities == 0 {
//             0
//         } else {
//             let last_authority = self.authority_map[(self.num_authorities - 1) as usize];
//             let last_offset = self.authority_offsets[(self.num_authorities - 1) as usize];
//             last_offset + last_authority.size()
//         };

//         if insertion_offset + authority_type.size() > swig_account_data.len() {
//             return Err(SwigStateError::InsufficentSpace);
//         }
//         self.authority_map[index as usize] = authority_type;
//         self.authority_offsets[index as usize] = insertion_offset;
//         self.num_authorities += 1;

//         let range = insertion_offset..(insertion_offset + authority_type.size());
//         swig_account_data[range].copy_from_slice(authority_data);
//         Ok(())
//     }

//     pub fn remove_authority(
//         &mut self,
//         index: u8,
//         swig_account_data: &mut [u8],
//     ) -> Result<Vec<u8>, SwigStateError> {
//         if (index as usize) >= self.num_authorities as usize {
//             return Err(SwigStateError::InvalidAuthorityIndex);
//         }

//         let authority_type = self.authority_map[index as usize];
//         if authority_type == AuthorityType::None {
//             return Err(SwigStateError::AuthorityNotFound);
//         }

//         let range = self.get_authority_range(index).unwrap();
//         let removed_authority = swig_account_data[range.clone()].to_vec();

//         // Shift the remaining authorities
//         for i in (index as usize + 1)..self.num_authorities as usize {
//             let src_range = self.get_authority_range(i as u8).unwrap();
//             let dst_start = self.authority_offsets[i - 1];
//             swig_account_data.copy_within(src_range, dst_start);
//             self.authority_offsets[i - 1] = dst_start;
//         }

//         // Update the SwigAccount structure
//         for i in index as usize..self.num_authorities as usize - 1 {
//             self.authority_map[i] = self.authority_map[i + 1];
//             self.authority_offsets[i] = self.authority_offsets[i + 1];
//         }
//         self.authority_map[self.num_authorities as usize - 1] = AuthorityType::None;
//         self.authority_offsets[self.num_authorities as usize - 1] = 0;
//         self.num_authorities -= 1;
//         Ok(removed_authority)
//     }

//     pub fn replace_authority(
//         &mut self,
//         index: u8,
//         new_authority_type: AuthorityType,
//         new_authority_data: &[u8],
//         swig_account_data: &mut [u8],
//     ) -> Result<Vec<u8>, SwigStateError> {
//         if (index as usize) >= self.num_authorities as usize {
//             return Err(SwigStateError::InvalidAuthorityIndex);
//         }

//         let old_authority_type = self.authority_map[index as usize];
//         if old_authority_type == AuthorityType::None {
//             return Err(SwigStateError::AuthorityNotFound);
//         }

//         if new_authority_type == AuthorityType::None {
//             return Err(SwigStateError::InvalidAuthorityType);
//         }

//         if new_authority_data.len() != new_authority_type.size() {
//             return Err(SwigStateError::InvalidAuthorityType);
//         }

//         let old_range = self.get_authority_range(index).unwrap();
//         let old_authority = swig_account_data[old_range.clone()].to_vec();

//         let size_difference =
//             new_authority_type.size() as isize - old_authority_type.size() as isize;

//         if size_difference != 0 {
//             // Shift the remaining authorities
//             for i in (index as usize + 1..self.num_authorities as usize).rev() {
//                 let src_range = self.get_authority_range(i as u8).unwrap();
//                 let dst_start = (src_range.start as isize + size_difference) as usize;
//                 swig_account_data.copy_within(src_range, dst_start);
//                 self.authority_offsets[i] = dst_start;
//             }
//         }

//         // Update the replaced authority
//         self.authority_map[index as usize] = new_authority_type;
//         let new_range = self.authority_offsets[index as usize]
//             ..(self.authority_offsets[index as usize] + new_authority_type.size());
//         swig_account_data[new_range].copy_from_slice(new_authority_data);

//         // Update offsets for subsequent authorities
//         for i in (index as usize + 1)..self.num_authorities as usize {
//             self.authority_offsets[i] =
//                 (self.authority_offsets[i] as isize + size_difference) as usize;
//         }

//         Ok(old_authority)
//     }

//     pub fn size_with_authorities(authority_types: &[AuthorityType]) -> usize {
//         let mut size = SwigAccount::SIZE;
//         for authority_type in authority_types {
//             size += authority_type.size();
//         }
//         size
//     }

//     pub fn total_size(&self) -> usize {
//         if self.num_authorities == 0 {
//             SwigAccount::SIZE
//         } else {
//             let last_authority = self.authority_map[(self.num_authorities - 1) as usize];
//             let last_offset = self.authority_offsets[(self.num_authorities - 1) as usize];
//             last_offset + last_authority.size()
//         }
//     }
// }

// #[derive(Debug, Copy, Default, Clone, Eq, PartialEq)]
// #[repr(u8)]
// pub enum AuthorityType {
//     #[default]
//     None = 0,
//     Ed25519 = 1,
//     Secp256k1 = 2,
// }
// unsafe impl Pod for AuthorityType {}
// unsafe impl Zeroable for AuthorityType {}

// impl AuthorityType {
//     pub fn size(&self) -> usize {
//         match self {
//             AuthorityType::None => 0,
//             AuthorityType::Ed25519 => 32,
//             AuthorityType::Secp256k1 => 64,
//         }
//     }
// }

// #[derive(Debug, Copy, Clone, Eq, PartialEq)]
// pub enum Authority<'a> {
//     None,
//     Ed25519(&'a [u8; 32]),
//     Secp256k1(&'a [u8; 64]),
// }

// impl Authority<'_> {
//     pub fn data(&self) -> &[u8] {
//         match self {
//             Authority::None => &[],
//             Authority::Ed25519(data) => data.as_ref(),
//             Authority::Secp256k1(data) => data.as_ref(),
//         }
//     }

//     pub fn authority_type(&self) -> AuthorityType {
//         match self {
//             Authority::None => AuthorityType::None,
//             Authority::Ed25519(_) => AuthorityType::Ed25519,
//             Authority::Secp256k1(_) => AuthorityType::Secp256k1,
//         }
//     }

//     pub fn from_bytes(
//         authority_type: AuthorityType,
//         authority_data: &[u8],
//     ) -> Result<Authority, SwigStateError> {
//         match authority_type {
//             AuthorityType::None => Ok(Authority::None),
//             AuthorityType::Ed25519 => {
//                 if authority_data.len() < 32 {
//                     return Err(SwigStateError::AuthorityDeserializationError);
//                 }
//                 Ok(Authority::Ed25519(
//                     authority_data[0..32]
//                         .try_into()
//                         .map_err(|_| SwigStateError::AuthorityDeserializationError)?,
//                 ))
//             }
//             AuthorityType::Secp256k1 => {
//                 if authority_data.len() < 64 {
//                     return Err(SwigStateError::AuthorityDeserializationError);
//                 }
//                 Ok(Authority::Secp256k1(
//                     authority_data[0..64]
//                         .try_into()
//                         .map_err(|_| SwigStateError::AuthorityDeserializationError)?,
//                 ))
//             }
//         }
//     }
// }
