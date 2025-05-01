use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Flags for managing sub-account permissions
pub const SUB_ACCOUNT_CAN_MODIFY_OWN_ROLES: u32 = 1 << 0;
pub const SUB_ACCOUNT_CAN_CREATE_SUB_ACCOUNTS: u32 = 1 << 1;
pub const SUB_ACCOUNT_PARENT_CONTROLS_ASSETS: u32 = 1 << 2;
pub const SUB_ACCOUNT_PARENT_CAN_SIGN: u32 = 1 << 3;

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct SubAccount {
    pub sub_account: [u8; 32], // Sub-account pubkey
    pub permissions: u32,      // Permission flags
    pub reserved: u32,         // Reserved for future use, ensures 8-byte alignment
    pub name: [u8; 32],        // Optional name for the sub-account (UTF-8 bytes)
}

impl Transmutable for SubAccount {
    const LEN: usize = 72; // 32 (pubkey) + 4 (permissions) + 4 (reserved) + 32 (name)
}

impl TransmutableMut for SubAccount {}

impl IntoBytes for SubAccount {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> Actionable<'a> for SubAccount {
    const TYPE: Permission = Permission::SubAccount;
    const REPEATABLE: bool = true;

    fn match_data(&self, data: &[u8]) -> bool {
        data.len() >= 32 && data[0..32] == self.sub_account
    }
}

/// Register a parent-child relationship between two Swig accounts
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct SubAccountRelationship {
    /// The parent Swig account public key
    pub parent: [u8; 32],
    /// The child Swig account public key
    pub child: [u8; 32],
    /// Configuration flags for this relationship
    pub flags: u32,
    /// Reserved for future use
    pub reserved: [u8; 4],
}

impl Transmutable for SubAccountRelationship {
    const LEN: usize = 72; // 32 + 32 + 4 + 4
}

impl TransmutableMut for SubAccountRelationship {}

impl IntoBytes for SubAccountRelationship {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl SubAccountRelationship {
    pub fn new(parent: [u8; 32], child: [u8; 32], flags: u32) -> Self {
        Self {
            parent,
            child,
            flags,
            reserved: [0; 4],
        }
    }
}
