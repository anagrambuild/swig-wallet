//! Blacklist action type.
//!
//! This module defines the Blacklist action type which prevents interaction with
//! specific programs or wallet addresses in the Swig wallet system.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Represents a blacklist entry that prevents interaction with a specific entity.
///
/// This struct contains the entity ID (program ID or wallet address) that is
/// blacklisted from interacting with the system. Multiple Blacklist actions can
/// exist in a role to blacklist different entities.
#[derive(NoPadding)]
#[repr(C, align(8))]
pub struct Blacklist {
    /// The entity ID that is blacklisted (program ID or wallet address)
    pub entity_id: [u8; 32],
    /// The type of entity being blacklisted (0 = program, 1 = wallet)
    pub entity_type: u8,
    /// Reserved field for future use
    pub reserved: [u8; 7],
}

impl Transmutable for Blacklist {
    /// Size of the Blacklist struct in bytes (32 bytes for entity_id + 1 for entity_type + 7 reserved)
    const LEN: usize = 40;
}

impl IntoBytes for Blacklist {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl TransmutableMut for Blacklist {}

impl<'a> Actionable<'a> for Blacklist {
    /// This action represents the Blacklist permission type
    const TYPE: Permission = Permission::Blacklist;
    /// Multiple blacklist entries can exist per role
    const REPEATABLE: bool = true;

    /// Checks if this blacklist entry matches the provided entity ID.
    ///
    /// # Arguments
    /// * `data` - The entity ID to check against (first 32 bytes)
    fn match_data(&self, data: &[u8]) -> bool {
        data.len() >= 32 && data[0..32] == self.entity_id
    }
}

impl Blacklist {
    /// Creates a new blacklist entry for a program.
    ///
    /// # Arguments
    /// * `program_id` - The program ID to blacklist
    pub fn new_program(program_id: [u8; 32]) -> Self {
        Self {
            entity_id: program_id,
            entity_type: 0,
            reserved: [0; 7],
        }
    }

    /// Creates a new blacklist entry for a wallet address.
    ///
    /// # Arguments
    /// * `wallet_address` - The wallet address to blacklist
    pub fn new_wallet(wallet_address: [u8; 32]) -> Self {
        Self {
            entity_id: wallet_address,
            entity_type: 1,
            reserved: [0; 7],
        }
    }

    /// Returns the entity ID as a byte array.
    pub fn entity_id(&self) -> &[u8; 32] {
        &self.entity_id
    }

    /// Returns the entity type (0 = program, 1 = wallet).
    pub fn entity_type(&self) -> u8 {
        self.entity_type
    }

    /// Checks if this blacklist entry is for a program.
    pub fn is_program(&self) -> bool {
        self.entity_type == 0
    }

    /// Checks if this blacklist entry is for a wallet address.
    pub fn is_wallet(&self) -> bool {
        self.entity_type == 1
    }
}
