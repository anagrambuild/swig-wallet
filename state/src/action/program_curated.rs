//! Program Curated action type.
//!
//! This module defines the ProgramCurated action type which grants permission
//! to interact with a curated list of popular programs in the Swig wallet
//! system.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Curated program IDs that are commonly used and considered safe
const CURATED_PROGRAMS: &[[u8; 32]] = &[
    pinocchio_pubkey::pubkey!("11111111111111111111111111111111"),
    pinocchio_pubkey::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
    pinocchio_pubkey::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"),
    pinocchio_pubkey::pubkey!("Stake11111111111111111111111111111111111111"),
];

/// Represents permission to interact with curated programs.
///
/// This action grants the authority the ability to make CPI calls to a
/// predefined list of popular and commonly used programs. This provides a
/// balance between security and functionality.
#[derive(NoPadding)]
#[repr(C, align(8))]
pub struct ProgramCurated {
    /// Reserved bytes for future use and alignment
    pub _reserved: [u8; 32],
}

impl ProgramCurated {
    /// Creates a new ProgramCurated permission
    pub fn new() -> Self {
        Self { _reserved: [0; 32] }
    }

    /// Checks if a program ID is in the curated list
    pub fn is_curated_program(program_id: &[u8; 32]) -> bool {
        CURATED_PROGRAMS.iter().any(|curated| curated == program_id)
    }

    /// Returns the list of curated program IDs
    pub fn get_curated_programs() -> &'static [[u8; 32]] {
        CURATED_PROGRAMS
    }
}

impl Default for ProgramCurated {
    fn default() -> Self {
        Self::new()
    }
}

impl Transmutable for ProgramCurated {
    /// Size of the ProgramCurated struct in bytes (32 bytes for alignment)
    const LEN: usize = 32;
}

impl IntoBytes for ProgramCurated {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl TransmutableMut for ProgramCurated {}

impl<'a> Actionable<'a> for ProgramCurated {
    /// This action represents the ProgramCurated permission type
    const TYPE: Permission = Permission::ProgramCurated;
    /// Only one ProgramCurated permission can exist per role
    const REPEATABLE: bool = false;

    /// Checks if the provided program ID is in the curated list.
    ///
    /// # Arguments
    /// * `data` - The program ID to check against (first 32 bytes)
    fn match_data(&self, data: &[u8]) -> bool {
        if data.len() < 32 {
            return false;
        }

        let program_id: [u8; 32] = match data[0..32].try_into() {
            Ok(id) => id,
            Err(_) => return false,
        };

        Self::is_curated_program(&program_id)
    }
}
