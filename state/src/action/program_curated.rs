//! Program Curated action type.
//!
//! This module defines the ProgramCurated action type which grants permission to
//! interact with a curated list of popular programs in the Swig wallet system.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Curated program IDs that are commonly used and considered safe
const CURATED_PROGRAMS: &[[u8; 32]] = &[
    // System Program (11111111111111111111111111111111)
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    // SPL Token Program (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
    [6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169],
    // SPL Token 2022 Program (TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb)
    [6, 221, 246, 225, 238, 117, 143, 222, 138, 60, 137, 215, 166, 35, 250, 133, 224, 81, 209, 114, 91, 157, 99, 29, 94, 145, 213, 104, 233, 4, 16, 238],
    // Staking Program (Stake11111111111111111111111111111111111111)
    [6, 161, 216, 23, 145, 55, 84, 42, 152, 52, 55, 189, 254, 42, 122, 178, 85, 86, 165, 18, 7, 142, 233, 0, 0, 0, 0, 0, 0, 0, 0, 0],
];

/// Represents permission to interact with curated programs.
///
/// This action grants the authority the ability to make CPI calls to a predefined
/// list of popular and commonly used programs. This provides a balance between
/// security and functionality.
#[derive(NoPadding)]
#[repr(C, align(8))]
pub struct ProgramCurated {
    /// Reserved bytes for future use and alignment
    pub _reserved: [u8; 32],
}

impl ProgramCurated {
    /// Creates a new ProgramCurated permission
    pub fn new() -> Self {
        Self {
            _reserved: [0; 32],
        }
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