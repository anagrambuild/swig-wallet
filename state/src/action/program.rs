//! Program interaction action type.
//!
//! This module defines the Program action type which grants permission to
//! interact with specific programs in the Swig wallet system.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Represents permission to interact with a specific program.
///
/// This struct contains the program ID that the role is allowed to interact
/// with. Multiple Program actions can exist in a role to allow interaction with
/// different programs.
#[derive(NoPadding)]
#[repr(C, align(8))]
pub struct Program {
    /// The program ID that this permission grants access to
    pub program_id: [u8; 32],
}

impl Transmutable for Program {
    /// Size of the Program struct in bytes (32 bytes for program_id)
    const LEN: usize = 32;
}

impl IntoBytes for Program {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl TransmutableMut for Program {}

impl<'a> Actionable<'a> for Program {
    /// This action represents the Program permission type
    const TYPE: Permission = Permission::Program;
    /// Multiple program permissions can exist per role
    const REPEATABLE: bool = true;

    /// Checks if this program permission matches the provided program ID.
    ///
    /// # Arguments
    /// * `data` - The program ID to check against (first 32 bytes)
    fn match_data(&self, data: &[u8]) -> bool {
        data[0..32] == self.program_id
    }
}
