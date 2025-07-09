//! Program All action type.
//!
//! This module defines the ProgramAll action type which grants permission to
//! interact with any program in the Swig wallet system (unrestricted CPI
//! access).

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Represents permission to interact with any program (unrestricted CPI
/// access).
///
/// This action grants the authority the ability to make CPI calls to any
/// program without restrictions. This is the most permissive program permission
/// and should be used with caution.
pub struct ProgramAll;

impl ProgramAll {
    /// Creates a new ProgramAll permission
    pub fn new() -> Self {
        Self
    }
}

impl Default for ProgramAll {
    fn default() -> Self {
        Self::new()
    }
}

impl Transmutable for ProgramAll {
    /// Size of the ProgramAll struct in bytes (32 bytes for alignment)
    const LEN: usize = 0;
}

impl IntoBytes for ProgramAll {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(&[])
    }
}

impl TransmutableMut for ProgramAll {}

impl<'a> Actionable<'a> for ProgramAll {
    /// This action represents the ProgramAll permission type
    const TYPE: Permission = Permission::ProgramAll;
    /// Only one ProgramAll permission can exist per role
    const REPEATABLE: bool = false;

    /// Always returns true since this grants access to all programs.
    ///
    /// # Arguments
    /// * `_data` - unused
    fn match_data(&self, _data: &[u8]) -> bool {
        true
    }
}
