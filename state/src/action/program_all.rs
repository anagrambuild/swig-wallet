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
#[derive(NoPadding)]
#[repr(C, align(8))]
pub struct ProgramAll {
    /// Reserved bytes for future use and alignment
    pub _reserved: [u8; 32],
}

impl ProgramAll {
    /// Creates a new ProgramAll permission
    pub fn new() -> Self {
        Self { _reserved: [0; 32] }
    }
}

impl Default for ProgramAll {
    fn default() -> Self {
        Self::new()
    }
}

impl Transmutable for ProgramAll {
    /// Size of the ProgramAll struct in bytes (32 bytes for alignment)
    const LEN: usize = 32;
}

impl IntoBytes for ProgramAll {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
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
    /// * `_data` - The program ID to check against (ignored for ProgramAll)
    fn match_data(&self, _data: &[u8]) -> bool {
        true
    }
}
