//! Close swig authority permission action type.
//!
//! This module defines the CloseSwigAuthority action type which grants permission
//! to close token accounts and the swig account itself within the Swig wallet system.

use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Represents permission to close swig-related accounts.
///
/// This is a marker struct that grants access to close operations
/// such as closing token accounts and closing the swig account. It contains
/// no data since its mere presence indicates close access.
#[repr(C)]
pub struct CloseSwigAuthority;

impl Transmutable for CloseSwigAuthority {
    const LEN: usize = 0; // Since this is just a marker with no data
}

impl TransmutableMut for CloseSwigAuthority {}

impl IntoBytes for CloseSwigAuthority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(&[])
    }
}

impl<'a> Actionable<'a> for CloseSwigAuthority {
    /// This action represents the CloseSwigAuthority permission type
    const TYPE: Permission = Permission::CloseSwigAuthority;
    /// Only one instance of close swig authority permissions can exist per role
    const REPEATABLE: bool = false;

    /// Always returns true since this represents close account access.
    fn match_data(&self, _data: &[u8]) -> bool {
        true
    }
}
