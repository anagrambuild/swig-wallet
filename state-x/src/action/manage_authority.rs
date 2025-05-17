//! Authority management action type.
//!
//! This module defines the ManageAuthority action type which grants permission
//! to manage authority settings within the Swig wallet system.

use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Represents permission to manage authority settings.
///
/// This is a marker struct that grants access to authority management
/// operations such as adding, removing, or modifying authorities. It contains
/// no data since its mere presence indicates management access.
#[repr(C)]
pub struct ManageAuthority;

impl Transmutable for ManageAuthority {
    const LEN: usize = 0; // Since this is just a marker with no data
}

impl TransmutableMut for ManageAuthority {}

impl IntoBytes for ManageAuthority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(&[])
    }
}

impl<'a> Actionable<'a> for ManageAuthority {
    /// This action represents the ManageAuthority permission type
    const TYPE: Permission = Permission::ManageAuthority;
    /// Only one instance of authority management permissions can exist per role
    const REPEATABLE: bool = false;
}
