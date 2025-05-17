//! All permission action type.
//!
//! This module defines the All action type which represents unrestricted
//! permissions within the Swig wallet system.

use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Represents unrestricted permissions in the system.
///
/// This is a marker struct that grants full access to all operations.
/// It contains no data since its mere presence indicates complete access.
pub struct All;

impl Transmutable for All {
    const LEN: usize = 0; // Since this is just a marker with no data
}

impl TransmutableMut for All {}

impl IntoBytes for All {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(&[])
    }
}

impl<'a> Actionable<'a> for All {
    /// This action represents the All permission type
    const TYPE: Permission = Permission::All;
    /// Only one instance of All permissions can exist per role
    const REPEATABLE: bool = false;

    /// Always returns true since this represents unrestricted access.
    fn match_data(&self, _data: &[u8]) -> bool {
        true
    }
}
