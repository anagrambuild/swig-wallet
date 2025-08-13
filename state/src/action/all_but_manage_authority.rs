//! All but manage authority permission action type.
//!
//! This module defines the AllButManageAuthority action type which represents
//! permissions to perform all operations within the Swig wallet system except
//! authority management operations.

use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Represents all permissions except authority management.
///
/// This is a marker struct that grants access to all operations except
/// authority management (add/remove/update authorities & subaccounts). It
/// contains no data since its mere presence indicates the restricted access
/// level.
pub struct AllButManageAuthority;

impl Transmutable for AllButManageAuthority {
    const LEN: usize = 0; // Since this is just a marker with no data
}

impl TransmutableMut for AllButManageAuthority {}

impl IntoBytes for AllButManageAuthority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(&[])
    }
}

impl<'a> Actionable<'a> for AllButManageAuthority {
    /// This action represents the AllButManageAuthority permission type
    const TYPE: Permission = Permission::AllButManageAuthority;
    /// Only one instance of AllButManageAuthority permissions can exist per
    /// role
    const REPEATABLE: bool = false;

    /// Returns true for all data except authority management operations.
    /// This should be handled by the permission checking logic in the program.
    fn match_data(&self, _data: &[u8]) -> bool {
        true
    }
}
