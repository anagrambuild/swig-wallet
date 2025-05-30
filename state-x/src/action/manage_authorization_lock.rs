//! Authorization lock management action type.
//!
//! This module defines the ManageAuthorizationLock action type which grants permission
//! to manage authorization lock settings within the Swig wallet system.

use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Represents permission to manage authorization lock settings.
///
/// This is a marker struct that grants access to authorization lock management
/// operations such as adding, removing, or modifying authorization locks. It contains
/// no data since its mere presence indicates management access.
#[repr(C)]
pub struct ManageAuthorizationLock;

impl Transmutable for ManageAuthorizationLock {
    const LEN: usize = 0; // Since this is just a marker with no data
}

impl TransmutableMut for ManageAuthorizationLock {}

impl IntoBytes for ManageAuthorizationLock {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(&[])
    }
}

impl<'a> Actionable<'a> for ManageAuthorizationLock {
    /// This action represents the ManageAuthorizationLock permission type
    const TYPE: Permission = Permission::ManageAuthorizationLock;
    /// Only one instance of authorization lock management permissions can exist per role
    const REPEATABLE: bool = false;
}
