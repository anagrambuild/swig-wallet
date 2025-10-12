//! ManageAuthorizationLocks action type.
//!
//! This module defines the ManageAuthorizationLocks action type which represents
//! the permission to manage authorization locks within the Swig wallet system.

use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Represents the permission to manage authorization locks.
///
/// This is a marker struct that grants permission to manage authorization locks.
/// The actual locks are stored as individual AuthorizationLock instances that follow
/// this header in the action data.
pub struct ManageAuthorizationLocks;

impl ManageAuthorizationLocks {
    /// Creates a new ManageAuthorizationLocks instance.
    ///
    /// # Returns
    /// * `Self` - A new instance
    pub fn new() -> Self {
        Self
    }
}

impl Transmutable for ManageAuthorizationLocks {
    const LEN: usize = 0; // This is just a marker with no data
}

impl TransmutableMut for ManageAuthorizationLocks {}

impl IntoBytes for ManageAuthorizationLocks {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(&[])
    }
}

impl<'a> Actionable<'a> for ManageAuthorizationLocks {
    /// This action represents the ManageAuthorizationLocks permission type
    const TYPE: Permission = Permission::ManageAuthorizationLocks;
    /// Only one instance of ManageAuthorizationLocks can exist per role
    const REPEATABLE: bool = false;

    /// Always returns true since this represents management access.
    fn match_data(&self, _data: &[u8]) -> bool {
        true
    }
}
