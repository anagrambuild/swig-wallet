//! Recovery authority action type.
//!
//! This marker grants access only to the dedicated recovery instruction. It is
//! intentionally narrower than ManageAuthority.

use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Permission to rotate a recoverable passkey role through the recovery path.
#[repr(C)]
pub struct RecoveryAuthority;

impl Transmutable for RecoveryAuthority {
    const LEN: usize = 0;
}

impl TransmutableMut for RecoveryAuthority {}

impl IntoBytes for RecoveryAuthority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(&[])
    }
}

impl<'a> Actionable<'a> for RecoveryAuthority {
    const TYPE: Permission = Permission::RecoveryAuthority;
    const REPEATABLE: bool = false;

    fn match_data(&self, _data: &[u8]) -> bool {
        true
    }
}
