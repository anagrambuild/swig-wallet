//! Permission to close token accounts without closing the Swig wallet.

use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Allows token-account closure while retaining spending and destination
/// checks. This marker does not authorize closing Swig or changing its rent
/// claimer.
#[repr(C)]
pub struct CloseTokenAccount;

impl Transmutable for CloseTokenAccount {
    const LEN: usize = 0;
}

impl TransmutableMut for CloseTokenAccount {}

impl IntoBytes for CloseTokenAccount {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(&[])
    }
}

impl Actionable<'_> for CloseTokenAccount {
    const TYPE: Permission = Permission::CloseTokenAccount;
    const REPEATABLE: bool = false;

    fn match_data(&self, _data: &[u8]) -> bool {
        true
    }
}
