use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::IntoBytes;
use crate::Transmutable;
use crate::TransmutableMut;

#[repr(C)]
pub struct ManageAuthority;

impl Transmutable for ManageAuthority {
    const LEN: usize = 0; // Since this is just a marker with no data
}

impl TransmutableMut for ManageAuthority {}

impl<'a> IntoBytes<'a> for ManageAuthority {
    fn into_bytes(&'a self) -> Result<&'a [u8], ProgramError> {
        Ok(&[])
    }
}

impl<'a> Actionable<'a> for ManageAuthority {
    const TYPE: Permission = Permission::ManageAuthority;
    const REPEATABLE: bool = false;
}
