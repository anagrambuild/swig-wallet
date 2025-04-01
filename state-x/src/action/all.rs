use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::IntoBytes;
use crate::Transmutable;
use crate::TransmutableMut;

pub struct All;

impl Transmutable for All {
    const LEN: usize = 0; // Since this is just a marker with no data
}

impl TransmutableMut for All {}

impl<'a> IntoBytes<'a> for All {
    fn into_bytes(&'a self) -> Result<&'a [u8], ProgramError> {
        Ok(&[])
    }
}

impl<'a> Actionable<'a> for All {
    const TYPE: Permission = Permission::All;

    fn validate(&mut self) {
        // No validation needed for a marker type
    }
}
