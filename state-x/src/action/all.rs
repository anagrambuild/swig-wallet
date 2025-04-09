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

impl IntoBytes for All {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(&[])
    }
}

impl<'a> Actionable<'a> for All {
    const TYPE: Permission = Permission::All;
    const REPEATABLE: bool = false;

    fn match_data(&self, _data: &[u8]) -> bool {
        true
    }
}
