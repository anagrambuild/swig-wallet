use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

pub struct StakeAll;

impl Transmutable for StakeAll {
    const LEN: usize = 0; // Since this is just a marker with no data
}

impl TransmutableMut for StakeAll {}

impl IntoBytes for StakeAll {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(&[])
    }
}

impl<'a> Actionable<'a> for StakeAll {
    const TYPE: Permission = Permission::StakeAll;
    const REPEATABLE: bool = false;

    fn match_data(&self, _data: &[u8]) -> bool {
        true
    }
}
