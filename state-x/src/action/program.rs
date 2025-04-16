use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

#[derive(NoPadding)]
#[repr(C, align(8))]
pub struct Program {
    pub program_id: [u8; 32],
}

impl Transmutable for Program {
    const LEN: usize = 32; // Since this is just a marker with no data
}

impl IntoBytes for Program {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl TransmutableMut for Program {}
impl<'a> Actionable<'a> for Program {
    const TYPE: Permission = Permission::Program;
    const REPEATABLE: bool = true;

    fn match_data(&self, data: &[u8]) -> bool {
        data[0..32] == self.program_id
    }
}
