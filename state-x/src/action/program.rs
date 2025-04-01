use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

static_assertions::const_assert!(core::mem::size_of::<Program>() % 8 == 0);
#[repr(C)]
pub struct Program {
    pub program_id: [u8; 32],
}

impl Transmutable for Program {
    const LEN: usize = 32; // Since this is just a marker with no data
}

impl<'a> IntoBytes<'a> for Program {
    fn into_bytes(&'a self) -> Result<&'a [u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl TransmutableMut for Program {}
impl<'a> Actionable<'a> for Program {
    const TYPE: Permission = Permission::Program;

    fn validate(&mut self) {
        // No validation needed for a marker type
    }
}
