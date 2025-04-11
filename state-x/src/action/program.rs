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

static_assertions::const_assert!(core::mem::size_of::<Program>() % 8 == 0);
#[repr(C)]
pub struct ProgramScope {
    pub program_id: [u8; 32],
    pub actions: [u8; 8],
}

impl Transmutable for ProgramScope {
    const LEN: usize = 40;
}

impl IntoBytes for ProgramScope {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl TransmutableMut for ProgramScope {}
impl<'a> Actionable<'a> for ProgramScope {
    const TYPE: Permission = Permission::ProgramScope;
    const REPEATABLE: bool = true;

    fn match_data(&self, data: &[u8]) -> bool {
        data[0..32] == self.program_id
    }
}
