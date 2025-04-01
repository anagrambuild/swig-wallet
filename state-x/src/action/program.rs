use super::{Actionable, Permission};

use crate::{Transmutable, TransmutableMut};

static_assertions::const_assert!(core::mem::size_of::<Program>() % 8 == 0);

#[repr(C)]
pub struct Program {
    pub program_id: [u8; 32],
}

impl Transmutable for Program {
    const LEN: usize = 32;
}

impl TransmutableMut for Program {}

impl<'a> Actionable<'a> for Program {
    const TYPE: Permission = Permission::Program;

    /// TODO
    fn validate(&mut self) {
        todo!()
    }
}
