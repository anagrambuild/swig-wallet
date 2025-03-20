use crate::Transmutable;

use super::{Actionable, Permission};

pub struct SolLimit {
    pub amount: u64,
}

impl Transmutable for SolLimit {
    const LEN: usize = core::mem::size_of::<SolLimit>();
}

impl<'a> Actionable<'a> for SolLimit {
    const TYPE: Permission = Permission::SolLimit;

    fn from_bytes(bytes: &[u8]) -> &Self {
        // TODO: Fix the unwrap.
        unsafe { SolLimit::load_unchecked(bytes).unwrap() }
    }

    /// TODO
    fn validate(&mut self) {
        todo!()
    }
}
