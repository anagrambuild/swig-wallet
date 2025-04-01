use super::{Actionable, Permission};

use crate::{AsBytes, Transmutable, TransmutableMut};

// SANITY CHECK: Make sure the type size is a multiple of 8 bytes.
static_assertions::const_assert!(core::mem::size_of::<SolLimit>() % 8 == 0);

pub struct SolLimit {
    pub amount: u64,
}

impl Transmutable for SolLimit {
    const LEN: usize = core::mem::size_of::<SolLimit>();
}

impl TransmutableMut for SolLimit {}

impl<'a> AsBytes<'a> for SolLimit {}

impl<'a> Actionable<'a> for SolLimit {
    const TYPE: Permission = Permission::SolLimit;

    /// TODO
    fn validate(&mut self) {
        todo!()
    }
}
