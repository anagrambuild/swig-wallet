use super::{Actionable, Permission};

use crate::{Transmutable, TransmutableMut};

// SANITY CHECK: Make sure the type size is a multiple of 8 bytes.
static_assertions::const_assert!(core::mem::size_of::<SolRecurringLimit>() % 8 == 0);

#[repr(C)]
pub struct SolRecurringLimit {
    pub recurring_amount: u64,
    pub window: u64,
    pub last_reset: u64,
    pub current_amount: u64,
}

impl Transmutable for SolRecurringLimit {
    const LEN: usize = core::mem::size_of::<SolRecurringLimit>();
}

impl TransmutableMut for SolRecurringLimit {}

impl<'a> Actionable<'a> for SolRecurringLimit {
    const TYPE: Permission = Permission::SolRecurringLimit;

    /// TODO
    fn validate(&mut self) {
        todo!()
    }
}
