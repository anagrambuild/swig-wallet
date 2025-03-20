use crate::Transmutable;

use super::{Actionable, Permission};

pub struct SolRecurringLimit {
    pub recurring_amount: u64,
    pub window: u64,
    pub last_reset: u64,
    pub current_amount: u64,
}

impl Transmutable for SolRecurringLimit {
    const LEN: usize = core::mem::size_of::<SolRecurringLimit>();
}

impl<'a> Actionable<'a> for SolRecurringLimit {
    const TYPE: Permission = Permission::SolRecurringLimit;

    fn from_bytes(bytes: &[u8]) -> &Self {
        // TODO: Fix the unwrap.
        unsafe { SolRecurringLimit::load_unchecked(bytes).unwrap() }
    }

    /// TODO
    fn validate(&mut self) {
        todo!()
    }
}
