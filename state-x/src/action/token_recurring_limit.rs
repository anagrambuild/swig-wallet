use super::{Actionable, Permission};

use crate::{AsBytes, Transmutable, TransmutableMut};

// SANITY CHECK: Make sure the type size is a multiple of 8 bytes.
static_assertions::const_assert!(core::mem::size_of::<TokenRecurringLimit>() % 8 == 0);

#[repr(C)]
pub struct TokenRecurringLimit {
    pub token_mint: [u8; 32],
    pub window: u64,
    pub limit: u64,
    pub current: u64,
    pub last_reset: u64,
}

impl Transmutable for TokenRecurringLimit {
    const LEN: usize = 64;
}

impl TransmutableMut for TokenRecurringLimit {}

impl<'a> AsBytes<'a> for TokenRecurringLimit {}

impl<'a> Actionable<'a> for TokenRecurringLimit {
    const TYPE: Permission = Permission::TokenRecurringLimit;

    /// TODO
    fn validate(&mut self) {
        todo!()
    }
}
