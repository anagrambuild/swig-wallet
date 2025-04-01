use super::{Actionable, Permission};

use crate::{Transmutable, TransmutableMut};

// SANITY CHECK: Make sure the type size is a multiple of 8 bytes.
static_assertions::const_assert!(core::mem::size_of::<TokenLimit>() % 8 == 0);

#[repr(C)]
pub struct TokenLimit {
    pub token_mint: [u8; 32],
    pub current_amount: u64,
}

impl Transmutable for TokenLimit {
    const LEN: usize = 40;
}

impl TransmutableMut for TokenLimit {}

impl<'a> Actionable<'a> for TokenLimit {
    const TYPE: Permission = Permission::TokenLimit;

    /// TODO
    fn validate(&mut self) {
        todo!()
    }
}
