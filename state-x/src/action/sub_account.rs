use super::{Actionable, Permission};

use crate::{Transmutable, TransmutableMut};

// SANITY CHECK: Make sure the type size is a multiple of 8 bytes.
static_assertions::const_assert!(core::mem::size_of::<SubAccount>() % 8 == 0);

pub struct SubAccount {
    pub sub_account: [u8; 32],
}

impl Transmutable for SubAccount {
    const LEN: usize = 32;
}

impl TransmutableMut for SubAccount {}

impl<'a> Actionable<'a> for SubAccount {
    const TYPE: Permission = Permission::SubAccount;

    /// TODO
    fn validate(&mut self) {
        todo!()
    }
}
