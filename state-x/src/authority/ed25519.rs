use super::{Authority, AuthorityType};

use crate::{AsBytes, Transmutable, TransmutableMut};

// SANITY CHECK: Make sure the type size is a multiple of 8 bytes.
static_assertions::const_assert!(core::mem::size_of::<ED25519Authority>() % 8 == 0);

pub struct ED25519Authority {
    pub proof: [u8; 32],
}

impl<'a> Authority<'a> for ED25519Authority {
    const TYPE: AuthorityType = AuthorityType::Ed25519;

    fn length(&self) -> usize {
        self.proof.len()
    }
}

impl Transmutable for ED25519Authority {
    const LEN: usize = core::mem::size_of::<ED25519Authority>();
}

impl TransmutableMut for ED25519Authority {}

impl<'a> AsBytes<'a> for ED25519Authority {}
