use super::{Authority, AuthorityType, TypedAuthority};

use crate::{Transmutable, TransmutableMut};

// SANITY CHECK: Make sure the type size is a multiple of 8 bytes.
static_assertions::const_assert!(core::mem::size_of::<SECP256K1Authority>() % 8 == 0);

pub struct SECP256K1Authority {
    pub id: u64,
}

impl<'a> Authority<'a> for SECP256K1Authority {
    const TYPE: AuthorityType = AuthorityType::Secp256k1;

    fn length(&self) -> usize {
        1
    }
}

impl Transmutable for SECP256K1Authority {
    const LEN: usize = core::mem::size_of::<SECP256K1Authority>();
}

impl TransmutableMut for SECP256K1Authority {}

impl TypedAuthority for SECP256K1Authority {
    fn authority_type(&self) -> AuthorityType {
        AuthorityType::Secp256k1
    }
}
