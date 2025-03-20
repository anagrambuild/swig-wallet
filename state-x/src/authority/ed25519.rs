use crate::Transmutable;

use super::{AuthorityData, AuthorityType};

pub struct ED25519 {
    pub proof: [u8; 32],
}

impl<'a> AuthorityData<'a> for ED25519 {
    const TYPE: AuthorityType = AuthorityType::Ed25519;

    fn length(&self) -> usize {
        self.proof.len()
    }
}

impl Transmutable for ED25519 {
    const LEN: usize = core::mem::size_of::<ED25519>();
}
