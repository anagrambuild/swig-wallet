use pinocchio::program_error::ProgramError;

use crate::{IntoBytes, Transmutable, TransmutableMut};

use super::{Authority, AuthorityType};

pub struct ED25519Authority {
    pub public_key: [u8; 32],
}

impl<'a> Authority<'a> for ED25519Authority {
    const TYPE: AuthorityType = AuthorityType::Ed25519;

    fn length(&self) -> usize {
        Self::LEN
    }
}

impl Transmutable for ED25519Authority {
    const LEN: usize = core::mem::size_of::<ED25519Authority>();
}

impl TransmutableMut for ED25519Authority {}

impl<'a> IntoBytes<'a> for ED25519Authority {
    fn into_bytes(&'a self) -> Result<&'a [u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}
