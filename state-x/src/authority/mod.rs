pub mod ed25519;

use pinocchio::program_error::ProgramError;

use crate::{Transmutable, TransmutableMut};

/// Trait for authority data.
///
/// The `Authority` defines the data of a particular authority.
pub trait Authority<'a>: Transmutable + TransmutableMut {
    const TYPE: AuthorityType;

    fn length(&self) -> usize {
        Self::LEN
    }
}

#[derive(PartialEq)]
#[repr(u16)]
pub enum AuthorityType {
    None,
    Ed25519,
    Ed25519Session,
    Secp256k1,
    Secp256k1Session,
    Secp256r1Session,
    R1PasskeySession,
}

impl TryFrom<u16> for AuthorityType {
    type Error = ProgramError;

    #[inline(always)]
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            // SAFETY: `value` is guaranteed to be in the range of the enum variants.
            0..=6 => Ok(unsafe { core::mem::transmute::<u16, AuthorityType>(value) }),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}
