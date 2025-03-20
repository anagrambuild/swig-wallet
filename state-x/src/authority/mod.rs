pub mod ed25519;

use pinocchio::program_error::ProgramError;

use crate::Transmutable;

#[repr(C)]
pub struct Authority {
    /// Data section.
    ///   0. type
    ///   1. ID
    ///   2. length
    ///   3. boundary
    data: [u16; 4],
}

impl Transmutable for Authority {
    const LEN: usize = core::mem::size_of::<Authority>();
}

impl Authority {
    pub fn authority_type(&self) -> Result<AuthorityType, ProgramError> {
        AuthorityType::try_from(self.data[0])
    }

    pub fn id(&self) -> u16 {
        self.data[1]
    }

    pub fn length(&self) -> u16 {
        self.data[2]
    }

    pub fn boundary(&self) -> u16 {
        self.data[3]
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

/// Trait for authority data.
///
/// The `AuthorityData` defines the data of a particular authority.
pub trait AuthorityData<'a>: Transmutable {
    const TYPE: AuthorityType;

    fn length(&self) -> usize {
        Self::LEN
    }
}
