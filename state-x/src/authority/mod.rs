pub mod ed25519;

use ed25519::ED25519Authority;
use pinocchio::{account_info::AccountInfo, msg, program_error::ProgramError};

use crate::{IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut};

/// Trait for authority data.
///
/// The `Authority` defines the data of a particular authority.
pub trait Authority<'a>: Transmutable + TransmutableMut + IntoBytes<'a> {
    const TYPE: AuthorityType;
    const SESSION_BASED: bool;

    fn length(&self) -> usize;
}

pub trait AuthorityInfo {
    fn authority_type(&self) -> AuthorityType;

    fn session_based(&self) -> bool;

    fn match_data(&self, data: &[u8]) -> bool;

    fn authenticate_session(
        &self,
        _account_infos: &[AccountInfo],
        _authority_payload: &[u8],
        _data_payload: &[u8],
        _slot: u64,
    ) -> Result<(), ProgramError> {
        return Err(SwigAuthenticateError::AuthorityDoesNotSupportSessionBasedAuth.into());
    }

    fn authenticate(
        &self,
        account_infos: &[AccountInfo],
        authority_payload: &[u8],
        data_payload: &[u8],
        slot: u64,
    ) -> Result<(), ProgramError>;
}

#[derive(Debug, PartialEq)]
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
            1 => Ok(AuthorityType::Ed25519),
            2 => Ok(AuthorityType::Ed25519Session),
            3 => Ok(AuthorityType::Secp256k1),
            4 => Ok(AuthorityType::Secp256k1Session),
            5 => Ok(AuthorityType::Secp256r1Session),
            6 => Ok(AuthorityType::R1PasskeySession),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

pub struct AuthorityLoader;

impl AuthorityLoader {
    #[inline(always)]
    pub fn authority_discriminator(data: &[u8]) -> Result<AuthorityType, ProgramError> {
        let discriminator = u16::from_le_bytes(data[0..2].try_into().unwrap());
        AuthorityType::try_from(discriminator)
    }

    pub fn load_authority<'a>(
        authority_type: AuthorityType,
        authority_data: &'a [u8],
    ) -> Result<&'a impl Authority<'a>, ProgramError> {
        match authority_type {
            AuthorityType::Ed25519 => {
                if authority_data.len() != ED25519Authority::LEN {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let authority = unsafe { ED25519Authority::load_unchecked(authority_data)? };
                Ok(authority)
            },
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}
