#[macro_use]
pub mod bloom;

pub mod ed25519;
pub mod secp256k1;

use std::any::Any;

use ed25519::{ED25519Authority, Ed25519SessionAuthority};
use pinocchio::{account_info::AccountInfo, program_error::ProgramError};
use secp256k1::{Secp256k1Authority, Secp256k1SessionAuthority};

use crate::{IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut};

/// Trait for authority data.
///
/// The `Authority` defines the data of a particular authority.
pub trait Authority: Transmutable + TransmutableMut + IntoBytes {
    const TYPE: AuthorityType;
    const SESSION_BASED: bool;

    fn set_into_bytes(create_data: &[u8], bytes: &mut [u8]) -> Result<(), ProgramError>;
}

pub trait AuthorityInfo: IntoBytes {
    fn authority_type(&self) -> AuthorityType;

    fn length(&self) -> usize;

    fn session_based(&self) -> bool;

    fn match_data(&self, data: &[u8]) -> bool;

    fn as_any(&self) -> &dyn Any;

    fn identity(&self) -> Result<&[u8], ProgramError>;

    fn authenticate_session(
        &mut self,
        _account_infos: &[AccountInfo],
        _authority_payload: &[u8],
        _data_payload: &[u8],
        _slot: u64,
    ) -> Result<(), ProgramError> {
        Err(SwigAuthenticateError::AuthorityDoesNotSupportSessionBasedAuth.into())
    }

    fn start_session(
        &mut self,
        _session_key: [u8; 32],
        _current_slot: u64,
        _duration: u64,
    ) -> Result<(), ProgramError> {
        Err(SwigAuthenticateError::AuthorityDoesNotSupportSessionBasedAuth.into())
    }

    fn authenticate(
        &mut self,
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

pub const fn authority_type_to_length(
    authority_type: &AuthorityType,
) -> Result<usize, ProgramError> {
    match authority_type {
        AuthorityType::Ed25519 => Ok(ED25519Authority::LEN),
        AuthorityType::Ed25519Session => Ok(Ed25519SessionAuthority::LEN),
        AuthorityType::Secp256k1 => Ok(Secp256k1Authority::LEN),
        AuthorityType::Secp256k1Session => Ok(Secp256k1SessionAuthority::LEN),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
