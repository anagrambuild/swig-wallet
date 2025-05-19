//! Authority module for the State-X crate.
//!
//! This module provides functionality for managing different types of
//! authorities in the Swig wallet system. It includes support for various
//! authentication methods like Ed25519 and Secp256k1, with both standard and
//! session-based variants.

pub mod ed25519;
pub mod secp256k1;

use std::any::Any;

use ed25519::{ED25519Authority, Ed25519SessionAuthority};
use pinocchio::{account_info::AccountInfo, program_error::ProgramError};
use secp256k1::{Secp256k1Authority, Secp256k1SessionAuthority};

use crate::{IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut};

/// Trait for authority data structures.
///
/// The `Authority` trait defines the interface for different types of
/// authentication authorities in the system. Each authority type has its own
/// specific data format and authentication mechanism.
pub trait Authority: Transmutable + TransmutableMut + IntoBytes {
    /// The type of authority this implementation represents
    const TYPE: AuthorityType;
    /// Whether this authority supports session-based authentication
    const SESSION_BASED: bool;

    /// Sets the authority data from raw bytes.
    ///
    /// # Arguments
    /// * `create_data` - The raw data to create the authority from
    /// * `bytes` - The buffer to write the authority data to
    fn set_into_bytes(create_data: &[u8], bytes: &mut [u8]) -> Result<(), ProgramError>;
}

/// Trait for authority information and operations.
///
/// This trait defines the interface for interacting with authorities,
/// including authentication and session management.
pub trait AuthorityInfo: IntoBytes {
    /// Returns the type of this authority
    fn authority_type(&self) -> AuthorityType;

    /// Returns the length of the authority data in bytes
    fn length(&self) -> usize;

    /// Returns whether this authority supports session-based authentication
    fn session_based(&self) -> bool;

    /// Checks if this authority matches the provided data
    fn match_data(&self, data: &[u8]) -> bool;

    /// Returns this authority as a dynamic Any type
    fn as_any(&self) -> &dyn Any;

    /// Returns the identity bytes for this authority
    fn identity(&self) -> Result<&[u8], ProgramError>;

    /// Authenticates a session-based operation.
    ///
    /// # Arguments
    /// * `account_infos` - Account information for the operation
    /// * `authority_payload` - Authority-specific payload data
    /// * `data_payload` - Operation-specific payload data
    /// * `slot` - Current slot number
    /// * `additional_payload` - Any extra payload required to authenticate
    fn authenticate_session(
        &mut self,
        _account_infos: &[AccountInfo],
        _authority_payload: &[u8],
        _data_payload: &[u8],
        _slot: u64,
    ) -> Result<(), ProgramError> {
        Err(SwigAuthenticateError::AuthorityDoesNotSupportSessionBasedAuth.into())
    }

    /// Starts a new authentication session.
    ///
    /// # Arguments
    /// * `session_key` - Key for the new session
    /// * `current_slot` - Current slot number
    /// * `duration` - Duration of the session
    fn start_session(
        &mut self,
        _session_key: [u8; 32],
        _current_slot: u64,
        _duration: u64,
    ) -> Result<(), ProgramError> {
        Err(SwigAuthenticateError::AuthorityDoesNotSupportSessionBasedAuth.into())
    }

    /// Authenticates a standard (non-session) operation.
    ///
    /// # Arguments
    /// * `account_infos` - Account information for the operation
    /// * `authority_payload` - Authority-specific payload data
    /// * `data_payload` - Operation-specific payload data
    /// * `slot` - Current slot number
    /// * `addtional_paylaod` - Any extra payload required to authenticate
    fn authenticate(
        &mut self,
        account_infos: &[AccountInfo],
        authority_payload: &[u8],
        data_payload: &[u8],
        slot: u64,
    ) -> Result<(), ProgramError>;
}

/// Represents different types of authorities supported by the system.
#[derive(Debug, PartialEq)]
#[repr(u16)]
pub enum AuthorityType {
    /// No authority (invalid state)
    None,
    /// Standard Ed25519 authority
    Ed25519,
    /// Session-based Ed25519 authority
    Ed25519Session,
    /// Standard Secp256k1 authority
    Secp256k1,
    /// Session-based Secp256k1 authority
    Secp256k1Session,
    /// Session-based Secp256r1 authority
    Secp256r1Session,
    /// Session-based R1 Passkey authority
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

/// Returns the length in bytes for a given authority type.
///
/// # Arguments
/// * `authority_type` - The type of authority to get the length for
///
/// # Returns
/// * `Ok(usize)` - The length in bytes for the authority type
/// * `Err(ProgramError)` - If the authority type is not supported
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
