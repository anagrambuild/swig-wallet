//! Authority module for the state crate.
//!
//! This module provides functionality for managing different types of
//! authorities in the Swig wallet system. It includes support for various
//! authentication methods like Ed25519 and Secp256k1, with both standard and
//! session-based variants.

pub mod ed25519;
pub mod secp256k1;
pub mod secp256r1;

use std::any::Any;

use ed25519::{ED25519Authority, Ed25519SessionAuthority};
use pinocchio::{account_info::AccountInfo, program_error::ProgramError};
use secp256k1::{Secp256k1Authority, Secp256k1SessionAuthority};
use secp256r1::{Secp256r1Authority, Secp256r1SessionAuthority};

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

    /// Returns the signature odometer for this authority if it exists
    fn signature_odometer(&self) -> Option<u32>;

    /// Authenticates a session-based operation.
    ///
    /// # Arguments
    /// * `account_infos` - Account information for the operation
    /// * `authority_payload` - Authority-specific payload data
    /// * `data_payload` - Operation-specific payload data
    /// * `slot` - Current slot number
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
    fn authenticate(
        &mut self,
        account_infos: &[AccountInfo],
        authority_payload: &[u8],
        data_payload: &[u8],
        slot: u64,
    ) -> Result<(), ProgramError>;
}

/// Represents different types of authorities supported by the system.
#[derive(Debug, PartialEq, Copy, Clone)]
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
    /// Standard Secp256r1 authority (for passkeys)
    Secp256r1,
    /// Session-based Secp256r1 authority
    Secp256r1Session,
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
            5 => Ok(AuthorityType::Secp256r1),
            6 => Ok(AuthorityType::Secp256r1Session),
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
        AuthorityType::Secp256r1 => Ok(Secp256r1Authority::LEN),
        AuthorityType::Secp256r1Session => Ok(Secp256r1SessionAuthority::LEN),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// Authority mask utilities for efficient authority checking

/// Type alias for authority mask, using u64 to support up to 64 authorities.
pub type AuthorityMask = u64;

/// Maximum valid authority index (Secp256r1Session).
const MAX_AUTHORITY_INDEX: u16 = AuthorityType::Secp256r1Session as u16;

/// Converts an authority to its corresponding bit in the mask.
#[inline(always)]
fn authority_bit(authority: AuthorityType) -> AuthorityMask {
    1u64 << (authority as u16)
}

/// Converts an index to an AuthorityType enum variant if valid.
#[inline(always)]
fn authority_from_index(index: u16) -> Option<AuthorityType> {
    if index <= MAX_AUTHORITY_INDEX {
        // SAFETY: `index` is guaranteed to be within the range of the enum variants.
        Some(unsafe { core::mem::transmute::<u16, AuthorityType>(index) })
    } else {
        None
    }
}

/// Converts an iterator of authorities into an authority mask.
///
/// Each authority sets its corresponding bit in the mask.
pub fn authorities_to_mask<I>(authorities: I) -> AuthorityMask
where
    I: IntoIterator<Item = AuthorityType>,
{
    authorities
        .into_iter()
        .fold(0u64, |mask, authority| mask | authority_bit(authority))
}

/// Converts an authority mask back into a vector of authorities.
///
/// Only valid authority bits (within the enum range) are included.
pub fn mask_to_authorities(mask: AuthorityMask) -> Vec<AuthorityType> {
    let mut authorities = Vec::new();
    let mut remaining = mask;

    while remaining != 0 {
        let index = remaining.trailing_zeros() as u16;
        if let Some(authority) = authority_from_index(index) {
            authorities.push(authority);
        }
        remaining &= !(1u64 << index);
    }

    authorities
}

/// Checks if all requested authorities are present in the allowed mask.
///
/// Returns `true` if all bits set in `requested` are also set in `allowed`.
#[inline(always)]
pub fn check_authorities(allowed: AuthorityMask, requested: AuthorityMask) -> bool {
    (requested & allowed) == requested
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_authorities_to_mask_is_zero() {
        let mask = authorities_to_mask(core::iter::empty());
        assert_eq!(mask, 0);
    }

    #[test]
    fn single_authority_sets_correct_bit() {
        let mask = authorities_to_mask([AuthorityType::Ed25519]);
        assert_eq!(mask, 1u64 << (AuthorityType::Ed25519 as u16));
    }

    #[test]
    fn multiple_authorities_set_combined_bits() {
        let mask = authorities_to_mask([AuthorityType::Ed25519, AuthorityType::Secp256k1]);
        let expected =
            (1u64 << (AuthorityType::Ed25519 as u16)) | (1u64 << (AuthorityType::Secp256k1 as u16));
        assert_eq!(mask, expected);
    }

    #[test]
    fn mask_to_authorities_ignores_out_of_range_bits() {
        // Set a very high bit, beyond defined enum range
        let mask = 1u64 << 63;
        let auths = mask_to_authorities(mask);
        assert!(auths.is_empty());
    }

    #[test]
    fn mask_to_authorities_includes_highest_defined_authority() {
        let highest = AuthorityType::Secp256r1Session as u16;
        let mask = 1u64 << highest;
        let auths = mask_to_authorities(mask);
        assert_eq!(auths.len(), 1);
        assert_eq!(auths[0], AuthorityType::Secp256r1Session);
    }

    #[test]
    fn round_trip_authorities_to_mask_and_back() {
        let original = vec![
            AuthorityType::Ed25519,
            AuthorityType::Secp256k1,
            AuthorityType::Secp256r1,
        ];
        let mask = authorities_to_mask(original.clone());
        let round_tripped = mask_to_authorities(mask);

        // Check that all original authorities are present
        for auth in &original {
            assert!(round_tripped.contains(auth));
        }
        // Check that no extra authorities were added
        assert_eq!(round_tripped.len(), original.len());
    }

    #[test]
    fn round_trip_mask_to_authorities_and_back() {
        let mask =
            (1u64 << (AuthorityType::Ed25519 as u16)) | (1u64 << (AuthorityType::Secp256k1 as u16));
        println!("mask: {:?}", mask);
        let auths = mask_to_authorities(mask);
        println!("auths: {:?}", auths);
        let rebuilt_mask = authorities_to_mask(auths);
        println!("rebuilt_mask: {:?}", rebuilt_mask);
        assert_eq!(rebuilt_mask, mask);
    }

    #[test]
    fn check_authorities_validates_subset() {
        let allowed = authorities_to_mask([AuthorityType::Ed25519, AuthorityType::Secp256k1]);

        assert!(check_authorities(
            allowed,
            authorities_to_mask([AuthorityType::Ed25519])
        ));
        assert!(!check_authorities(
            allowed,
            authorities_to_mask([
                AuthorityType::Ed25519,
                AuthorityType::Secp256k1,
                AuthorityType::Secp256r1, // Not in allowed
            ])
        ));
        assert!(check_authorities(
            allowed,
            authorities_to_mask([AuthorityType::Ed25519, AuthorityType::Secp256k1])
        ));
    }
}
