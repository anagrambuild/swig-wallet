//! Global authority implementation.
//!
//! This module provides a GlobalAuthority that can contain any of the existing
//! authority types. It acts as a wrapper that enables polymorphic authority
//! handling while maintaining type safety and performance.

use core::any::Any;

use no_padding::NoPadding;
use pinocchio::{account_info::AccountInfo, program_error::ProgramError};

use super::{Authority, AuthorityInfo, AuthorityType};
use crate::{IntoBytes, SwigStateError, Transmutable, TransmutableMut};

// Import all authority types for dynamic dispatch
use super::ed25519::{ED25519Authority, Ed25519SessionAuthority};
use super::secp256k1::{Secp256k1Authority, Secp256k1SessionAuthority};
use super::secp256r1::{Secp256r1Authority, Secp256r1SessionAuthority};

/// Maximum size needed to store any authority type
/// Based on the largest authority (Secp256k1SessionAuthority or Secp256r1SessionAuthority)
const MAX_AUTHORITY_SIZE: usize = 88; // Conservative estimate for largest authority

/// Global authority that can contain any authority type.
///
/// This struct acts as a wrapper around any existing authority type,
/// enabling polymorphic authority handling. It stores the authority type
/// and the serialized authority data, then delegates authentication calls
/// to the contained authority.
#[repr(C, align(8))]
#[derive(Debug, PartialEq, NoPadding)]
pub struct GlobalAuthority {
    pub identifier: [u8; 32],
    /// The type of authority contained within this global authority
    pub contained_authority_type: AuthorityType,
    /// Padding for alignment
    _padding: [u8; 6],
    /// The serialized authority data
    pub authority_data: [u8; MAX_AUTHORITY_SIZE],
}

impl GlobalAuthority {
    /// Creates a new GlobalAuthority containing the specified authority.
    ///
    /// # Arguments
    /// * `authority_type` - The type of authority to contain
    /// * `authority_bytes` - The serialized authority data
    ///
    /// # Returns
    /// * `Ok(GlobalAuthority)` - If the authority data is valid
    /// * `Err(ProgramError)` - If the authority data is invalid
    pub fn new(
        authority_type: AuthorityType,
        authority_bytes: &[u8],
    ) -> Result<Self, ProgramError> {
        let expected_length = super::authority_type_to_length(&authority_type)?;

        if authority_bytes.len() != expected_length {
            return Err(SwigStateError::InvalidRoleData.into());
        }

        let mut authority_data = [0u8; MAX_AUTHORITY_SIZE];
        authority_data[..expected_length].copy_from_slice(authority_bytes);

        Ok(Self {
            identifier: [0; 32],
            contained_authority_type: authority_type,
            _padding: [0; 6],
            authority_data,
        })
    }

    /// Creates a new GlobalAuthority containing the specified authority.
    ///
    /// # Arguments
    /// * `authority_type` - The type of authority to contain
    /// * `authority_bytes` - The serialized authority data
    ///
    /// # Returns
    /// * `Ok(GlobalAuthority)` - If the authority data is valid
    /// * `Err(ProgramError)` - If the authority data is invalid
    pub fn new_with_identifier(
        authority_type: AuthorityType,
        authority_bytes: &[u8],
        identifier: [u8; 32],
    ) -> Result<Self, ProgramError> {
        let expected_length = super::authority_type_to_length(&authority_type)?;

        if authority_bytes.len() != expected_length {
            return Err(SwigStateError::InvalidRoleData.into());
        }

        let mut authority_data = [0u8; MAX_AUTHORITY_SIZE];
        authority_data[..expected_length].copy_from_slice(authority_bytes);

        Ok(Self {
            identifier,
            contained_authority_type: authority_type,
            _padding: [0; 6],
            authority_data,
        })
    }

    /// Gets the contained authority as a trait object for dynamic dispatch.
    ///
    /// # Returns
    /// * `Ok(&dyn AuthorityInfo)` - The contained authority
    /// * `Err(ProgramError)` - If the authority type is invalid or data is corrupted
    fn get_contained_authority(&self) -> Result<&dyn AuthorityInfo, ProgramError> {
        let authority_length = super::authority_type_to_length(&self.contained_authority_type)?;
        let authority_bytes = &self.authority_data[..authority_length];

        match self.contained_authority_type {
            AuthorityType::Ed25519 => {
                let authority = unsafe { ED25519Authority::load_unchecked(authority_bytes)? };
                Ok(authority)
            },
            AuthorityType::Ed25519Session => {
                let authority =
                    unsafe { Ed25519SessionAuthority::load_unchecked(authority_bytes)? };
                Ok(authority)
            },
            AuthorityType::Secp256k1 => {
                let authority = unsafe { Secp256k1Authority::load_unchecked(authority_bytes)? };
                Ok(authority)
            },
            AuthorityType::Secp256k1Session => {
                let authority =
                    unsafe { Secp256k1SessionAuthority::load_unchecked(authority_bytes)? };
                Ok(authority)
            },
            AuthorityType::Secp256r1 => {
                let authority = unsafe { Secp256r1Authority::load_unchecked(authority_bytes)? };
                Ok(authority)
            },
            AuthorityType::Secp256r1Session => {
                let authority =
                    unsafe { Secp256r1SessionAuthority::load_unchecked(authority_bytes)? };
                Ok(authority)
            },
            AuthorityType::Global => {
                // Prevent infinite recursion
                return Err(SwigStateError::InvalidAuthorityData.into());
            },
            AuthorityType::None => {
                return Err(SwigStateError::InvalidAuthorityData.into());
            },
        }
    }

    /// Gets the contained authority as a mutable trait object for dynamic dispatch.
    ///
    /// # Returns
    /// * `Ok(&mut dyn AuthorityInfo)` - The contained authority
    /// * `Err(ProgramError)` - If the authority type is invalid or data is corrupted
    fn get_contained_authority_mut(&mut self) -> Result<&mut dyn AuthorityInfo, ProgramError> {
        let authority_length = super::authority_type_to_length(&self.contained_authority_type)?;
        let authority_bytes = &mut self.authority_data[..authority_length];

        match self.contained_authority_type {
            AuthorityType::Ed25519 => {
                let authority = unsafe { ED25519Authority::load_mut_unchecked(authority_bytes)? };
                Ok(authority)
            },
            AuthorityType::Ed25519Session => {
                let authority =
                    unsafe { Ed25519SessionAuthority::load_mut_unchecked(authority_bytes)? };
                Ok(authority)
            },
            AuthorityType::Secp256k1 => {
                let authority = unsafe { Secp256k1Authority::load_mut_unchecked(authority_bytes)? };
                Ok(authority)
            },
            AuthorityType::Secp256k1Session => {
                let authority =
                    unsafe { Secp256k1SessionAuthority::load_mut_unchecked(authority_bytes)? };
                Ok(authority)
            },
            AuthorityType::Secp256r1 => {
                let authority = unsafe { Secp256r1Authority::load_mut_unchecked(authority_bytes)? };
                Ok(authority)
            },
            AuthorityType::Secp256r1Session => {
                let authority =
                    unsafe { Secp256r1SessionAuthority::load_mut_unchecked(authority_bytes)? };
                Ok(authority)
            },
            AuthorityType::Global => {
                // Prevent infinite recursion
                return Err(SwigStateError::InvalidAuthorityData.into());
            },
            AuthorityType::None => {
                return Err(SwigStateError::InvalidAuthorityData.into());
            },
        }
    }
}

impl Transmutable for GlobalAuthority {
    const LEN: usize = core::mem::size_of::<GlobalAuthority>();
}

impl TransmutableMut for GlobalAuthority {}

impl IntoBytes for GlobalAuthority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

impl Authority for GlobalAuthority {
    const TYPE: AuthorityType = AuthorityType::Global;
    const SESSION_BASED: bool = true; // Global authority supports both session and non-session based authorities

    fn set_into_bytes(create_data: &[u8], bytes: &mut [u8]) -> Result<(), ProgramError> {
        if create_data.len() < 2 {
            return Err(SwigStateError::InvalidRoleData.into());
        }

        // First 2 bytes contain the contained authority type
        let contained_type = u16::from_le_bytes([create_data[0], create_data[1]]);
        let contained_authority_type = AuthorityType::try_from(contained_type)?;

        // Rest of the data contains the authority data
        let authority_data = &create_data[2..];
        let expected_length = super::authority_type_to_length(&contained_authority_type)?;

        if authority_data.len() != expected_length {
            return Err(SwigStateError::InvalidRoleData.into());
        }

        let global_authority = unsafe { GlobalAuthority::load_mut_unchecked(bytes)? };
        global_authority.contained_authority_type = contained_authority_type;
        global_authority._padding = [0; 6];
        global_authority.authority_data[..expected_length].copy_from_slice(authority_data);

        Ok(())
    }
}

impl AuthorityInfo for GlobalAuthority {
    fn authority_type(&self) -> AuthorityType {
        Self::TYPE
    }

    fn length(&self) -> usize {
        Self::LEN
    }

    fn session_based(&self) -> bool {
        // Global authority supports both session and non-session based authorities
        // We need to check the contained authority to determine this
        match self.get_contained_authority() {
            Ok(authority) => authority.session_based(),
            Err(_) => false, // Default to false if we can't determine
        }
    }

    fn match_data(&self, data: &[u8]) -> bool {
        match self.get_contained_authority() {
            Ok(authority) => authority.match_data(data),
            Err(_) => false,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn identity(&self) -> Result<&[u8], ProgramError> {
        match self.get_contained_authority() {
            Ok(authority) => authority.identity(),
            Err(e) => Err(e),
        }
    }

    fn signature_odometer(&self) -> Option<u32> {
        match self.get_contained_authority() {
            Ok(authority) => authority.signature_odometer(),
            Err(_) => None,
        }
    }

    fn authenticate_session(
        &mut self,
        account_infos: &[AccountInfo],
        authority_payload: &[u8],
        data_payload: &[u8],
        slot: u64,
    ) -> Result<(), ProgramError> {
        match self.get_contained_authority_mut() {
            Ok(authority) => {
                authority.authenticate_session(account_infos, authority_payload, data_payload, slot)
            },
            Err(e) => Err(e),
        }
    }

    fn start_session(
        &mut self,
        session_key: [u8; 32],
        current_slot: u64,
        duration: u64,
    ) -> Result<(), ProgramError> {
        match self.get_contained_authority_mut() {
            Ok(authority) => authority.start_session(session_key, current_slot, duration),
            Err(e) => Err(e),
        }
    }

    fn authenticate(
        &mut self,
        account_infos: &[AccountInfo],
        authority_payload: &[u8],
        data_payload: &[u8],
        slot: u64,
    ) -> Result<(), ProgramError> {
        match self.get_contained_authority_mut() {
            Ok(authority) => {
                authority.authenticate(account_infos, authority_payload, data_payload, slot)
            },
            Err(e) => Err(e),
        }
    }
}
