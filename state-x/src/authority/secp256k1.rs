//! Secp256k1 authority implementation.
//!
//! This module provides implementations for Secp256k1-based authority types in
//! the Swig wallet system. It includes both standard Secp256k1 authority and
//! session-based Secp256k1 authority with expiration support. The
//! implementation handles key compression, signature recovery, and Keccak256
//! hashing.

#![warn(unexpected_cfgs)]

use core::mem::MaybeUninit;

#[allow(unused_imports)]
use pinocchio::syscalls::{sol_keccak256, sol_secp256k1_recover, sol_sha256};
use pinocchio::{account_info::AccountInfo, msg, program_error::ProgramError, pubkey::Pubkey};
use swig_assertions::sol_assert_bytes_eq;

use super::{ed25519::ed25519_authenticate, Authority, AuthorityInfo, AuthorityType};
use crate::{IntoBytes, SwigAuthenticateError, SwigStateError, Transmutable, TransmutableMut};

/// Maximum age (in slots) for a Secp256k1 signature to be considered valid
const MAX_SIGNATURE_AGE_IN_SLOTS: u64 = 60;

/// Creation parameters for a session-based Secp256k1 authority.
#[derive(Debug, no_padding::NoPadding)]
#[repr(C, align(8))]
pub struct CreateSecp256k1SessionAuthority {
    /// The uncompressed Secp256k1 public key (64 bytes)
    pub public_key: [u8; 64],
    /// The session key for temporary authentication
    pub session_key: [u8; 32],
    /// Maximum duration a session can be valid for
    pub max_session_length: u64,
}

impl CreateSecp256k1SessionAuthority {
    /// Creates a new set of session authority parameters.
    ///
    /// # Arguments
    /// * `public_key` - The uncompressed Secp256k1 public key
    /// * `session_key` - The initial session key
    /// * `max_session_length` - Maximum allowed session duration
    pub fn new(public_key: [u8; 64], session_key: [u8; 32], max_session_length: u64) -> Self {
        Self {
            public_key,
            session_key,
            max_session_length,
        }
    }
}

impl Transmutable for CreateSecp256k1SessionAuthority {
    const LEN: usize = 64 + 32 + 8;
}

impl TransmutableMut for CreateSecp256k1SessionAuthority {}

impl IntoBytes for CreateSecp256k1SessionAuthority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

/// Standard Secp256k1 authority implementation.
///
/// This struct represents a Secp256k1 authority with a compressed public key
/// for signature verification.
#[derive(Debug, no_padding::NoPadding)]
#[repr(C, align(8))]
pub struct Secp256k1Authority {
    /// The compressed Secp256k1 public key (33 bytes)
    pub public_key: [u8; 33],
    /// Padding for u32 alignment
    _padding: [u8; 3],
    /// Signature counter to prevent signature replay attacks
    pub signature_odometer: u32,
}

impl Secp256k1Authority {
    /// Creates a new Secp256k1Authority with a compressed public key.
    pub fn new(public_key: [u8; 33]) -> Self {
        Self {
            public_key,
            _padding: [0; 3],
            signature_odometer: 0,
        }
    }
}

impl Transmutable for Secp256k1Authority {
    const LEN: usize = core::mem::size_of::<Secp256k1Authority>();
}

impl TransmutableMut for Secp256k1Authority {}

impl Authority for Secp256k1Authority {
    const TYPE: AuthorityType = AuthorityType::Secp256k1;
    const SESSION_BASED: bool = false;

    fn set_into_bytes(create_data: &[u8], bytes: &mut [u8]) -> Result<(), ProgramError> {
        if create_data.len() != 64 {
            return Err(SwigStateError::InvalidRoleData.into());
        }
        let authority = unsafe { Secp256k1Authority::load_mut_unchecked(bytes)? };
        let compressed = compress(create_data.try_into().unwrap());
        authority.public_key = compressed;
        authority.signature_odometer = 0;
        Ok(())
    }
}

impl AuthorityInfo for Secp256k1Authority {
    fn authority_type(&self) -> AuthorityType {
        Self::TYPE
    }

    fn length(&self) -> usize {
        Self::LEN
    }

    fn session_based(&self) -> bool {
        Self::SESSION_BASED
    }

    fn identity(&self) -> Result<&[u8], ProgramError> {
        Ok(self.public_key.as_ref())
    }

    fn match_data(&self, data: &[u8]) -> bool {
        if data.len() != 64 {
            return false;
        }
        let expanded = compress(data.try_into().unwrap());
        sol_assert_bytes_eq(&self.public_key, &expanded, 32)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn authenticate(
        &mut self,
        account_infos: &[pinocchio::account_info::AccountInfo],
        authority_payload: &[u8],
        data_payload: &[u8],
        slot: u64,
    ) -> Result<(), ProgramError> {
        secp_authority_authenticate(self, authority_payload, data_payload, slot, account_infos)
    }
}

impl IntoBytes for Secp256k1Authority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

/// Session-based Secp256k1 authority implementation.
///
/// This struct represents a Secp256k1 authority that supports temporary session
/// keys with expiration times. It maintains both a root public key and a
/// session key.
#[derive(Debug, no_padding::NoPadding)]
#[repr(C, align(8))]
pub struct Secp256k1SessionAuthority {
    /// The compressed Secp256k1 public key (33 bytes)
    pub public_key: [u8; 33],
    _padding: [u8; 3],
    /// Signature counter to prevent signature replay attacks
    pub signature_odometer: u32,
    /// The current session key
    pub session_key: [u8; 32],
    /// Maximum allowed session duration
    pub max_session_age: u64,
    /// Slot when the current session expires
    pub current_session_expiration: u64,
}

impl Transmutable for Secp256k1SessionAuthority {
    const LEN: usize = core::mem::size_of::<Secp256k1SessionAuthority>();
}

impl TransmutableMut for Secp256k1SessionAuthority {}

impl Authority for Secp256k1SessionAuthority {
    const TYPE: AuthorityType = AuthorityType::Secp256k1Session;
    const SESSION_BASED: bool = true;

    fn set_into_bytes(create_data: &[u8], bytes: &mut [u8]) -> Result<(), ProgramError> {
        let create = unsafe { CreateSecp256k1SessionAuthority::load_unchecked(create_data)? };
        let authority = unsafe { Secp256k1SessionAuthority::load_mut_unchecked(bytes)? };
        let compressed = compress(&create.public_key);
        authority.public_key = compressed;
        authority.signature_odometer = 0;
        authority.session_key = create.session_key;
        authority.max_session_age = create.max_session_length;
        Ok(())
    }
}

impl AuthorityInfo for Secp256k1SessionAuthority {
    fn authority_type(&self) -> AuthorityType {
        Self::TYPE
    }

    fn length(&self) -> usize {
        Self::LEN
    }

    fn session_based(&self) -> bool {
        Self::SESSION_BASED
    }

    fn match_data(&self, data: &[u8]) -> bool {
        if data.len() != 64 {
            return false;
        }
        let expanded = compress(data.try_into().unwrap());
        sol_assert_bytes_eq(data, &expanded, 33)
    }

    fn identity(&self) -> Result<&[u8], ProgramError> {
        Ok(self.public_key.as_ref())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn authenticate(
        &mut self,
        account_infos: &[pinocchio::account_info::AccountInfo],
        authority_payload: &[u8],
        data_payload: &[u8],
        slot: u64,
    ) -> Result<(), ProgramError> {
        secp_session_authority_authenticate(
            self,
            authority_payload,
            data_payload,
            slot,
            account_infos,
        )
    }

    fn authenticate_session(
        &mut self,
        account_infos: &[AccountInfo],
        authority_payload: &[u8],
        _data_payload: &[u8],
        slot: u64,
    ) -> Result<(), ProgramError> {
        if slot > self.current_session_expiration {
            return Err(SwigAuthenticateError::PermissionDeniedSessionExpired.into());
        }
        ed25519_authenticate(
            account_infos,
            authority_payload[0] as usize,
            &self.session_key,
        )
    }

    fn start_session(
        &mut self,
        session_key: [u8; 32],
        current_slot: u64,
        duration: u64,
    ) -> Result<(), ProgramError> {
        if sol_assert_bytes_eq(&self.session_key, &session_key, 32) {
            return Err(SwigAuthenticateError::InvalidSessionKeyCannotReuseSessionKey.into());
        }
        if duration > self.max_session_age {
            return Err(SwigAuthenticateError::InvalidSessionDuration.into());
        }
        self.current_session_expiration = current_slot + duration;
        self.session_key = session_key;
        Ok(())
    }
}

impl IntoBytes for Secp256k1SessionAuthority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

/// Authenticates a Secp256k1 authority with additional payload data.
///
/// # Arguments
/// * `authority` - The mutable authority reference for counter updates
/// * `authority_payload` - The authority payload including slot, counter, and
///   signature
/// * `data_payload` - Additional data to be included in signature verification
/// * `current_slot` - The current slot number
/// * `account_infos` - List of accounts involved in the transaction
fn secp_authority_authenticate(
    authority: &mut Secp256k1Authority,
    authority_payload: &[u8],
    data_payload: &[u8],
    current_slot: u64,
    account_infos: &[AccountInfo],
) -> Result<(), ProgramError> {
    if authority_payload.len() < 77 {
        return Err(SwigAuthenticateError::InvalidAuthorityPayload.into());
    }

    let authority_slot = u64::from_le_bytes(unsafe {
        authority_payload
            .get_unchecked(..8)
            .try_into()
            .map_err(|_| SwigAuthenticateError::InvalidAuthorityPayload)?
    });

    let counter = u32::from_le_bytes(unsafe {
        authority_payload
            .get_unchecked(8..12)
            .try_into()
            .map_err(|_| SwigAuthenticateError::InvalidAuthorityPayload)?
    });

    let expected_counter = authority.signature_odometer.wrapping_add(1);
    if counter != expected_counter {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256k1SignatureReused.into());
    }
    secp256k1_authenticate(
        &authority.public_key,
        authority_payload[12..77].try_into().unwrap(),
        data_payload,
        authority_slot,
        current_slot,
        account_infos,
        authority_payload[77..].try_into().unwrap(),
        counter,
    )?;

    authority.signature_odometer = counter;
    Ok(())
}

/// Authenticates a Secp256k1 session authority with additional payload data.
///
/// # Arguments
/// * `authority` - The mutable authority reference for counter updates
/// * `authority_payload` - The authority payload including slot, counter, and
///   signature
/// * `data_payload` - Additional data to be included in signature verification
/// * `current_slot` - The current slot number
/// * `account_infos` - List of accounts involved in the transaction
fn secp_session_authority_authenticate(
    authority: &mut Secp256k1SessionAuthority,
    authority_payload: &[u8],
    data_payload: &[u8],
    current_slot: u64,
    account_infos: &[AccountInfo],
) -> Result<(), ProgramError> {
    if authority_payload.len() < 77 {
        return Err(SwigAuthenticateError::InvalidAuthorityPayload.into());
    }
    let authority_slot =
        u64::from_le_bytes(unsafe { authority_payload.get_unchecked(..8).try_into().unwrap() });

    let counter =
        u32::from_le_bytes(unsafe { authority_payload.get_unchecked(8..12).try_into().unwrap() });

    let expected_counter = authority.signature_odometer.wrapping_add(1);
    if counter != expected_counter {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256k1SignatureReused.into());
    }

    secp256k1_authenticate(
        &authority.public_key,
        authority_payload[12..77].try_into().unwrap(),
        data_payload,
        authority_slot,
        current_slot,
        account_infos,
        authority_payload[77..].try_into().unwrap(),
        counter, // Now use proper counter-based replay protection
    )?;

    authority.signature_odometer = counter;
    Ok(())
}

/// Core Secp256k1 signature verification function.
///
/// This function performs the actual signature verification, including:
/// - Signature age validation
/// - Message hash computation (including counter for replay protection)
/// - Public key recovery
/// - Key comparison
fn secp256k1_authenticate(
    expected_key: &[u8; 33],
    authority_payload: &[u8],
    data_payload: &[u8],
    authority_slot: u64,
    current_slot: u64,
    account_infos: &[AccountInfo],
    prefix: &[u8],
    counter: u32,
) -> Result<(), ProgramError> {
    if authority_payload.len() != 65 {
        return Err(SwigAuthenticateError::InvalidAuthorityPayload.into());
    }
    if current_slot < authority_slot || current_slot - authority_slot > MAX_SIGNATURE_AGE_IN_SLOTS {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256k1InvalidSignature.into());
    }

    let signature = libsecp256k1::Signature::parse_standard_slice(&authority_payload[..64])
        .map_err(|_| SwigAuthenticateError::PermissionDeniedSecp256k1InvalidSignature)?;

    if signature.s.is_high() {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256k1InvalidSignature.into());
    }

    let mut accounts_payload = [0u8; 64 * AccountsPayload::LEN];

    let mut cursor = 0;

    for account in account_infos {
        let offset = cursor + AccountsPayload::LEN;
        accounts_payload[cursor..offset]
            .copy_from_slice(AccountsPayload::from(account).into_bytes()?);
        cursor = offset;
    }

    #[allow(unused)]
    let mut data_payload_hash = [0; 32];
    #[allow(unused)]
    let mut data_payload_hash_hex = [0; 64];

    #[allow(unused)]
    let mut recovered_key = MaybeUninit::<[u8; 64]>::uninit();
    #[allow(unused)]
    let mut hash = MaybeUninit::<[u8; 32]>::uninit();

    #[allow(unused)]
    let data: &[&[u8]] = &[
        data_payload,
        &accounts_payload[..cursor],
        &authority_slot.to_le_bytes(),
        &counter.to_le_bytes(), // Include counter in the hash
    ];

    let matches = unsafe {
        // get the sha256 hash of our instruction payload
        #[cfg(target_os = "solana")]
        let res = sol_sha256(
            data.as_ptr() as *const u8,
            4, // Updated count to include counter
            data_payload_hash.as_mut_ptr() as *mut u8,
        );
        #[cfg(not(target_os = "solana"))]
        let res = 0;
        if res != 0 {
            return Err(SwigAuthenticateError::PermissionDeniedSecp256k1InvalidHash.into());
        }

        hex_encode(&data_payload_hash, &mut data_payload_hash_hex);

        #[allow(unused)]
        let keccak_data: &[&[u8]] = &[prefix, &data_payload_hash_hex];

        // do not remove this line we must hash the instruction payload
        #[cfg(target_os = "solana")]
        let res = sol_keccak256(
            keccak_data.as_ptr() as *const u8,
            2,
            hash.as_mut_ptr() as *mut u8,
        );
        #[cfg(not(target_os = "solana"))]
        let res = 0;
        if res != 0 {
            return Err(SwigAuthenticateError::PermissionDeniedSecp256k1InvalidHash.into());
        }
        #[allow(unused)]
        let recovery_id = if *authority_payload.get_unchecked(64) == 27 {
            0
        } else {
            1
        };

        #[cfg(target_os = "solana")]
        let res = sol_secp256k1_recover(
            hash.as_ptr() as *const u8,
            recovery_id,
            authority_payload.get_unchecked(..64).as_ptr() as *const u8,
            recovered_key.as_mut_ptr() as *mut u8,
        );
        #[cfg(not(target_os = "solana"))]
        let res = 0;
        if res != 0 {
            return Err(SwigAuthenticateError::PermissionDeniedSecp256k1InvalidSignature.into());
        }
        // First compress the recovered key to 33 bytes
        let compressed_recovered_key = compress(&recovered_key.assume_init());
        sol_assert_bytes_eq(&compressed_recovered_key, expected_key, 33)
    };
    if !matches {
        return Err(SwigAuthenticateError::PermissionDenied.into());
    }
    Ok(())
}

/// Compresses a 64-byte uncompressed public key to a 33-byte compressed format.
///
/// The compressed format uses:
/// - First byte: 0x02 if Y is even, 0x03 if Y is odd
/// - Remaining 32 bytes: The X coordinate
///
/// # Arguments
/// * `key` - The 64-byte uncompressed public key (X,Y coordinates)
///
/// # Returns
/// * `[u8; 33]` - The compressed public key
fn compress(key: &[u8; 64]) -> [u8; 33] {
    let mut compressed = [0u8; 33];
    compressed[0] = if key[63] & 1 == 0 { 0x02 } else { 0x03 };
    compressed[1..33].copy_from_slice(&key[..32]);
    compressed
}

/// Represents account information in a format suitable for payload
/// construction.
#[repr(C, align(8))]
#[derive(Copy, Clone, no_padding::NoPadding)]
pub struct AccountsPayload {
    /// The account's public key
    pub pubkey: Pubkey,
    /// Whether the account is writable
    pub is_writable: bool,
    /// Whether the account is a signer
    pub is_signer: bool,
    _padding: [u8; 6],
}

impl AccountsPayload {
    /// Creates a new AccountsPayload.
    ///
    /// # Arguments
    /// * `pubkey` - The account's public key
    /// * `is_writable` - Whether the account is writable
    /// * `is_signer` - Whether the account is a signer
    pub fn new(pubkey: Pubkey, is_writable: bool, is_signer: bool) -> Self {
        Self {
            pubkey,
            is_writable,
            is_signer,
            _padding: [0u8; 6],
        }
    }
}

impl Transmutable for AccountsPayload {
    const LEN: usize = core::mem::size_of::<AccountsPayload>();
}

impl IntoBytes for AccountsPayload {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

impl From<&AccountInfo> for AccountsPayload {
    fn from(info: &AccountInfo) -> Self {
        Self::new(*info.key(), info.is_writable(), info.is_signer())
    }
}

pub fn hex_encode(input: &[u8], output: &mut [u8]) {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    for (i, &byte) in input.iter().enumerate() {
        output[i * 2] = HEX_CHARS[(byte >> 4) as usize];
        output[i * 2 + 1] = HEX_CHARS[(byte & 0x0F) as usize];
    }
}
