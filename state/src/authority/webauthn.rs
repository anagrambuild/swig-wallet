//! WebAuthn authority implementation for passkey support.
//!
//! This module provides implementations for WebAuthn-based authority types in
//! the Swig wallet system, designed specifically for WebAuthn/passkey authentication.
//! It includes both standard WebAuthn authority and session-based WebAuthn
//! authority with expiration support. The implementation relies on the Solana
//! secp256r1 precompile program for signature verification but includes WebAuthn-specific
//! message formatting and validation.

#![warn(unexpected_cfgs)]

use core::mem::MaybeUninit;

#[allow(unused_imports)]
use pinocchio::syscalls::sol_sha256;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::instructions::{Instructions, INSTRUCTIONS_ID},
};
use pinocchio_pubkey::pubkey;
use swig_assertions::sol_assert_bytes_eq;

use super::{Authority, AuthorityInfo, AuthorityType};
use crate::{IntoBytes, SwigAuthenticateError, SwigStateError, Transmutable, TransmutableMut};

/// Maximum age (in slots) for a WebAuthn signature to be considered valid
const MAX_SIGNATURE_AGE_IN_SLOTS: u64 = 60;

/// Secp256r1 program ID (used for WebAuthn signature verification)
const SECP256R1_PROGRAM_ID: [u8; 32] = pubkey!("Secp256r1SigVerify1111111111111111111111111");

/// Constants from the secp256r1 program
const COMPRESSED_PUBKEY_SERIALIZED_SIZE: usize = 33;
const SIGNATURE_SERIALIZED_SIZE: usize = 64;
const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 14;
const SIGNATURE_OFFSETS_START: usize = 2;
const DATA_START: usize = SIGNATURE_OFFSETS_SERIALIZED_SIZE + SIGNATURE_OFFSETS_START;
const PUBKEY_DATA_OFFSET: usize = DATA_START;
const SIGNATURE_DATA_OFFSET: usize = DATA_START + COMPRESSED_PUBKEY_SERIALIZED_SIZE;
const MESSAGE_DATA_OFFSET: usize = SIGNATURE_DATA_OFFSET + SIGNATURE_SERIALIZED_SIZE;
const MESSAGE_DATA_SIZE: usize = 32;
const WEBAUTHN_AUTHENTICATOR_DATA_MAX_SIZE: usize = 196;

/// Secp256r1 signature offsets structure (matches solana-secp256r1-program)
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Secp256r1SignatureOffsets {
    /// Offset to compact secp256r1 signature of 64 bytes
    pub signature_offset: u16,
    /// Instruction index where the signature can be found
    pub signature_instruction_index: u16,
    /// Offset to compressed public key of 33 bytes
    pub public_key_offset: u16,
    /// Instruction index where the public key can be found
    pub public_key_instruction_index: u16,
    /// Offset to the start of message data
    pub message_data_offset: u16,
    /// Size of message data in bytes
    pub message_data_size: u16,
    /// Instruction index where the message data can be found
    pub message_instruction_index: u16,
}

/// Creation parameters for a session-based WebAuthn authority.
#[derive(Debug, no_padding::NoPadding)]
#[repr(C, align(8))]
pub struct CreateWebAuthnSessionAuthority {
    /// The compressed Secp256r1 public key (33 bytes)
    pub public_key: [u8; 33],
    /// Padding for alignment
    _padding: [u8; 7],
    /// The session key for temporary authentication
    pub session_key: [u8; 32],
    /// Maximum duration a session can be valid for
    pub max_session_length: u64,
}

impl CreateWebAuthnSessionAuthority {
    /// Creates a new set of session authority parameters.
    ///
    /// # Arguments
    /// * `public_key` - The compressed Secp256r1 public key
    /// * `session_key` - The initial session key
    /// * `max_session_length` - Maximum allowed session duration
    pub fn new(public_key: [u8; 33], session_key: [u8; 32], max_session_length: u64) -> Self {
        Self {
            public_key,
            _padding: [0; 7],
            session_key,
            max_session_length,
        }
    }
}

impl Transmutable for CreateWebAuthnSessionAuthority {
    const LEN: usize = 33 + 7 + 32 + 8; // Include the 7 bytes of padding
}

impl TransmutableMut for CreateWebAuthnSessionAuthority {}

impl IntoBytes for CreateWebAuthnSessionAuthority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

/// Standard WebAuthn authority implementation for passkey support.
///
/// This struct represents a WebAuthn authority with a compressed public key
/// for signature verification using the Solana secp256r1 precompile program
/// with WebAuthn-specific message formatting.
#[derive(Debug, no_padding::NoPadding)]
#[repr(C, align(8))]
pub struct WebAuthnAuthority {
    /// The compressed Secp256r1 public key (33 bytes)
    pub public_key: [u8; 33],
    /// Padding for u32 alignment
    _padding: [u8; 3],
    /// Signature counter to prevent signature replay attacks
    pub signature_odometer: u32,
}

impl WebAuthnAuthority {
    /// Creates a new WebAuthnAuthority with a compressed public key.
    pub fn new(public_key: [u8; 33]) -> Self {
        Self {
            public_key,
            _padding: [0; 3],
            signature_odometer: 0,
        }
    }
}

impl Transmutable for WebAuthnAuthority {
    const LEN: usize = core::mem::size_of::<WebAuthnAuthority>();
}

impl TransmutableMut for WebAuthnAuthority {}

impl Authority for WebAuthnAuthority {
    const TYPE: AuthorityType = AuthorityType::WebAuthn;
    const SESSION_BASED: bool = false;

    fn set_into_bytes(create_data: &[u8], bytes: &mut [u8]) -> Result<(), ProgramError> {
        if create_data.len() != 33 {
            return Err(SwigStateError::InvalidRoleData.into());
        }
        let authority = unsafe { WebAuthnAuthority::load_mut_unchecked(bytes)? };
        authority.public_key.copy_from_slice(create_data);
        authority.signature_odometer = 0;
        Ok(())
    }
}

impl AuthorityInfo for WebAuthnAuthority {
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

    fn signature_odometer(&self) -> Option<u32> {
        Some(self.signature_odometer)
    }

    fn match_data(&self, data: &[u8]) -> bool {
        if data.len() != 33 {
            return false;
        }
        sol_assert_bytes_eq(&self.public_key, data, 33)
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
        webauthn_authority_authenticate(self, authority_payload, data_payload, slot, account_infos)
    }
}

impl IntoBytes for WebAuthnAuthority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

/// Session-based WebAuthn authority implementation.
///
/// This struct represents a WebAuthn authority that supports temporary session
/// keys with expiration times. It maintains both a root public key and a
/// session key.
#[derive(Debug, no_padding::NoPadding)]
#[repr(C, align(8))]
pub struct WebAuthnSessionAuthority {
    /// The compressed Secp256r1 public key (33 bytes)
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

impl Transmutable for WebAuthnSessionAuthority {
    const LEN: usize = core::mem::size_of::<WebAuthnSessionAuthority>();
}

impl TransmutableMut for WebAuthnSessionAuthority {}

impl Authority for WebAuthnSessionAuthority {
    const TYPE: AuthorityType = AuthorityType::WebAuthnSession;
    const SESSION_BASED: bool = true;

    fn set_into_bytes(create_data: &[u8], bytes: &mut [u8]) -> Result<(), ProgramError> {
        let create = unsafe { CreateWebAuthnSessionAuthority::load_unchecked(create_data)? };
        let authority = unsafe { WebAuthnSessionAuthority::load_mut_unchecked(bytes)? };
        authority.public_key = create.public_key;
        authority.signature_odometer = 0;
        authority.session_key = create.session_key;
        authority.max_session_age = create.max_session_length;
        Ok(())
    }
}

impl AuthorityInfo for WebAuthnSessionAuthority {
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
        if data.len() != 33 {
            return false;
        }
        sol_assert_bytes_eq(&self.public_key, data, 33)
    }

    fn identity(&self) -> Result<&[u8], ProgramError> {
        Ok(self.public_key.as_ref())
    }

    fn signature_odometer(&self) -> Option<u32> {
        Some(self.signature_odometer)
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
        webauthn_session_authority_authenticate(
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
        use super::ed25519::ed25519_authenticate;

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

impl IntoBytes for WebAuthnSessionAuthority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

/// Authenticates a WebAuthn authority with additional payload data.
///
/// # Arguments
/// * `authority` - The mutable authority reference for counter updates
/// * `authority_payload` - The authority payload including slot, counter,
///   instruction index, and WebAuthn-specific data
/// * `data_payload` - Additional data to be included in signature verification
/// * `current_slot` - The current slot number
/// * `account_infos` - List of accounts involved in the transaction
fn webauthn_authority_authenticate(
    authority: &mut WebAuthnAuthority,
    authority_payload: &[u8],
    data_payload: &[u8],
    current_slot: u64,
    account_infos: &[AccountInfo],
) -> Result<(), ProgramError> {
    if authority_payload.len() < 17 {
        // 8 + 4 + 1 + 4 = slot + counter + instructions_account_index + extra data
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

    let instruction_account_index = authority_payload[12] as usize;

    let expected_counter = authority.signature_odometer.wrapping_add(1);
    if counter != expected_counter {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1SignatureReused.into());
    }

    webauthn_authenticate(
        &authority.public_key,
        data_payload,
        authority_slot,
        current_slot,
        account_infos,
        instruction_account_index,
        counter,
        &authority_payload[17..],
    )?;

    authority.signature_odometer = counter;
    Ok(())
}

/// Authenticates a WebAuthn session authority with additional payload data.
///
/// # Arguments
/// * `authority` - The mutable authority reference for counter updates
/// * `authority_payload` - The authority payload including slot, counter, and
///   instruction index
/// * `data_payload` - Additional data to be included in signature verification
/// * `current_slot` - The current slot number
/// * `account_infos` - List of accounts involved in the transaction
fn webauthn_session_authority_authenticate(
    authority: &mut WebAuthnSessionAuthority,
    authority_payload: &[u8],
    data_payload: &[u8],
    current_slot: u64,
    account_infos: &[AccountInfo],
) -> Result<(), ProgramError> {
    if authority_payload.len() < 13 {
        // 8 + 4 + 1 = slot + counter + instruction_index
        return Err(SwigAuthenticateError::InvalidAuthorityPayload.into());
    }

    let authority_slot =
        u64::from_le_bytes(unsafe { authority_payload.get_unchecked(..8).try_into().unwrap() });

    let counter =
        u32::from_le_bytes(unsafe { authority_payload.get_unchecked(8..12).try_into().unwrap() });

    let instruction_index = authority_payload[12] as usize;

    let expected_counter = authority.signature_odometer.wrapping_add(1);
    if counter != expected_counter {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1SignatureReused.into());
    }

    webauthn_authenticate(
        &authority.public_key,
        data_payload,
        authority_slot,
        current_slot,
        account_infos,
        instruction_index,
        counter,
        &authority_payload[17..],
    )?;

    authority.signature_odometer = counter;
    Ok(())
}

/// Core WebAuthn signature verification function.
///
/// This function performs the actual signature verification by:
/// - Validating signature age
/// - Computing the message hash (including counter for replay protection)
/// - Processing WebAuthn-specific message formatting
/// - Finding and validating the secp256r1 precompile instruction
/// - Verifying the message hash matches what was passed to the precompile
/// - Verifying the public key matches
fn webauthn_authenticate(
    expected_key: &[u8; 33],
    data_payload: &[u8],
    authority_slot: u64,
    current_slot: u64,
    account_infos: &[AccountInfo],
    instruction_account_index: usize,
    counter: u32,
    additional_payload: &[u8],
) -> Result<(), ProgramError> {
    // Validate signature age
    if current_slot < authority_slot || current_slot - authority_slot > MAX_SIGNATURE_AGE_IN_SLOTS {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256k1InvalidSignatureAge.into());
    }

    // Compute our expected message hash
    let computed_hash = compute_message_hash(data_payload, account_infos, authority_slot, counter)?;
    let mut message_buf: MaybeUninit<[u8; WEBAUTHN_AUTHENTICATOR_DATA_MAX_SIZE + 32]> =
        MaybeUninit::uninit();

    // WebAuthn requires additional payload processing
    let message = if additional_payload.is_empty() {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
    } else {
        webauthn_message(
            additional_payload,
            computed_hash,
            unsafe { &mut *message_buf.as_mut_ptr() },
            counter,
        )?
    };

    // Get the sysvar instructions account
    let sysvar_instructions = account_infos
        .get(instruction_account_index)
        .ok_or(SwigAuthenticateError::InvalidAuthorityPayload)?;

    // Verify this is the sysvar instructions account
    if sysvar_instructions.key().as_ref() != &INSTRUCTIONS_ID {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidInstruction.into());
    }

    let sysvar_instructions_data = unsafe { sysvar_instructions.borrow_data_unchecked() };
    let ixs = unsafe { Instructions::new_unchecked(sysvar_instructions_data) };
    let current_index = ixs.load_current_index() as usize;
    if current_index == 0 {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidInstruction.into());
    }
    let secpr1ix = unsafe { ixs.deserialize_instruction_unchecked(current_index - 1) };
    // Verify the instruction is calling the secp256r1 program
    if secpr1ix.get_program_id() != &SECP256R1_PROGRAM_ID {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidInstruction.into());
    }
    let instruction_data = secpr1ix.get_instruction_data();
    // Parse and verify the secp256r1 instruction data
    verify_secp256r1_instruction_data(&instruction_data, expected_key, message)?;
    Ok(())
}

/// Compute the message hash for WebAuthn authentication
fn compute_message_hash(
    data_payload: &[u8],
    account_infos: &[AccountInfo],
    authority_slot: u64,
    counter: u32,
) -> Result<[u8; 32], ProgramError> {
    use super::secp256k1::AccountsPayload;

    let mut accounts_payload = [0u8; 64 * AccountsPayload::LEN];
    let mut cursor = 0;
    for account in account_infos {
        let offset = cursor + AccountsPayload::LEN;
        accounts_payload[cursor..offset]
            .copy_from_slice(AccountsPayload::from(account).into_bytes()?);
        cursor = offset;
    }
    let mut hash = MaybeUninit::<[u8; 32]>::uninit();
    let data: &[&[u8]] = &[
        data_payload,
        &accounts_payload[..cursor],
        &authority_slot.to_le_bytes(),
        &counter.to_le_bytes(),
    ];

    unsafe {
        #[cfg(target_os = "solana")]
        let res = pinocchio::syscalls::sol_keccak256(
            data.as_ptr() as *const u8,
            4,
            hash.as_mut_ptr() as *mut u8,
        );
        #[cfg(not(target_os = "solana"))]
        let res = 0;
        if res != 0 {
            return Err(SwigAuthenticateError::PermissionDeniedSecp256k1InvalidHash.into());
        }

        Ok(hash.assume_init())
    }
}

/// Process WebAuthn-specific message formatting.
///
/// This function handles the WebAuthn-specific message format which includes:
/// - Authenticator data
/// - Client data JSON hash
/// - Counter verification within challenge excerpt
/// - Proper message construction for signature verification
fn webauthn_message<'a>(
    auth_payload: &[u8],
    computed_hash: [u8; 32],
    message_buf: &'a mut [u8],
    expected_counter: u32,
) -> Result<&'a [u8], ProgramError> {
    // Check minimum length for auth_payload (need at least 4 bytes for auth_len)
    if auth_payload.len() < 4 {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
    }
    
    // let _auth_type = u16::from_le_bytes(prefix[..2].try_into().unwrap());
    let auth_len = u16::from_le_bytes(auth_payload[2..4].try_into().unwrap()) as usize;

    if auth_len >= WEBAUTHN_AUTHENTICATOR_DATA_MAX_SIZE {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
    }

    let auth_data = &auth_payload[4..4 + auth_len];

    // Check if we have the required data: 32 bytes for clientDataJSON hash +
    // 4 bytes for counter + at least 2 bytes for challenge excerpt length
    let remaining_bytes = auth_payload.len() - (4 + auth_len);
    if remaining_bytes < 38 {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
    }

    let client_data_json_hash = &auth_payload[4 + auth_len..4 + auth_len + 32];
    let provided_counter_bytes = &auth_payload[4 + auth_len + 32..4 + auth_len + 36];
    let provided_counter = u32::from_le_bytes(provided_counter_bytes.try_into().unwrap());

    if provided_counter != expected_counter {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1SignatureReused.into());
    }

    // Get the challenge excerpt length and data
    let challenge_excerpt_len_offset = 4 + auth_len + 36;
    if challenge_excerpt_len_offset + 2 > auth_payload.len() {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
    }

    let challenge_excerpt_len = u16::from_le_bytes(
        auth_payload[challenge_excerpt_len_offset..challenge_excerpt_len_offset + 2]
            .try_into()
            .unwrap(),
    ) as usize;

    let challenge_excerpt_start = challenge_excerpt_len_offset + 2;
    if challenge_excerpt_start + challenge_excerpt_len > auth_payload.len() {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
    }

    let challenge_excerpt =
        &auth_payload[challenge_excerpt_start..challenge_excerpt_start + challenge_excerpt_len];

    // Verify the counter appears in the challenge excerpt
    // The challenge should contain the counter in little-endian format
    let counter_found = challenge_excerpt
        .windows(4)
        .any(|window| window == provided_counter_bytes);

    if !counter_found {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1SignatureReused.into());
    }

    // The client_data_json_hash is the SHA256 of clientDataJSON provided by the
    // frontend We use this directly instead of computing it from the full JSON
    message_buf[0..auth_len].copy_from_slice(auth_data);
    message_buf[auth_len..auth_len + 32].copy_from_slice(client_data_json_hash);

    Ok(&message_buf[..auth_len + 32])
}

/// Verify the secp256r1 instruction data contains the expected signature and
/// public key
fn verify_secp256r1_instruction_data(
    instruction_data: &[u8],
    expected_pubkey: &[u8; 33],
    expected_message: &[u8],
) -> Result<(), ProgramError> {
    // Minimum check: must have at least the header and offsets
    if instruction_data.len() < DATA_START {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidInstruction.into());
    }
    let num_signatures = instruction_data[0] as usize;
    if num_signatures == 0 || num_signatures > 1 {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidInstruction.into());
    }

    if instruction_data.len() < MESSAGE_DATA_OFFSET + expected_message.len() {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidInstruction.into());
    }
    let pubkey_data = &instruction_data
        [PUBKEY_DATA_OFFSET..PUBKEY_DATA_OFFSET + COMPRESSED_PUBKEY_SERIALIZED_SIZE];
    let message_data =
        &instruction_data[MESSAGE_DATA_OFFSET..MESSAGE_DATA_OFFSET + expected_message.len()];

    if pubkey_data != expected_pubkey {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidPubkey.into());
    }
    if message_data != expected_message {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessageHash.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to create real secp256r1 instruction data using the
    /// official Solana secp256r1 program
    fn create_test_secp256r1_instruction_data(
        message: &[u8],
        signature: &[u8; 64],
        pubkey: &[u8; 33],
    ) -> Vec<u8> {
        use solana_secp256r1_program::new_secp256r1_instruction_with_signature;

        // Use the official Solana function to create the instruction data
        // This ensures we match exactly what the Solana runtime expects
        let instruction = new_secp256r1_instruction_with_signature(message, signature, pubkey);

        instruction.data
    }

    /// Helper function to create a signature using OpenSSL for testing
    fn create_test_signature_and_pubkey(message: &[u8]) -> ([u8; 64], [u8; 33]) {
        use openssl::{
            bn::BigNumContext,
            ec::{EcGroup, EcKey, PointConversionForm},
            nid::Nid,
        };
        use solana_secp256r1_program::sign_message;

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let signing_key = EcKey::generate(&group).unwrap();

        let signature = sign_message(message, &signing_key.private_key_to_der().unwrap()).unwrap();

        let mut ctx = BigNumContext::new().unwrap();
        let pubkey_bytes = signing_key
            .public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap();

        assert_eq!(pubkey_bytes.len(), COMPRESSED_PUBKEY_SERIALIZED_SIZE);

        (signature, pubkey_bytes.try_into().unwrap())
    }

    #[test]
    fn test_webauthn_message_with_counter_verification() {
        let auth_data = [0x01, 0x02, 0x03, 0x04]; // 4 bytes of authenticator data
        let client_data_hash = [0xAB; 32]; // 32 bytes of clientDataJSON hash
        let counter: u32 = 12345;
        let counter_bytes = counter.to_le_bytes();

        // Create a challenge excerpt that contains the counter
        let challenge_excerpt = [
            0x00,
            0x11,
            0x22, // Some prefix data
            counter_bytes[0],
            counter_bytes[1],
            counter_bytes[2],
            counter_bytes[3], // Counter
            0x33,
            0x44,
            0x55, // Some suffix data
        ];

        // Build the auth_payload with counter verification data
        let mut auth_payload = Vec::new();
        auth_payload.extend_from_slice(&0u16.to_le_bytes()); // auth_type (2 bytes)
        auth_payload.extend_from_slice(&(auth_data.len() as u16).to_le_bytes()); // auth_len (2 bytes)
        auth_payload.extend_from_slice(&auth_data); // auth_data
        auth_payload.extend_from_slice(&client_data_hash); // client_data_json_hash (32 bytes)
        auth_payload.extend_from_slice(&counter_bytes); // counter (4 bytes)
        auth_payload.extend_from_slice(&(challenge_excerpt.len() as u16).to_le_bytes()); // excerpt_len (2 bytes)
        auth_payload.extend_from_slice(&challenge_excerpt); // challenge_excerpt

        // Create a computed hash that includes the counter (simulating the original
        // message hash)
        let mut computed_hash = [0u8; 32];
        computed_hash[28..32].copy_from_slice(&counter_bytes); // Put counter in last 4 bytes

        let mut message_buf = [0u8; WEBAUTHN_AUTHENTICATOR_DATA_MAX_SIZE + 32];

        // Should succeed with matching counter
        let result = webauthn_message(&auth_payload, computed_hash, &mut message_buf, counter);
        assert!(
            result.is_ok(),
            "Should succeed with matching counter in challenge"
        );

        // Should fail with counter not in challenge
        let mut bad_challenge_excerpt = challenge_excerpt.clone();
        bad_challenge_excerpt[3] = 0xFF; // Corrupt the counter in the challenge

        let mut bad_auth_payload = Vec::new();
        bad_auth_payload.extend_from_slice(&0u16.to_le_bytes()); // auth_type (2 bytes)
        bad_auth_payload.extend_from_slice(&(auth_data.len() as u16).to_le_bytes()); // auth_len (2 bytes)
        bad_auth_payload.extend_from_slice(&auth_data); // auth_data
        bad_auth_payload.extend_from_slice(&client_data_hash); // client_data_json_hash (32 bytes)
        bad_auth_payload.extend_from_slice(&counter_bytes); // counter (4 bytes)
        bad_auth_payload.extend_from_slice(&(bad_challenge_excerpt.len() as u16).to_le_bytes()); // excerpt_len (2 bytes)
        bad_auth_payload.extend_from_slice(&bad_challenge_excerpt); // bad challenge_excerpt

        let result = webauthn_message(&bad_auth_payload, computed_hash, &mut message_buf, counter);
        assert!(
            result.is_err(),
            "Should fail when counter not found in challenge"
        );
        assert_eq!(
            result.unwrap_err(),
            SwigAuthenticateError::PermissionDeniedSecp256r1SignatureReused.into()
        );
    }

    #[test]
    fn test_webauthn_message_counter_mismatch() {
        let test_counter = 42u32;
        let wrong_counter = 43u32;
        let auth_data = [0u8; 37]; // Minimal auth data
        let client_data_json_hash = [1u8; 32];
        let counter_bytes = test_counter.to_le_bytes();
        let challenge_excerpt = [
            &[0u8; 32][..],     // message hash
            &counter_bytes[..], // counter in challenge
        ]
        .concat();
        let challenge_excerpt_len = (challenge_excerpt.len() as u16).to_le_bytes();

        let mut auth_payload = Vec::new();
        auth_payload.extend_from_slice(&[0u8; 2]); // auth_type
        auth_payload.extend_from_slice(&(auth_data.len() as u16).to_le_bytes()); // auth_len
        auth_payload.extend_from_slice(&auth_data); // auth_data
        auth_payload.extend_from_slice(&client_data_json_hash); // clientDataJSON hash
        auth_payload.extend_from_slice(&counter_bytes); // counter (matches challenge)
        auth_payload.extend_from_slice(&challenge_excerpt_len); // challenge_excerpt_len
        auth_payload.extend_from_slice(&challenge_excerpt); // challenge_excerpt

        let computed_hash = [0u8; 32];
        let mut message_buf = [0u8; WEBAUTHN_AUTHENTICATOR_DATA_MAX_SIZE + 32];

        // Should fail when expected counter doesn't match counter in WebAuthn prefix
        let result = webauthn_message(
            &auth_payload,
            computed_hash,
            &mut message_buf,
            wrong_counter,
        );
        assert!(
            result.is_err(),
            "Should fail when expected counter doesn't match WebAuthn prefix counter"
        );
        assert_eq!(
            result.unwrap_err(),
            SwigAuthenticateError::PermissionDeniedSecp256r1SignatureReused.into()
        );
    }

    #[test]
    fn test_webauthn_message_requires_additional_payload() {
        let computed_hash = [0u8; 32];
        let mut message_buf = [0u8; WEBAUTHN_AUTHENTICATOR_DATA_MAX_SIZE + 32];

        // Empty payload should fail for WebAuthn (unlike regular secp256r1)
        let result = webauthn_message(&[], computed_hash, &mut message_buf, 1);
        assert!(
            result.is_err(),
            "WebAuthn should require additional payload data"
        );
    }
}