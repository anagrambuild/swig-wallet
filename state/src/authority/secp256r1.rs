//! Secp256r1 authority implementation for passkey support.
//!
//! This module provides implementations for Secp256r1-based authority types in
//! the Swig wallet system, designed to work with passkeys. It
//! includes both standard Secp256r1 authority and session-based Secp256r1
//! authority with expiration support. The implementation relies on the Solana
//! secp256r1 precompile program for signature verification.

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

/// Maximum age (in slots) for a Secp256r1 signature to be considered valid
const MAX_SIGNATURE_AGE_IN_SLOTS: u64 = 60;

/// Secp256r1 program ID
pub const SECP256R1_PROGRAM_ID: [u8; 32] = pubkey!("Secp256r1SigVerify1111111111111111111111111");

/// Constants from the secp256r1 program
pub const COMPRESSED_PUBKEY_SERIALIZED_SIZE: usize = 33;
pub const SIGNATURE_SERIALIZED_SIZE: usize = 64;
pub const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 14;
pub const SIGNATURE_OFFSETS_START: usize = 2;
pub const DATA_START: usize = SIGNATURE_OFFSETS_SERIALIZED_SIZE + SIGNATURE_OFFSETS_START;
pub const PUBKEY_DATA_OFFSET: usize = DATA_START;
pub const SIGNATURE_DATA_OFFSET: usize = DATA_START + COMPRESSED_PUBKEY_SERIALIZED_SIZE;
pub const MESSAGE_DATA_OFFSET: usize = SIGNATURE_DATA_OFFSET + SIGNATURE_SERIALIZED_SIZE;
pub const MESSAGE_DATA_SIZE: usize = 32;

/// Constants from the secp256r1 program
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

/// Creation parameters for a session-based Secp256r1 authority.
#[derive(Debug, no_padding::NoPadding)]
#[repr(C, align(8))]
pub struct CreateSecp256r1SessionAuthority {
    /// The compressed Secp256r1 public key (33 bytes)
    pub public_key: [u8; 33],
    /// Padding for alignment
    _padding: [u8; 7],
    /// The session key for temporary authentication
    pub session_key: [u8; 32],
    /// Maximum duration a session can be valid for
    pub max_session_length: u64,
}

impl CreateSecp256r1SessionAuthority {
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

impl Transmutable for CreateSecp256r1SessionAuthority {
    const LEN: usize = 33 + 7 + 32 + 8; // Include the 7 bytes of padding
}

impl TransmutableMut for CreateSecp256r1SessionAuthority {}

impl IntoBytes for CreateSecp256r1SessionAuthority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

/// Standard Secp256r1 authority implementation for passkey support.
///
/// This struct represents a Secp256r1 authority with a compressed public key
/// for signature verification using the Solana secp256r1 precompile program.
#[derive(Debug, no_padding::NoPadding)]
#[repr(C, align(8))]
pub struct Secp256r1Authority {
    /// The compressed Secp256r1 public key (33 bytes)
    pub public_key: [u8; 33],
    /// Padding for u32 alignment
    _padding: [u8; 3],
    /// Signature counter to prevent signature replay attacks
    pub signature_odometer: u32,
}

impl Secp256r1Authority {
    /// Creates a new Secp256r1Authority with a compressed public key.
    pub fn new(public_key: [u8; 33]) -> Self {
        Self {
            public_key,
            _padding: [0; 3],
            signature_odometer: 0,
        }
    }
}

impl Transmutable for Secp256r1Authority {
    const LEN: usize = core::mem::size_of::<Secp256r1Authority>();
}

impl TransmutableMut for Secp256r1Authority {}

impl Authority for Secp256r1Authority {
    const TYPE: AuthorityType = AuthorityType::Secp256r1;
    const SESSION_BASED: bool = false;

    fn set_into_bytes(create_data: &[u8], bytes: &mut [u8]) -> Result<(), ProgramError> {
        if create_data.len() != 33 {
            return Err(SwigStateError::InvalidRoleData.into());
        }
        let authority = unsafe { Secp256r1Authority::load_mut_unchecked(bytes)? };
        authority.public_key.copy_from_slice(create_data);
        authority.signature_odometer = 0;
        Ok(())
    }
}

impl AuthorityInfo for Secp256r1Authority {
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
        secp256r1_authority_authenticate(self, authority_payload, data_payload, slot, account_infos)
    }
}

impl IntoBytes for Secp256r1Authority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

/// Session-based Secp256r1 authority implementation.
///
/// This struct represents a Secp256r1 authority that supports temporary session
/// keys with expiration times. It maintains both a root public key and a
/// session key.
#[derive(Debug, no_padding::NoPadding)]
#[repr(C, align(8))]
pub struct Secp256r1SessionAuthority {
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

impl Transmutable for Secp256r1SessionAuthority {
    const LEN: usize = core::mem::size_of::<Secp256r1SessionAuthority>();
}

impl TransmutableMut for Secp256r1SessionAuthority {}

impl Authority for Secp256r1SessionAuthority {
    const TYPE: AuthorityType = AuthorityType::Secp256r1Session;
    const SESSION_BASED: bool = true;

    fn set_into_bytes(create_data: &[u8], bytes: &mut [u8]) -> Result<(), ProgramError> {
        let create = unsafe { CreateSecp256r1SessionAuthority::load_unchecked(create_data)? };
        let authority = unsafe { Secp256r1SessionAuthority::load_mut_unchecked(bytes)? };
        authority.public_key = create.public_key;
        authority.signature_odometer = 0;
        authority.session_key = create.session_key;
        authority.max_session_age = create.max_session_length;
        Ok(())
    }
}

impl AuthorityInfo for Secp256r1SessionAuthority {
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
        secp256r1_session_authority_authenticate(
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

impl IntoBytes for Secp256r1SessionAuthority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

/// Authenticates a Secp256r1 authority with additional payload data.
///
/// # Arguments
/// * `authority` - The mutable authority reference for counter updates
/// * `authority_payload` - The authority payload including slot, counter,
///   instruction index, and signature
/// * `data_payload` - Additional data to be included in signature verification
/// * `current_slot` - The current slot number
/// * `account_infos` - List of accounts involved in the transaction
fn secp256r1_authority_authenticate(
    authority: &mut Secp256r1Authority,
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

    secp256r1_authenticate(
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

/// Authenticates a Secp256r1 session authority with additional payload data.
///
/// # Arguments
/// * `authority` - The mutable authority reference for counter updates
/// * `authority_payload` - The authority payload including slot, counter, and
///   instruction index
/// * `data_payload` - Additional data to be included in signature verification
/// * `current_slot` - The current slot number
/// * `account_infos` - List of accounts involved in the transaction
fn secp256r1_session_authority_authenticate(
    authority: &mut Secp256r1SessionAuthority,
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

    secp256r1_authenticate(
        &authority.public_key,
        data_payload,
        authority_slot,
        current_slot,
        account_infos,
        instruction_index,
        counter, // Now use proper counter-based replay protection
        &authority_payload[17..],
    )?;

    authority.signature_odometer = counter;
    Ok(())
}

/// Core Secp256r1 signature verification function.
///
/// This function performs the actual signature verification by:
/// - Validating signature age
/// - Computing the message hash (including counter for replay protection)
/// - Finding and validating the secp256r1 precompile instruction
/// - Verifying the message hash matches what was passed to the precompile
/// - Verifying the public key matches
fn secp256r1_authenticate(
    expected_key: &[u8; 33],
    data_payload: &[u8],
    authority_slot: u64,
    current_slot: u64,
    account_infos: &[AccountInfo],
    instruction_account_index: usize,
    counter: u32,
    additional_paylaod: &[u8],
) -> Result<(), ProgramError> {
    // Validate signature age
    if current_slot < authority_slot || current_slot - authority_slot > MAX_SIGNATURE_AGE_IN_SLOTS {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256k1InvalidSignatureAge.into());
    }

    // Compute our expected message hash
    let computed_hash = compute_message_hash(data_payload, account_infos, authority_slot, counter)?;

    let mut message_buf: MaybeUninit<[u8; WEBAUTHN_AUTHENTICATOR_DATA_MAX_SIZE + 32]> =
        MaybeUninit::uninit();

    // if there is no additional payload attatched to the auth payload, use base r1 authentication with computed hash
    // if there is addtional payload, detect the r1 authentication kind using the discriminator, and derived the signed message
    let message = if additional_paylaod.is_empty() {
        &computed_hash
    } else {
        let r1_auth_kind = u16::from_le_bytes(additional_paylaod[..2].try_into().unwrap());

        match r1_auth_kind.try_into()? {
            R1AuthenticationKind::WebAuthn => {
                webauthn_message(additional_paylaod, computed_hash, unsafe {
                    &mut *message_buf.as_mut_ptr()
                })?
            },
        }
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

/// Compute the message hash for secp256r1 authentication
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

/// Verify the secp256r1 instruction data contains the expected signature and
/// public key
pub fn verify_secp256r1_instruction_data(
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

    if instruction_data.len() < MESSAGE_DATA_OFFSET + MESSAGE_DATA_SIZE {
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

fn generate_client_data_json(
    field_order: &[u8],
    challenge: &str,
    origin: &str,
) -> Result<String, ProgramError> {
    let mut fields = Vec::new();

    for key in field_order {
        match WebAuthnField::try_from(*key)? {
            WebAuthnField::None => {},
            WebAuthnField::Challenge => fields.push(format!(r#""challenge":"{}""#, challenge)),
            WebAuthnField::Type => fields.push(r#""type":"webauthn.get""#.to_string()),
            WebAuthnField::Origin => fields.push(format!(r#""origin":"{}""#, origin)),
            WebAuthnField::CrossOrigin => fields.push(r#""crossOrigin":false"#.to_string()),
        }
    }

    Ok(format!("{{{}}}", fields.join(",")))
}

#[repr(u8)]
pub enum WebAuthnField {
    None,
    Type,
    Challenge,
    Origin,
    CrossOrigin,
}

impl TryFrom<u8> for WebAuthnField {
    type Error = SwigAuthenticateError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Type),
            2 => Ok(Self::Challenge),
            3 => Ok(Self::Origin),
            4 => Ok(Self::CrossOrigin),
            // todo: change this error message
            _ => Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage),
        }
    }
}

#[repr(u16)]
pub enum R1AuthenticationKind {
    WebAuthn = 1,
}

impl TryFrom<u16> for R1AuthenticationKind {
    type Error = SwigAuthenticateError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::WebAuthn),
            _ => Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidAuthenticationKind),
        }
    }
}

/// Process WebAuthn-specific message data
fn webauthn_message<'a>(
    auth_payload: &[u8],
    computed_hash: [u8; 32],
    message_buf: &'a mut [u8],
) -> Result<&'a [u8], ProgramError> {
    // Parse the WebAuthn payload format:
    // [2 bytes auth_type]
    // [2 bytes auth_data_len][auth_data]
    // [4 bytes webauthn client json field_order]
    // [2 bytes origin_len]
    // [2 bytes huffman_tree_len][huffman_tree]
    // [2 bytes huffman_encoded_len][huffman_encoded_origin]

    if auth_payload.len() < 6 {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
    }

    let auth_len = u16::from_le_bytes(auth_payload[2..4].try_into().unwrap()) as usize;

    if auth_len >= WEBAUTHN_AUTHENTICATOR_DATA_MAX_SIZE {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
    }

    if auth_payload.len() < 4 + auth_len + 4 {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
    }

    let auth_data = &auth_payload[4..4 + auth_len];

    let mut offset = 4 + auth_len;

    let field_order = &auth_payload[offset..offset + 4];

    offset += 4;

    let origin_len =
        u16::from_le_bytes(auth_payload[offset..offset + 2].try_into().unwrap()) as usize;

    offset += 2;

    // Parse huffman tree length
    if auth_payload.len() < offset + 2 {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
    }
    let huffman_tree_len =
        u16::from_le_bytes(auth_payload[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;

    // Parse huffman encoded origin length
    if auth_payload.len() < offset + 2 {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
    }
    let huffman_encoded_len =
        u16::from_le_bytes(auth_payload[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;

    // Validate we have enough data
    if auth_payload.len() < offset + huffman_tree_len + huffman_encoded_len {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
    }

    let huffman_tree = &auth_payload[offset..offset + huffman_tree_len];
    let huffman_encoded_origin =
        &auth_payload[offset + huffman_tree_len..offset + huffman_tree_len + huffman_encoded_len];

    // Log the huffman input for monitoring
    pinocchio::msg!(
        "WebAuthn Huffman input: {} bytes encoded",
        huffman_encoded_len
    );

    // Decode the huffman-encoded origin URL
    let decoded_origin = decode_huffman_origin(huffman_tree, huffman_encoded_origin, origin_len)?;

    // Log the decoded origin for monitoring
    let origin_str = core::str::from_utf8(&decoded_origin).unwrap_or("<invalid utf8>");
    pinocchio::msg!("WebAuthn Huffman decoded origin: '{}'", origin_str);

    // Reconstruct the client data JSON using the decoded origin and reconstructed
    // challenge
    let client_data_json =
        reconstruct_client_data_json(field_order, &decoded_origin, &computed_hash)?;

    // Compute SHA256 hash of the reconstructed client data JSON
    let mut client_data_hash = [0u8; 32];
    unsafe {
        #[cfg(target_os = "solana")]
        let res = pinocchio::syscalls::sol_sha256(
            [client_data_json.as_slice()].as_ptr() as *const u8,
            1,
            client_data_hash.as_mut_ptr(),
        );
        #[cfg(not(target_os = "solana"))]
        let res = 0;
        if res != 0 {
            return Err(SwigAuthenticateError::PermissionDeniedSecp256k1InvalidHash.into());
        }
    }

    // Build the final message: authenticator_data + client_data_json_hash
    message_buf[0..auth_len].copy_from_slice(auth_data);
    message_buf[auth_len..auth_len + 32].copy_from_slice(&client_data_hash);

    Ok(&message_buf[..auth_len + 32])
}

/// Decode huffman-encoded origin URL
fn decode_huffman_origin(
    tree_data: &[u8],
    encoded_data: &[u8],
    decoded_len: usize,
) -> Result<Vec<u8>, ProgramError> {
    // Constants for huffman decoding
    const NODE_SIZE: usize = 3;
    const LEAF_NODE: u8 = 0;
    // const INTERNAL_NODE: u8 = 1;
    const BIT_MASKS: [u8; 8] = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];

    if tree_data.len() % NODE_SIZE != 0 || tree_data.is_empty() {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
    }

    let node_count = tree_data.len() / NODE_SIZE;
    let root_index = node_count - 1;
    let mut current_node_index = root_index;
    let mut decoded = Vec::new();

    for &byte in encoded_data.iter() {
        for bit_pos in 0..8 {
            if decoded.len() == decoded_len {
                return Ok(decoded);
            }

            let bit = (byte & BIT_MASKS[bit_pos]) != 0;

            let node_offset = current_node_index * NODE_SIZE;
            let node_type = tree_data[node_offset];

            // Should not start a loop at a leaf
            if node_type == LEAF_NODE {
                return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
            }

            // Navigate to the correct child index
            let left_or_char = tree_data[node_offset + 1];
            let right = tree_data[node_offset + 2];
            current_node_index = if bit {
                right as usize
            } else {
                left_or_char as usize
            };

            if current_node_index >= node_count {
                return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
            }

            // Check if the new node is a leaf
            let next_node_offset = current_node_index * NODE_SIZE;
            let next_node_type = tree_data[next_node_offset];

            if next_node_type == LEAF_NODE {
                let character = tree_data[next_node_offset + 1];
                decoded.push(character);
                current_node_index = root_index; // Reset for the next bit
            }
        }
    }

    Ok(decoded)
}

/// Reconstruct client data JSON from origin and challenge data
fn reconstruct_client_data_json(
    field_order: &[u8],
    origin: &[u8],
    challenge_data: &[u8],
) -> Result<Vec<u8>, ProgramError> {
    // Convert origin bytes to string
    let origin_str = core::str::from_utf8(origin)
        .map_err(|_| SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage)?;

    // Base64url encode the challenge data (without padding)
    let challenge_b64 = base64url_encode_no_pad(challenge_data);

    let mut fields = Vec::with_capacity(4);

    for key in field_order {
        match WebAuthnField::try_from(*key)? {
            WebAuthnField::None => {},
            WebAuthnField::Challenge => fields.push(format!(r#""challenge":"{}""#, challenge_b64)),
            WebAuthnField::Type => fields.push(r#""type":"webauthn.get""#.to_string()),
            WebAuthnField::Origin => fields.push(format!(r#""origin":"{}""#, origin_str)),
            WebAuthnField::CrossOrigin => fields.push(r#""crossOrigin":false"#.to_string()),
        }
    }

    let client_data_json = format!("{{{}}}", fields.join(","));

    Ok(client_data_json.into_bytes())
}

/// Base64url encode without padding
fn base64url_encode_no_pad(data: &[u8]) -> String {
    const BASE64URL_CHARS: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut result = String::new();
    let mut i = 0;

    while i + 2 < data.len() {
        let b1 = data[i];
        let b2 = data[i + 1];
        let b3 = data[i + 2];

        result.push(BASE64URL_CHARS[(b1 >> 2) as usize] as char);
        result.push(BASE64URL_CHARS[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize] as char);
        result.push(BASE64URL_CHARS[(((b2 & 0x0f) << 2) | (b3 >> 6)) as usize] as char);
        result.push(BASE64URL_CHARS[(b3 & 0x3f) as usize] as char);

        i += 3;
    }

    // Handle remaining bytes
    if i < data.len() {
        let b1 = data[i];
        result.push(BASE64URL_CHARS[(b1 >> 2) as usize] as char);

        if i + 1 < data.len() {
            let b2 = data[i + 1];
            result.push(BASE64URL_CHARS[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize] as char);
            result.push(BASE64URL_CHARS[((b2 & 0x0f) << 2) as usize] as char);
        } else {
            result.push(BASE64URL_CHARS[((b1 & 0x03) << 4) as usize] as char);
        }
    }

    result
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
    fn test_verify_secp256r1_instruction_data_single_signature() {
        let test_message = [0u8; 32];
        let test_signature = [0xCD; 64]; // Test signature
        let test_pubkey = [0x02; 33]; // Test compressed pubkey

        let instruction_data =
            create_test_secp256r1_instruction_data(&test_message, &test_signature, &test_pubkey);

        // Should succeed with matching pubkey and message hash
        let result =
            verify_secp256r1_instruction_data(&instruction_data, &test_pubkey, &test_message);
        assert!(
            result.is_ok(),
            "Verification should succeed with correct data. Error: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_verify_secp256r1_instruction_data_wrong_pubkey() {
        let test_message = [0u8; 32];
        let test_pubkey = [0x02; 33];
        let wrong_pubkey = [0x03; 33]; // Different pubkey
        let test_signature = [0xCD; 64];

        let instruction_data =
            create_test_secp256r1_instruction_data(&test_message, &test_signature, &test_pubkey);

        // Should fail with wrong pubkey
        let result =
            verify_secp256r1_instruction_data(&instruction_data, &wrong_pubkey, &test_message);
        assert!(
            result.is_err(),
            "Verification should fail with wrong pubkey"
        );
        assert_eq!(
            result.unwrap_err(),
            SwigAuthenticateError::PermissionDeniedSecp256r1InvalidPubkey.into()
        );
    }

    #[test]
    fn test_verify_secp256r1_instruction_data_wrong_message_hash() {
        let test_message = [0u8; 32];
        let wrong_message = [1u8; 32]; // Different message
        let test_pubkey = [0x02; 33];
        let test_signature = [0xCD; 64];

        let instruction_data =
            create_test_secp256r1_instruction_data(&test_message, &test_signature, &test_pubkey);

        // Should fail with wrong message hash
        let result =
            verify_secp256r1_instruction_data(&instruction_data, &test_pubkey, &wrong_message);
        assert!(
            result.is_err(),
            "Verification should fail with wrong message hash"
        );
        assert_eq!(
            result.unwrap_err(),
            SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessageHash.into()
        );
    }

    #[test]
    fn test_verify_secp256r1_instruction_data_insufficient_length() {
        let short_data = vec![0x01, 0x00]; // Only 2 bytes

        let test_pubkey = [0x02; 33];
        let test_message_hash = [0xAB; 32];

        let result =
            verify_secp256r1_instruction_data(&short_data, &test_pubkey, &test_message_hash);
        assert!(
            result.is_err(),
            "Verification should fail with insufficient data"
        );
        assert_eq!(
            result.unwrap_err(),
            SwigAuthenticateError::PermissionDeniedSecp256r1InvalidInstruction.into()
        );
    }

    #[test]
    fn test_verify_secp256r1_instruction_data_zero_signatures() {
        let mut instruction_data = Vec::new();
        instruction_data.push(0u8); // Zero signatures (1 byte, not 2)
        instruction_data.push(0u8); // Padding

        let test_pubkey = [0x02; 33];
        let test_message_hash = [0xAB; 32];

        let result =
            verify_secp256r1_instruction_data(&instruction_data, &test_pubkey, &test_message_hash);
        assert!(
            result.is_err(),
            "Verification should fail with zero signatures"
        );
        assert_eq!(
            result.unwrap_err(),
            SwigAuthenticateError::PermissionDeniedSecp256r1InvalidInstruction.into()
        );
    }

    #[test]
    fn test_verify_secp256r1_instruction_data_cross_instruction_reference() {
        let mut instruction_data = Vec::new();

        // Number of signature sets (1 byte) and padding (1 byte)
        instruction_data.push(1u8); // Number of signature sets
        instruction_data.push(0u8); // Padding

        // Signature offsets with cross-instruction reference
        instruction_data.extend_from_slice(&16u16.to_le_bytes()); // signature_offset
        instruction_data.extend_from_slice(&1u16.to_le_bytes()); // signature_instruction_index (different instruction)
        instruction_data.extend_from_slice(&80u16.to_le_bytes()); // public_key_offset
        instruction_data.extend_from_slice(&0u16.to_le_bytes()); // public_key_instruction_index
        instruction_data.extend_from_slice(&113u16.to_le_bytes()); // message_data_offset
        instruction_data.extend_from_slice(&32u16.to_le_bytes()); // message_data_size
        instruction_data.extend_from_slice(&0u16.to_le_bytes()); // message_instruction_index

        let test_pubkey = [0x02; 33];
        let test_message_hash = [0xAB; 32];

        let result =
            verify_secp256r1_instruction_data(&instruction_data, &test_pubkey, &test_message_hash);
        assert!(
            result.is_err(),
            "Verification should fail with cross-instruction reference"
        );
        assert_eq!(
            result.unwrap_err(),
            SwigAuthenticateError::PermissionDeniedSecp256r1InvalidInstruction.into()
        );
    }

    #[test]
    fn test_verify_secp256r1_with_real_crypto() {
        // Create a test message 32 bytes
        let test_message = b"Hello, secp256r1 world! dddddddd";

        // Generate real cryptographic signature and pubkey using OpenSSL
        let (signature_bytes, pubkey_bytes) = create_test_signature_and_pubkey(test_message);

        // Create instruction data using the official Solana function
        let instruction_data =
            create_test_secp256r1_instruction_data(test_message, &signature_bytes, &pubkey_bytes);

        // Should succeed with real cryptographic data
        let result =
            verify_secp256r1_instruction_data(&instruction_data, &pubkey_bytes, test_message);
        assert!(
            result.is_ok(),
            "Verification should succeed with real cryptographic data"
        );

        // Should fail with wrong message
        let wrong_message = b"Different message";
        let result =
            verify_secp256r1_instruction_data(&instruction_data, &pubkey_bytes, wrong_message);
        assert!(
            result.is_err(),
            "Verification should fail with wrong message"
        );

        // Should fail with wrong public key
        let wrong_pubkey = [0xFF; 33];
        let result =
            verify_secp256r1_instruction_data(&instruction_data, &wrong_pubkey, test_message);
        assert!(
            result.is_err(),
            "Verification should fail with wrong public key"
        );
    }
}
