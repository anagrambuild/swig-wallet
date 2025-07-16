//! WebAuthn authority implementation for passkey support.
//!
//! This module provides implementations for WebAuthn-based authority types in
//! the Swig wallet system, designed specifically for WebAuthn passkey
//! authentication. It includes both standard WebAuthn authority and
//! session-based WebAuthn authority with expiration support. The implementation
//! relies on the Solana secp256r1 precompile program for signature
//! verification.

#![warn(unexpected_cfgs)]

use core::mem::MaybeUninit;

#[allow(unused_imports)]
use pinocchio::syscalls::sol_sha256;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::instructions::{Instructions, INSTRUCTIONS_ID},
};
use swig_assertions::sol_assert_bytes_eq;

use super::{Authority, AuthorityInfo, AuthorityType};
use crate::{
    authority::secp256r1::{
        verify_secp256r1_instruction_data, COMPRESSED_PUBKEY_SERIALIZED_SIZE, DATA_START,
        MESSAGE_DATA_OFFSET, MESSAGE_DATA_SIZE, PUBKEY_DATA_OFFSET, SECP256R1_PROGRAM_ID,
    },
    IntoBytes, SwigAuthenticateError, SwigStateError, Transmutable, TransmutableMut,
};

/// Maximum age (in slots) for a WebAuthn signature to be considered valid
const MAX_SIGNATURE_AGE_IN_SLOTS: u64 = 60;

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

/// Creation parameters for a session-based WebAuthn authority.
#[derive(Debug, no_padding::NoPadding)]
#[repr(C, align(8))]
pub struct CreateWebAuthnSessionAuthority {
    /// The compressed secp256r1 public key (33 bytes)
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
    /// * `public_key` - The compressed secp256r1 public key
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
/// for signature verification using the Solana secp256r1 precompile program.
#[derive(Debug, no_padding::NoPadding)]
#[repr(C, align(8))]
pub struct WebAuthnAuthority {
    /// The compressed secp256r1 public key (33 bytes)
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
    /// The compressed secp256r1 public key (33 bytes)
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
///   instruction index, and WebAuthn data
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
/// - Processing WebAuthn-specific data (authenticator data, client data JSON)
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
    webauthn_payload: &[u8],
) -> Result<(), ProgramError> {
    // Validate signature age
    if current_slot < authority_slot || current_slot - authority_slot > MAX_SIGNATURE_AGE_IN_SLOTS {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256k1InvalidSignatureAge.into());
    }

    // Compute our expected message hash
    let computed_hash = compute_message_hash(data_payload, account_infos, authority_slot, counter)?;

    let mut message_buf: MaybeUninit<[u8; WEBAUTHN_AUTHENTICATOR_DATA_MAX_SIZE + 32]> =
        MaybeUninit::uninit();

    // Process WebAuthn-specific data to create the final message
    let message = webauthn_message(webauthn_payload, computed_hash, unsafe {
        &mut *message_buf.as_mut_ptr()
    })?;

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

/// Process WebAuthn-specific message data
fn webauthn_message<'a>(
    auth_payload: &[u8],
    computed_hash: [u8; 32],
    message_buf: &'a mut [u8],
) -> Result<&'a [u8], ProgramError> {
    // Parse the WebAuthn payload format:
    // [2 bytes auth_type][2 bytes auth_len][auth_data][4 bytes counter][2 bytes
    // huffman_tree_len][huffman_tree][2 bytes
    // huffman_encoded_len][huffman_encoded_origin]

    if auth_payload.len() < 6 {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
    }

    let auth_len = u16::from_le_bytes(auth_payload[2..4].try_into().unwrap()) as usize;

    if auth_len >= WEBAUTHN_AUTHENTICATOR_DATA_MAX_SIZE {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
    }

    if auth_payload.len() < 4 + auth_len + 4 + 4 {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
    }

    let auth_data = &auth_payload[4..4 + auth_len];
    let counter_bytes = &auth_payload[4 + auth_len..4 + auth_len + 4];
    let counter = u32::from_le_bytes(counter_bytes.try_into().unwrap());

    let mut offset = 4 + auth_len + 4;

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
    let decoded_origin = decode_huffman_origin(huffman_tree, huffman_encoded_origin)?;

    // Log the decoded origin for monitoring
    let origin_str = core::str::from_utf8(&decoded_origin).unwrap_or("<invalid utf8>");
    pinocchio::msg!("WebAuthn Huffman decoded origin: '{}'", origin_str);

    // Reconstruct the challenge: computed_hash + counter (this is what should have
    // been signed)
    let mut challenge_data = [0u8; 36]; // 32 bytes hash + 4 bytes counter
    challenge_data[0..32].copy_from_slice(&computed_hash);
    challenge_data[32..36].copy_from_slice(&counter.to_le_bytes());

    // Reconstruct the client data JSON using the decoded origin and reconstructed
    // challenge
    let client_data_json = reconstruct_client_data_json(&decoded_origin, &challenge_data)?;

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
fn decode_huffman_origin(tree_data: &[u8], encoded_data: &[u8]) -> Result<Vec<u8>, ProgramError> {
    // Constants for huffman decoding
    const NODE_SIZE: usize = 3;
    const LEAF_NODE: u8 = 0;
    const INTERNAL_NODE: u8 = 1;
    const BIT_MASKS: [u8; 8] = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];

    if tree_data.len() % NODE_SIZE != 0 || tree_data.is_empty() {
        return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
    }

    let node_count = tree_data.len() / NODE_SIZE;
    let root_index = node_count - 1;
    let mut current_node = root_index;
    let mut decoded = Vec::new();

    let mut bit_count = 0;
    let total_bits = encoded_data.len() * 8;

    for (_byte_idx, &byte) in encoded_data.iter().enumerate() {
        for bit_pos in 0..8 {
            if bit_count >= total_bits {
                break;
            }

            let bit = (byte & BIT_MASKS[bit_pos]) != 0;
            bit_count += 1;

            // Navigate tree based on current bit
            let node_offset = current_node * NODE_SIZE;
            if node_offset + 2 >= tree_data.len() {
                return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
            }

            let node_type = tree_data[node_offset];
            let left_or_char = tree_data[node_offset + 1];
            let right = tree_data[node_offset + 2];

            if node_type == LEAF_NODE {
                // We're at a leaf, output the character and reset to root
                decoded.push(left_or_char);
                current_node = root_index;

                // Stop when we've decoded the expected URL length
                // Re-process the current bit from the root
                let root_node_offset = current_node * NODE_SIZE;
                if root_node_offset + 2 < tree_data.len() {
                    let root_node_type = tree_data[root_node_offset];
                    let root_left_or_char = tree_data[root_node_offset + 1];
                    let root_right = tree_data[root_node_offset + 2];

                    if root_node_type == INTERNAL_NODE {
                        current_node = if bit {
                            root_right as usize
                        } else {
                            root_left_or_char as usize
                        };

                        if current_node >= node_count {
                            return Err(
                                SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage
                                    .into(),
                            );
                        }
                    }
                }
            } else if node_type == INTERNAL_NODE {
                // Navigate tree based on bit (false=left, true=right)
                current_node = if bit {
                    right as usize
                } else {
                    left_or_char as usize
                };

                if current_node >= node_count {
                    return Err(
                        SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into(),
                    );
                }
            } else {
                return Err(SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage.into());
            }
        }
    }

    Ok(decoded)
}

/// Reconstruct client data JSON from origin and challenge data
fn reconstruct_client_data_json(
    origin: &[u8],
    challenge_data: &[u8],
) -> Result<Vec<u8>, ProgramError> {
    // Convert origin bytes to string
    let origin_str = core::str::from_utf8(origin)
        .map_err(|_| SwigAuthenticateError::PermissionDeniedSecp256r1InvalidMessage)?;

    // Base64url encode the challenge data (without padding)
    let challenge_b64 = base64url_encode_no_pad(challenge_data);

    // Construct the client data JSON to match the exact format that WebAuthn
    // creates This must match exactly what the frontend creates for the
    // WebAuthn challenge
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
        challenge_b64, origin_str
    );

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
