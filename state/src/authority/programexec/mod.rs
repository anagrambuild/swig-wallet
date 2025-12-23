//! Program execution authority implementation.
//!
//! This module provides implementations for program execution-based authority
//! types in the Swig wallet system. This authority type validates that a
//! preceding instruction in the transaction matches configured program and
//! instruction prefix requirements, and that the instruction was successful.

pub mod session;

use core::any::Any;

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::instructions::{Instructions, INSTRUCTIONS_ID},
};
use swig_assertions::sol_assert_bytes_eq;

use super::{Authority, AuthorityInfo, AuthorityType};
use crate::{IntoBytes, SwigAuthenticateError, SwigStateError, Transmutable, TransmutableMut};

const MAX_INSTRUCTION_PREFIX_LEN: usize = 40;
const IX_PREFIX_OFFSET: usize = 32 + 1 + 7; // program_id + instruction_prefix_len + padding

/// Standard Program Execution authority implementation.
///
/// This struct represents a program execution authority that validates
/// a preceding instruction matches the configured program and instruction
/// prefix.
#[repr(C, align(8))]
#[derive(Debug, PartialEq, no_padding::NoPadding)]
pub struct ProgramExecAuthority {
    pub instruction_prefix_len: u8,
    /// Padding for alignment
    _padding: [u8; 7],
    /// The program ID that must execute the preceding instruction
    pub program_id: [u8; 32],
    /// Length of the instruction prefix to match (0-40)
    pub instruction_prefix: [u8; MAX_INSTRUCTION_PREFIX_LEN],
}

impl ProgramExecAuthority {
    /// Creates a new ProgramExecAuthority.
    ///
    /// # Arguments
    /// * `program_id` - The program ID to validate against
    /// * `instruction_prefix_len` - Length of the prefix to match
    pub fn new(program_id: [u8; 32], instruction_prefix_len: u8) -> Self {
        Self {
            program_id,
            instruction_prefix_len,
            _padding: [0; 7],
            instruction_prefix: [0; MAX_INSTRUCTION_PREFIX_LEN],
        }
    }

    /// Creates authority data bytes for creating a ProgramExec authority.
    ///
    /// # Arguments
    /// * `program_id` - The program ID that must execute the preceding
    ///   instruction
    /// * `instruction_prefix` - The instruction discriminator/prefix to match
    ///   (up to 40 bytes)
    ///
    /// # Returns
    /// Returns a vector of bytes that can be used as authority data when
    /// creating a ProgramExec authority
    pub fn create_authority_data(program_id: &[u8; 32], instruction_prefix: &[u8]) -> Vec<u8> {
        let prefix_len = instruction_prefix.len().min(MAX_INSTRUCTION_PREFIX_LEN);
        let mut data = Vec::with_capacity(Self::LEN);

        // program_id: 32 bytes
        data.extend_from_slice(program_id);

        // instruction_prefix_len: 1 byte
        data.push(prefix_len as u8);

        // padding: 7 bytes
        data.extend_from_slice(&[0u8; 7]);

        // instruction_prefix: up to MAX_INSTRUCTION_PREFIX_LEN bytes
        data.extend_from_slice(&instruction_prefix[..prefix_len]);

        // Pad remaining bytes to MAX_INSTRUCTION_PREFIX_LEN
        data.extend_from_slice(&vec![0u8; MAX_INSTRUCTION_PREFIX_LEN - prefix_len]);

        data
    }
}

///

impl Transmutable for ProgramExecAuthority {
    // len of header
    const LEN: usize = core::mem::size_of::<ProgramExecAuthority>();
}

impl TransmutableMut for ProgramExecAuthority {}

impl Authority for ProgramExecAuthority {
    const TYPE: AuthorityType = AuthorityType::ProgramExec;
    const SESSION_BASED: bool = false;

    fn set_into_bytes(create_data: &[u8], bytes: &mut [u8]) -> Result<(), ProgramError> {
        if create_data.len() != Self::LEN {
            return Err(SwigStateError::InvalidRoleData.into());
        }

        let prefix_len = create_data[32] as usize;
        if prefix_len > MAX_INSTRUCTION_PREFIX_LEN {
            return Err(SwigStateError::InvalidRoleData.into());
        }

        let authority = unsafe { ProgramExecAuthority::load_mut_unchecked(bytes)? };
        let create_data_program_id = &create_data[..32];
        assert_program_exec_cant_be_swig(create_data_program_id)?;
        authority.program_id.copy_from_slice(create_data_program_id);
        authority.instruction_prefix_len = prefix_len as u8;
        authority.instruction_prefix[..prefix_len]
            .copy_from_slice(&create_data[IX_PREFIX_OFFSET..IX_PREFIX_OFFSET + prefix_len]);
        Ok(())
    }
}

impl AuthorityInfo for ProgramExecAuthority {
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
        // Data format should match identity(): program_id (32) + instruction_prefix (prefix_len)
        let expected_len = 32 + self.instruction_prefix_len as usize;
        if data.len() != expected_len {
            return false;
        }
        sol_assert_bytes_eq(&self.program_id, &data[..32], 32)
            && sol_assert_bytes_eq(
                &self.instruction_prefix[..self.instruction_prefix_len as usize],
                &data[32..],
                self.instruction_prefix_len as usize,
            )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn identity(&self) -> Result<&[u8], ProgramError> {
        // program_id and instruction_prefix are contiguous in memory
        let len = 32 + self.instruction_prefix_len as usize;
        let bytes = unsafe { core::slice::from_raw_parts(self.program_id.as_ptr(), len) };
        Ok(bytes)
    }

    fn signature_odometer(&self) -> Option<u32> {
        None
    }

    fn authenticate(
        &mut self,
        account_infos: &[AccountInfo],
        authority_payload: &[u8],
        _data_payload: &[u8],
        _slot: u64,
    ) -> Result<(), ProgramError> {
        // authority_payload format: [instruction_sysvar_index: 1 byte]
        // Config is always at index 0, wallet is always at index 0 (same as config)
        if authority_payload.len() != 1 {
            return Err(SwigAuthenticateError::InvalidAuthorityPayload.into());
        }

        let instruction_sysvar_index = authority_payload[0] as usize;
        let config_account_index = 0; // Config is always the first account (swig account)
        let wallet_account_index = 1; // Wallet is the second account (swig wallet address)

        program_exec_authenticate(
            account_infos,
            instruction_sysvar_index,
            config_account_index,
            wallet_account_index,
            &self.program_id,
            &self.instruction_prefix,
            self.instruction_prefix_len as usize,
        )
    }
}

impl IntoBytes for ProgramExecAuthority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

fn assert_program_exec_cant_be_swig(program_id: &[u8]) -> Result<(), ProgramError> {
    if sol_assert_bytes_eq(program_id, &swig_assertions::id(), 32) {
        return Err(SwigAuthenticateError::PermissionDeniedProgramExecCannotBeSwig.into());
    }
    Ok(())
}

/// Authenticates a program execution authority.
///
/// Validates that a preceding instruction:
/// - Was executed by the expected program
/// - Has instruction data matching the expected prefix
/// - Passed the config and wallet accounts as its first two accounts
/// - Executed successfully (implied by the transaction being valid)
///
/// # Arguments
/// * `account_infos` - List of accounts involved in the transaction
/// * `instruction_sysvar_index` - Index of the instructions sysvar account
/// * `config_account_index` - Index of the config account
/// * `wallet_account_index` - Index of the wallet account
/// * `expected_program_id` - The program ID that should have executed
/// * `expected_instruction_prefix` - The instruction data prefix to match
/// * `prefix_len` - Length of the prefix to match
pub fn program_exec_authenticate(
    account_infos: &[AccountInfo],
    instruction_sysvar_index: usize,
    config_account_index: usize,
    wallet_account_index: usize,
    expected_program_id: &[u8; 32],
    expected_instruction_prefix: &[u8; MAX_INSTRUCTION_PREFIX_LEN],
    prefix_len: usize,
) -> Result<(), ProgramError> {
    // Get the sysvar instructions account
    let sysvar_instructions = account_infos
        .get(instruction_sysvar_index)
        .ok_or(SwigAuthenticateError::InvalidAuthorityPayload)?;

    // Verify this is the sysvar instructions account
    if sysvar_instructions.key().as_ref() != &INSTRUCTIONS_ID {
        return Err(SwigAuthenticateError::PermissionDeniedProgramExecInvalidInstruction.into());
    }

    // Get the config and wallet accounts
    let config_account = account_infos
        .get(config_account_index)
        .ok_or(SwigAuthenticateError::InvalidAuthorityPayload)?;
    let wallet_account = account_infos
        .get(wallet_account_index)
        .ok_or(SwigAuthenticateError::InvalidAuthorityPayload)?;

    // Load instructions sysvar
    let sysvar_instructions_data = unsafe { sysvar_instructions.borrow_data_unchecked() };
    let ixs = unsafe { Instructions::new_unchecked(sysvar_instructions_data) };
    let current_index = ixs.load_current_index() as usize;

    // Must have at least one preceding instruction
    if current_index == 0 {
        return Err(SwigAuthenticateError::PermissionDeniedProgramExecInvalidInstruction.into());
    }

    // Get the preceding instruction
    let preceding_ix = unsafe { ixs.deserialize_instruction_unchecked(current_index - 1) };
    let num_accounts = u16::from_le_bytes(unsafe {
        *(preceding_ix.get_instruction_data().as_ptr() as *const [u8; 2])
    });
    if num_accounts < 2 {
        return Err(
            SwigAuthenticateError::PermissionDeniedProgramExecInvalidInstructionData.into(),
        );
    }

    // Verify the instruction is calling the expected program
    if !sol_assert_bytes_eq(preceding_ix.get_program_id(), expected_program_id, 32) {
        return Err(SwigAuthenticateError::PermissionDeniedProgramExecInvalidProgram.into());
    }

    // Verify the instruction data prefix matches
    let instruction_data = preceding_ix.get_instruction_data();
    if instruction_data.len() < prefix_len {
        return Err(
            SwigAuthenticateError::PermissionDeniedProgramExecInvalidInstructionData.into(),
        );
    }

    if !sol_assert_bytes_eq(
        &instruction_data[..prefix_len],
        &expected_instruction_prefix[..prefix_len],
        prefix_len,
    ) {
        return Err(
            SwigAuthenticateError::PermissionDeniedProgramExecInvalidInstructionData.into(),
        );
    }

    // Verify the first two accounts of the preceding instruction are config and
    // wallet Get account meta at index 0 (should be config)
    let account_0 = unsafe { preceding_ix.get_account_meta_at_unchecked(0) };
    let account_1 = unsafe { preceding_ix.get_account_meta_at_unchecked(1) };

    // Verify the accounts match the config and wallet keys
    if !sol_assert_bytes_eq(account_0.key.as_ref(), config_account.key(), 32) {
        return Err(SwigAuthenticateError::PermissionDeniedProgramExecInvalidConfigAccount.into());
    }

    if !sol_assert_bytes_eq(account_1.key.as_ref(), wallet_account.key(), 32) {
        return Err(SwigAuthenticateError::PermissionDeniedProgramExecInvalidWalletAccount.into());
    }

    // If we get here, all checks passed - the instruction executed successfully
    // (implied by the transaction being valid) with the correct program, data, and
    // accounts
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_authority(program_id: [u8; 32], prefix: &[u8]) -> ProgramExecAuthority {
        let mut authority = ProgramExecAuthority::new(program_id, prefix.len() as u8);
        authority.instruction_prefix[..prefix.len()].copy_from_slice(prefix);
        authority
    }

    #[test]
    fn test_identity_returns_program_id_and_prefix() {
        let program_id = [1u8; 32];
        let prefix = [0x01, 0xAB, 0xCD]; // 3-byte prefix (e.g., discriminator + sub_hash start)
        let authority = create_test_authority(program_id, &prefix);

        let identity = authority.identity().unwrap();

        // Identity should be program_id (32 bytes) + instruction_prefix (prefix_len bytes)
        assert_eq!(identity.len(), 32 + prefix.len());
        assert_eq!(&identity[..32], &program_id);
        assert_eq!(&identity[32..], &prefix);
    }

    #[test]
    fn test_identity_with_33_byte_prefix() {
        // Test the IDP use case: 1 byte discriminator + 32 byte sub_hash
        let program_id = [2u8; 32];
        let mut prefix = [0u8; 33];
        prefix[0] = 0x01; // VerifyJwt discriminator
        prefix[1..33].copy_from_slice(&[0xAB; 32]); // sub_hash

        let authority = create_test_authority(program_id, &prefix);

        let identity = authority.identity().unwrap();

        assert_eq!(identity.len(), 65); // 32 + 33
        assert_eq!(&identity[..32], &program_id);
        assert_eq!(identity[32], 0x01); // discriminator
        assert_eq!(&identity[33..65], &[0xAB; 32]); // sub_hash
    }

    #[test]
    fn test_identity_with_zero_prefix_len() {
        let program_id = [3u8; 32];
        let authority = create_test_authority(program_id, &[]);

        let identity = authority.identity().unwrap();

        assert_eq!(identity.len(), 32);
        assert_eq!(identity, &program_id);
    }

    #[test]
    fn test_match_data_matches_identity() {
        let program_id = [4u8; 32];
        let prefix = [0x01, 0x02, 0x03, 0x04];
        let authority = create_test_authority(program_id, &prefix);

        let identity = authority.identity().unwrap();

        // match_data should return true when given the identity
        assert!(authority.match_data(identity));
    }

    #[test]
    fn test_match_data_with_33_byte_prefix() {
        let program_id = [5u8; 32];
        let mut prefix = [0u8; 33];
        prefix[0] = 0x01;
        prefix[1..33].copy_from_slice(&[0xCD; 32]);

        let authority = create_test_authority(program_id, &prefix);

        let identity = authority.identity().unwrap();

        assert!(authority.match_data(identity));
        assert_eq!(identity.len(), 65);
    }

    #[test]
    fn test_match_data_rejects_wrong_program_id() {
        let program_id = [6u8; 32];
        let prefix = [0x01, 0x02];
        let authority = create_test_authority(program_id, &prefix);

        // Create data with wrong program_id
        let mut wrong_data = vec![7u8; 32]; // wrong program_id
        wrong_data.extend_from_slice(&prefix);

        assert!(!authority.match_data(&wrong_data));
    }

    #[test]
    fn test_match_data_rejects_wrong_prefix() {
        let program_id = [8u8; 32];
        let prefix = [0x01, 0x02];
        let authority = create_test_authority(program_id, &prefix);

        // Create data with wrong prefix
        let mut wrong_data = program_id.to_vec();
        wrong_data.extend_from_slice(&[0xFF, 0xFF]); // wrong prefix

        assert!(!authority.match_data(&wrong_data));
    }

    #[test]
    fn test_match_data_rejects_wrong_length() {
        let program_id = [9u8; 32];
        let prefix = [0x01, 0x02];
        let authority = create_test_authority(program_id, &prefix);

        // Too short
        assert!(!authority.match_data(&program_id));

        // Too long
        let mut too_long = program_id.to_vec();
        too_long.extend_from_slice(&[0x01, 0x02, 0x03]);
        assert!(!authority.match_data(&too_long));
    }

    #[test]
    fn test_struct_size() {
        // Verify the struct size is as expected
        assert_eq!(
            ProgramExecAuthority::LEN,
            1 + 7 + 32 + 40 // prefix_len + padding + program_id + instruction_prefix
        );
        assert_eq!(ProgramExecAuthority::LEN, 80);
    }
}
