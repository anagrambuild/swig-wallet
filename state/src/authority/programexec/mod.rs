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
    /// The program ID that must execute the preceding instruction
    pub program_id: [u8; 32],
    /// Length of the instruction prefix to match (0-8)
    pub instruction_prefix_len: u8,
    /// Padding for alignment
    _padding: [u8; 7],
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
        authority.program_id.copy_from_slice(&create_data[..32]);
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
        if data.len() < 32 {
            return false;
        }
        sol_assert_bytes_eq(&self.program_id, &data[..32], 32)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn identity(&self) -> Result<&[u8], ProgramError> {
        Ok(&self.program_id)
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
