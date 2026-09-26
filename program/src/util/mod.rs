//! Utility functions and types for the Swig wallet program.
//!
//! This module provides helper functionality for common operations such as:
//! - Token transfer operations
//! The utilities are optimized for performance and safety.

pub(crate) mod token_integrity;

use std::mem::MaybeUninit;

use pinocchio::{
    account_info::AccountInfo,
    cpi::invoke_signed,
    instruction::{AccountMeta, Instruction, Signer},
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    syscalls::sol_sha256,
    ProgramResult,
};
use swig_state::{
    action::{
        all::All, manage_authority::ManageAuthority, replace_authority::ReplaceAuthority, Action,
        ActionLoader, Permission,
    },
    authority::AuthorityType,
    role::{Position, RoleMut},
    swig::Swig,
    SwigAuthenticateError, Transmutable,
};

use crate::error::SwigError;

/// Reject grants targeting root in a non-root caller's add/update payload.
/// Instruction action boundaries are normalized when stored, so scan by header
/// lengths here. Stored actions still use the stricter ActionLoader decoder.
pub(crate) fn reject_root_recovery_grants(mut actions: &[u8]) -> ProgramResult {
    while !actions.is_empty() {
        let header = actions
            .get(..Action::LEN)
            .ok_or(ProgramError::InvalidInstructionData)?;
        let action = unsafe { Action::load_unchecked(header)? };
        let end = Action::LEN
            .checked_add(action.length() as usize)
            .ok_or(ProgramError::InvalidInstructionData)?;
        let action_data = actions
            .get(Action::LEN..end)
            .ok_or(ProgramError::InvalidInstructionData)?;
        if action.permission()? == Permission::ReplaceAuthority
            && unsafe { ReplaceAuthority::load_unchecked(action_data)? }.role_id == 0
        {
            return Err(SwigAuthenticateError::PermissionDeniedToManageAuthority.into());
        }
        actions = &actions[end..];
    }
    Ok(())
}

/// Ensures the current role buffer still contains an administrator.
pub(crate) fn ensure_admin_remains(roles: &[u8], role_count: u16) -> Result<(), ProgramError> {
    let mut cursor = 0usize;
    for _ in 0..role_count {
        let position_end = cursor
            .checked_add(Position::LEN)
            .ok_or(ProgramError::InvalidAccountData)?;
        let position = unsafe {
            Position::load_unchecked(
                roles
                    .get(cursor..position_end)
                    .ok_or(ProgramError::InvalidAccountData)?,
            )?
        };
        let actions_start = position_end
            .checked_add(position.authority_length() as usize)
            .ok_or(ProgramError::InvalidAccountData)?;
        let boundary = position.boundary() as usize;
        let actions = roles
            .get(actions_start..boundary)
            .ok_or(ProgramError::InvalidAccountData)?;

        if ActionLoader::find_action::<All>(actions)?.is_some()
            || ActionLoader::find_action::<ManageAuthority>(actions)?.is_some()
        {
            return Ok(());
        }
        cursor = boundary;
    }

    Err(SwigError::NoAdminAuthorityWouldRemain.into())
}

/// Uninitialized byte constant for token transfer operations
const UNINIT_BYTE: MaybeUninit<u8> = MaybeUninit::<u8>::uninit();

/// Helper struct for token transfer operations.
///
/// This struct encapsulates all the information needed to perform a token
/// transfer, including the accounts involved and the transfer amount. It
/// provides methods to execute the transfer with or without additional signers.
pub struct TokenTransfer<'a> {
    /// Token program ID (SPL Token or Token-2022)
    pub token_program: &'a Pubkey,
    /// Sender account
    pub from: &'a AccountInfo,
    /// Recipient account
    pub to: &'a AccountInfo,
    /// Authority account
    pub authority: &'a AccountInfo,
    /// Amount of microtokens to transfer
    pub amount: u64,
}

impl<'a> TokenTransfer<'a> {
    /// Executes the token transfer without additional signers.
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    /// Executes the token transfer with additional signers.
    ///
    /// # Arguments
    /// * `signers` - Additional signers for the transfer
    ///
    /// # Returns
    /// * `ProgramResult` - Success or error status
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        // account metadata
        let account_metas: [AccountMeta; 3] = [
            AccountMeta::writable(self.from.key()),
            AccountMeta::writable(self.to.key()),
            AccountMeta::readonly_signer(self.authority.key()),
        ];

        // Instruction data layout:
        // - [0]: instruction discriminator (1 byte, u8)
        // - [1..9]: amount (8 bytes, u64)
        let mut instruction_data = [0u8; 9];

        // Set discriminator as u8 at offset [0]
        instruction_data[0] = 3;
        // Set amount as u64 at offset [1..9]
        instruction_data[1..9].copy_from_slice(&self.amount.to_le_bytes());

        let instruction = Instruction {
            program_id: self.token_program,
            accounts: &account_metas,
            data: &instruction_data,
        };

        invoke_signed(&instruction, &[self.from, self.to, self.authority], signers)
    }
}

/// Helper struct for closing token accounts.
///
/// This struct encapsulates all the information needed to close a token
/// account, transferring the remaining rent lamports to a destination.
pub struct TokenClose<'a> {
    /// Token program ID (SPL Token or Token-2022)
    pub token_program: &'a Pubkey,
    /// Token account to close
    pub account: &'a AccountInfo,
    /// Destination for rent lamports
    pub destination: &'a AccountInfo,
    /// Authority account (owner of the token account)
    pub authority: &'a AccountInfo,
}

impl<'a> TokenClose<'a> {
    /// Executes the token close without additional signers.
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    /// Executes the token close with additional signers.
    ///
    /// # Arguments
    /// * `signers` - Additional signers for the close operation
    ///
    /// # Returns
    /// * `ProgramResult` - Success or error status
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        // account metadata
        let account_metas: [AccountMeta; 3] = [
            AccountMeta::writable(self.account.key()),
            AccountMeta::writable(self.destination.key()),
            AccountMeta::readonly_signer(self.authority.key()),
        ];

        // Instruction data layout:
        // - [0]: instruction discriminator (1 byte, u8) - CloseAccount = 9
        let instruction_data = [9u8];

        let instruction = Instruction {
            program_id: self.token_program,
            accounts: &account_metas,
            data: &instruction_data,
        };

        invoke_signed(
            &instruction,
            &[self.account, self.destination, self.authority],
            signers,
        )
    }
}

/// Builds a restricted keys array for transaction signing.
///
/// This function creates an array of public keys that are restricted from being
/// used as signers in the transaction. The behavior differs based on the
/// authority type:
/// - For Secp256k1 and Secp256r1: Only includes the payer key
/// - For other authority types: Includes both the payer key and the authority
///   key
///
/// # Arguments
/// * `role` - The role containing the authority type information
/// * `payer_key` - The payer account's public key
/// * `authority_payload` - The authority payload containing the authority index
/// * `all_accounts` - All accounts involved in the transaction
///
/// # Returns
/// * `Result<&[&Pubkey], ProgramError>` - A slice of restricted public keys
///
/// # Safety
/// This function uses unsafe operations for performance. The caller must
/// ensure:
/// - `authority_payload` has at least one byte when authority type is not
///   Secp256k1/r1
/// - `all_accounts` contains the account at the specified authority index
#[inline(always)]
pub unsafe fn build_restricted_keys<'a>(
    role: &RoleMut,
    payer_key: &'a Pubkey,
    authority_payload: &[u8],
    all_accounts: &'a [AccountInfo],
    restricted_keys_storage: &'a mut [MaybeUninit<&'a Pubkey>; 2],
) -> Result<&'a [&'a Pubkey], ProgramError> {
    if role.position.authority_type()? == AuthorityType::Secp256k1
        || role.position.authority_type()? == AuthorityType::Secp256r1
    {
        restricted_keys_storage[0].write(payer_key);
        Ok(core::slice::from_raw_parts(
            restricted_keys_storage.as_ptr() as _,
            1,
        ))
    } else {
        let authority_index = *authority_payload.get_unchecked(0) as usize;
        restricted_keys_storage[0].write(payer_key);
        restricted_keys_storage[1].write(all_accounts[authority_index].key());
        Ok(core::slice::from_raw_parts(
            restricted_keys_storage.as_ptr() as _,
            2,
        ))
    }
}

/// Computes a hash of account data and owner while excluding specified byte
/// ranges.
///
/// This function uses the SHA256 hash algorithm which is optimized
/// for low compute units on Solana. It hashes the account owner followed by
/// all bytes in the account's data except those in the specified exclusion
/// ranges. This ensures that program ownership changes are detected during
/// execution.
///
/// # Arguments
/// * `data` - The account data to hash
/// * `owner` - The account owner pubkey
/// * `exclude_ranges` - Sorted list of byte ranges to exclude from data hashing
///
/// # Returns
/// * `[u8; 32]` - The computed SHA256 hash including owner and data (32 bytes)
///
/// # Safety
/// This function assumes that:
/// - The exclude_ranges are non-overlapping and sorted by start position
/// - All ranges are within the bounds of the data
#[inline(always)]
pub fn hash_except(
    data: &[u8],
    owner: &Pubkey,
    exclude_ranges: &[core::ops::Range<usize>],
) -> [u8; 32] {
    // Maximum possible segments: owner + one before each exclude range + one after
    // all ranges
    const MAX_SEGMENTS: usize = 17; // 1 for owner + 16 for data segments
    let mut segments: [&[u8]; MAX_SEGMENTS] = [&[]; MAX_SEGMENTS];
    let mut segment_count = 0;

    // Always include the owner as the first segment
    segments[0] = owner.as_ref();
    segment_count = 1;

    let mut position = 0;

    // If no exclude ranges, hash the entire data after owner
    if exclude_ranges.is_empty() {
        segments[segment_count] = data;
        segment_count += 1;
    } else {
        for range in exclude_ranges {
            // Add bytes before this exclusion range
            if position < range.start {
                segments[segment_count] = &data[position..range.start];
                segment_count += 1;
            }
            // Skip to end of exclusion range
            position = range.end;
        }

        // Add any remaining bytes after the last exclusion range
        if position < data.len() {
            segments[segment_count] = &data[position..];
            segment_count += 1;
        }
    }

    let mut data_payload_hash = [0u8; 32];

    #[cfg(target_os = "solana")]
    unsafe {
        let res = sol_sha256(
            segments.as_ptr() as *const u8,
            segment_count as u64,
            data_payload_hash.as_mut_ptr() as *mut u8,
        );
    }

    #[cfg(not(target_os = "solana"))]
    let res = 0;

    data_payload_hash
}
