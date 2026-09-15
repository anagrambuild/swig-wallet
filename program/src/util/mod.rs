//! Utility functions and types for the Swig wallet program.
//!
//! This module provides helper functionality for common operations such as:
//! - Program scope caching and lookup
//! - Account balance reading
//! - Token transfer operations
//! The utilities are optimized for performance and safety.

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
        all::All,
        manage_authority::ManageAuthority,
        program_scope::{NumericType, ProgramScope},
        replace_authority::ReplaceAuthority,
        Action, ActionLoader, Permission,
    },
    authority::AuthorityType,
    constants::PROGRAM_SCOPE_BYTE_SIZE,
    read_numeric_field,
    role::{Position, RoleMut},
    swig::{Swig, SwigWithRoles},
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

/// Cache for program scope information to optimize lookups.
///
/// This struct maintains a mapping of target account public keys to their
/// associated role IDs and program scope data. It helps avoid repeated
/// parsing of program scope data from the Swig account.
pub(crate) struct ProgramScopeCache {
    /// Maps target account pubkey to (role_id, raw program scope bytes)
    scopes: Vec<([u8; 32], (u8, [u8; PROGRAM_SCOPE_BYTE_SIZE]))>,
}

impl ProgramScopeCache {
    /// Creates a new empty program scope cache.
    ///
    /// Initializes with a reasonable capacity to avoid frequent reallocations.
    pub(crate) fn new() -> Self {
        Self {
            scopes: Vec::with_capacity(16), // Reasonable initial capacity
        }
    }

    /// Loads program scope information from a Swig account's data.
    ///
    /// This function parses the Swig account data to extract all program
    /// scope actions and builds a cache for efficient lookup.
    ///
    /// # Arguments
    /// * `data` - Raw Swig account data
    ///
    /// # Returns
    /// * `Option<Self>` - The populated cache if successful, None if data is
    ///   invalid
    pub(crate) fn load_from_swig(data: &[u8]) -> Option<Self> {
        if data.len() < Swig::LEN {
            return None;
        }

        let swig_with_roles = SwigWithRoles::from_bytes(data).ok()?;
        let mut cache = Self::new();

        // Iterate through all roles and their program scopes
        for role_id in 0..swig_with_roles.state.role_counter {
            if let Ok(Some(role)) = swig_with_roles.get_role(role_id) {
                let mut cursor = 0;
                while cursor < role.actions.len() {
                    if cursor + Action::LEN > role.actions.len() {
                        break;
                    }

                    // Load the action header
                    if let Ok(action_header) = unsafe {
                        Action::load_unchecked(&role.actions[cursor..cursor + Action::LEN])
                    } {
                        cursor += Action::LEN;

                        let action_len = action_header.length() as usize;
                        if cursor + action_len > role.actions.len() {
                            break;
                        }

                        // Try to load as ProgramScope
                        if action_header.permission().ok() == Some(Permission::ProgramScope) {
                            let action_data = &role.actions[cursor..cursor + action_len];
                            if action_data.len() == PROGRAM_SCOPE_BYTE_SIZE {
                                // Size of ProgramScope
                                // Store in cache using target account as key
                                let program_scope = unsafe {
                                    // SAFETY: We've verified the length matches exactly
                                    let mut scope_bytes = [0u8; PROGRAM_SCOPE_BYTE_SIZE];
                                    core::ptr::copy_nonoverlapping(
                                        action_data.as_ptr(),
                                        scope_bytes.as_mut_ptr(),
                                        PROGRAM_SCOPE_BYTE_SIZE,
                                    );
                                    let program_scope: ProgramScope =
                                        core::mem::transmute(scope_bytes);
                                    program_scope
                                };

                                let mut target_account = [0u8; 32];
                                target_account.copy_from_slice(&program_scope.target_account);

                                // Store raw bytes
                                let scope_bytes = unsafe {
                                    core::mem::transmute::<
                                        ProgramScope,
                                        [u8; PROGRAM_SCOPE_BYTE_SIZE],
                                    >(program_scope)
                                };
                                cache
                                    .scopes
                                    .push((target_account, (role_id as u8, scope_bytes)));
                            }
                        }

                        cursor += action_len;
                    } else {
                        break;
                    }
                }
            }
        }

        Some(cache)
    }

    /// Finds program scope information for a target account.
    ///
    /// # Arguments
    /// * `target_account` - Public key of the target account to look up
    ///
    /// # Returns
    /// * `Option<(u8, ProgramScope)>` - Role ID and program scope if found
    pub(crate) fn find_program_scope(&self, target_account: &[u8]) -> Option<(u8, ProgramScope)> {
        self.scopes
            .iter()
            .find(|(key, _)| key == target_account)
            .map(|(_, (role_id, scope_bytes))| {
                // SAFETY: We know these bytes represent a valid ProgramScope since we stored
                // them that way
                let program_scope = unsafe {
                    core::mem::transmute::<[u8; PROGRAM_SCOPE_BYTE_SIZE], ProgramScope>(
                        *scope_bytes,
                    )
                };
                (*role_id, program_scope)
            })
    }
}

/// Reads a numeric balance from an account's data based on a `ProgramScope`
/// configuration.
///
/// This function extracts a numeric value (balance) from the raw data of an
/// account according to the field positions and numeric type specified in the
/// `ProgramScope`. It supports reading different size integers (u8, u32, u64,
/// u128) and handles byte order assembly for little-endian representation.
///
/// # Arguments
/// * `data` - The raw account data to read from
/// * `program_scope` - The ProgramScope containing balance field specifications
///
/// # Returns
/// * `Result<u128, ProgramError>` - The account balance as u128 or an error if
///   reading fails
///
/// # Errors
/// Returns `SwigError::InvalidProgramScopeBalanceFields` if:
/// * The balance field range is invalid
/// * The account data doesn't have enough bytes
/// * The specified numeric type doesn't match the field width
///
/// # Safety
/// This function uses unchecked memory access for performance and assumes the
/// caller has verified the `data` parameter contains valid account data.
#[inline(always)]
pub unsafe fn read_program_scope_account_balance(
    data: &[u8],
    program_scope: &ProgramScope,
) -> Result<u128, ProgramError> {
    // For Basic scope, return 0
    if program_scope.scope_type == 0 {
        return Ok(0);
    }

    // Check if we can read the balance directly from data
    let start = program_scope.balance_field_start as usize;
    let end = program_scope.balance_field_end as usize;
    // Index out of bounds check & return error
    if data.len() < end {
        return Err(SwigError::InvalidProgramScopeBalanceFields.into());
    }

    // Handle Possible NumericType fields
    let error = SwigError::InvalidProgramScopeBalanceFields.into();
    match program_scope.numeric_type as u8 {
        numeric_type if numeric_type == NumericType::U8 as u8 => {
            read_numeric_field!(data, start, end, u8, 1, error)
        },
        numeric_type if numeric_type == NumericType::U32 as u8 => {
            read_numeric_field!(data, start, end, u32, 4, error)
        },
        numeric_type if numeric_type == NumericType::U64 as u8 => {
            read_numeric_field!(data, start, end, u64, 8, error)
        },
        numeric_type if numeric_type == NumericType::U128 as u8 => {
            read_numeric_field!(data, start, end, u128, 16, error)
        },
        _ => Err(SwigError::InvalidProgramScopeBalanceFields.into()),
    }
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

const TOKEN_ACCOUNT_BASE_DATA_LEN: usize = 165;
const TOKEN_MINT_BASE_LEN: usize = 82;
const TOKEN_MULTISIG_LEN: usize = 355;
const TOKEN_AUTHORITY_OFF: usize = 32;
const TOKEN_AMOUNT_OFF: usize = 64;
const TOKEN_2022_ACCOUNT_TYPE_OFF: usize = 165;
const TOKEN_2022_MINT_TYPE_OFF: usize = 82;
const TOKEN_2022_TYPE_ACCOUNT: u8 = 2;
const TOKEN_2022_TYPE_MINT: u8 = 1;
const MAX_PROTECTED_TOKENS: usize = 4;
pub const MAX_PROTECTED_SIGNERS: usize = 64;
const MAX_FROZEN: usize = 4;
const MAX_WRITABLE: usize = 8;
const STAKE_STAKER_OFF: usize = 12;
const STAKE_WITHDRAWER_OFF: usize = 44;
const VOTE_WITHDRAWER_OFF: usize = 32;
const NONCE_AUTHORITY_OFF_A: usize = 4;
const NONCE_AUTHORITY_OFF_B: usize = 40;
const NONCE_ACCOUNT_LEN: usize = 80;
const PROGRAMDATA_AUTHORITY_TAG_OFF: usize = 12;
const PROGRAMDATA_AUTHORITY_OFF: usize = 16;

pub struct AuthorityIsolationGuard {
    signer_count: u8,
    token_count: u8,
    writable_count: u8,
    frozen_count: u8,
    signer_index: [u8; MAX_PROTECTED_SIGNERS],
    signer_lamports: [u64; MAX_PROTECTED_SIGNERS],
    writable_index: [u8; MAX_WRITABLE],
    writable_lamports: [u64; MAX_WRITABLE],
    token_index: [u8; MAX_PROTECTED_TOKENS],
    token_amount: [u64; MAX_PROTECTED_TOKENS],
    token_lamports: [u64; MAX_PROTECTED_TOKENS],
    token_data_len: [u16; MAX_PROTECTED_TOKENS],
    token_rest: [MaybeUninit<[u8; 157]>; MAX_PROTECTED_TOKENS],
    token_tail_hash: [MaybeUninit<[u8; 32]>; MAX_PROTECTED_TOKENS],
    frozen_index: [u8; MAX_FROZEN],
    frozen_lamports: [u64; MAX_FROZEN],
    frozen_hash: [MaybeUninit<[u8; 32]>; MAX_FROZEN],
}

#[inline(never)]
pub fn collect_outer_signer_indices(
    all_accounts: &[AccountInfo],
    pda: &Pubkey,
    out: &mut [u8; MAX_PROTECTED_SIGNERS],
) -> Result<u8, ProgramError> {
    let mut count = 0u8;
    for (index, account) in all_accounts.iter().enumerate() {
        if !account.is_signer() || account.key() == pda {
            continue;
        }
        if count as usize >= MAX_PROTECTED_SIGNERS {
            return Err(SwigError::InvalidAccountsLength.into());
        }
        out[count as usize] = index as u8;
        count += 1;
    }
    Ok(count)
}

#[inline(never)]
pub fn new_authority_isolation(
    all_accounts: &[AccountInfo],
    signer_indices: &[u8],
    signer_count: u8,
) -> Result<AuthorityIsolationGuard, ProgramError> {
    if signer_count == 0 {
        return Err(SwigError::InvalidAuthorityPayload.into());
    }
    let mut signer_index = [0u8; MAX_PROTECTED_SIGNERS];
    let mut signer_lamports = [0u64; MAX_PROTECTED_SIGNERS];
    let n = signer_count as usize;
    for i in 0..n {
        let idx = signer_indices[i] as usize;
        if idx >= all_accounts.len() {
            return Err(SwigError::InvalidAuthorityPayload.into());
        }
        signer_index[i] = signer_indices[i];
        signer_lamports[i] = unsafe { all_accounts.get_unchecked(idx).lamports() };
    }
    Ok(AuthorityIsolationGuard {
        signer_count,
        token_count: 0,
        writable_count: 0,
        frozen_count: 0,
        signer_index,
        signer_lamports,
        writable_index: [0; MAX_WRITABLE],
        writable_lamports: [0; MAX_WRITABLE],
        token_index: [0; MAX_PROTECTED_TOKENS],
        token_amount: [0; MAX_PROTECTED_TOKENS],
        token_lamports: [0; MAX_PROTECTED_TOKENS],
        token_data_len: [0; MAX_PROTECTED_TOKENS],
        token_rest: [MaybeUninit::uninit(); MAX_PROTECTED_TOKENS],
        token_tail_hash: [MaybeUninit::uninit(); MAX_PROTECTED_TOKENS],
        frozen_index: [0; MAX_FROZEN],
        frozen_lamports: [0; MAX_FROZEN],
        frozen_hash: [MaybeUninit::uninit(); MAX_FROZEN],
    })
}

#[inline(always)]
fn pubkey_eq(data: &[u8], authority_key: &Pubkey) -> bool {
    data == authority_key.as_ref()
}

#[inline(always)]
fn pubkey_eq_any_signer(
    data: &[u8],
    all_accounts: &[AccountInfo],
    signer_indices: &[u8],
    signer_count: u8,
) -> bool {
    for i in 0..signer_count as usize {
        let key = unsafe { all_accounts.get_unchecked(signer_indices[i] as usize).key() };
        if pubkey_eq(data, key) {
            return true;
        }
    }
    false
}

#[inline(always)]
fn coption_is_key(data: &[u8], off: usize, authority_key: &Pubkey) -> bool {
    data.len() >= off + 36
        && data[off..off + 4] == [1, 0, 0, 0]
        && pubkey_eq(&data[off + 4..off + 36], authority_key)
}

#[inline(always)]
fn is_token_program(owner: &Pubkey) -> bool {
    owner == &crate::SPL_TOKEN_ID || owner == &crate::SPL_TOKEN_2022_ID
}

#[inline(always)]
fn is_token_account(data: &[u8]) -> bool {
    let len = data.len();
    (len == TOKEN_ACCOUNT_BASE_DATA_LEN)
        || (len > TOKEN_ACCOUNT_BASE_DATA_LEN
            && data[TOKEN_2022_ACCOUNT_TYPE_OFF] == TOKEN_2022_TYPE_ACCOUNT)
}

#[inline(always)]
fn is_mint_account(data: &[u8]) -> bool {
    let len = data.len();
    if is_token_account(data) {
        return false;
    }
    (len == TOKEN_MINT_BASE_LEN)
        || (len > TOKEN_MINT_BASE_LEN && data[TOKEN_2022_MINT_TYPE_OFF] == TOKEN_2022_TYPE_MINT)
}

#[inline(never)]
fn alice_is_mint_authority(data: &[u8], authority_key: &Pubkey) -> bool {
    coption_is_key(data, 0, authority_key) || coption_is_key(data, 46, authority_key)
}

#[inline(never)]
fn alice_in_multisig(data: &[u8], authority_key: &Pubkey) -> bool {
    if data.len() != TOKEN_MULTISIG_LEN || data[2] != 1 {
        return false;
    }
    let n = data[1] as usize;
    if n > 11 {
        return false;
    }
    let mut off = 3;
    for _ in 0..n {
        if pubkey_eq(&data[off..off + 32], authority_key) {
            return true;
        }
        off += 32;
    }
    false
}

#[inline(always)]
fn token_owner_is_alice_or_multisig(
    owner: &[u8],
    authority_key: &Pubkey,
    all_accounts: &[AccountInfo],
) -> bool {
    if pubkey_eq(owner, authority_key) {
        return true;
    }
    for account in all_accounts {
        if account.key().as_ref() != owner {
            continue;
        }
        if !is_token_program(account.owner()) || account.data_len() != TOKEN_MULTISIG_LEN {
            return false;
        }
        let data = unsafe { account.borrow_data_unchecked() };
        return alice_in_multisig(data, authority_key);
    }
    false
}

#[inline(always)]
fn token_owner_is_any_signer_or_multisig(
    owner: &[u8],
    all_accounts: &[AccountInfo],
    signer_indices: &[u8],
    signer_count: u8,
) -> bool {
    for i in 0..signer_count as usize {
        let key = unsafe { all_accounts.get_unchecked(signer_indices[i] as usize).key() };
        if token_owner_is_alice_or_multisig(owner, key, all_accounts) {
            return true;
        }
    }
    false
}

#[inline(always)]
fn any_signer_controls_frozen(
    account: &AccountInfo,
    all_accounts: &[AccountInfo],
    signer_indices: &[u8],
    signer_count: u8,
) -> bool {
    for i in 0..signer_count as usize {
        let key = unsafe { all_accounts.get_unchecked(signer_indices[i] as usize).key() };
        if alice_controls_frozen_account(account, key) {
            return true;
        }
    }
    false
}

#[inline(never)]
fn alice_controls_frozen_account(account: &AccountInfo, authority_key: &Pubkey) -> bool {
    let owner = account.owner();
    let len = account.data_len();
    if is_token_program(owner) {
        if len < TOKEN_MINT_BASE_LEN {
            return false;
        }
        let data = unsafe { account.borrow_data_unchecked() };
        if is_mint_account(data) {
            return alice_is_mint_authority(data, authority_key);
        }
        return alice_in_multisig(data, authority_key);
    }
    if owner == &crate::STAKING_ID && len >= STAKE_WITHDRAWER_OFF + 32 {
        let data = unsafe { account.borrow_data_unchecked() };
        return pubkey_eq(
            &data[STAKE_STAKER_OFF..STAKE_STAKER_OFF + 32],
            authority_key,
        ) || pubkey_eq(
            &data[STAKE_WITHDRAWER_OFF..STAKE_WITHDRAWER_OFF + 32],
            authority_key,
        );
    }
    if owner == &crate::VOTE_PROGRAM_ID && len >= VOTE_WITHDRAWER_OFF + 32 {
        let data = unsafe { account.borrow_data_unchecked() };
        return pubkey_eq(
            &data[VOTE_WITHDRAWER_OFF..VOTE_WITHDRAWER_OFF + 32],
            authority_key,
        );
    }
    if owner == &crate::SYSTEM_PROGRAM_ID && len == NONCE_ACCOUNT_LEN {
        let data = unsafe { account.borrow_data_unchecked() };
        return pubkey_eq(
            &data[NONCE_AUTHORITY_OFF_A..NONCE_AUTHORITY_OFF_A + 32],
            authority_key,
        ) || pubkey_eq(
            &data[NONCE_AUTHORITY_OFF_B..NONCE_AUTHORITY_OFF_B + 32],
            authority_key,
        );
    }
    if owner == &crate::BPF_LOADER_UPGRADEABLE_ID && len >= PROGRAMDATA_AUTHORITY_OFF + 32 {
        let data = unsafe { account.borrow_data_unchecked() };
        return data[PROGRAMDATA_AUTHORITY_TAG_OFF..PROGRAMDATA_AUTHORITY_TAG_OFF + 4]
            == [1, 0, 0, 0]
            && pubkey_eq(
                &data[PROGRAMDATA_AUTHORITY_OFF..PROGRAMDATA_AUTHORITY_OFF + 32],
                authority_key,
            );
    }
    false
}

#[inline(always)]
pub fn isolation_should_observe(
    account: &AccountInfo,
    all_accounts: &[AccountInfo],
    signer_indices: &[u8],
    signer_count: u8,
) -> bool {
    if signer_count == 0 {
        return false;
    }
    if account.lamports() == 0 {
        return true;
    }
    let len = account.data_len();
    if len == 0 {
        return false;
    }
    if is_token_program(account.owner()) && len >= TOKEN_ACCOUNT_BASE_DATA_LEN {
        let data = unsafe { account.borrow_data_unchecked() };
        return pubkey_eq_any_signer(
            &data[TOKEN_AUTHORITY_OFF..TOKEN_AUTHORITY_OFF + 32],
            all_accounts,
            signer_indices,
            signer_count,
        );
    }
    if len == TOKEN_ACCOUNT_BASE_DATA_LEN {
        return false;
    }
    for i in 0..signer_count as usize {
        let key = unsafe { all_accounts.get_unchecked(signer_indices[i] as usize).key() };
        if alice_controls_frozen_account(account, key) {
            return true;
        }
    }
    false
}

#[inline(never)]
pub fn observe_writable_for_isolation(
    guard: &mut AuthorityIsolationGuard,
    index: usize,
    account: &AccountInfo,
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    let owner = account.owner();
    let is_token = is_token_program(owner);
    if is_token || account.lamports() == 0 {
        let count = guard.writable_count as usize;
        if count >= MAX_WRITABLE {
            return Err(SwigError::InvalidAccountsLength.into());
        }
        guard.writable_index[count] = index as u8;
        guard.writable_lamports[count] = account.lamports();
        guard.writable_count = (count + 1) as u8;
    }
    if any_signer_controls_frozen(
        account,
        all_accounts,
        &guard.signer_index,
        guard.signer_count,
    ) {
        let frozen_i = guard.frozen_count as usize;
        if frozen_i >= MAX_FROZEN {
            return Err(SwigError::InvalidAccountsLength.into());
        }
        let data = unsafe { account.borrow_data_unchecked() };
        guard.frozen_index[frozen_i] = index as u8;
        guard.frozen_lamports[frozen_i] = account.lamports();
        guard.frozen_hash[frozen_i].write(hash_except(data, owner, &[]));
        guard.frozen_count = (frozen_i + 1) as u8;
        return Ok(());
    }
    if !is_token || account.data_len() < TOKEN_ACCOUNT_BASE_DATA_LEN {
        return Ok(());
    }
    let data = unsafe { account.borrow_data_unchecked() };
    if !is_token_account(data)
        || !token_owner_is_any_signer_or_multisig(
            &data[TOKEN_AUTHORITY_OFF..TOKEN_AUTHORITY_OFF + 32],
            all_accounts,
            &guard.signer_index,
            guard.signer_count,
        )
    {
        return Ok(());
    }
    let token_i = guard.token_count as usize;
    if token_i >= MAX_PROTECTED_TOKENS {
        return Err(SwigError::InvalidAccountsLength.into());
    }
    let mut amount = [0u8; 8];
    amount.copy_from_slice(&data[TOKEN_AMOUNT_OFF..TOKEN_AMOUNT_OFF + 8]);
    let mut rest = [0u8; 157];
    rest[..64].copy_from_slice(&data[..64]);
    rest[64..].copy_from_slice(&data[72..165]);
    guard.token_index[token_i] = index as u8;
    guard.token_amount[token_i] = u64::from_le_bytes(amount);
    guard.token_lamports[token_i] = account.lamports();
    guard.token_data_len[token_i] = data.len() as u16;
    guard.token_rest[token_i].write(rest);
    if data.len() > TOKEN_ACCOUNT_BASE_DATA_LEN {
        guard.token_tail_hash[token_i].write(hash_except(
            &data[TOKEN_ACCOUNT_BASE_DATA_LEN..],
            owner,
            &[],
        ));
    }
    guard.token_count = (token_i + 1) as u8;
    Ok(())
}

#[inline(always)]
pub fn capture_authority_isolation(
    all_accounts: &[AccountInfo],
    pda: &Pubkey,
) -> Result<Option<AuthorityIsolationGuard>, ProgramError> {
    let mut signer_indices = [0u8; MAX_PROTECTED_SIGNERS];
    let signer_count = collect_outer_signer_indices(all_accounts, pda, &mut signer_indices)?;
    if signer_count == 0 {
        return Ok(None);
    }
    let mut guard = new_authority_isolation(all_accounts, &signer_indices, signer_count)?;
    for (index, account) in all_accounts.iter().enumerate() {
        if account.is_writable()
            && isolation_should_observe(account, all_accounts, &signer_indices, signer_count)
        {
            observe_writable_for_isolation(&mut guard, index, account, all_accounts)?;
        }
    }
    Ok(Some(guard))
}

#[inline(never)]
pub fn verify_authority_isolation(
    guard: &AuthorityIsolationGuard,
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    let token_count = guard.token_count as usize;
    if token_count != 0 {
        for i in 0..token_count {
            let account = unsafe { all_accounts.get_unchecked(guard.token_index[i] as usize) };
            if account.data_len() < TOKEN_ACCOUNT_BASE_DATA_LEN {
                return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
            }
            let owner = account.owner();
            if owner != &crate::SPL_TOKEN_ID && owner != &crate::SPL_TOKEN_2022_ID {
                return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
            }
            let data = unsafe { account.borrow_data_unchecked() };
            let rest = unsafe { guard.token_rest[i].assume_init_ref() };
            if data.len() != guard.token_data_len[i] as usize
                || data[..64] != rest[..64]
                || data[72..165] != rest[64..]
            {
                return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
            }
            if data.len() > TOKEN_ACCOUNT_BASE_DATA_LEN {
                let tail = hash_except(&data[TOKEN_ACCOUNT_BASE_DATA_LEN..], owner, &[]);
                if tail != unsafe { *guard.token_tail_hash[i].assume_init_ref() } {
                    return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
                }
            }
            let mut amount = [0u8; 8];
            amount.copy_from_slice(&data[TOKEN_AMOUNT_OFF..TOKEN_AMOUNT_OFF + 8]);
            if u64::from_le_bytes(amount) < guard.token_amount[i]
                || account.lamports() < guard.token_lamports[i]
            {
                return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
            }
        }
    }

    let frozen_count = guard.frozen_count as usize;
    for i in 0..frozen_count {
        let account = unsafe { all_accounts.get_unchecked(guard.frozen_index[i] as usize) };
        if account.lamports() < guard.frozen_lamports[i] {
            return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
        }
        let data = unsafe { account.borrow_data_unchecked() };
        let hash = hash_except(data, account.owner(), &[]);
        if hash != unsafe { *guard.frozen_hash[i].assume_init_ref() } {
            return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
        }
    }

    let mut spent = 0u64;
    let signer_count = guard.signer_count as usize;
    for i in 0..signer_count {
        let after = unsafe {
            all_accounts
                .get_unchecked(guard.signer_index[i] as usize)
                .lamports()
        };
        if after < guard.signer_lamports[i] {
            spent = spent.saturating_add(guard.signer_lamports[i] - after);
        }
    }
    if spent == 0 {
        return Ok(());
    }
    let mut explained = 0u64;
    let writable_count = guard.writable_count as usize;
    for i in 0..writable_count {
        let index = guard.writable_index[i];
        let mut is_protected_signer = false;
        for s in 0..signer_count {
            if index == guard.signer_index[s] {
                is_protected_signer = true;
                break;
            }
        }
        if is_protected_signer {
            continue;
        }
        let account = unsafe { all_accounts.get_unchecked(index as usize) };
        let after = account.lamports();
        let before = guard.writable_lamports[i];
        if after <= before {
            continue;
        }
        let gained = after - before;
        let owner = account.owner();
        if owner != &crate::SPL_TOKEN_ID
            && owner != &crate::SPL_TOKEN_2022_ID
            && !(before == 0 && owner != &crate::SYSTEM_PROGRAM_ID)
        {
            return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
        }
        explained = explained.saturating_add(gained);
    }
    if explained < spent {
        return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
    }
    Ok(())
}
