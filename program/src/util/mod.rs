//! Utility functions and types for the Swig wallet program.
//!
//! This module provides helper functionality for common operations such as:
//! - Program scope caching and lookup
//! - Account balance reading
//! - Token transfer operations
//! - Oracle Program for token price fetch
//! The utilities are optimized for performance and safety.

use std::mem::MaybeUninit;

use pinocchio::{
    account_info::AccountInfo,
    cpi::invoke_signed,
    instruction::{AccountMeta, Instruction, Signer},
    msg,
    program_error::ProgramError,
    pubkey::{self, Pubkey},
    syscalls::sol_sha256,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use pinocchio_pubkey::pubkey;
use swig_state::{
    action::{
        program_scope::{NumericType, ProgramScope},
        Action, Permission,
    },
    authority::AuthorityType,
    constants::PROGRAM_SCOPE_BYTE_SIZE,
    read_numeric_field,
    role::RoleMut,
    swig::{Swig, SwigWithRoles},
    Transmutable,
};

use crate::error::SwigError;

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

use oracle_mapping_state::{DataLen, MintMapping, ScopeMappingRegistry};

/// Calculate token value with configurable precision
///
/// # Arguments
/// * `base_price` - Oracle price value
/// * `base_exponent` - Oracle price exponent
/// * `oracle_base_decimal` - Oracle decimal places
/// * `mint_amount` - Token amount in mint decimals
/// * `mint_decimal` - Token decimal places
/// * `target_precision` - Target precision for result
///
/// # Returns
/// Token value in target precision
pub fn calculate_token_value(
    base_price: u64,
    base_exponent: u8,
    oracle_base_decimal: u8,
    mint_amount: u64,
    mint_decimal: u8,
    target_precision: u8,
) -> Result<u64, SwigError> {
    let price = base_price as u128;
    let amount = mint_amount as u128;
    let base_exp = base_exponent as u32;
    let mint_dec = mint_decimal as u32;
    let target_prec = target_precision as u32;

    // value = (amount * price * 10^target_precision) / (10^mint_decimal * 10^base_exponent)
    let numerator = amount
        .saturating_mul(price)
        .saturating_mul(10u128.pow(target_prec));
    let denominator = 10u128.pow(mint_dec).saturating_mul(10u128.pow(base_exp));

    if denominator == 0 {
        return Ok(0);
    }
    let value = numerator / denominator;
    if value > u64::MAX as u128 {
        return Err(SwigError::OracleValueOverflow);
    }
    Ok(value as u64)
}

pub const NULL_PUBKEY: [u8; 32] = [
    11, 193, 238, 216, 208, 116, 241, 195, 55, 212, 76, 22, 75, 202, 40, 216, 76, 206, 27, 169,
    138, 64, 177, 28, 19, 90, 156, 0, 0, 0, 0, 0,
];

pub fn get_price_data(
    mapping_registry: &[u8],
    scope_data: &[u8],
    mint: &[u8; 32],
    clock: &Clock,
) -> Result<(u64, u8, u8), SwigError> {
    let mapping = MintMapping::get_mapping_details(&mapping_registry, mint)
        .map_err(|_| SwigError::OracleMintNotFound)?;

    let (mut scope_price, mut scope_exp) = get_scope_price_data(
        scope_data,
        mapping.scope_details.ok_or(SwigError::OracleMintNotFound)?,
        clock.slot,
    )?;

    Ok((scope_price, scope_exp, mapping.decimals))
}

fn get_scope_price_data(
    data: &[u8],
    price_chain: [u16; 3],
    current_slot: u64,
) -> Result<(u64, u8), SwigError> {
    let prices_start = 8 + 32;

    const SCOPE_PRICE_FEED_LEN: usize = 56;

    // Check if price_chain is valid
    if price_chain == [u16::MAX, u16::MAX, u16::MAX] {
        return Err(SwigError::OraclePriceChainEmpty);
    }
    let mut price_chain_raw = Vec::new();

    for &token_id in &price_chain {
        if token_id == u16::MAX {
            break;
        }

        let start_offset = prices_start + (token_id as usize * SCOPE_PRICE_FEED_LEN);
        let end_offset = start_offset + SCOPE_PRICE_FEED_LEN;

        if end_offset > data.len() {
            return Err(SwigError::OraclePriceChainEmpty);
        }

        let price_data = unsafe { data.get_unchecked(start_offset..end_offset) };
        let value =
            u64::from_le_bytes(unsafe { price_data.get_unchecked(0..8).try_into().unwrap() });
        let exp =
            u64::from_le_bytes(unsafe { price_data.get_unchecked(8..16).try_into().unwrap() });
        let last_updated_slot =
            u64::from_le_bytes(unsafe { price_data.get_unchecked(16..24).try_into().unwrap() });
        let unix_timestamp =
            u64::from_le_bytes(unsafe { price_data.get_unchecked(24..32).try_into().unwrap() });

        // time to allow: 60 seconds = 60 seconds / 0.4ms per slot = 150 slots
        if last_updated_slot < current_slot - 150 {
            return Err(SwigError::OraclePriceStale);
        }

        price_chain_raw.push((value, exp, unix_timestamp));
    }

    if price_chain_raw.is_empty() {
        return Err(SwigError::OraclePriceChainEmpty);
    }

    let last_updated_slot: u64 = u64::from_le_bytes(unsafe {
        data.get_unchecked(
            prices_start + (price_chain[0] as usize * SCOPE_PRICE_FEED_LEN) + 16
                ..prices_start + (price_chain[0] as usize * SCOPE_PRICE_FEED_LEN) + 24,
        )
        .try_into()
        .unwrap()
    });

    // If only one price in chain, return it directly
    if price_chain_raw.len() == 1 {
        let (value, exp, unix_timestamp) = price_chain_raw[0];
        return Ok((value, exp as u8));
    }

    // Chain multiple prices together by multiplying them
    let mut chained_value: u128 = 1;
    let mut chained_exp: u64 = 0;

    for (value, exp, _) in price_chain_raw {
        let value_u128 = value as u128;

        // Pre-scale values if they're too large to prevent overflow
        let mut scaled_value = value_u128;
        let mut scaled_exp = exp;

        // Scale down the input value if it's too large
        while scaled_value > u64::MAX as u128 && scaled_exp > 0 {
            scaled_value /= 10;
            scaled_exp = scaled_exp
                .checked_sub(1)
                .ok_or(SwigError::OraclePriceChainEmpty)?;
        }

        // Also scale down the current chained value if it's too large
        while chained_value > u64::MAX as u128 && chained_exp > 0 {
            chained_value /= 10;
            chained_exp = chained_exp
                .checked_sub(1)
                .ok_or(SwigError::OraclePriceChainEmpty)?;
        }

        // Now perform the multiplication with scaled values
        chained_value = chained_value
            .checked_mul(scaled_value)
            .ok_or(SwigError::OraclePriceChainEmpty)?;

        // Add the exponents
        chained_exp = chained_exp
            .checked_add(scaled_exp)
            .ok_or(SwigError::OraclePriceChainEmpty)?;

        // Scale down if the value is too large to fit in u64
        while chained_value > u64::MAX as u128 && chained_exp > 0 {
            chained_value /= 10;
            chained_exp = chained_exp
                .checked_sub(1)
                .ok_or(SwigError::OraclePriceChainEmpty)?;
        }
    }

    let final_value = if chained_value <= u64::MAX as u128 {
        chained_value as u64
    } else {
        return Err(SwigError::OracleValueOverflow);
    };

    // Ensure the exponent is within reasonable bounds to prevent overflow in pow operations
    let (final_value, final_exp) = if chained_exp > 18 {
        // If exponent is too large, scale down the value and reduce exponent
        let scale_factor = chained_exp - 18;
        let scaled_value = final_value / 10_u64.pow(scale_factor as u32);
        (scaled_value, (chained_exp - scale_factor) as u8)
    } else {
        (final_value, chained_exp as u8)
    };

    Ok((final_value, final_exp))
}
