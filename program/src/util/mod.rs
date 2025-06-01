//! Utility functions and types for the Swig wallet program.
//!
//! This module provides helper functionality for common operations such as:
//! - Program scope caching and lookup
//! - Account balance reading
//! - Token transfer operations
//! The utilities are optimized for performance and safety.

use std::{collections::HashMap, mem::MaybeUninit};

use pinocchio::{
    account_info::AccountInfo,
    cpi::invoke_signed,
    instruction::{AccountMeta, Instruction, Signer},
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use swig_state_x::{
    action::{
        authorization_lock::AuthorizationLock,
        program_scope::{NumericType, ProgramScope},
        Action, Permission,
    },
    constants::PROGRAM_SCOPE_BYTE_SIZE,
    read_numeric_field,
    role::{Position, RoleMut},
    swig::{Swig, SwigWithRoles},
    Transmutable, TransmutableMut,
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

/// Cache for authorization lock information to optimize lookups.
///
/// This struct maintains a mapping of token mints to their authorization locks
/// across all roles in the Swig wallet. Authorization locks apply to the entire
/// wallet regardless of which authority is signing.
pub struct AuthorizationLockCache {
    /// Maps token mint to authorization lock data from any role
    locks: Vec<([u8; 32], AuthorizationLock)>,
    /// Expired locks with their location information (role_id, cursor_start,
    /// cursor_end)
    expired_locks: Vec<(u32, usize, usize)>,
}

impl AuthorizationLockCache {
    /// Creates a new authorization lock cache by scanning all roles for
    /// authorization locks Filters out any locks that have expired before
    /// the current slot
    pub fn new(swig_roles: &[u8]) -> Result<Self, ProgramError> {
        let clock = Clock::get()?;
        let current_slot = clock.slot;
        let mut lock_map: HashMap<[u8; 32], (u64, u64)> = HashMap::new(); // mint -> (total_locked_amount, latest_expiry_slot)
        let mut expired_locks = Vec::new();

        if swig_roles.len() < Swig::LEN {
            return Ok(Self {
                locks: Vec::new(),
                expired_locks: Vec::new(),
            });
        }

        let swig_with_roles = SwigWithRoles::from_bytes(swig_roles)
            .map_err(|_| SwigError::InvalidSwigAccountDiscriminator)?;

        // Iterate through all roles and their authorization locks
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
                        let action_start = cursor;
                        cursor += Action::LEN;

                        let action_len = action_header.length() as usize;
                        if cursor + action_len > role.actions.len() {
                            break;
                        }

                        // Try to load as AuthorizationLock
                        if action_header.permission().ok() == Some(Permission::AuthorizationLock) {
                            let action_data = &role.actions[cursor..cursor + action_len];
                            if action_data.len() == AuthorizationLock::LEN {
                                if let Ok(auth_lock) =
                                    unsafe { AuthorizationLock::load_unchecked(action_data) }
                                {
                                    if auth_lock.is_expired(current_slot) {
                                        // Cache expired lock location
                                        expired_locks.push((
                                            role_id,
                                            action_start,
                                            cursor + action_len,
                                        ));
                                    } else {
                                        // Only include locks that haven't expired
                                        // Combine locks for the same token mint
                                        lock_map
                                            .entry(auth_lock.token_mint)
                                            .and_modify(|(amount, expiry)| {
                                                *amount += auth_lock.locked_amount;
                                                *expiry = (*expiry).max(auth_lock.expiry_slot);
                                            })
                                            .or_insert((
                                                auth_lock.locked_amount,
                                                auth_lock.expiry_slot,
                                            ));
                                    }
                                }
                            }
                        }

                        cursor += action_len;
                    } else {
                        break;
                    }
                }
            }
        }

        // Convert HashMap to Vec of combined locks
        let locks = lock_map
            .into_iter()
            .map(|(mint, (total_amount, latest_expiry))| {
                let combined_lock = AuthorizationLock::new(mint, total_amount, latest_expiry, 0);
                (mint, combined_lock)
            })
            .collect();

        Ok(Self {
            locks,
            expired_locks,
        })
    }

    /// Checks if any authorization locks would prevent the given transfer
    pub fn check_authorization_locks(
        &self,
        mint: &[u8],
        current_balance: &u64,
        transfer_amount: u64,
        current_slot: u64,
    ) -> Result<(), ProgramError> {
        for lock in &self.locks {
            // Skip expired locks (should already be filtered out during cache creation)
            if lock.1.is_expired(current_slot) {
                continue;
            }

            // Check if this lock applies to the mint being transferred
            if lock.0 == mint {
                // Check if the transfer would violate the authorization lock
                if let Err(e) =
                    lock.1
                        .check_authorization(current_balance, transfer_amount, current_slot)
                {
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Removes expired authorization locks from the Swig account data
    ///
    /// This method uses the cached expired lock locations to efficiently remove
    /// expired authorization locks from the role data. It processes removals in
    /// reverse order to maintain cursor validity.
    ///
    /// # Arguments
    /// * `swig_roles` - Mutable reference to the roles data portion of the Swig
    ///   account
    ///
    /// # Returns
    /// * `ProgramResult` - Success or error status
    pub fn remove_expired_locks(&self, swig_roles: &mut [u8]) -> ProgramResult {
        use swig_state_x::{role::Position, swig::Swig, TransmutableMut};

        if self.expired_locks.is_empty() {
            return Ok(());
        }

        // Group expired locks by role_id
        let mut locks_by_role: HashMap<u32, Vec<(usize, usize)>> = HashMap::new();
        for &(role_id, start, end) in &self.expired_locks {
            locks_by_role.entry(role_id).or_default().push((start, end));
        }

        // First pass: collect role information
        let mut role_info: Vec<(u32, usize, usize, usize, usize, Vec<(usize, usize)>)> = Vec::new();

        for (role_id, mut lock_positions) in locks_by_role {
            // Sort positions in reverse order (largest start position first)
            lock_positions.sort_by(|a, b| b.0.cmp(&a.0));

            // Find the role's position in the buffer
            let mut cursor = 0;

            for _ in 0..100 {
                // Reasonable upper bound to prevent infinite loops
                if cursor + Position::LEN > swig_roles.len() {
                    break;
                }

                let position = unsafe {
                    Position::load_unchecked(&swig_roles[cursor..cursor + Position::LEN])?
                };

                if position.id() == role_id {
                    let auth_length = position.authority_length() as usize;
                    let actions_start = cursor + Position::LEN + auth_length;
                    let actions_end = position.boundary() as usize;

                    if actions_start < actions_end && actions_end <= swig_roles.len() {
                        role_info.push((
                            role_id,
                            cursor,
                            actions_start,
                            actions_end,
                            auth_length,
                            lock_positions,
                        ));
                    }
                    break;
                }

                cursor = position.boundary() as usize;
            }
        }

        // Second pass: perform the actual removals
        for (role_id, offset, actions_start, actions_end, auth_length, lock_positions) in role_info
        {
            // Calculate total bytes to remove and count
            let mut total_removed_bytes = 0;
            let mut removed_count = 0u16;

            for (lock_start, lock_end) in &lock_positions {
                let relative_start = actions_start + lock_start;
                let relative_end = actions_start + lock_end;
                let lock_size = relative_end - relative_start;

                if relative_end <= actions_end {
                    // Shift remaining data to fill the gap
                    let copy_start = relative_end;
                    let copy_end = actions_end - total_removed_bytes;
                    let copy_dest = relative_start;

                    if copy_start < copy_end {
                        // Use a temporary buffer to avoid overlapping copy issues
                        let remaining_data = swig_roles[copy_start..copy_end].to_vec();
                        swig_roles[copy_dest..copy_dest + remaining_data.len()]
                            .copy_from_slice(&remaining_data);
                    }

                    total_removed_bytes += lock_size;
                    removed_count += 1;
                }
            }

            if removed_count > 0 {
                // Update the position metadata
                let position = unsafe {
                    Position::load_mut_unchecked(&mut swig_roles[offset..offset + Position::LEN])?
                };

                position.num_actions = position.num_actions.saturating_sub(removed_count);
                position.boundary = (position.boundary() as usize - total_removed_bytes) as u32;

                // Clear the now-unused space at the end
                let new_actions_end = actions_end - total_removed_bytes;
                if new_actions_end < actions_end {
                    swig_roles[new_actions_end..actions_end].fill(0);
                }
            }
        }

        Ok(())
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
