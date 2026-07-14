/// Module for handling transaction signing and execution in the Swig wallet.
/// This module implements the logic for authenticating and executing
/// transactions using wallet authorities, including support for various
/// permission types and transaction limits.
use core::mem::MaybeUninit;

use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use pinocchio_pubkey::from_str;
use swig_assertions::*;
use swig_compact_instructions::InstructionIterator;
use swig_state::{
    action::{
        all::All,
        all_but_manage_authority::AllButManageAuthority,
        close_swig_authority::CloseSwigAuthority,
        program::Program,
        program_all::ProgramAll,
        program_curated::ProgramCurated,
        program_scope::{NumericType, ProgramScope},
        sol_destination_limit::SolDestinationLimit,
        sol_limit::SolLimit,
        sol_recurring_destination_limit::SolRecurringDestinationLimit,
        sol_recurring_limit::SolRecurringLimit,
        stake_all::StakeAll,
        stake_limit::StakeLimit,
        stake_recurring_limit::StakeRecurringLimit,
        token_destination_limit::TokenDestinationLimit,
        token_limit::TokenLimit,
        token_recurring_destination_limit::TokenRecurringDestinationLimit,
        token_recurring_limit::TokenRecurringLimit,
        Action, Permission,
    },
    role::RoleMut,
    swig::{swig_account_signer, swig_wallet_address_signer, Swig},
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, SignV2Accounts},
        SwigInstruction,
    },
    util::hash_except,
    AccountClassification, SPL_TOKEN_2022_ID, SPL_TOKEN_ID, SYSTEM_PROGRAM_ID,
};
// use swig_instructions::InstructionIterator;

pub const INSTRUCTION_SYSVAR_ACCOUNT: Pubkey =
    from_str("Sysvar1nstructions1111111111111111111111111");

/// Exclude range for token account balance field (bytes 64-72)
const TOKEN_BALANCE_EXCLUDE_RANGE: core::ops::Range<usize> = 64..72;

/// Exclude range for stake account balance field (bytes 184-192)
const STAKE_BALANCE_EXCLUDE_RANGE: core::ops::Range<usize> = 184..192;

/// Token account field ranges
const TOKEN_MINT_RANGE: core::ops::Range<usize> = 0..32;
const TOKEN_AUTHORITY_RANGE: core::ops::Range<usize> = 32..64;
const TOKEN_BALANCE_RANGE: core::ops::Range<usize> = 64..72;
const TOKEN_STATE_INDEX: usize = 108;

/// Stake account field ranges
const STAKE_BALANCE_RANGE: core::ops::Range<usize> = 184..192;

/// Account state constants
const TOKEN_ACCOUNT_INITIALIZED_STATE: u8 = 1;

/// Empty exclude ranges for hash_except when no exclusions are needed
const NO_EXCLUDE_RANGES: &[core::ops::Range<usize>] = &[];

/// Maximum number of accounts that can have pre-CPI snapshot hashes.
const MAX_ACCOUNT_SNAPSHOTS: usize = 100;

const SYSTEM_TRANSFER_DISCRIMINATOR: u32 = 2;
const SYSTEM_TRANSFER_DATA_LEN: usize = 12;
const TOKEN_TRANSFER_DISCRIMINATOR: u8 = 3;
const TOKEN_TRANSFER_CHECKED_DISCRIMINATOR: u8 = 12;
const TOKEN_TRANSFER_DATA_LEN: usize = 9;
const TOKEN_TRANSFER_CHECKED_DATA_LEN: usize = 10;

/// Arguments for signing a transaction with a Swig wallet.
///
/// # Fields
/// * `instruction` - The instruction type identifier
/// * `instruction_payload_len` - Length of the instruction payload
/// * `role_id` - ID of the role attempting to sign
#[derive(Debug, NoPadding)]
#[repr(C, align(8))]
pub struct SignV2Args {
    instruction: SwigInstruction,
    pub instruction_payload_len: u16,
    pub role_id: u32,
}

impl SignV2Args {
    /// Creates a new instance of SignV2Args.
    ///
    /// # Arguments
    /// * `role_id` - ID of the signing role
    /// * `instruction_payload_len` - Length of the instruction payload
    pub fn new(role_id: u32, instruction_payload_len: u16) -> Self {
        Self {
            instruction: SwigInstruction::SignV2,
            role_id,
            instruction_payload_len,
        }
    }
}

impl Transmutable for SignV2Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for SignV2Args {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

/// Struct representing the complete sign transaction instruction data.
///
/// # Fields
/// * `args` - The signing arguments
/// * `authority_payload` - Authority-specific payload data
/// * `instruction_payload` - Transaction instruction data
pub struct SignV2<'a> {
    pub args: &'a SignV2Args,
    authority_payload: &'a [u8],
    instruction_payload: &'a [u8],
}

impl<'a> SignV2<'a> {
    /// Parses the instruction data bytes into a SignV2 instance.
    ///
    /// # Arguments
    /// * `data` - Raw instruction data bytes
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - Parsed instruction or error
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < SignV2Args::LEN {
            return Err(SwigError::InvalidSwigSignInstructionDataTooShort.into());
        }
        let (inst, rest) = unsafe { data.split_at_unchecked(SignV2Args::LEN) };
        let args = unsafe { SignV2Args::load_unchecked(inst)? };
        let instruction_payload_len = args.instruction_payload_len as usize;

        if instruction_payload_len > rest.len() {
            return Err(SwigError::InvalidSwigSignInstructionDataTooShort.into());
        }

        let (instruction_payload, authority_payload) =
            unsafe { rest.split_at_unchecked(instruction_payload_len) };

        Ok(Self {
            args,
            authority_payload,
            instruction_payload,
        })
    }
}

/// Signs and executes a transaction using a Swig wallet authority.
///
/// This function handles the complete flow of transaction signing:
/// 1. Validates the authority and role
/// 2. Authenticates the transaction
/// 3. Checks all relevant permissions and limits
/// 4. Executes the transaction instructions
///
/// # Arguments
/// * `ctx` - The account context for signing
/// * `all_accounts` - All accounts involved in the transaction
/// * `data` - Raw signing instruction data
/// * `account_classifiers` - Classifications for involved accounts
///
/// # Returns
/// * `ProgramResult` - Success or error status
#[inline(always)]
pub fn sign_v2(
    ctx: Context<SignV2Accounts>,
    all_accounts: &[AccountInfo],
    data: &[u8],
    account_classifiers: &mut [AccountClassification],
) -> ProgramResult {
    check_stack_height(1, SwigError::Cpi)?;

    if !matches!(
        account_classifiers[0],
        AccountClassification::ThisSwigV2 { .. }
    ) {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    if !matches!(
        account_classifiers[1],
        AccountClassification::SwigWalletAddress
    ) {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }

    let sign_v2 = SignV2::from_instruction_bytes(data)?;
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigConfigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
    // The generic account classifier already identified account 0 as Swig config.
    // Keep this hot-path discriminator check as a local unsafe-read precondition.
    let Some(role) = Swig::get_mut_role(sign_v2.args.role_id, swig_roles)? else {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    };
    let clock = Clock::get()?;
    let slot = clock.slot;
    if role.authority.session_based() {
        role.authority.authenticate_session(
            all_accounts,
            sign_v2.authority_payload,
            sign_v2.instruction_payload,
            slot,
        )?;
    } else {
        role.authority.authenticate(
            all_accounts,
            sign_v2.authority_payload,
            sign_v2.instruction_payload,
            slot,
        )?;
    }
    // Intentionally no restricted keys: SignV2 forwards existing outer signer
    // bits in compact CPI metas in addition to the Swig wallet PDA signer.
    let rkeys: &[&Pubkey] = &[];
    let ix_iter = InstructionIterator::new(
        all_accounts,
        sign_v2.instruction_payload,
        ctx.accounts.swig_wallet_address.key(),
        rkeys,
    )?;
    let b = [swig.wallet_bump];
    let seeds = swig_wallet_address_signer(ctx.accounts.swig.key().as_ref(), &b);
    let signer = seeds.as_slice();

    let has_unrestricted_sign_permission = RoleMut::get_action_mut::<All>(role.actions, &[])?
        .is_some()
        || RoleMut::get_action_mut::<AllButManageAuthority>(role.actions, &[])?.is_some();

    if has_unrestricted_sign_permission {
        for ix in ix_iter {
            let instruction = ix.map_err(|_| SwigError::InstructionExecutionError)?;
            instruction.execute(
                all_accounts,
                ctx.accounts.swig_wallet_address.key(),
                &[signer.into()],
            )?;
        }

        return Ok(());
    }

    let has_program_all_permission =
        RoleMut::get_action_mut::<ProgramAll>(role.actions, &[])?.is_some();
    let has_program_curated_permission = !has_program_all_permission
        && RoleMut::get_action_mut::<ProgramCurated>(role.actions, &[])?.is_some();

    // Snapshot hashes are the pre-CPI integrity baseline for writable accounts.
    // SignV2 permits specific balance fields to change, then verifies the rest
    // of each protected account is unchanged after CPI execution.
    const UNINIT_HASH: MaybeUninit<[u8; 32]> = MaybeUninit::uninit();
    let mut account_snapshots: [MaybeUninit<[u8; 32]>; MAX_ACCOUNT_SNAPSHOTS] =
        [UNINIT_HASH; MAX_ACCOUNT_SNAPSHOTS];

    let mut total_sol_spent: u64 = 0;

    // Build exclusion ranges for each account type for snapshots
    for (index, account_classifier) in account_classifiers.iter().enumerate() {
        let account = unsafe { all_accounts.get_unchecked(index) };

        // Only check writable accounts as read-only accounts won't modify data
        if !account.is_writable() {
            continue;
        }

        let hash = match account_classifier {
            AccountClassification::ThisSwigV2 { .. } => {
                // For ThisSwigV2 accounts, hash the entire account data and owner to ensure no
                // unexpected modifications. Lamports are handled separately in
                // the permission check, but we still need to verify
                // that the account data itself and ownership hasn't been tampered with
                let data = unsafe { account.borrow_data_unchecked() };
                let hash = hash_except(&data, account.owner(), NO_EXCLUDE_RANGES);
                Some(hash)
            },
            AccountClassification::SwigTokenAccount { .. } => {
                let data = unsafe { account.borrow_data_unchecked() };
                // Exclude token balance field (bytes 64-72) but include owner
                let exclude_ranges = [TOKEN_BALANCE_EXCLUDE_RANGE];
                let hash = hash_except(&data, account.owner(), &exclude_ranges);
                Some(hash)
            },
            AccountClassification::SwigStakeAccount { .. } => {
                let data = unsafe { account.borrow_data_unchecked() };
                // Exclude stake balance field (bytes 184-192) but include owner
                let exclude_ranges = [STAKE_BALANCE_EXCLUDE_RANGE];
                let hash = hash_except(&data, account.owner(), &exclude_ranges);
                Some(hash)
            },
            AccountClassification::ProgramScope { .. } => {
                let data = unsafe { account.borrow_data_unchecked() };
                // For program scope, we need to get the actual program scope to know what to
                // exclude, and include owner in hash
                let account_key = unsafe { all_accounts.get_unchecked(index).key() };
                if let Some(program_scope) =
                    RoleMut::get_action_mut::<ProgramScope>(role.actions, account_key.as_ref())?
                {
                    let start = program_scope.balance_field_start as usize;
                    let end = program_scope.balance_field_end as usize;
                    if start < end && end <= data.len() {
                        let exclude_ranges = [start..end];
                        let hash = hash_except(&data, account.owner(), &exclude_ranges);
                        Some(hash)
                    } else {
                        None
                    }
                } else {
                    None
                }
            },
            _ => None,
        };

        if let Some(hash) = hash {
            if index >= MAX_ACCOUNT_SNAPSHOTS {
                return Err(SwigError::InvalidAccountsLength.into());
            }

            account_snapshots[index].write(hash);
        }
    }

    for ix in ix_iter {
        if let Ok(instruction) = ix {
            if !has_program_all_permission && instruction.uses_swig_signer {
                let program_id_bytes = instruction.program_id.as_ref();
                let has_permission = (has_program_curated_permission
                    && ProgramCurated::is_curated_program(
                        &program_id_bytes.try_into().unwrap_or([0; 32]),
                    ))
                    || RoleMut::get_action_mut::<Program>(role.actions, program_id_bytes)?
                        .is_some();

                if !has_permission {
                    return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
                }
            }

            let swig_wallet_address_balance_before = ctx.accounts.swig_wallet_address.lamports();
            instruction.execute(
                all_accounts,
                ctx.accounts.swig_wallet_address.key(),
                &[signer.into()],
            )?;

            let swig_wallet_address_balance_after = ctx.accounts.swig_wallet_address.lamports();
            if swig_wallet_address_balance_after < swig_wallet_address_balance_before {
                let amount_spent = swig_wallet_address_balance_before
                    .saturating_sub(swig_wallet_address_balance_after);
                total_sol_spent = total_sol_spent.saturating_add(amount_spent);
            }

            // After execution, scan writable accounts once and update spent in-place
            for (account_index, classifier) in account_classifiers.iter_mut().enumerate() {
                let account = unsafe { all_accounts.get_unchecked(account_index) };

                if !account.is_writable() {
                    continue;
                }

                match classifier {
                    AccountClassification::SwigTokenAccount { balance, spent } => {
                        let data = unsafe { account.borrow_data_unchecked() };

                        if data.len() < TOKEN_BALANCE_RANGE.end {
                            continue;
                        }

                        let current = u64::from_le_bytes(unsafe {
                            data.get_unchecked(TOKEN_BALANCE_RANGE)
                                .try_into()
                                .unwrap_or([0; 8])
                        });

                        if current < *balance {
                            *spent = spent.saturating_add(*balance - current);
                        }

                        *balance = current;
                    },
                    AccountClassification::SwigStakeAccount {
                        state: _,
                        balance,
                        spent,
                    } => {
                        let data = unsafe { account.borrow_data_unchecked() };

                        if data.len() < STAKE_BALANCE_RANGE.end {
                            continue;
                        }

                        let current = u64::from_le_bytes(unsafe {
                            data.get_unchecked(STAKE_BALANCE_RANGE)
                                .try_into()
                                .unwrap_or([0; 8])
                        });

                        if current < *balance {
                            *spent = spent.saturating_add(*balance - current);
                        }

                        *balance = current;
                    },
                    AccountClassification::ProgramScope {
                        role_index: _,
                        balance,
                        spent,
                    } => {
                        let account_key = account.key();
                        let Some(program_scope) = RoleMut::get_action_mut::<ProgramScope>(
                            role.actions,
                            account_key.as_ref(),
                        )?
                        else {
                            continue;
                        };

                        let data = unsafe { account.borrow_data_unchecked() };
                        let Ok(current) = program_scope.read_account_balance(data) else {
                            continue;
                        };

                        if current < *balance {
                            *spent = spent.saturating_add(*balance - current);
                        }

                        *balance = current;
                    },
                    _ => {},
                }
            }
        } else {
            return Err(SwigError::InstructionExecutionError.into());
        }
    }

    let actions = role.actions;
    for (index, account) in account_classifiers.iter_mut().enumerate() {
        match account {
            AccountClassification::ThisSwigV2 { .. } => {
                // SOL spend enforcement for the Swig config account:
                // 1. Verify writable Swig account data/owner did not change unexpectedly.
                // 2. Verify the Swig wallet PDA remains rent-exempt after CPIs.
                // 3. If SOL was spent, charge a general SOL limit when present.
                // 4. If any SOL destination limits exist, every actual debit must be
                //    parsed and charged to a matching destination limit.
                // 5. If SOL was spent but neither a general nor destination limit applies,
                //    reject the instruction.
                let account_info = unsafe { all_accounts.get_unchecked(index) };

                if account_info.is_writable() {
                    let data = unsafe { &account_info.borrow_data_unchecked() };
                    let current_hash = hash_except(&data, account_info.owner(), NO_EXCLUDE_RANGES);
                    let snapshot_hash = unsafe { account_snapshots[index].assume_init_ref() };
                    if *snapshot_hash != current_hash {
                        return Err(SwigError::AccountDataModifiedUnexpectedly.into());
                    }
                }

                let swig_wallet_balance = ctx.accounts.swig_wallet_address.lamports();
                let swig_wallet_rent_exempt_minimum = pinocchio::sysvars::rent::Rent::get()?
                    .minimum_balance(ctx.accounts.swig_wallet_address.data_len());
                if swig_wallet_balance < swig_wallet_rent_exempt_minimum {
                    return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
                }

                if total_sol_spent == 0 {
                    continue;
                }

                let general_sol_limit_applied =
                    if let Some(action) = RoleMut::get_action_mut::<SolLimit>(actions, &[])? {
                        action.run(total_sol_spent)?;
                        true
                    } else if let Some(action) =
                        RoleMut::get_action_mut::<SolRecurringLimit>(actions, &[])?
                    {
                        action.run(total_sol_spent, slot)?;
                        true
                    } else {
                        false
                    };

                let has_destination_sol_limits = has_sol_destination_limits(actions)?;
                let destination_sol_limit_applied = if has_destination_sol_limits {
                    let mut matched_any_destination_limit = false;
                    let mut parsed_sol_spent = 0u64;

                    process_sol_transfers(
                        sign_v2.instruction_payload,
                        ctx.accounts.swig_wallet_address.key(),
                        all_accounts,
                        ctx.accounts.swig_wallet_address.key(),
                        |destination_pubkey, amount| -> Result<(), ProgramError> {
                            parsed_sol_spent = parsed_sol_spent
                                .checked_add(amount)
                                .ok_or(SwigAuthenticateError::PermissionDeniedMissingPermission)?;

                            let dest_pubkey = destination_pubkey.as_ref();

                            if let Some(action) = RoleMut::get_action_mut::<
                                SolRecurringDestinationLimit,
                            >(
                                actions, dest_pubkey
                            )? {
                                action.run(amount, slot)?;
                                matched_any_destination_limit = true;
                                return Ok(());
                            }

                            if let Some(action) = RoleMut::get_action_mut::<SolDestinationLimit>(
                                actions,
                                dest_pubkey,
                            )? {
                                action.run(amount)?;
                                matched_any_destination_limit = true;
                                return Ok(());
                            }

                            Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into())
                        },
                    )?;

                    if !matched_any_destination_limit || parsed_sol_spent != total_sol_spent {
                        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
                    }

                    true
                } else {
                    false
                };

                if !general_sol_limit_applied && !destination_sol_limit_applied {
                    return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
                }

                continue;
            },
            AccountClassification::SwigTokenAccount { spent, .. } => {
                let account_info = unsafe { all_accounts.get_unchecked(index) };
                let data = unsafe { &account_info.borrow_data_unchecked() };

                // The on-chain token program resizes closed accounts to zero bytes,
                // while its native test processor retains zeroed data. Both forms
                // drain the account's lamports and assign it to the system program.
                if data.is_empty() || account_info.lamports() == 0 {
                    let has_close_permission =
                        RoleMut::get_action_mut::<CloseSwigAuthority>(actions, &[])?.is_some();
                    if !has_close_permission {
                        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
                    }
                    if account_info.lamports() != 0 || account_info.owner() != &SYSTEM_PROGRAM_ID {
                        return Err(SwigError::AccountDataModifiedUnexpectedly.into());
                    }

                    continue;
                }

                if account_info.is_writable() {
                    let exclude_ranges = [TOKEN_BALANCE_EXCLUDE_RANGE];
                    let current_hash = hash_except(&data, account_info.owner(), &exclude_ranges);
                    let snapshot_hash = unsafe { account_snapshots[index].assume_init_ref() };
                    if *snapshot_hash != current_hash {
                        return Err(SwigError::AccountDataModifiedUnexpectedly.into());
                    }
                }

                let mint = unsafe { data.get_unchecked(TOKEN_MINT_RANGE) };
                let state = unsafe { *data.get_unchecked(TOKEN_STATE_INDEX) };
                let authority = unsafe { data.get_unchecked(TOKEN_AUTHORITY_RANGE) };

                if authority != ctx.accounts.swig_wallet_address.key() {
                    return Err(
                        SwigAuthenticateError::PermissionDeniedTokenAccountAuthorityNotSwig.into(),
                    );
                }
                if state != TOKEN_ACCOUNT_INITIALIZED_STATE {
                    return Err(
                        SwigAuthenticateError::PermissionDeniedTokenAccountNotInitialized.into(),
                    );
                }

                let total_token_spent = *spent;
                if total_token_spent == 0 {
                    continue;
                }

                let general_token_limit_applied =
                    if let Some(action) = RoleMut::get_action_mut::<TokenLimit>(actions, mint)? {
                        action.run(total_token_spent)?;
                        true
                    } else if let Some(action) =
                        RoleMut::get_action_mut::<TokenRecurringLimit>(actions, mint)?
                    {
                        action.run(total_token_spent, slot)?;
                        true
                    } else {
                        false
                    };

                let has_destination_token_limits = has_token_destination_limits(actions, mint)?;
                let destination_token_limit_applied = if has_destination_token_limits {
                    let source_account_key = account_info.key();
                    let mut matched_any_destination_limit = false;
                    let mut parsed_token_spent = 0u64;

                    process_token_destinations(
                        sign_v2.instruction_payload,
                        source_account_key,
                        all_accounts,
                        ctx.accounts.swig_wallet_address.key(),
                        |destination, amount| -> Result<(), ProgramError> {
                            parsed_token_spent = parsed_token_spent
                                .checked_add(amount)
                                .ok_or(SwigAuthenticateError::PermissionDeniedMissingPermission)?;

                            let mut combined_key = [0u8; 64];
                            combined_key[..32].copy_from_slice(mint);
                            combined_key[32..].copy_from_slice(destination.as_ref());

                            if let Some(action) = RoleMut::get_action_mut::<
                                TokenRecurringDestinationLimit,
                            >(
                                actions, &combined_key
                            )? {
                                action.run(amount, slot)?;
                                matched_any_destination_limit = true;
                                return Ok(());
                            }

                            if let Some(action) = RoleMut::get_action_mut::<TokenDestinationLimit>(
                                actions,
                                &combined_key,
                            )? {
                                action.run(amount)?;
                                matched_any_destination_limit = true;
                                return Ok(());
                            }

                            Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into())
                        },
                    )?;

                    if !matched_any_destination_limit || parsed_token_spent != total_token_spent {
                        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
                    }

                    true
                } else {
                    false
                };

                if !general_token_limit_applied && !destination_token_limit_applied {
                    return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
                }

                continue;
            },
            AccountClassification::SwigStakeAccount { spent, .. } => {
                let account_info = unsafe { all_accounts.get_unchecked(index) };

                if account_info.is_writable() {
                    let data = unsafe { &account_info.borrow_data_unchecked() };
                    let exclude_ranges = [STAKE_BALANCE_EXCLUDE_RANGE];
                    let current_hash = hash_except(&data, account_info.owner(), &exclude_ranges);
                    let snapshot_hash = unsafe { account_snapshots[index].assume_init_ref() };
                    if *snapshot_hash != current_hash {
                        return Err(SwigError::AccountDataModifiedUnexpectedly.into());
                    }
                }

                let total_stake_spent = *spent;
                if total_stake_spent == 0 {
                    continue;
                }

                if let Some(action) = RoleMut::get_action_mut::<StakeLimit>(actions, &[])? {
                    action.run(total_stake_spent)?;
                    continue;
                }

                if let Some(action) = RoleMut::get_action_mut::<StakeRecurringLimit>(actions, &[])?
                {
                    action.run(total_stake_spent, slot)?;
                    continue;
                }

                return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
            },
            AccountClassification::ProgramScope { spent, .. } => {
                let account_info = unsafe { all_accounts.get_unchecked(index) };
                let Some(program_scope) =
                    RoleMut::get_action_mut::<ProgramScope>(actions, account_info.key().as_ref())?
                else {
                    return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
                };

                let data = unsafe { account_info.borrow_data_unchecked() };
                let balance_field_start = program_scope.balance_field_start as usize;
                let balance_field_end = program_scope.balance_field_end as usize;

                if balance_field_start >= balance_field_end || balance_field_end > data.len() {
                    return Err(SwigError::InvalidProgramScopeBalanceFields.into());
                }

                if account_info.is_writable() {
                    let exclude_ranges = [balance_field_start..balance_field_end];
                    let current_hash = hash_except(&data, account_info.owner(), &exclude_ranges);
                    let snapshot_hash = unsafe { account_snapshots[index].assume_init_ref() };
                    if *snapshot_hash != current_hash {
                        return Err(SwigError::AccountDataModifiedUnexpectedly.into());
                    }
                }

                let total_program_scope_spent = *spent;
                if total_program_scope_spent == 0 {
                    continue;
                }

                program_scope.run(total_program_scope_spent, Some(slot))?;
                continue;
            },
            _ => {},
        }
    }

    Ok(())
}

/// Checks if the role has any SOL destination limits configured.
///
/// # Arguments
/// * `actions_data` - The raw action bytes for the role
///
/// # Returns
/// * `Result<bool, ProgramError>` - True if any SOL destination limits exist
fn has_sol_destination_limits(actions_data: &[u8]) -> Result<bool, ProgramError> {
    let mut cursor = 0;
    while cursor < actions_data.len() {
        if cursor + Action::LEN > actions_data.len() {
            break;
        }

        let action =
            unsafe { Action::load_unchecked(&actions_data[cursor..cursor + Action::LEN])? };

        let permission = action.permission()?;
        if permission == Permission::SolDestinationLimit
            || permission == Permission::SolRecurringDestinationLimit
        {
            return Ok(true);
        }

        cursor = action.boundary() as usize;
    }

    Ok(false)
}

/// Checks if the role has token destination limits configured for a mint.
fn has_token_destination_limits(
    actions_data: &[u8],
    token_mint: &[u8],
) -> Result<bool, ProgramError> {
    let mut cursor = 0;
    while cursor < actions_data.len() {
        if cursor + Action::LEN > actions_data.len() {
            break;
        }

        let action =
            unsafe { Action::load_unchecked(&actions_data[cursor..cursor + Action::LEN])? };
        let permission = action.permission()?;
        let action_start = cursor + Action::LEN;
        let boundary = action.boundary() as usize;

        if (permission == Permission::TokenDestinationLimit
            || permission == Permission::TokenRecurringDestinationLimit)
            && boundary >= action_start + 32
            && actions_data.len() >= action_start + 32
            && token_mint == &actions_data[action_start..action_start + 32]
        {
            return Ok(true);
        }

        cursor = boundary;
    }

    Ok(false)
}

/// Processes SOL transfer destinations and amounts from instruction payload
/// using a callback. This zero-copy approach avoids allocations by calling the
/// provided function for each transfer.
///
/// # Arguments
/// * `instruction_payload` - The raw instruction payload bytes
/// * `source_account` - The source account (Swig wallet) to look for
/// * `all_accounts` - All accounts in the transaction
/// * `signer` - The signer pubkey for the transaction
/// * `callback` - Function called for each SOL transfer found
///
/// # Returns
/// * `Result<(), ProgramError>` - Success or error status
fn process_sol_transfers<F>(
    instruction_payload: &[u8],
    source_account: &Pubkey,
    all_accounts: &[AccountInfo],
    signer: &Pubkey,
    mut callback: F,
) -> Result<(), ProgramError>
where
    F: FnMut(&Pubkey, u64) -> Result<(), ProgramError>,
{
    let source_account_bytes = source_account.as_ref();
    let restricted_keys: &[&Pubkey] = &[];
    let mut instruction_iter =
        InstructionIterator::new(all_accounts, instruction_payload, signer, restricted_keys)?;

    while let Some(instruction) = instruction_iter.next() {
        let instruction = instruction?;

        if *instruction.program_id != crate::SYSTEM_PROGRAM_ID {
            continue;
        }

        if instruction.data.len() < SYSTEM_TRANSFER_DATA_LEN {
            continue;
        }

        let discriminator = u32::from_le_bytes([
            instruction.data[0],
            instruction.data[1],
            instruction.data[2],
            instruction.data[3],
        ]);

        if discriminator != SYSTEM_TRANSFER_DISCRIMINATOR {
            continue;
        }

        if instruction.accounts.len() < 2 {
            continue;
        }

        if instruction.accounts[0].pubkey != source_account_bytes {
            continue;
        }

        let destination_pubkey = instruction.accounts[1].pubkey;
        let amount = u64::from_le_bytes([
            instruction.data[4],
            instruction.data[5],
            instruction.data[6],
            instruction.data[7],
            instruction.data[8],
            instruction.data[9],
            instruction.data[10],
            instruction.data[11],
        ]);

        callback(destination_pubkey, amount)?;
    }

    Ok(())
}

/// Processes token destination accounts from instruction payload using a
/// callback. This zero-copy approach avoids allocations by calling the provided
/// function for each destination.
///
/// # Arguments
/// * `instruction_payload` - The raw instruction payload bytes
/// * `source_account` - The source token account to look for
/// * `all_accounts` - All accounts in the transaction
/// * `signer` - The signer pubkey for the transaction
/// * `callback` - Function called for each token destination found
///
/// # Returns
/// * `Result<(), ProgramError>` - Success or error status
fn process_token_destinations<F>(
    instruction_payload: &[u8],
    source_account: &Pubkey,
    all_accounts: &[AccountInfo],
    signer: &Pubkey,
    mut callback: F,
) -> Result<(), ProgramError>
where
    F: FnMut(&Pubkey, u64) -> Result<(), ProgramError>,
{
    let source_account_bytes = source_account.as_ref();
    let restricted_keys: &[&Pubkey] = &[];
    let mut instruction_iter =
        InstructionIterator::new(all_accounts, instruction_payload, signer, restricted_keys)?;

    while let Some(instruction) = instruction_iter.next() {
        let instruction = instruction?;

        let is_token_program = *instruction.program_id == crate::SPL_TOKEN_ID
            || *instruction.program_id == crate::SPL_TOKEN_2022_ID;

        if !is_token_program || instruction.data.is_empty() {
            continue;
        }

        let (min_data_len, destination_index) = match instruction.data[0] {
            TOKEN_TRANSFER_DISCRIMINATOR => (TOKEN_TRANSFER_DATA_LEN, 1),
            TOKEN_TRANSFER_CHECKED_DISCRIMINATOR => (TOKEN_TRANSFER_CHECKED_DATA_LEN, 2),
            _ => continue,
        };

        if instruction.data.len() < min_data_len || instruction.accounts.len() <= destination_index
        {
            continue;
        }

        if instruction.accounts[0].pubkey != source_account_bytes {
            continue;
        }

        let destination_pubkey = instruction.accounts[destination_index].pubkey;
        let amount = u64::from_le_bytes([
            instruction.data[1],
            instruction.data[2],
            instruction.data[3],
            instruction.data[4],
            instruction.data[5],
            instruction.data[6],
            instruction.data[7],
            instruction.data[8],
        ]);

        callback(destination_pubkey, amount)?;
    }

    Ok(())
}
