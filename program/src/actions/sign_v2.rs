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
    authority::AuthorityType,
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
    util::{build_restricted_keys, hash_except},
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

        let (instruction_payload, authority_payload) =
            unsafe { rest.split_at_unchecked(args.instruction_payload_len as usize) };

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
    // KEEP remove since we enfoce swig is owned in lib.rs
    // check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    let sign_v2 = SignV2::from_instruction_bytes(data)?;
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
    let role = Swig::get_mut_role(sign_v2.args.role_id, swig_roles)?;
    if role.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let role = role.unwrap();
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
    const UNINIT_KEY: MaybeUninit<&Pubkey> = MaybeUninit::uninit();
    let mut restricted_keys: [MaybeUninit<&Pubkey>; 2] = [UNINIT_KEY; 2];
    let rkeys: &[&Pubkey] = unsafe {
        if role.position.authority_type()? == AuthorityType::Secp256k1
            || role.position.authority_type()? == AuthorityType::Secp256r1
        {
            restricted_keys[0].write(ctx.accounts.payer.key());
            core::slice::from_raw_parts(restricted_keys.as_ptr() as _, 1)
        } else {
            let authority_index = *sign_v2.authority_payload.get_unchecked(0) as usize;
            restricted_keys[0].write(ctx.accounts.payer.key());
            restricted_keys[1].write(all_accounts[authority_index].key());
            core::slice::from_raw_parts(restricted_keys.as_ptr() as _, 2)
        }
    };
    let ix_iter = InstructionIterator::new(
        all_accounts,
        sign_v2.instruction_payload,
        ctx.accounts.swig_wallet_address.key(),
        rkeys,
    )?;
    let b = [swig.wallet_bump];
    let seeds = swig_wallet_address_signer(ctx.accounts.swig.key().as_ref(), &b);
    let signer = seeds.as_slice();

    // Check if we have All or AllButManageAuthority permission to skip CPI
    // validation
    let has_all_permission = RoleMut::get_action_mut::<All>(role.actions, &[])?.is_some()
        || RoleMut::get_action_mut::<AllButManageAuthority>(role.actions, &[])?.is_some();

    // Capture account snapshots before instruction execution
    const UNINIT_HASH: MaybeUninit<[u8; 32]> = MaybeUninit::uninit();
    let mut account_snapshots: [MaybeUninit<[u8; 32]>; 100] = [UNINIT_HASH; 100];

    let mut total_sol_spent: u64 = 0;

    // Build exclusion ranges for each account type for snapshots
    for (index, account_classifier) in account_classifiers.iter().enumerate() {
        let account = unsafe { all_accounts.get_unchecked(index) };

        // Only check writable accounts as read-only accounts won't modify data
        if !account.is_writable() {
            continue;
        }

        let hash = match account_classifier {
            AccountClassification::ThisSwig { .. } => {
                let data = unsafe { account.borrow_data_unchecked() };
                // For ThisSwig accounts, hash the entire account data and owner to ensure no
                // unexpected modifications. Lamports are handled separately in
                // the permission check, but we still need to verify
                // that the account data itself and ownership hasn't been tampered with
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
                let owner = unsafe { all_accounts.get_unchecked(index).owner() };
                if let Some(program_scope) =
                    RoleMut::get_action_mut::<ProgramScope>(role.actions, owner.as_ref())?
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

        if hash != None && index < 100 {
            account_snapshots[index].write(hash.unwrap());
        }
    }

    for ix in ix_iter {
        if let Ok(instruction) = ix {
            // Check CPI signing permissions if not All permission
            if !has_all_permission {
                // Check if swig_wallet_address account is being used as a signer for this
                // instruction
                let swig_wallet_address_is_signer =
                    instruction.accounts.iter().any(|account_meta| {
                        account_meta.pubkey == ctx.accounts.swig_wallet_address.key()
                            && account_meta.is_signer
                    });

                if swig_wallet_address_is_signer {
                    // This is a CPI call where swig_wallet_address is signing - check Program
                    // permissions
                    let program_id_bytes = instruction.program_id.as_ref();

                    // Check if we have any program permission that allows this program
                    let has_permission =
                        // Check for ProgramAll permission (allows any program)
                        RoleMut::get_action_mut::<ProgramAll>(role.actions, &[])?.is_some() ||
                        // Check for ProgramCurated permission (allows curated programs)
                        (RoleMut::get_action_mut::<ProgramCurated>(role.actions, &[])?.is_some() && ProgramCurated::is_curated_program(&program_id_bytes.try_into().unwrap_or([0; 32]))) ||
                        // Check for specific Program permission
                        RoleMut::get_action_mut::<Program>(role.actions, program_id_bytes)?.is_some();

                    if !has_permission {
                        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
                    }
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
                        if data.len() >= 72 {
                            let current = u64::from_le_bytes(unsafe {
                                data.get_unchecked(TOKEN_BALANCE_RANGE)
                                    .try_into()
                                    .unwrap_or([0; 8])
                            });
                            if current < *balance {
                                let delta = (*balance).saturating_sub(current);
                                *spent = spent.saturating_add(delta);
                                *balance = current;
                            } else if current > *balance {
                                *balance = current;
                            }
                        }
                    },
                    AccountClassification::SwigStakeAccount {
                        state: _,
                        balance,
                        spent,
                    } => {
                        let data = unsafe { account.borrow_data_unchecked() };
                        if data.len() >= 192 {
                            let current = u64::from_le_bytes(unsafe {
                                data.get_unchecked(STAKE_BALANCE_RANGE)
                                    .try_into()
                                    .unwrap_or([0; 8])
                            });
                            if current < *balance {
                                let delta = (*balance).saturating_sub(current);
                                *spent = spent.saturating_add(delta);
                                *balance = current;
                            } else if current > *balance {
                                *balance = current;
                            }
                        }
                    },
                    AccountClassification::ProgramScope {
                        role_index: _,
                        balance,
                        spent,
                    } => {
                        let owner = unsafe { account.owner() };
                        if let Some(program_scope) =
                            RoleMut::get_action_mut::<ProgramScope>(role.actions, owner.as_ref())?
                        {
                            let data = unsafe { account.borrow_data_unchecked() };
                            if let Ok(current) = program_scope.read_account_balance(data) {
                                if current < *balance {
                                    let delta = (*balance).saturating_sub(current);
                                    *spent = spent.saturating_add(delta);
                                    *balance = current;
                                } else if current > *balance {
                                    *balance = current;
                                }
                            }
                        }
                    },
                    _ => {},
                }
            }
        } else {
            return Err(SwigError::InstructionExecutionError.into());
        }
    }

    let actions = role.actions;
    if has_all_permission {
        return Ok(());
    } else {
        'account_loop: for (index, account) in account_classifiers.iter_mut().enumerate() {
            match account {
                AccountClassification::ThisSwig { lamports } => {
                    let account_info = unsafe { all_accounts.get_unchecked(index) };

                    // Only validate snapshots for writable accounts
                    if account_info.is_writable() {
                        let data = unsafe { &account_info.borrow_data_unchecked() };
                        let current_hash =
                            hash_except(&data, account_info.owner(), NO_EXCLUDE_RANGES);
                        let snapshot_hash = unsafe { account_snapshots[index].assume_init_ref() };
                        if *snapshot_hash != current_hash {
                            return Err(SwigError::AccountDataModifiedUnexpectedly.into());
                        }
                    }

                    let current_lamports = account_info.lamports();
                    let mut matched = false;
                    // Ensure the account has some minimum balance for rent exemption
                    let account_data = unsafe { account_info.borrow_data_unchecked() };
                    let rent_exempt_minimum =
                        pinocchio::sysvars::rent::Rent::get()?.minimum_balance(account_data.len());
                    if current_lamports < rent_exempt_minimum {
                        return Err(
                            SwigAuthenticateError::PermissionDeniedInsufficientBalance.into()
                        );
                    }

                    if total_sol_spent > 0 {
                        // First check general SOL limits
                        let mut general_limit_applied = false;

                        if let Some(action) = RoleMut::get_action_mut::<SolLimit>(actions, &[])? {
                            action.run(total_sol_spent)?;
                            general_limit_applied = true;
                        } else if let Some(action) =
                            RoleMut::get_action_mut::<SolRecurringLimit>(actions, &[])?
                        {
                            action.run(total_sol_spent, slot)?;
                            general_limit_applied = true;
                        }

                        // Only check destination limits if they exist
                        if has_sol_destination_limits(actions)? {
                            let mut destination_limit_applied = false;
                            // Process SOL transfers using zero-copy callback approach
                            process_sol_transfers(
                                sign_v2.instruction_payload,
                                ctx.accounts.swig_wallet_address.key(),
                                all_accounts,
                                ctx.accounts.swig_wallet_address.key(),
                                |destination_pubkey, amount| -> Result<bool, ProgramError> {
                                    let dest_pubkey = destination_pubkey.as_ref();

                                    // First check recurring destination limits (higher precedence)
                                    if let Some(dest_action) = RoleMut::get_action_mut::<
                                        SolRecurringDestinationLimit,
                                    >(
                                        actions, dest_pubkey
                                    )? {
                                        dest_action.run(amount, slot)?;
                                        destination_limit_applied = true;
                                        return Ok(false); // Stop processing
                                                          // after first match
                                    }

                                    // Then check non-recurring destination limits
                                    if let Some(dest_action) = RoleMut::get_action_mut::<
                                        SolDestinationLimit,
                                    >(
                                        actions, dest_pubkey
                                    )? {
                                        dest_action.run(amount)?;
                                        destination_limit_applied = true;
                                        return Ok(false); // Stop processing
                                                          // after first match
                                    }

                                    Ok(true) // Continue processing
                                },
                            )?;

                            // If destination limits exist but none matched, that's an error
                            if !destination_limit_applied {
                                return Err(
                                    SwigAuthenticateError::PermissionDeniedMissingPermission.into(),
                                );
                            }
                        }

                        // If we have general limits OR destination limits exist, continue
                        if general_limit_applied || has_sol_destination_limits(actions)? {
                            continue;
                        }

                        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
                    }
                },
                AccountClassification::SwigTokenAccount { balance, .. } => {
                    let account_info = unsafe { all_accounts.get_unchecked(index) };

                    // Only validate snapshots for writable accounts
                    if account_info.is_writable() {
                        let data = unsafe { &account_info.borrow_data_unchecked() };
                        let exclude_ranges = [TOKEN_BALANCE_EXCLUDE_RANGE];
                        let current_hash =
                            hash_except(&data, account_info.owner(), &exclude_ranges);
                        let snapshot_hash = unsafe { account_snapshots[index].assume_init_ref() };
                        if *snapshot_hash != current_hash {
                            return Err(SwigError::AccountDataModifiedUnexpectedly.into());
                        }
                    }

                    let data = unsafe { &account_info.borrow_data_unchecked() };
                    let mint = unsafe { data.get_unchecked(TOKEN_MINT_RANGE) };
                    let state = unsafe { *data.get_unchecked(TOKEN_STATE_INDEX) };

                    let authority = unsafe { data.get_unchecked(TOKEN_AUTHORITY_RANGE) };
                    let current_token_balance = u64::from_le_bytes(unsafe {
                        data.get_unchecked(TOKEN_BALANCE_RANGE)
                            .try_into()
                            .map_err(|_| ProgramError::InvalidAccountData)?
                    });

                    if authority != ctx.accounts.swig_wallet_address.key() {
                        return Err(
                            SwigAuthenticateError::PermissionDeniedTokenAccountAuthorityNotSwig
                                .into(),
                        );
                    }
                    if state != TOKEN_ACCOUNT_INITIALIZED_STATE {
                        return Err(
                            SwigAuthenticateError::PermissionDeniedTokenAccountNotInitialized
                                .into(),
                        );
                    }

                    // Find the cumulative amount spent for this token account
                    let mut total_token_spent: u64 = 0;
                    if let AccountClassification::SwigTokenAccount { balance: _, spent } = account {
                        total_token_spent = *spent;
                    }

                    if total_token_spent > 0 {
                        // Check token destination limits for outgoing transfers using zero-copy
                        // approach
                        let source_account_key = unsafe { all_accounts.get_unchecked(index) }.key();
                        let mut destination_limit_applied = false;

                        process_token_destinations(
                            sign_v2.instruction_payload,
                            source_account_key,
                            all_accounts,
                            ctx.accounts.swig_wallet_address.key(),
                            |destination| -> Result<bool, ProgramError> {
                                // Create the combined key [mint + destination] for matching
                                let mut combined_key = [0u8; 64];
                                combined_key[..32].copy_from_slice(mint);
                                combined_key[32..].copy_from_slice(destination.as_ref());

                                // First check recurring destination limits
                                if let Some(action) = RoleMut::get_action_mut::<
                                    TokenRecurringDestinationLimit,
                                >(
                                    actions, &combined_key
                                )? {
                                    action.run(total_token_spent, slot)?;
                                    destination_limit_applied = true;
                                    return Ok(false); // Stop processing after
                                                      // first match
                                }

                                // Then check non-recurring destination limits
                                if let Some(action) = RoleMut::get_action_mut::<
                                    TokenDestinationLimit,
                                >(
                                    actions, &combined_key
                                )? {
                                    action.run(total_token_spent)?;
                                    destination_limit_applied = true;
                                    return Ok(false); // Stop processing after
                                                      // first match
                                }

                                Ok(true) // Continue processing
                            },
                        )?;

                        // If a destination limit was applied, continue to next account
                        if destination_limit_applied {
                            continue 'account_loop;
                        }

                        // Check regular token limits for outgoing transfers
                        if let Some(action) = RoleMut::get_action_mut::<TokenLimit>(actions, mint)?
                        {
                            action.run(total_token_spent)?;
                            continue;
                        } else if let Some(action) =
                            RoleMut::get_action_mut::<TokenRecurringLimit>(actions, mint)?
                        {
                            action.run(total_token_spent, slot)?;
                            continue;
                        }
                        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
                    }
                },
                AccountClassification::SwigStakeAccount {
                    state: _,
                    balance,
                    spent,
                } => {
                    let account_info = unsafe { all_accounts.get_unchecked(index) };

                    // Only validate snapshots for writable accounts
                    if account_info.is_writable() {
                        let data = unsafe { &account_info.borrow_data_unchecked() };
                        let exclude_ranges = [STAKE_BALANCE_EXCLUDE_RANGE];
                        let current_hash =
                            hash_except(&data, account_info.owner(), &exclude_ranges);
                        let snapshot_hash = unsafe { account_snapshots[index].assume_init_ref() };
                        if *snapshot_hash != current_hash {
                            return Err(SwigError::AccountDataModifiedUnexpectedly.into());
                        }
                    }

                    // Validate stake spending permissions if any stake was spent
                    if *spent > 0 {
                        if let Some(action) = RoleMut::get_action_mut::<StakeLimit>(actions, &[])? {
                            action.run(*spent)?;
                            continue;
                        } else if let Some(action) =
                            RoleMut::get_action_mut::<StakeRecurringLimit>(actions, &[])?
                        {
                            action.run(*spent, slot)?;
                            continue;
                        }
                        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
                    }

                    continue;
                },
                AccountClassification::ProgramScope {
                    role_index,
                    balance,
                    ..
                } => {
                    let account_info = unsafe { all_accounts.get_unchecked(index) };

                    // Get the role with the ProgramScope action
                    let owner = unsafe { all_accounts.get_unchecked(index).owner() };
                    let program_scope =
                        RoleMut::get_action_mut::<ProgramScope>(actions, owner.as_ref())?;

                    match program_scope {
                        Some(program_scope) => {
                            // First verify this is the target account
                            let account_key =
                                unsafe { all_accounts.get_unchecked(index).key().as_slice() };
                            if account_key != program_scope.target_account {
                                return Err(
                                    SwigAuthenticateError::PermissionDeniedMissingPermission.into(),
                                );
                            }

                            // Get the current balance by using the program_scope's
                            // read_account_balance method
                            let data = unsafe { account_info.borrow_data_unchecked() };

                            // Check if balance field range is valid
                            if program_scope.balance_field_end - program_scope.balance_field_start
                                > 0
                                && program_scope.balance_field_end as usize <= data.len()
                            {
                                // Only validate snapshots for writable accounts
                                if account_info.is_writable() {
                                    // Hash the data excluding the balance field but including owner
                                    let exclude_ranges =
                                        [program_scope.balance_field_start as usize
                                            ..program_scope.balance_field_end as usize];
                                    let current_hash =
                                        hash_except(&data, account_info.owner(), &exclude_ranges);
                                    let snapshot_hash =
                                        unsafe { account_snapshots[index].assume_init_ref() };
                                    if *snapshot_hash != current_hash {
                                        return Err(
                                            SwigError::AccountDataModifiedUnexpectedly.into()
                                        );
                                    }
                                }

                                let mut total_program_scope_spent: u128 = 0;
                                if let AccountClassification::ProgramScope {
                                    role_index: _,
                                    balance: _,
                                    spent,
                                } = account
                                {
                                    total_program_scope_spent = *spent;
                                }

                                program_scope.run(total_program_scope_spent, Some(slot))?;
                            } else {
                                return Err(SwigError::InvalidProgramScopeBalanceFields.into());
                            }
                        },
                        None => {
                            return Err(
                                SwigAuthenticateError::PermissionDeniedMissingPermission.into()
                            );
                        },
                    }

                    continue;
                },
                _ => {},
            }
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
    F: FnMut(&Pubkey, u64) -> Result<bool, ProgramError>, /* Returns true to continue, false to
                                                           * stop */
{
    // Parse the instruction payload using the instruction iterator
    let restricted_keys: &[&Pubkey] = &[]; // No restricted keys for this use case
    let mut instruction_iter =
        InstructionIterator::new(all_accounts, instruction_payload, signer, restricted_keys)?;

    while let Some(instruction) = instruction_iter.next() {
        let instruction = instruction?;

        // Check if this is a System Program instruction
        if *instruction.program_id == crate::SYSTEM_PROGRAM_ID {
            // Check if this is a Transfer instruction (discriminator = 2)
            if instruction.data.len() >= 12
                && u32::from_le_bytes([
                    instruction.data[0],
                    instruction.data[1],
                    instruction.data[2],
                    instruction.data[3],
                ]) == 2
            {
                // System Program Transfer instruction layout:
                // - accounts[0]: source account (funding account)
                // - accounts[1]: destination account (recipient)
                // - data[4..12]: amount (u64 little-endian)
                if instruction.accounts.len() >= 2 {
                    let source_pubkey = &instruction.accounts[0].pubkey;

                    // Check if this transfer is from our source account
                    if *source_pubkey == source_account.as_ref() {
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

                        // Call the callback with the transfer data
                        if !callback(destination_pubkey, amount)? {
                            return Ok(()); // Early exit if callback returns
                                           // false
                        }
                    }
                }
            }
        }
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
    F: FnMut(&Pubkey) -> Result<bool, ProgramError>, // Returns true to continue, false to stop
{
    // Parse the instruction payload using the instruction iterator
    let restricted_keys: &[&Pubkey] = &[]; // No restricted keys for this use case
    let mut instruction_iter =
        InstructionIterator::new(all_accounts, instruction_payload, signer, restricted_keys)?;

    while let Some(instruction) = instruction_iter.next() {
        let instruction = instruction?;

        // Check if this is a token program instruction
        if *instruction.program_id == crate::SPL_TOKEN_ID
            || *instruction.program_id == crate::SPL_TOKEN_2022_ID
        {
            // Check if this is a Transfer instruction (discriminator = 3)
            if !instruction.data.is_empty() && instruction.data[0] == 3 {
                // SPL Token Transfer instruction layout:
                // - accounts[0]: source token account
                // - accounts[1]: destination token account
                // - accounts[2]: authority
                if instruction.accounts.len() >= 2 {
                    let source_pubkey = &instruction.accounts[0].pubkey;

                    // Check if this transfer is from our source account
                    if *source_pubkey == source_account.as_ref() {
                        let destination_pubkey = instruction.accounts[1].pubkey;

                        // Call the callback with the destination
                        if !callback(destination_pubkey)? {
                            return Ok(()); // Early exit if callback returns
                                           // false
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
