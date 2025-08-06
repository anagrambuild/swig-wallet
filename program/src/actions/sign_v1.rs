/// Module for handling transaction signing and execution in the Swig wallet.
/// This module implements the logic for authenticating and executing
/// transactions using wallet authorities, including support for various
/// permission types and transaction limits.
use core::mem::MaybeUninit;

use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    msg,
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
        program::Program,
        program_all::ProgramAll,
        program_curated::ProgramCurated,
        program_scope::{NumericType, ProgramScope},
        sol_limit::SolLimit,
        sol_recurring_limit::SolRecurringLimit,
        stake_all::StakeAll,
        stake_limit::StakeLimit,
        stake_recurring_limit::StakeRecurringLimit,
        token_limit::TokenLimit,
        token_recurring_limit::TokenRecurringLimit,
    },
    authority::AuthorityType,
    role::RoleMut,
    swig::{swig_account_signer, Swig},
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, SignV1Accounts},
        SwigInstruction,
    },
    util::{build_restricted_keys, hash_except},
    AccountClassification,
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
pub struct SignV1Args {
    instruction: SwigInstruction,
    pub instruction_payload_len: u16,
    pub role_id: u32,
}

impl SignV1Args {
    /// Creates a new instance of SignV1Args.
    ///
    /// # Arguments
    /// * `role_id` - ID of the signing role
    /// * `instruction_payload_len` - Length of the instruction payload
    pub fn new(role_id: u32, instruction_payload_len: u16) -> Self {
        Self {
            instruction: SwigInstruction::SignV1,
            role_id,
            instruction_payload_len,
        }
    }
}

impl Transmutable for SignV1Args {
    const LEN: usize = core::mem::size_of::<Self>();
}

impl IntoBytes for SignV1Args {
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
pub struct SignV1<'a> {
    pub args: &'a SignV1Args,
    authority_payload: &'a [u8],
    instruction_payload: &'a [u8],
}

impl<'a> SignV1<'a> {
    /// Parses the instruction data bytes into a SignV1 instance.
    ///
    /// # Arguments
    /// * `data` - Raw instruction data bytes
    ///
    /// # Returns
    /// * `Result<Self, ProgramError>` - Parsed instruction or error
    pub fn from_instruction_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < SignV1Args::LEN {
            return Err(SwigError::InvalidSwigSignInstructionDataTooShort.into());
        }
        let (inst, rest) = unsafe { data.split_at_unchecked(SignV1Args::LEN) };
        let args = unsafe { SignV1Args::load_unchecked(inst)? };

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
pub fn sign_v1(
    ctx: Context<SignV1Accounts>,
    all_accounts: &[AccountInfo],
    data: &[u8],
    account_classifiers: &[AccountClassification],
) -> ProgramResult {
    check_stack_height(1, SwigError::Cpi)?;
    // KEEP remove since we enfoce swig is owned in lib.rs
    // check_self_owned(ctx.accounts.swig, SwigError::OwnerMismatchSwigAccount)?;
    let sign_v1 = SignV1::from_instruction_bytes(data)?;
    let swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
    if unsafe { *swig_account_data.get_unchecked(0) } != Discriminator::SwigAccount as u8 {
        return Err(SwigError::InvalidSwigAccountDiscriminator.into());
    }
    let (swig_header, swig_roles) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
    let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
    let role = Swig::get_mut_role(sign_v1.args.role_id, swig_roles)?;
    if role.is_none() {
        return Err(SwigError::InvalidAuthorityNotFoundByRoleId.into());
    }
    let role = role.unwrap();
    let clock = Clock::get()?;
    let slot = clock.slot;
    if role.authority.session_based() {
        role.authority.authenticate_session(
            all_accounts,
            sign_v1.authority_payload,
            sign_v1.instruction_payload,
            slot,
        )?;
    } else {
        role.authority.authenticate(
            all_accounts,
            sign_v1.authority_payload,
            sign_v1.instruction_payload,
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
            let authority_index = *sign_v1.authority_payload.get_unchecked(0) as usize;
            restricted_keys[0].write(ctx.accounts.payer.key());
            restricted_keys[1].write(all_accounts[authority_index].key());
            core::slice::from_raw_parts(restricted_keys.as_ptr() as _, 2)
        }
    };
    let ix_iter = InstructionIterator::new(
        all_accounts,
        sign_v1.instruction_payload,
        ctx.accounts.swig.key(),
        rkeys,
    )?;
    let b = [swig.bump];
    let seeds = swig_account_signer(&swig.id, &b);
    let signer = seeds.as_slice();

    // Check if we have All permission to skip CPI validation
    let has_all_permission = RoleMut::get_action_mut::<All>(role.actions, &[])?.is_some();

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
                // Check if swig account is being used as a signer for this instruction
                let swig_is_signer = instruction.accounts.iter().any(|account_meta| {
                    account_meta.pubkey == ctx.accounts.swig.key() && account_meta.is_signer
                });

                if swig_is_signer {
                    // This is a CPI call where swig is signing - check Program permissions
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

            let swig_balance_before = ctx.accounts.swig.lamports();

            instruction.execute(all_accounts, ctx.accounts.swig.key(), &[signer.into()])?;

            let swig_balance_after = ctx.accounts.swig.lamports();
            if swig_balance_after < swig_balance_before {
                let amount_spent = swig_balance_before.saturating_sub(swig_balance_after);
                total_sol_spent = total_sol_spent.saturating_add(amount_spent);
            }
        } else {
            return Err(SwigError::InstructionExecutionError.into());
        }
    }

    let actions = role.actions;
    if has_all_permission {
        return Ok(());
    } else {
        for (index, account) in account_classifiers.iter().enumerate() {
            match account {
                AccountClassification::ThisSwig { lamports } => {
                    let account = unsafe { all_accounts.get_unchecked(index) };

                    // Only validate snapshots for writable accounts
                    if account.is_writable() {
                        let data = unsafe { &account.borrow_data_unchecked() };
                        let current_hash = hash_except(&data, account.owner(), NO_EXCLUDE_RANGES);
                        let snapshot_hash = unsafe { account_snapshots[index].assume_init_ref() };
                        if *snapshot_hash != current_hash {
                            return Err(SwigError::AccountDataModifiedUnexpectedly.into());
                        }
                    }

                    let current_lamports = account.lamports();
                    let mut matched = false;
                    if current_lamports < swig.reserved_lamports {
                        return Err(
                            SwigAuthenticateError::PermissionDeniedInsufficientBalance.into()
                        );
                    }

                    if total_sol_spent > 0 {
                        if let Some(action) = RoleMut::get_action_mut::<SolLimit>(actions, &[])? {
                            action.run(total_sol_spent)?;
                            continue;
                        } else if let Some(action) =
                            RoleMut::get_action_mut::<SolRecurringLimit>(actions, &[])?
                        {
                            action.run(total_sol_spent, slot)?;
                            continue;
                        }
                        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
                    }
                },
                AccountClassification::SwigTokenAccount { balance } => {
                    let account = unsafe { all_accounts.get_unchecked(index) };

                    // Only validate snapshots for writable accounts
                    if account.is_writable() {
                        let data = unsafe { &account.borrow_data_unchecked() };
                        let exclude_ranges = [TOKEN_BALANCE_EXCLUDE_RANGE];
                        let current_hash = hash_except(&data, account.owner(), &exclude_ranges);
                        let snapshot_hash = unsafe { account_snapshots[index].assume_init_ref() };
                        if *snapshot_hash != current_hash {
                            return Err(SwigError::AccountDataModifiedUnexpectedly.into());
                        }
                    }

                    let data = unsafe { &account.borrow_data_unchecked() };
                    let mint = unsafe { data.get_unchecked(TOKEN_MINT_RANGE) };
                    let state = unsafe { *data.get_unchecked(TOKEN_STATE_INDEX) };

                    let authority = unsafe { data.get_unchecked(TOKEN_AUTHORITY_RANGE) };
                    let current_token_balance = u64::from_le_bytes(unsafe {
                        data.get_unchecked(TOKEN_BALANCE_RANGE)
                            .try_into()
                            .map_err(|_| ProgramError::InvalidAccountData)?
                    });

                    if authority != ctx.accounts.swig.key() {
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

                    if balance > &current_token_balance {
                        let diff = balance - current_token_balance;
                        {
                            if let Some(action) =
                                RoleMut::get_action_mut::<TokenRecurringLimit>(actions, mint)?
                            {
                                action.run(diff, slot)?;
                                continue;
                            };
                        }
                        {
                            if let Some(action) =
                                RoleMut::get_action_mut::<TokenLimit>(actions, mint)?
                            {
                                action.run(diff)?;
                                continue;
                            };
                        }
                        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
                    }
                },
                AccountClassification::SwigStakeAccount { state, balance } => {
                    let account = unsafe { all_accounts.get_unchecked(index) };

                    // Only validate snapshots for writable accounts
                    if account.is_writable() {
                        let data = unsafe { &account.borrow_data_unchecked() };
                        let exclude_ranges = [STAKE_BALANCE_EXCLUDE_RANGE];
                        let current_hash = hash_except(&data, account.owner(), &exclude_ranges);
                        let snapshot_hash = unsafe { account_snapshots[index].assume_init_ref() };
                        if *snapshot_hash != current_hash {
                            return Err(SwigError::AccountDataModifiedUnexpectedly.into());
                        }
                    }

                    // Get current stake balance from account data
                    let data = unsafe { &account.borrow_data_unchecked() };

                    // Extract current stake balance from account
                    let current_stake_balance = u64::from_le_bytes(unsafe {
                        data.get_unchecked(STAKE_BALANCE_RANGE)
                            .try_into()
                            .map_err(|_| ProgramError::InvalidAccountData)?
                    });

                    // Calculate the absolute difference in stake amount, regardless of direction
                    let diff = if balance > &current_stake_balance {
                        balance - current_stake_balance // Staking
                    } else if balance < &current_stake_balance {
                        current_stake_balance - balance // Unstaking
                    } else {
                        0 // No change
                    };

                    // Skip further checks if there's no change in stake amount
                    if diff == 0 {
                        continue;
                    }

                    // Both staking and unstaking operations use the same permission system
                    // We check permissions using the absolute difference calculated above

                    // First check if we have unlimited staking permission
                    if RoleMut::get_action_mut::<StakeAll>(actions, &[])?.is_some() {
                        continue;
                    }

                    // Check for fixed limit
                    if let Some(action) = RoleMut::get_action_mut::<StakeLimit>(actions, &[])? {
                        action.run(diff)?;
                        continue;
                    }

                    // Check for recurring limit
                    if let Some(action) =
                        RoleMut::get_action_mut::<StakeRecurringLimit>(actions, &[])?
                    {
                        action.run(diff, slot)?;
                        continue;
                    }

                    // No matching permission found
                    return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
                },
                AccountClassification::ProgramScope {
                    role_index,
                    balance,
                } => {
                    let account = unsafe { all_accounts.get_unchecked(index) };

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
                            let data = unsafe { account.borrow_data_unchecked() };

                            // Check if balance field range is valid
                            if program_scope.balance_field_end - program_scope.balance_field_start
                                > 0
                                && program_scope.balance_field_end as usize <= data.len()
                            {
                                // Only validate snapshots for writable accounts
                                if account.is_writable() {
                                    // Hash the data excluding the balance field but including owner
                                    let exclude_ranges =
                                        [program_scope.balance_field_start as usize
                                            ..program_scope.balance_field_end as usize];
                                    let current_hash =
                                        hash_except(&data, account.owner(), &exclude_ranges);
                                    let snapshot_hash =
                                        unsafe { account_snapshots[index].assume_init_ref() };
                                    if *snapshot_hash != current_hash {
                                        return Err(
                                            SwigError::AccountDataModifiedUnexpectedly.into()
                                        );
                                    }
                                }

                                // Read the current balance from the account data
                                let current_balance = match program_scope.read_account_balance(data)
                                {
                                    Ok(bal) => bal,
                                    Err(err) => {
                                        msg!("Error reading balance from account data: {:?}", err);
                                        return Err(
                                            SwigError::InvalidProgramScopeBalanceFields.into()
                                        );
                                    },
                                };

                                let amount_spent = balance - current_balance;

                                // Execute the program scope run with proper amount and slot
                                program_scope.run(amount_spent, Some(slot))?;
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
