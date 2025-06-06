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
use swig_state_x::{
    action::{
        all::All,
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
    swig::{swig_account_signer, AuthorizationLock, Swig, SwigWithRoles},
    Discriminator, IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut,
};

use crate::{
    error::SwigError,
    instruction::{
        accounts::{Context, SignV1Accounts},
        SwigInstruction,
    },
    AccountClassification,
};
// use swig_instructions::InstructionIterator;

pub const INSTRUCTION_SYSVAR_ACCOUNT: Pubkey =
    from_str("Sysvar1nstructions1111111111111111111111111");

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
        if role.position.authority_type()? == AuthorityType::Ed25519 {
            let authority_index = *sign_v1.authority_payload.get_unchecked(0) as usize;
            restricted_keys[0].write(ctx.accounts.payer.key());
            restricted_keys[1].write(all_accounts[authority_index].key());
            core::slice::from_raw_parts(restricted_keys.as_ptr() as _, 2)
        } else {
            restricted_keys[0].write(ctx.accounts.payer.key());

            core::slice::from_raw_parts(restricted_keys.as_ptr() as _, 1)
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

    for ix in ix_iter {
        if let Ok(instruction) = ix {
            instruction.execute(all_accounts, ctx.accounts.swig.key(), &[signer.into()])?;
        } else {
            return Err(SwigError::InstructionExecutionError.into());
        }
    }
    let actions = role.actions;
    if RoleMut::get_action_mut::<All>(actions, &[])?.is_some() {
        return Ok(());
    } else {
        for (index, account) in account_classifiers.iter().enumerate() {
            match account {
                AccountClassification::ThisSwig { lamports } => {
                    let current_lamports = all_accounts[index].lamports();
                    if current_lamports < swig.reserved_lamports {
                        return Err(
                            SwigAuthenticateError::PermissionDeniedInsufficientBalance.into()
                        );
                    }
                    if lamports > &current_lamports {
                        let amount_diff = lamports - current_lamports;

                        {
                            if let Some(action) = RoleMut::get_action_mut::<SolLimit>(actions, &[])?
                            {
                                action.run(amount_diff)?;
                                continue;
                            };
                        }
                        {
                            if let Some(action) =
                                RoleMut::get_action_mut::<SolRecurringLimit>(actions, &[])?
                            {
                                action.run(amount_diff, slot)?;
                            };
                        }
                        return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
                    }
                },
                AccountClassification::SwigTokenAccount { balance } => {
                    let data =
                        unsafe { &all_accounts.get_unchecked(index).borrow_data_unchecked() };
                    let mint = unsafe { data.get_unchecked(0..32) };
                    let delegate = unsafe { data.get_unchecked(72..76) };
                    let state = unsafe { *data.get_unchecked(108) };
                    let current_token_balance = u64::from_le_bytes(unsafe {
                        data.get_unchecked(64..72)
                            .try_into()
                            .map_err(|_| ProgramError::InvalidAccountData)?
                    });

                    if delegate != [0u8; 4] {
                        return Err(
                            SwigAuthenticateError::PermissionDeniedTokenAccountDelegatePresent
                                .into(),
                        );
                    }
                    if state != 1 {
                        return Err(
                            SwigAuthenticateError::PermissionDeniedTokenAccountNotInitialized
                                .into(),
                        );
                    }
                    if balance > &current_token_balance {
                        let mut matched = false;
                        let diff = balance - current_token_balance;

                        // Check authorization locks first
                        // Re-borrow the swig account data to check authorization locks
                        let swig_account_data = unsafe { ctx.accounts.swig.borrow_data_unchecked() };
                        let swig_with_roles = SwigWithRoles::from_bytes(&swig_account_data)?;
                        
                        // Convert mint slice to array for comparison
                        let mint_array: [u8; 32] = mint.try_into()
                            .map_err(|_| ProgramError::InvalidAccountData)?;
                        
                        // Check if spending is allowed by authorization locks
                        // Sum up all non-expired authorization locks for this mint
                        let mut total_authorized_amount = 0u64;
                        let mut has_active_locks = false;
                        
                        let _: Result<(), ProgramError> = swig_with_roles.for_each_authorization_lock_by_mint(&mint_array, |auth_lock| {
                            // Only check non-expired locks
                            if auth_lock.expiry_slot > slot {
                                has_active_locks = true;
                                total_authorized_amount = total_authorized_amount.saturating_add(auth_lock.amount);
                            }
                            Ok(())
                        });
                        
                        // If there are active authorization locks, check against the total
                        if has_active_locks {
                            if diff > total_authorized_amount {
                                return Err(SwigAuthenticateError::PermissionDeniedMissingPermission.into());
                            } else {
                                // This spending is within the combined authorization lock limits
                                matched = true;
                            }
                        }

                        // If not covered by authorization locks, check regular token permissions
                        if !matched {
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
                                    matched = true;
                                };
                            }
                        }

                        if !matched {
                            return Err(
                                SwigAuthenticateError::PermissionDeniedMissingPermission.into()
                            );
                        }
                    }
                },
                AccountClassification::SwigStakeAccount { state, balance } => {
                    // Get current stake balance from account data
                    let data =
                        unsafe { &all_accounts.get_unchecked(index).borrow_data_unchecked() };

                    // Extract current stake balance from account
                    let current_stake_balance = u64::from_le_bytes(unsafe {
                        data.get_unchecked(184..192)
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
                    // Get the data from the account
                    let data =
                        unsafe { &all_accounts.get_unchecked(index).borrow_data_unchecked() };

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
                            let account = unsafe { all_accounts.get_unchecked(index) };
                            let data = unsafe { account.borrow_data_unchecked() };

                            let current_balance = if program_scope.balance_field_end
                                - program_scope.balance_field_start
                                > 0
                            {
                                // Use the defined balance field indices to read the balance
                                match program_scope.read_account_balance(data) {
                                    Ok(bal) => bal,
                                    Err(err) => {
                                        msg!("Error reading balance from account data: {:?}", err);
                                        return Err(
                                            SwigError::InvalidProgramScopeBalanceFields.into()
                                        );
                                    },
                                }
                            } else {
                                return Err(SwigError::InvalidProgramScopeBalanceFields.into());
                            };

                            let amount_spent = balance - current_balance;

                            // Execute the program scope run with proper amount and slot
                            program_scope.run(amount_spent, Some(slot))?;
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

    // Clean up expired authorization locks at the end of the transaction
    // Note: We don't reallocate the account to keep it simple and avoid potential issues.
    // The unused space at the end of the account is acceptable.
    {
        let mut swig_account_data = unsafe { ctx.accounts.swig.borrow_mut_data_unchecked() };
        if unsafe { *swig_account_data.get_unchecked(0) } == Discriminator::SwigAccount as u8 {
            let (swig_header, rest) = unsafe { swig_account_data.split_at_mut_unchecked(Swig::LEN) };
            let swig = unsafe { Swig::load_mut_unchecked(swig_header)? };
            let _removed_count = SwigWithRoles::remove_expired_authorization_locks_mut(swig, rest, slot)?;
            // Account size remains the same - unused space at the end is acceptable
        }
    }

    Ok(())
}
