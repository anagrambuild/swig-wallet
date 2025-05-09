pub mod actions;
mod error;
pub mod instruction;
mod util;
use core::mem::MaybeUninit;

use actions::process_action;
use error::SwigError;
#[cfg(not(feature = "no-entrypoint"))]
use pinocchio::lazy_entrypoint;
use pinocchio::{
    account_info::AccountInfo,
    lazy_entrypoint::{InstructionContext, MaybeAccount},
    memory::sol_memcmp,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};
use pinocchio_pubkey::{declare_id, pubkey};
use swig_state_x::{
    action::{
        program_scope::{NumericType, ProgramScope},
        Action, Actionable, Permission,
    },
    swig::{Swig, SwigWithRoles},
    AccountClassification, Discriminator, Transmutable,
};
use util::ProgramScopeCache;

declare_id!("swigDk8JezhiAVde8k6NMwxpZfgGm2NNuMe1KYCmUjP");
const SPL_TOKEN_ID: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const SPL_TOKEN_2022_ID: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
const STAKING_ID: Pubkey = pubkey!("Stake11111111111111111111111111111111111111");

pinocchio::default_allocator!();
pinocchio::default_panic_handler!();

#[cfg(not(feature = "no-entrypoint"))]
lazy_entrypoint!(process_instruction);
pub fn process_instruction(mut ctx: InstructionContext) -> ProgramResult {
    const AI: MaybeUninit<AccountInfo> = MaybeUninit::<AccountInfo>::uninit();
    const AC: MaybeUninit<AccountClassification> = MaybeUninit::<AccountClassification>::uninit();
    let mut accounts = [AI; 100];
    let mut classifiers = [AC; 100];
    unsafe {
        execute(&mut ctx, &mut accounts, &mut classifiers)?;
    }
    Ok(())
}

/// classify_accountstest_token_transfer_performance_comparison
/// This functions classifies all accounts as either the swig account (assumed
/// in all instructions to be the first account) or an asset account owned by
/// the swig.
#[inline(always)]
unsafe fn execute(
    ctx: &mut InstructionContext,
    accounts: &mut [MaybeUninit<AccountInfo>],
    account_classification: &mut [MaybeUninit<AccountClassification>],
) -> Result<(), ProgramError> {
    let mut index: usize = 0;

    // First account must be processed to get SwigWithRoles
    if let Ok(acc) = ctx.next_account() {
        match acc {
            MaybeAccount::Account(account) => {
                let classification = classify_account(0, &account, accounts, None)?;
                account_classification[0].write(classification);
                accounts[0].write(account);
            },
            MaybeAccount::Duplicated(account_index) => {
                accounts[0].write(accounts[account_index as usize].assume_init_ref().clone());
            },
        }
        index = 1;
    }

    // Create program scope cache if first account is a valid Swig account
    let program_scope_cache = if index > 0 {
        let first_account = accounts[0].assume_init_ref();
        if first_account.owner() == &crate::ID {
            let data = first_account.borrow_data_unchecked();
            if data.len() >= Swig::LEN && *data.get_unchecked(0) == Discriminator::SwigAccount as u8
            {
                ProgramScopeCache::load_from_swig(data)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    // Process remaining accounts using the cache
    while let Ok(acc) = ctx.next_account() {
        let classification = match &acc {
            MaybeAccount::Account(account) => {
                classify_account(index, account, accounts, program_scope_cache.as_ref())?
            },
            MaybeAccount::Duplicated(account_index) => {
                let account = accounts[*account_index as usize].assume_init_ref().clone();
                classify_account(index, &account, accounts, program_scope_cache.as_ref())?
            },
        };
        account_classification[index].write(classification);
        accounts[index].write(match acc {
            MaybeAccount::Account(account) => account,
            MaybeAccount::Duplicated(account_index) => {
                accounts[account_index as usize].assume_init_ref().clone()
            },
        });
        index += 1;
    }

    let instruction = unsafe { ctx.instruction_data_unchecked() };
    process_action(
        core::slice::from_raw_parts(accounts.as_ptr() as _, index),
        core::slice::from_raw_parts(account_classification.as_ptr() as _, index),
        instruction,
    )?;
    Ok(())
}

#[inline(always)]
unsafe fn classify_account(
    index: usize,
    account: &AccountInfo,
    accounts: &[MaybeUninit<AccountInfo>],
    program_scope_cache: Option<&ProgramScopeCache>,
) -> Result<AccountClassification, ProgramError> {
    let mut target_index: usize = 0;
    match account.owner() {
        &crate::ID => {
            let data = account.borrow_data_unchecked();
            let first_byte = unsafe { *data.get_unchecked(0) }.into();
            match first_byte {
                Discriminator::SwigAccount if index == 0 => Ok(AccountClassification::ThisSwig {
                    lamports: account.lamports(),
                }),
                Discriminator::SwigAccount if index != 0 => {
                    return Err(SwigError::InvalidAccountsSwigMustBeFirst.into());
                },
                _ => Ok(AccountClassification::None),
            }
        },
        &STAKING_ID => {
            let data = account.borrow_data_unchecked();
            // TODO add staking account
            Ok(AccountClassification::None)
        },
        #[cfg(not(feature = "program_scope_test"))]
        &SPL_TOKEN_2022_ID | &SPL_TOKEN_ID if account.data_len() == 165 && index > 0 => unsafe {
            let data = account.borrow_data_unchecked();
            if sol_memcmp(
                accounts.get_unchecked(0).assume_init_ref().key(),
                data.get_unchecked(32..64),
                32,
            ) == 0
            {
                Ok(AccountClassification::SwigTokenAccount {
                    balance: u64::from_le_bytes(
                        data.get_unchecked(64..72)
                            .try_into()
                            .map_err(|_| ProgramError::InvalidAccountData)?,
                    ),
                })
            } else {
                Ok(AccountClassification::None)
            }
        },
        _ => {
            if index > 0 {
                // Use the program scope cache if available
                if let Some(cache) = program_scope_cache {
                    if let Some((role_id, program_scope)) =
                        cache.find_program_scope(account.key().as_ref())
                    {
                        return Ok(AccountClassification::ProgramScope {
                            role_index: role_id,
                            balance: match program_scope.scope_type {
                                x if x == 0 => 0, // Basic type
                                x if x == 1 || x == 2 => {
                                    // Convert based on numeric type
                                    match program_scope.numeric_type {
                                        x if x == NumericType::U8 as u8 => {
                                            program_scope.current_amount
                                        },
                                        x if x == NumericType::U32 as u8 => {
                                            program_scope.current_amount
                                        },
                                        x if x == NumericType::U64 as u8 => {
                                            program_scope.current_amount
                                        },
                                        x if x == NumericType::U128 as u8 => {
                                            program_scope.current_amount
                                        },
                                        _ => return Err(SwigError::InvalidOperation.into()),
                                    }
                                },
                                _ => return Err(SwigError::InvalidOperation.into()),
                            },
                        });
                    }
                }
            }
            Ok(AccountClassification::None)
        },
    }
}
