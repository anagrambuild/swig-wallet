pub mod actions;
mod assertions;
mod authority_models;
mod error;
pub mod instruction;
pub mod util;
use std::mem::MaybeUninit;

use actions::process_action;
use error::SwigError;
#[cfg(not(feature = "no-entrypoint"))]
use pinocchio::lazy_entrypoint;
use pinocchio::{
    account_info::AccountInfo,
    lazy_entrypoint::{InstructionContext, MaybeAccount},
    memory::sol_memcmp,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};
use pinocchio_pubkey::{declare_id, pubkey};
use swig_state::Discriminator;
declare_id!("swigNmWhy8RvUYXBKV5TSU8Hh3f4o5EczHouzBzEsLC");
const SPL_TOKEN_ID: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const SPL_TOKEN_2022_ID: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
const STAKING_ID: Pubkey = pubkey!("Stake11111111111111111111111111111111111111");

pinocchio::default_allocator!();
pinocchio::default_panic_handler!();

#[cfg(not(feature = "no-entrypoint"))]
lazy_entrypoint!(process_instruction);
pub fn process_instruction(mut ctx: InstructionContext) -> ProgramResult {
    // Allocate vectors on the heap with initial capacity of 32
    let mut accounts = Vec::with_capacity(128);
    let mut classifiers = Vec::with_capacity(128);

    unsafe {
        execute(&mut ctx, &mut accounts, &mut classifiers)?;
    }
    Ok(())
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum StakeAccountState {
    Uninitialized,
    Initialized,
    Stake,
    RewardsPool,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum AccountClassification {
    None,
    ThisSwig {
        lamports: u64,
    },
    SwigTokenAccount {
        balance: u64,
    },
    SwigStakingAccount {
        state: StakeAccountState,
        balance: u64,
    },
}
/// classify_accounts
/// This functions classifies all accounts as either the swig account (assumed
/// in all instructions to be the first account) or an asset account owned by
/// the swig.
#[inline(always)]
unsafe fn execute(
    ctx: &mut InstructionContext,
    accounts: &mut Vec<MaybeUninit<AccountInfo>>,
    account_classification: &mut Vec<MaybeUninit<AccountClassification>>,
) -> Result<(), ProgramError> {
    let mut index: usize = 0;
    while let Ok(acc) = ctx.next_account() {
        match acc {
            MaybeAccount::Account(account) => {
                let classification = classify_account(index, &account, accounts)?;
                if index >= account_classification.len() {
                    account_classification.push(MaybeUninit::new(classification));
                } else {
                    account_classification[index].write(classification);
                }
                if index >= accounts.len() {
                    accounts.push(MaybeUninit::new(account));
                } else {
                    accounts[index].write(account);
                }
            },
            MaybeAccount::Duplicated(account_index) => {
                if index >= accounts.len() {
                    accounts.push(MaybeUninit::new(
                        accounts[account_index as usize].assume_init_ref().clone(),
                    ));
                } else {
                    let account_to_clone =
                        accounts[account_index as usize].assume_init_ref().clone();
                    accounts[index].write(account_to_clone);
                }
            },
        }
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
) -> Result<AccountClassification, ProgramError> {
    match account.owner() {
        &crate::ID if index != 0 => {
            Err(SwigError::InvalidAccounts("Swig Account must be first account").into())
        },
        &crate::ID => {
            let data = account.borrow_data_unchecked();
            if data[0] == Discriminator::SwigAccount as u8 {
                Ok(AccountClassification::ThisSwig {
                    lamports: account.lamports(),
                })
            } else {
                Ok(AccountClassification::None)
            }
        },
        &STAKING_ID => {
            let data = account.borrow_data_unchecked();

            // TODO add staking account
            Ok(AccountClassification::None)
        },
        &SPL_TOKEN_2022_ID | &SPL_TOKEN_ID if account.data_len() == 165 && index > 0 => unsafe {
            let data = account.borrow_data_unchecked();
            if sol_memcmp(accounts[0].assume_init_ref().key(), &data[32..64], 32) == 0 {
                Ok(AccountClassification::SwigTokenAccount {
                    balance: u64::from_le_bytes(
                        data[64..72]
                            .try_into()
                            .map_err(|_| ProgramError::InvalidAccountData)?,
                    ),
                })
            } else {
                Ok(AccountClassification::None)
            }
        },
        // TODO add staking account
        _ => Ok(AccountClassification::None),
    }
}
