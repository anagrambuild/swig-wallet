pub mod actions;
mod assertions;
mod authority_models;
mod error;
pub mod instruction;
pub mod util;
mod vm;
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
    const AI: MaybeUninit<AccountInfo> = MaybeUninit::<AccountInfo>::uninit();
    const AC: MaybeUninit<AccountClassification> = MaybeUninit::<AccountClassification>::uninit();
    let mut accounts = [AI; 100];
    let mut classifiers = [AC; 100];
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
    accounts: &mut [MaybeUninit<AccountInfo>],
    account_classification: &mut [MaybeUninit<AccountClassification>],
) -> Result<(), ProgramError> {
    let mut index: usize = 0;
    while let Ok(acc) = ctx.next_account() {
        match acc {
            MaybeAccount::Account(account) => {
                let classification = classify_account(index, &account, accounts)?;
                account_classification[index].write(classification);
                accounts[index].write(account);
            },
            MaybeAccount::Duplicated(account_index) => {
                accounts[index].write(accounts[account_index as usize].assume_init_ref().clone());
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
    // Debug print account information
    // msg!(
    //     "Classifying account at index {}: {:?}",
    //     index,
    //     account.key()
    // );
    // msg!("  Owner: {:?}", account.owner());

    match account.owner() {
        &crate::ID if index != 0 => {
            // Check if this is a plugin bytecode account (which is allowed to be in any
            // position)
            let is_plugin_account =
                account.data_len() >= std::mem::size_of::<swig_state::PluginBytecodeAccount>();

            if is_plugin_account {
                // Likely a plugin bytecode account, allow it to be in any position
                // msg!(
                //     "  Account at index {} appears to be a plugin bytecode account,
                // allowing",     index
                // );
                return Ok(AccountClassification::None);
            }

            // For other Swig-owned accounts, enforce position 0
            // msg!(
            //     "ERROR: Account owned by Swig program detected at index {} != 0",
            //     index
            // );
            Err(SwigError::InvalidAccounts("Swig Account must be first account").into())
        },
        &crate::ID => {
            let data = account.borrow_data_unchecked();
            if data[0] == Discriminator::SwigAccount as u8 {
                // msg!("  Account identified as Swig Account");
                Ok(AccountClassification::ThisSwig {
                    lamports: account.lamports(),
                })
            } else {
                // msg!("  Account owned by Swig but not a Swig Account");
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
