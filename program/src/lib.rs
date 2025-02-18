pub mod actions;
mod assertions;
mod authority_models;
mod error;
pub mod instruction;
pub mod util;
use std::mem::MaybeUninit;

use actions::process_action;
use error::SwigError;
use pinocchio::{
    account_info::AccountInfo, lazy_entrypoint::{InstructionContext, MaybeAccount}, memory::sol_memcmp, msg, program_error::ProgramError, pubkey::Pubkey, ProgramResult
};

#[cfg(not(feature = "no-entrypoint"))]
use pinocchio::lazy_entrypoint;
use pinocchio_pubkey::declare_id;
use pinocchio_pubkey::pubkey;
use swig_state::Discriminator;

declare_id!("swigNmWhy8RvUYXBKV5TSU8Hh3f4o5EczHouzBzEsLC");
const SPL_TOKEN_ID: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const SPL_TOKEN_2022_ID: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
const STAKING_ID: Pubkey = pubkey!("Stake11111111111111111111111111111111111111");

#[cfg(not(feature = "no-entrypoint"))]
lazy_entrypoint!(process_instruction);
pub fn process_instruction(mut ctx: InstructionContext) -> ProgramResult {
    const AI: MaybeUninit<AccountInfo> = MaybeUninit::<AccountInfo>::uninit();
    let mut accounts = [AI; 128];
    let mut classifiers = [AccountClassification::None; 128];
    unsafe {
        execute(&mut ctx, &mut accounts, &mut classifiers)?;
    }
    pinocchio::default_allocator!();
    pinocchio::default_panic_handler!();
    Ok(())
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum AccountClassification {
    None,
    ThisSwig{
        lamports: u64,
    },
    SwigTokenAccount {
        balance: u64,
    },
    SwigStakingAccount {
        balance: u64,
    },
}
/**
 * classify_accounts
 * This functions classifies all accounts as either the swig account (assumed in all instructions to be the first account)
 * or an asset account owned by the swig.
 */
#[inline(always)]
unsafe fn execute(
    ctx: &mut InstructionContext,
    accounts: &mut [MaybeUninit<AccountInfo>],
    account_classification: &mut [AccountClassification],
) -> Result<(), ProgramError> {
    let mut index: usize = 0;
    let mut remaining = ctx.remaining();
    while remaining > 0 {
        match ctx.next_account_unchecked() {
            MaybeAccount::Account(account) => {
                let classification = classify_account(index, &account, accounts)?;
                account_classification[index] = classification;
                accounts[index] = MaybeUninit::new(account);
            }
            MaybeAccount::Duplicated(account_index) => {
                accounts[index].write(accounts[account_index as usize].assume_init_ref().clone());
            }
        }
        remaining -= 1;
        index += 1;
    }
    let instruction = unsafe { ctx.instruction_data_unchecked() };
    process_action(core::slice::from_raw_parts(accounts.as_ptr() as _, index+1), core::slice::from_raw_parts(account_classification.as_ptr() as _, index+1), instruction)?;
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
        }
        &crate::ID => {
            let data = account.borrow_data_unchecked();
            if data[0] == Discriminator::SwigAccount as u8 {
                Ok(AccountClassification::ThisSwig{
                    lamports: account.lamports(),
                })
            } else {
                Ok(AccountClassification::None)
            }
        }
        &SPL_TOKEN_2022_ID | &SPL_TOKEN_ID if account.data_len() == 165 && index > 0 => unsafe {
            let data = account.borrow_data_unchecked();
            if sol_memcmp(accounts[0].assume_init_ref().key(), &data[32..64], 32) == 0 {
                Ok(AccountClassification::SwigTokenAccount{
                    balance: u64::from_le_bytes(data[64..72].try_into().map_err(|_| ProgramError::InvalidAccountData)?),
                })
            } else {
                Ok(AccountClassification::None)
            }
        }
        //TODO add staking account
        _ => Ok(AccountClassification::None),
    }
}
