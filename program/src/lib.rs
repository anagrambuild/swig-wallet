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
        stake: u64,
    },
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct StakeDelegation {
    pub stake: u64,
    pub activation_epoch: u64,
    pub deactivation_epoch: u64,
    pub warmup_cooldown_rate: u8,
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
        &STAKING_ID => {
            // let data = account.borrow_data_unchecked();
            parse_stake_account_data(account)
        },
        _ => Ok(AccountClassification::None),
    }
}

#[inline(always)]
unsafe fn parse_stake_account_data(
    account: &AccountInfo,
) -> Result<AccountClassification, ProgramError> {
    let data = account.borrow_data_unchecked();
    // Parse StakeStateV2 from the account data
    // The first byte indicates the stake state variant
    let state = match data.get(0) {
        Some(0) => StakeAccountState::Uninitialized,
        Some(1) => StakeAccountState::Initialized,
        Some(2) => StakeAccountState::Stake,
        Some(3) => StakeAccountState::RewardsPool,
        _ => return Ok(AccountClassification::None),
    };

    // Extract delegation information if in Stake state
    let (voter_pubkey, delegation) = if state == StakeAccountState::Stake {
        // For the Stake variant, the delegation data starts at a specific offset
        let voter_pubkey_offset = 112;

        // Only proceed if we have enough data
        if data.len() >= voter_pubkey_offset + 32 + 8 + 8 + 8 + 1 {
            // Create voter_pubkey array directly
            let mut voter_pubkey_array = [0u8; 32];
            voter_pubkey_array
                .copy_from_slice(&data[voter_pubkey_offset..voter_pubkey_offset + 32]);

            // Use direct slice access without creating intermediate variables where
            // possible
            let stake = u64::from_le_bytes(
                data[voter_pubkey_offset + 32..voter_pubkey_offset + 40]
                    .try_into()
                    .unwrap_or([0; 8]),
            );

            let activation_epoch = u64::from_le_bytes(
                data[voter_pubkey_offset + 40..voter_pubkey_offset + 48]
                    .try_into()
                    .unwrap_or([0; 8]),
            );

            let deactivation_epoch = u64::from_le_bytes(
                data[voter_pubkey_offset + 48..voter_pubkey_offset + 56]
                    .try_into()
                    .unwrap_or([0; 8]),
            );

            let warmup_cooldown_rate = data[voter_pubkey_offset + 56];

            (
                Some(voter_pubkey_array),
                Some(StakeDelegation {
                    stake,
                    activation_epoch,
                    deactivation_epoch,
                    warmup_cooldown_rate,
                }),
            )
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    let stake = if let Some(del) = delegation {
        del.stake
    } else {
        0
    };
    Ok(AccountClassification::SwigStakingAccount {
        state,
        stake, /* balance: lamports,
                * voter_pubkey,
                * delegation, */
    })
}
