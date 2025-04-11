pub mod actions;
mod error;
pub mod instruction;
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
    action::program::ProgramScope,
    swig::{Swig, SwigWithRoles},
    AccountClassification, Discriminator, Transmutable,
};

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
        &crate::ID if index != 0 => Err(SwigError::InvalidAccountsSwigMustBeFirst.into()),
        &crate::ID => {
            let data = account.borrow_data_unchecked();
            if data.len() < Swig::LEN {
                return Err(SwigError::InvalidSwigAccountDiscriminator.into());
            }
            if unsafe { *data.get_unchecked(0) == Discriminator::SwigAccount as u8 } {
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
        // &SPL_TOKEN_2022_ID | &SPL_TOKEN_ID if account.data_len() == 165 && index > 0 => unsafe {
        //     let data = account.borrow_data_unchecked();
        //     if sol_memcmp(
        //         accounts.get_unchecked(0).assume_init_ref().key(),
        //         data.get_unchecked(32..64),
        //         32,
        //     ) == 0
        //     {
        //         Ok(AccountClassification::SwigTokenAccount {
        //             balance: u64::from_le_bytes(
        //                 data.get_unchecked(64..72)
        //                     .try_into()
        //                     .map_err(|_| ProgramError::InvalidAccountData)?,
        //             ),
        //         })
        //     } else {
        //         Ok(AccountClassification::None)
        //     }
        // },
        // TODO add staking account
        _ => {
            if index > 0 {
                let first_account = accounts.get_unchecked(0).assume_init_ref();
                if first_account.owner() == &crate::ID {
                    let data = first_account.borrow_data_unchecked();
                    if data.len() >= Swig::LEN
                        && *data.get_unchecked(0) == Discriminator::SwigAccount as u8
                    {
                        if let Ok(swig_with_roles) = SwigWithRoles::from_bytes(data) {
                            // Check each role for ProgramScope actions that match this account's owner
                            let owner = account.owner();
                            // msg!("Checking account with owner: {:?}", owner);

                            for role_id in 0..swig_with_roles.state.role_counter {
                                if let Ok(Some(role)) = swig_with_roles.get_role(role_id) {
                                    // Check if this role has a ProgramScope action for this program
                                    // msg!("Checking role {} for ProgramScope action", role_id);

                                    // Add debug for data length
                                    let owner_bytes = owner.as_ref();
                                    // msg!("Owner bytes length: {}", owner_bytes.len());

                                    if let Ok(Some(program_scope)) =
                                        role.get_action::<ProgramScope>(owner_bytes)
                                    {
                                        // msg!(
                                        //     "Found ProgramScope action! Program ID in action: {:?}",
                                        //     &program_scope.program_id[0..4]
                                        // );
                                        // msg!(
                                        //     "Comparing with owner bytes: {:?}",
                                        //     &owner_bytes[0..4]
                                        // );

                                        return Ok(AccountClassification::ProgramScope {
                                            role_index: role_id as u8,
                                        });
                                    } else {
                                        // msg!(
                                        //     "No matching ProgramScope action found in role {}",
                                        //     role_id
                                        // );
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(AccountClassification::None)
        },
    }
}
