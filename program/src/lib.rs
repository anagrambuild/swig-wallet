//! Swig Wallet Program Implementation
//!
//! This module provides the core program implementation for the Swig wallet
//! system. It handles account classification, instruction processing, and
//! program state management. The program supports various account types
//! including Swig accounts, stake accounts, token accounts, and program-scoped
//! accounts.

pub mod actions;
mod error;
pub mod instruction;
pub mod util;
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
use swig_state::{
    action::{
        program_scope::{NumericType, ProgramScope},
        Action, Actionable, Permission,
    },
    swig::{Swig, SwigWithRoles},
    AccountClassification, Discriminator, StakeAccountState, Transmutable,
};
use util::{read_program_scope_account_balance, ProgramScopeCache};
#[cfg(not(feature = "no-entrypoint"))]
use {default_env::default_env, solana_security_txt::security_txt};

/// Program ID for the Swig wallet program
declare_id!("swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB");
/// Program ID for the SPL Token program
const SPL_TOKEN_ID: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
/// Program ID for the SPL Token 2022 program
const SPL_TOKEN_2022_ID: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
/// Program ID for the Solana Staking program
const STAKING_ID: Pubkey = pubkey!("Stake11111111111111111111111111111111111111");
/// Program ID for the Solana System program
const SYSTEM_PROGRAM_ID: Pubkey = pubkey!("11111111111111111111111111111111");

pinocchio::default_allocator!();
pinocchio::default_panic_handler!();

#[cfg(not(feature = "no-entrypoint"))]
lazy_entrypoint!(process_instruction);

#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    name: "Swig",
    project_url: "https://onswig.com",
    contacts: "email:security@onswig.com",
    policy: "https://github.com/anagrambuild/swig-wallet/security/policy",

    // Optional Fields
    preferred_languages: "en",
    source_code: "https://github.com/anagrambuild/swig-wallet",
    source_revision: "",
    source_release: "",
    encryption: "",
    auditors: "https://accretion.xyz/",
    acknowledgements: "Thank you to our bug bounty hunters!"
}

/// Main program entry point.
///
/// This function is called by the Solana runtime to process instructions sent
/// to the Swig wallet program. It sets up the execution context and delegates
/// to the `execute` function for actual instruction processing.
///
/// # Arguments
/// * `ctx` - The instruction context containing accounts and instruction data
///
/// # Returns
/// * `ProgramResult` - The result of processing the instruction
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

/// Determines if a Swig account is v2 format by checking the last 7 bytes.
///
/// # Account Format Differences
///
/// **Swig V2** (last 8 bytes): `[wallet_bump: u8, _padding: [u8; 7]]`
/// - Example bytes: `[253, 0, 0, 0, 0, 0, 0, 0]` where 253 is the bump seed
/// - As little-endian u64: `0x0000000000000FD` (the wallet_bump in the lowest
///   byte)
/// - After right shift by 8: `0x000000000000000` (removes wallet_bump, leaves
///   only padding)
/// - Result: equals 0 ✓ → **V2 account**
///
/// **Swig V1** (last 8 bytes): `u64` value (typically role_counter,
/// session_expiry, etc.)
/// - Example values: 1, 2, 100, 256, 1000, etc.
/// - Example bytes for 256: `[0, 1, 0, 0, 0, 0, 0, 0]` (little-endian)
/// - As little-endian u64: `0x0000000000000100`
/// - After right shift by 8: `0x0000000000000001` (non-zero in upper 7 bytes)
/// - Result: non-zero ✓ → **V1 account**
///
/// # Why This Works
///
/// The key insight is that v2 accounts have 7 consecutive zero bytes (padding),
/// while v1 accounts store a u64 value that, when interpreted as bytes, will
/// almost certainly have at least one non-zero byte in positions other than the
/// first byte. Even small u64 values like 1, 2, 100 will have zeros in the
/// first byte but the actual value stored in subsequent bytes.
///
/// By reading the last 8 bytes as a u64 and right-shifting by 8 bits, we:
/// 1. Remove the first byte (wallet_bump in v2, or low byte of u64 in v1)
/// 2. Check if the remaining 7 bytes are all zeros
///
/// This is a zero-copy operation using a single unaligned u64 read, followed by
/// a single shift and comparison, making it extremely efficient (3 CPU
/// operations total).
///
/// # Safety
///
/// This function assumes `data.len() >= Swig::LEN` has been checked by the
/// caller. Reading beyond the end of the slice would be undefined behavior.
///
/// # Arguments
/// * `data` - The account data slice, must be `Swig::LEN` bytes
///
/// # Returns
/// * `true` if the account is v2 format (last 7 bytes are zero)
/// * `false` if the account is v1 format (last 7 bytes contain non-zero values)
#[inline(always)]
unsafe fn is_swig_v2(data: &[u8]) -> bool {
    let last_8_bytes_ptr = data.as_ptr().add(Swig::LEN - 8) as *const u64;
    let last_8_bytes = last_8_bytes_ptr.read_unaligned();
    last_8_bytes >> 8 == 0
}

/// Core instruction execution function.
///
/// This function processes all accounts in the instruction context, classifies
/// them according to their type and ownership, and then processes the
/// instruction action. It handles special cases for Swig accounts, stake
/// accounts, token accounts, and program-scoped accounts.
///
/// # Safety
/// This function uses unsafe code for performance optimization. Callers must
/// ensure that:
/// - The account arrays have sufficient capacity
/// - The instruction context is valid
/// - All memory accesses are properly bounds-checked
///
/// # Arguments
/// * `ctx` - The instruction context
/// * `accounts` - Array to store processed account information
/// * `account_classification` - Array to store account classifications
///
/// # Returns
/// * `Result<(), ProgramError>` - Success or error status
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
                let classification =
                    classify_account(0, &account, accounts, account_classification, None)?;
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
            if data.len() >= Swig::LEN
                && *data.get_unchecked(0) == Discriminator::SwigConfigAccount as u8
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
            MaybeAccount::Account(account) => classify_account(
                index,
                account,
                accounts,
                account_classification,
                program_scope_cache.as_ref(),
            )?,
            MaybeAccount::Duplicated(account_index) => {
                let account = accounts[*account_index as usize].assume_init_ref().clone();
                classify_account(
                    index,
                    &account,
                    accounts,
                    account_classification,
                    program_scope_cache.as_ref(),
                )?
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

    process_action(
        core::slice::from_raw_parts(accounts.as_ptr() as _, index),
        core::slice::from_raw_parts_mut(account_classification.as_mut_ptr() as _, index),
        ctx.instruction_data_unchecked(),
    )?;
    Ok(())
}

/// Classifies an account based on its owner and data.
///
/// This function determines the type and role of an account in the Swig wallet
/// system. It handles several special cases:
/// - Swig accounts (the first one must be at index 0 for signing/permission
///   checking)
/// - Stake accounts (with validation of withdrawer authority)
/// - Token accounts (SPL Token and Token-2022)
/// - Program-scoped accounts (using the program scope cache)
///
/// # Safety
/// This function uses unsafe code for performance optimization. Callers must
/// ensure that:
/// - The account data is valid and properly aligned
/// - The account index is within bounds
/// - All memory accesses are properly bounds-checked
///
/// # Arguments
/// * `index` - Index of the account in the account list
/// * `account` - The account to classify
/// * `accounts` - Array of all accounts in the instruction
/// * `program_scope_cache` - Optional cache of program scope information
///
/// # Returns
/// * `Result<AccountClassification, ProgramError>` - The account classification
///   or error
#[inline(always)]
unsafe fn classify_account(
    index: usize,
    account: &AccountInfo,
    accounts: &[MaybeUninit<AccountInfo>],
    account_classifications: &[MaybeUninit<AccountClassification>],
    program_scope_cache: Option<&ProgramScopeCache>,
) -> Result<AccountClassification, ProgramError> {
    let mut target_index: usize = 0;
    match account.owner() {
        &crate::ID => {
            let data = account.borrow_data_unchecked();
            let first_byte = *data.get_unchecked(0);
            match first_byte {
                disc if disc == Discriminator::SwigConfigAccount as u8 && index == 0 => {
                    if data.len() >= Swig::LEN && is_swig_v2(data) {
                        Ok(AccountClassification::ThisSwigV2 {
                            lamports: account.lamports(),
                        })
                    } else {
                        Ok(AccountClassification::ThisSwig {
                            lamports: account.lamports(),
                        })
                    }
                },
                disc if disc == Discriminator::SwigConfigAccount as u8 && index != 0 => {
                    let first_account = accounts.get_unchecked(0).assume_init_ref();
                    let first_data = first_account.borrow_data_unchecked();

                    if first_account.owner() == &crate::ID
                        && first_data.len() >= 8
                        && *first_data.get_unchecked(0) == Discriminator::SwigConfigAccount as u8
                    {
                        Ok(AccountClassification::None)
                    } else {
                        Err(SwigError::InvalidAccountsSwigMustBeFirst.into())
                    }
                },
                _ => Ok(AccountClassification::None),
            }
        },
        &SYSTEM_PROGRAM_ID if index == 1 => {
            let first_account = accounts.get_unchecked(0).assume_init_ref();
            let first_data = first_account.borrow_data_unchecked();

            // When the account is the new Swig account structure, it's safe to assume the
            // account directly after will be the SwigWalletAddress. This is validated
            // further down in instructions relevant to the V2 account structure via signer
            // seeds.
            if first_account.owner() == &crate::ID
                && first_data.len() >= Swig::LEN
                && *first_data.get_unchecked(0) == Discriminator::SwigConfigAccount as u8
                && is_swig_v2(first_data)
            {
                return Ok(AccountClassification::SwigWalletAddress);
            }
            Ok(AccountClassification::None)
        },
        &STAKING_ID => {
            let data = account.borrow_data_unchecked();
            // Check if this is a stake account by checking the data
            if data.len() >= 200 && index > 0 {
                // Verify if this stake account belongs to the swig
                // First get the authorized withdrawer from the stake account data
                // In stake account data, the authorized withdrawer is at offset 44 (36 + 8) for
                // 32 bytes
                let authorized_withdrawer = unsafe { data.get_unchecked(44..76) };

                // Check if the withdrawer is the swig account
                if sol_memcmp(
                    accounts.get_unchecked(0).assume_init_ref().key(),
                    authorized_withdrawer,
                    32,
                ) == 0
                {
                    // Extract the stake state from the account
                    // The state enum is at offset 196 (36 + 8 + 32 + 32 + 8 + 8 + 32 + 4 + 8 + 16 +
                    // 8 + 4) for 4 bytes
                    let state_value = u32::from_le_bytes(
                        data.get_unchecked(196..200)
                            .try_into()
                            .map_err(|_| ProgramError::InvalidAccountData)?,
                    );

                    let state = match state_value {
                        0 => swig_state::StakeAccountState::Uninitialized,
                        1 => swig_state::StakeAccountState::Initialized,
                        2 => swig_state::StakeAccountState::Stake,
                        3 => swig_state::StakeAccountState::RewardsPool,
                        _ => return Err(ProgramError::InvalidAccountData),
                    };
                    // Extract the stake amount from the account
                    // The delegated stake amount is at offset 184 (36 + 8 + 32 + 32 + 8 + 8 + 32 +
                    // 4 + 8 + 16) for 8 bytes
                    let stake_amount = u64::from_le_bytes(
                        data.get_unchecked(184..192)
                            .try_into()
                            .map_err(|_| ProgramError::InvalidAccountData)?,
                    );

                    return Ok(AccountClassification::SwigStakeAccount {
                        state,
                        balance: stake_amount,
                        spent: 0,
                    });
                }
            }
            Ok(AccountClassification::None)
        },
        #[cfg(not(feature = "program_scope_test"))]
        &SPL_TOKEN_2022_ID | &SPL_TOKEN_ID if account.data_len() >= 165 && index > 0 => unsafe {
            let data = account.borrow_data_unchecked();
            let token_authority = data.get_unchecked(32..64);

            let matches_swig_account = sol_memcmp(
                accounts.get_unchecked(0).assume_init_ref().key(),
                token_authority,
                32,
            ) == 0;

            let matches_swig_wallet_address = if index > 1 {
                // Only check wallet address if account[1] is actually classified as
                // SwigWalletAddress
                if matches!(
                    account_classifications.get_unchecked(1).assume_init_ref(),
                    AccountClassification::SwigWalletAddress
                ) {
                    sol_memcmp(
                        accounts.get_unchecked(1).assume_init_ref().key(),
                        token_authority,
                        32,
                    ) == 0
                } else {
                    false
                }
            } else {
                false
            };

            if matches_swig_account || matches_swig_wallet_address {
                Ok(AccountClassification::SwigTokenAccount {
                    balance: u64::from_le_bytes(
                        data.get_unchecked(64..72)
                            .try_into()
                            .map_err(|_| ProgramError::InvalidAccountData)?,
                    ),
                    spent: 0,
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
                        let data = account.borrow_data_unchecked();
                        let balance = read_program_scope_account_balance(data, &program_scope)?;
                        return Ok(AccountClassification::ProgramScope {
                            role_index: role_id,
                            balance,
                            spent: 0,
                        });
                    }
                }
            }
            Ok(AccountClassification::None)
        },
    }
}
