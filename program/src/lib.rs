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
use swig_compact_instructions::MAX_ACCOUNTS;
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
    validate_entry_account_count(ctx.remaining())?;

    // These are capacity buffers. `execute` initializes only the consumed
    // `0..index` prefix before passing slices to the action handlers.
    let mut accounts =
        unsafe { Box::<[MaybeUninit<AccountInfo>; MAX_ACCOUNTS]>::new_uninit().assume_init() };
    let mut classifiers = unsafe {
        Box::<[MaybeUninit<AccountClassification>; MAX_ACCOUNTS]>::new_uninit().assume_init()
    };
    unsafe {
        execute(&mut ctx, accounts.as_mut(), classifiers.as_mut())?;
    }
    Ok(())
}

#[inline(always)]
fn validate_entry_account_count(account_count: u64) -> ProgramResult {
    if account_count > MAX_ACCOUNTS as u64 {
        return Err(SwigError::InvalidAccountsLength.into());
    }

    Ok(())
}

#[inline(always)]
fn validate_account_capacity(
    end: usize,
    accounts_len: usize,
    account_classification_len: usize,
) -> ProgramResult {
    if end > accounts_len || end > account_classification_len {
        return Err(SwigError::InvalidAccountsLength.into());
    }

    Ok(())
}

#[inline(always)]
fn validated_duplicate_account_index(
    account_index: u8,
    current_index: usize,
) -> Result<usize, ProgramError> {
    let account_index = account_index as usize;
    if account_index >= current_index {
        return Err(SwigError::InvalidAccountsLength.into());
    }

    Ok(account_index)
}

#[inline(always)]
unsafe fn is_swig_config_account(account: &AccountInfo) -> bool {
    if account.owner() != &crate::ID {
        return false;
    }

    let data = account.borrow_data_unchecked();
    data.len() >= Swig::LEN && *data.get_unchecked(0) == Discriminator::SwigConfigAccount as u8
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
pub(crate) unsafe fn is_swig_v2(data: &[u8]) -> bool {
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
#[inline(never)]
unsafe fn execute(
    ctx: &mut InstructionContext,
    accounts: &mut [MaybeUninit<AccountInfo>],
    account_classification: &mut [MaybeUninit<AccountClassification>],
) -> Result<(), ProgramError> {
    let acc = ctx
        .next_account()
        .map_err(|_| SwigError::InvalidAccountsLength)?;

    match acc {
        MaybeAccount::Account(account) => {
            let classification =
                classify_account(0, &account, accounts, account_classification, None)?;
            account_classification[0].write(classification);
            accounts[0].write(account);
        },
        MaybeAccount::Duplicated(_) => return Err(SwigError::InvalidAccountsLength.into()),
    }
    let mut index: usize = 1;

    let first_account = accounts[0].assume_init_ref();
    // Non-Swig first accounts are valid for instructions that do not use the
    // SignV2 account layout, so absence of a cache is not an error here.
    let program_scope_cache = if is_swig_config_account(first_account) {
        let data = first_account.borrow_data_unchecked();
        ProgramScopeCache::load_from_swig(data)
    } else {
        None
    };

    let remaining_accounts =
        usize::try_from(ctx.remaining()).map_err(|_| SwigError::InvalidAccountsLength)?;
    let end = index
        .checked_add(remaining_accounts)
        .ok_or(SwigError::InvalidAccountsLength)?;
    validate_account_capacity(end, accounts.len(), account_classification.len())?;

    // Process the remaining known account count using the program-scope cache.
    for _ in 0..remaining_accounts {
        let acc = ctx
            .next_account()
            .map_err(|_| SwigError::InvalidAccountsLength)?;
        let (account, classification) = match acc {
            MaybeAccount::Account(account) => {
                let classification = classify_account(
                    index,
                    &account,
                    accounts,
                    account_classification,
                    program_scope_cache.as_ref(),
                )?;
                (account, classification)
            },
            MaybeAccount::Duplicated(account_index) => {
                let account_index = validated_duplicate_account_index(account_index, index)?;
                let account = accounts[account_index].assume_init_ref().clone();
                let classification = classify_account(
                    index,
                    &account,
                    accounts,
                    account_classification,
                    program_scope_cache.as_ref(),
                )?;
                (account, classification)
            },
        };
        account_classification[index].write(classification);
        accounts[index].write(account);
        index += 1;
    }

    // Only the consumed prefix of the scratch buffers has been initialized.
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
    match account.owner() {
        &crate::ID => {
            if !is_swig_config_account(account) {
                return Ok(AccountClassification::None);
            }

            if index == 0 {
                return Ok(AccountClassification::ThisSwigV2 {
                    lamports: account.lamports(),
                });
            }

            let first_account = accounts.get_unchecked(0).assume_init_ref();
            if is_swig_config_account(first_account) {
                Ok(AccountClassification::None)
            } else {
                Err(SwigError::InvalidAccountsSwigMustBeFirst.into())
            }
        },
        &SYSTEM_PROGRAM_ID if index == 1 => {
            let first_account = accounts.get_unchecked(0).assume_init_ref();

            // When the account is a Swig account, it's safe to assume the
            // account directly after will be the SwigWalletAddress. This is validated
            // further down in instructions relevant to the account structure via signer
            // seeds.
            if is_swig_config_account(first_account) {
                return Ok(AccountClassification::SwigWalletAddress);
            }
            Ok(AccountClassification::None)
        },
        &STAKING_ID => {
            if index == 0 {
                return Ok(AccountClassification::None);
            }

            let data = account.borrow_data_unchecked();
            if data.len() < 200 {
                return Ok(AccountClassification::None);
            }

            // Stake account authorized withdrawer is at offset 44 for 32 bytes.
            let authorized_withdrawer = data.get_unchecked(44..76);
            if sol_memcmp(
                accounts.get_unchecked(0).assume_init_ref().key(),
                authorized_withdrawer,
                32,
            ) != 0
            {
                return Ok(AccountClassification::None);
            }

            // Stake state is at offset 196; delegated stake amount is at 184.
            let state_value = u32::from_le_bytes(
                data.get_unchecked(196..200)
                    .try_into()
                    .map_err(|_| ProgramError::InvalidAccountData)?,
            );
            let state = match state_value {
                0 => StakeAccountState::Uninitialized,
                1 => StakeAccountState::Initialized,
                2 => StakeAccountState::Stake,
                3 => StakeAccountState::RewardsPool,
                _ => return Err(ProgramError::InvalidAccountData),
            };
            let stake_amount = u64::from_le_bytes(
                data.get_unchecked(184..192)
                    .try_into()
                    .map_err(|_| ProgramError::InvalidAccountData)?,
            );

            Ok(AccountClassification::SwigStakeAccount {
                state,
                balance: stake_amount,
                spent: 0,
            })
        },
        #[cfg(not(feature = "program_scope_test"))]
        &SPL_TOKEN_2022_ID | &SPL_TOKEN_ID if index > 0 && account.data_len() >= 165 => {
            let data = account.borrow_data_unchecked();
            let token_authority = data.get_unchecked(32..64);

            let matches_swig_account = sol_memcmp(
                accounts.get_unchecked(0).assume_init_ref().key(),
                token_authority,
                32,
            ) == 0;

            let matches_swig_wallet_address = index > 1
                && matches!(
                    account_classifications.get_unchecked(1).assume_init_ref(),
                    AccountClassification::SwigWalletAddress
                )
                && sol_memcmp(
                    accounts.get_unchecked(1).assume_init_ref().key(),
                    token_authority,
                    32,
                ) == 0;

            if !matches_swig_account && !matches_swig_wallet_address {
                return Ok(AccountClassification::None);
            }

            Ok(AccountClassification::SwigTokenAccount {
                balance: u64::from_le_bytes(
                    data.get_unchecked(64..72)
                        .try_into()
                        .map_err(|_| ProgramError::InvalidAccountData)?,
                ),
                spent: 0,
            })
        },
        _ => {
            if index == 0 {
                return Ok(AccountClassification::None);
            }

            let Some(cache) = program_scope_cache else {
                return Ok(AccountClassification::None);
            };
            let Some((role_id, program_scope)) = cache.find_program_scope(account.key().as_ref())
            else {
                return Ok(AccountClassification::None);
            };

            let data = account.borrow_data_unchecked();
            let balance = read_program_scope_account_balance(data, &program_scope)?;
            Ok(AccountClassification::ProgramScope {
                role_index: role_id,
                balance,
                spent: 0,
            })
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_invalid_accounts_length(result: Result<(), ProgramError>) {
        assert!(matches!(
            result,
            Err(ProgramError::Custom(code)) if code == SwigError::InvalidAccountsLength as u32
        ));
    }

    #[test]
    fn validate_entry_account_count_accepts_max_accounts() {
        assert!(validate_entry_account_count(MAX_ACCOUNTS as u64).is_ok());
    }

    #[test]
    fn validate_entry_account_count_rejects_more_than_max_accounts() {
        assert_invalid_accounts_length(validate_entry_account_count(MAX_ACCOUNTS as u64 + 1));
    }

    #[test]
    fn validate_account_capacity_rejects_array_capacity_overflow() {
        assert_invalid_accounts_length(validate_account_capacity(4, 3, 4));
        assert_invalid_accounts_length(validate_account_capacity(4, 4, 3));
    }

    #[test]
    fn validated_duplicate_account_index_requires_prior_account() {
        assert_eq!(validated_duplicate_account_index(0, 1).unwrap(), 0);
        assert!(matches!(
            validated_duplicate_account_index(1, 1),
            Err(ProgramError::Custom(code)) if code == SwigError::InvalidAccountsLength as u32
        ));
        assert!(matches!(
            validated_duplicate_account_index(2, 1),
            Err(ProgramError::Custom(code)) if code == SwigError::InvalidAccountsLength as u32
        ));
    }
}
