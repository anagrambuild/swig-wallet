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

/// Byte offset of `Swig::wallet_bump`, the first byte of the window
/// [`is_swig_v2`] reads.
const WALLET_BUMP_OFFSET: usize = core::mem::offset_of!(Swig, wallet_bump);

// The window is exactly `wallet_bump ++ _padding`. Any field added after
// `_padding` must stay outside it: `sub_account_counter` is non-zero for a swig
// that has created a V2 sub-account, and including it would flip a live V2
// account back to being read as V1.
const _: () = {
    assert!(core::mem::offset_of!(Swig, _padding) == WALLET_BUMP_OFFSET + 1);
    assert!(core::mem::offset_of!(Swig, sub_account_counter) == WALLET_BUMP_OFFSET + 4);
};

/// Determines if a Swig account is v2 format from its wallet bump and the three
/// reserved bytes that follow it.
///
/// # Account Format Differences
///
/// **Swig V2** stores `wallet_bump: u8` followed by `_padding: [u8; 3]`. A
/// migrated account always has a non-zero bump and zeroed padding.
/// - Example bytes: `[253, 0, 0, 0]` where 253 is the bump seed
/// - Low byte non-zero, upper three zero ✓ → **V2 account**
///
/// **Swig V1** stored a `reserved_lamports: u64` starting at the same offset.
/// - A rent-carrying balance sets at least one of the upper three bytes
/// - Result: non-zero upper bytes ✓ → **V1 account**
///
/// # Why the counter is excluded
///
/// `sub_account_counter` occupies the four bytes after `_padding` and becomes
/// non-zero as soon as a V2 sub-account is created. The previous check read the
/// last eight bytes as a `u64` and required the upper seven to be zero, which
/// covered the counter — so creating a single sub-account permanently flipped a
/// V2 account to being read as V1.
///
/// # Known limits
///
/// This is a heuristic over bytes V1 used for a different purpose, so it is not
/// exact. A V1 account misreads as V2 when `reserved_lamports % 2^32` lands in
/// `1..=255`. The previous check was wrong for `reserved_lamports <= 255`,
/// including `0`, which is the more likely V1 state; this narrows the common
/// case at the cost of a wrap-around band around every 2^32 lamports. The only
/// caller, `close_token_account_v1`, tries the other authority as a fallback,
/// so a misread costs an extra comparison rather than correctness.
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
/// * `true` if the account is v2 format (non-zero bump, zeroed padding)
/// * `false` otherwise
#[inline(always)]
pub(crate) unsafe fn is_swig_v2(data: &[u8]) -> bool {
    // `wallet_bump ++ _padding` as one little-endian u32: bump in the low byte,
    // the three reserved bytes above it. Equivalent to
    // `wallet_bump != 0 && _padding == [0u8; 3]`, without a fallible load.
    let window = (data.as_ptr().add(WALLET_BUMP_OFFSET) as *const u32).read_unaligned();
    window & 0xFF != 0 && window >> 8 == 0
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
            // The withdrawer may be either the Swig config account (index 0) or
            // the Swig wallet address (index 1), which is the CPI signer for
            // SignV2. Both must classify so stake spending is accounted for.
            let authorized_withdrawer = data.get_unchecked(44..76);

            let matches_swig_account = sol_memcmp(
                accounts.get_unchecked(0).assume_init_ref().key(),
                authorized_withdrawer,
                32,
            ) == 0;

            let matches_swig_wallet_address = index > 1
                && matches!(
                    account_classifications.get_unchecked(1).assume_init_ref(),
                    AccountClassification::SwigWalletAddress
                )
                && sol_memcmp(
                    accounts.get_unchecked(1).assume_init_ref().key(),
                    authorized_withdrawer,
                    32,
                ) == 0;

            if !matches_swig_account && !matches_swig_wallet_address {
                return Ok(AccountClassification::None);
            }

            // `StakeStateV2` is bincode: the state discriminant is the leading
            // u32 and the delegated stake amount sits at 156..164, inside the
            // Delegation struct.
            let state_value = u32::from_le_bytes(
                data.get_unchecked(0..4)
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
                data.get_unchecked(156..164)
                    .try_into()
                    .map_err(|_| ProgramError::InvalidAccountData)?,
            );

            Ok(AccountClassification::SwigStakeAccount {
                state,
                balance: stake_amount,
                lamports: account.lamports(),
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

    /// Serializes a Swig header with the given wallet bump and V2 sub-account
    /// counter.
    fn swig_header_bytes(wallet_bump: u8, sub_account_counter: u32) -> Vec<u8> {
        use swig_state::IntoBytes;

        let mut swig = Swig::new([7u8; 32], 254, wallet_bump);
        swig.sub_account_counter = sub_account_counter;
        swig.into_bytes().unwrap().to_vec()
    }

    /// Overlays a V1 `reserved_lamports: u64` over the bump+padding window.
    fn v1_header_bytes(reserved_lamports: u64) -> Vec<u8> {
        let mut data = swig_header_bytes(0, 0);
        data[WALLET_BUMP_OFFSET..WALLET_BUMP_OFFSET + 8]
            .copy_from_slice(&reserved_lamports.to_le_bytes());
        data
    }

    #[test]
    fn is_swig_v2_accepts_migrated_account() {
        assert!(unsafe { is_swig_v2(&swig_header_bytes(253, 0)) });
    }

    /// Regression: `sub_account_counter` reuses former padding, so it must sit
    /// outside the window `is_swig_v2` reads. Creating a V2 sub-account must
    /// not flip a migrated account back to being read as V1.
    #[test]
    fn is_swig_v2_ignores_sub_account_counter() {
        for counter in [1u32, 2, 255, 256, 65_536, u32::MAX] {
            assert!(
                unsafe { is_swig_v2(&swig_header_bytes(253, counter)) },
                "counter {counter} must not affect v2 detection"
            );
        }
    }

    /// A rent-carrying V1 `reserved_lamports` sets the upper window bytes.
    #[test]
    fn is_swig_v2_rejects_v1_reserved_lamports() {
        for reserved_lamports in [256u64, 890_880, 1_392_000, 2_039_280, 1u64 << 32, u64::MAX] {
            assert!(
                !unsafe { is_swig_v2(&v1_header_bytes(reserved_lamports)) },
                "reserved_lamports {reserved_lamports} must read as v1"
            );
        }
    }

    /// An unmigrated account with a zero bump is V1. The previous last-8-bytes
    /// check read this as V2.
    #[test]
    fn is_swig_v2_rejects_zero_wallet_bump() {
        assert!(!unsafe { is_swig_v2(&v1_header_bytes(0)) });
        assert!(!unsafe { is_swig_v2(&swig_header_bytes(0, 0)) });
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
