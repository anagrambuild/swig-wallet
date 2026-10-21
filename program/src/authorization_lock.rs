//! Authorization lock validation and enforcement.
//!
//! A lock reserves part of one wallet asset account: the swig wallet address
//! for native SOL, or one token account whose authority is the wallet address.
//! [`LockGuard`] enforces active locks around SignV2 execution for every role,
//! including `All`: an account may receive funds freely, but may not end a
//! transaction below `min(balance_before, reserved)`, and a locked token account
//! must keep the wallet as its authority with no delegate or foreign close
//! authority.

extern crate alloc;
use alloc::vec::Vec;

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{rent::Rent, Sysvar},
};
use swig_state::{
    action::{
        sol_destination_limit::SolDestinationLimit, sol_limit::SolLimit,
        sol_recurring_destination_limit::SolRecurringDestinationLimit,
        sol_recurring_limit::SolRecurringLimit, token_destination_limit::TokenDestinationLimit,
        token_limit::TokenLimit, token_recurring_destination_limit::TokenRecurringDestinationLimit,
        token_recurring_limit::TokenRecurringLimit, Action, Permission,
    },
    tail::authorization_locks::{self, AuthorizationLock},
    Transmutable,
};

use crate::{error::SwigError, SPL_TOKEN_2022_ID, SPL_TOKEN_ID};

const TOKEN_ACCOUNT_LEN: usize = 165;
const TOKEN_MINT: core::ops::Range<usize> = 0..32;
const TOKEN_AUTHORITY: core::ops::Range<usize> = 32..64;
const TOKEN_AMOUNT: core::ops::Range<usize> = 64..72;
const TOKEN_DELEGATE_TAG: core::ops::Range<usize> = 72..76;
const TOKEN_STATE: usize = 108;
const TOKEN_CLOSE_AUTHORITY_TAG: core::ops::Range<usize> = 129..133;
const TOKEN_CLOSE_AUTHORITY: core::ops::Range<usize> = 133..165;
const TOKEN_STATE_INITIALIZED: u8 = 1;
const TOKEN_STATE_FROZEN: u8 = 2;
const TOKEN_2022_ACCOUNT_TYPE_INDEX: usize = TOKEN_ACCOUNT_LEN;
const TOKEN_2022_ACCOUNT_TYPE_ACCOUNT: u8 = 2;
const COPTION_NONE: [u8; 4] = [0; 4];
const COPTION_SOME: [u8; 4] = [1, 0, 0, 0];

/// Returns the native SOL the wallet address can reserve: lamports above the
/// rent-exempt minimum that SignV2 always preserves.
pub(crate) fn lockable_lamports(wallet: &AccountInfo) -> Result<u64, ProgramError> {
    Ok(wallet
        .lamports()
        .saturating_sub(Rent::get()?.minimum_balance(0)))
}

/// Returns the balance of a token account that can carry a lock, or `None`
/// when the account is not a token account of `mint` controlled solely by
/// `wallet`. New locks require an initialized account; the SignV2 guard also
/// accepts a frozen one, since a mint's freeze authority can freeze and thaw a
/// locked account at will and the reservation must hold either way.
pub(crate) fn lockable_token_balance(
    account: &AccountInfo,
    mint: &[u8; 32],
    wallet: &Pubkey,
    allow_frozen: bool,
) -> Option<u64> {
    let owner = account.owner();
    if owner != &SPL_TOKEN_ID && owner != &SPL_TOKEN_2022_ID {
        return None;
    }
    let data = unsafe { account.borrow_data_unchecked() };
    if data.len() < TOKEN_ACCOUNT_LEN || (owner == &SPL_TOKEN_ID && data.len() != TOKEN_ACCOUNT_LEN)
    {
        return None;
    }
    if data.len() > TOKEN_ACCOUNT_LEN
        && data[TOKEN_2022_ACCOUNT_TYPE_INDEX] != TOKEN_2022_ACCOUNT_TYPE_ACCOUNT
    {
        return None;
    }
    let state_ok = data[TOKEN_STATE] == TOKEN_STATE_INITIALIZED
        || (allow_frozen && data[TOKEN_STATE] == TOKEN_STATE_FROZEN);
    if data[TOKEN_MINT] != mint[..]
        || data[TOKEN_AUTHORITY] != wallet[..]
        || !state_ok
        || data[TOKEN_DELEGATE_TAG] != COPTION_NONE
    {
        return None;
    }
    let close_authority_tag = &data[TOKEN_CLOSE_AUTHORITY_TAG];
    let close_authority_ok = close_authority_tag == COPTION_NONE
        || (close_authority_tag == COPTION_SOME && data[TOKEN_CLOSE_AUTHORITY] == wallet[..]);
    if !close_authority_ok {
        return None;
    }
    Some(u64::from_le_bytes(
        data[TOKEN_AMOUNT].try_into().expect("fixed-size field"),
    ))
}

const MINT_BASE_LEN: usize = 82;
const TOKEN_2022_ACCOUNT_TYPE_MINT: u8 = 1;
const EXTENSION_PERMANENT_DELEGATE: u16 = 12;

/// Rejects Token-2022 mints whose extensions let a third party move tokens out
/// of any holder's account. A permanent delegate can debit a locked account
/// without the wallet's signature, so a lock on such a mint guarantees nothing.
pub(crate) fn check_lockable_mint(
    asset_account: &AccountInfo,
    mint_account: Option<&AccountInfo>,
    mint: &[u8; 32],
) -> Result<(), ProgramError> {
    if asset_account.owner() != &SPL_TOKEN_2022_ID {
        return Ok(());
    }
    let mint_account = mint_account.ok_or(SwigError::InvalidAuthorizationLockAsset)?;
    if mint_account.key() != mint || mint_account.owner() != &SPL_TOKEN_2022_ID {
        return Err(SwigError::InvalidAuthorizationLockAsset.into());
    }
    let data = unsafe { mint_account.borrow_data_unchecked() };
    if data.len() == MINT_BASE_LEN {
        return Ok(());
    }
    if data.len() <= TOKEN_2022_ACCOUNT_TYPE_INDEX
        || data[TOKEN_2022_ACCOUNT_TYPE_INDEX] != TOKEN_2022_ACCOUNT_TYPE_MINT
    {
        return Err(SwigError::InvalidAuthorizationLockAsset.into());
    }
    let mut cursor = TOKEN_2022_ACCOUNT_TYPE_INDEX + 1;
    while cursor + 4 <= data.len() {
        let extension = u16::from_le_bytes([data[cursor], data[cursor + 1]]);
        let len = u16::from_le_bytes([data[cursor + 2], data[cursor + 3]]) as usize;
        if extension == EXTENSION_PERMANENT_DELEGATE {
            return Err(SwigError::InvalidAuthorizationLockAsset.into());
        }
        if extension == 0 {
            break;
        }
        cursor = cursor
            .checked_add(4 + len)
            .ok_or(SwigError::InvalidAuthorizationLockAsset)?;
    }
    Ok(())
}

/// Returns how much of `mint` the role's limit actions would let it spend at
/// `slot`. A role without any applicable limit has no capacity, so it cannot
/// reserve an asset it could never capture.
///
/// A role's active locks must always fit within this amount: the creator's
/// limits back its reservations, so it cannot lock more than it may spend nor
/// spend what it has reserved.
///
/// SignV2 charges one general limit (one-shot before recurring) and, when
/// destination limits exist, requires every debit to also match one, so the
/// capacity is the smaller of the two. Recurring limits count what is left in
/// the current window, or the full allowance once SignV2 would reset it.
pub(crate) fn remaining_spend_capacity(
    actions: &[u8],
    mint: &[u8; 32],
    slot: u64,
) -> Result<u64, ProgramError> {
    let native = mint == &authorization_locks::NATIVE_SOL_MINT;
    let mut one_shot: Option<u64> = None;
    let mut recurring: Option<u64> = None;
    let mut destination_groups: Vec<(DestinationKey, DestinationPair)> = Vec::new();
    let mut cursor = 0usize;
    while cursor < actions.len() {
        let header_end = cursor
            .checked_add(Action::LEN)
            .ok_or(ProgramError::InvalidAccountData)?;
        let header = actions
            .get(cursor..header_end)
            .ok_or(ProgramError::InvalidAccountData)?;
        let action = unsafe { Action::load_unchecked(header)? };
        let data_end = header_end
            .checked_add(action.length() as usize)
            .ok_or(ProgramError::InvalidAccountData)?;
        let data = actions
            .get(header_end..data_end)
            .ok_or(ProgramError::InvalidAccountData)?;

        let (kind, amount, destination_key) = match action.permission()? {
            Permission::SolLimit if native => {
                (LimitKind::OneShot, load::<SolLimit>(data)?.amount, None)
            },
            Permission::SolRecurringLimit if native => {
                let limit = load::<SolRecurringLimit>(data)?;
                (
                    LimitKind::Recurring,
                    recurring_remaining(
                        limit.window,
                        limit.last_reset,
                        limit.recurring_amount,
                        limit.current_amount,
                        slot,
                    ),
                    None,
                )
            },
            Permission::SolDestinationLimit if native => {
                let limit = load::<SolDestinationLimit>(data)?;
                (
                    LimitKind::Destination,
                    limit.amount,
                    Some(DestinationKey::Sol(limit.destination)),
                )
            },
            Permission::SolRecurringDestinationLimit if native => {
                let limit = load::<SolRecurringDestinationLimit>(data)?;
                (
                    LimitKind::Destination,
                    recurring_remaining(
                        limit.window,
                        limit.last_reset,
                        limit.recurring_amount,
                        limit.current_amount,
                        slot,
                    ),
                    Some(DestinationKey::Sol(limit.destination)),
                )
            },
            Permission::TokenLimit if !native => {
                let limit = load::<TokenLimit>(data)?;
                if &limit.token_mint != mint {
                    cursor = data_end;
                    continue;
                }
                (LimitKind::OneShot, limit.current_amount, None)
            },
            Permission::TokenRecurringLimit if !native => {
                let limit = load::<TokenRecurringLimit>(data)?;
                if &limit.token_mint != mint {
                    cursor = data_end;
                    continue;
                }
                (
                    LimitKind::Recurring,
                    recurring_remaining(
                        limit.window,
                        limit.last_reset,
                        limit.limit,
                        limit.current,
                        slot,
                    ),
                    None,
                )
            },
            Permission::TokenDestinationLimit if !native => {
                let limit = load::<TokenDestinationLimit>(data)?;
                if &limit.token_mint != mint {
                    cursor = data_end;
                    continue;
                }
                (
                    LimitKind::Destination,
                    limit.amount,
                    Some(DestinationKey::Token {
                        mint: limit.token_mint,
                        destination: limit.destination,
                    }),
                )
            },
            Permission::TokenRecurringDestinationLimit if !native => {
                let limit = load::<TokenRecurringDestinationLimit>(data)?;
                if &limit.token_mint != mint {
                    cursor = data_end;
                    continue;
                }
                (
                    LimitKind::Destination,
                    recurring_remaining(
                        limit.window,
                        limit.last_reset,
                        limit.recurring_amount,
                        limit.current_amount,
                        slot,
                    ),
                    Some(DestinationKey::Token {
                        mint: limit.token_mint,
                        destination: limit.destination,
                    }),
                )
            },
            _ => {
                cursor = data_end;
                continue;
            },
        };

        // SignV2 charges the first matching action of each general type. For
        // destination limits it charges the first regular and first recurring
        // action matching the same destination key, so a debit must fit within
        // whichever of the two types is present, and a pair's debit drains
        // both ledgers.
        match (kind, destination_key) {
            (LimitKind::OneShot, _) => {
                one_shot.get_or_insert(amount);
            },
            (LimitKind::Recurring, _) => {
                recurring.get_or_insert(amount);
            },
            (LimitKind::Destination, Some(key)) => {
                let is_recurring_limit = matches!(
                    action.permission()?,
                    Permission::SolRecurringDestinationLimit
                        | Permission::TokenRecurringDestinationLimit
                );
                match destination_groups
                    .iter_mut()
                    .find(|(existing, ..)| existing == &key)
                {
                    Some((_, group)) => {
                        if is_recurring_limit {
                            group.recurring.get_or_insert(amount);
                        } else {
                            group.one_shot.get_or_insert(amount);
                        }
                    },
                    None => destination_groups.push((
                        key,
                        DestinationPair {
                            one_shot: if is_recurring_limit {
                                None
                            } else {
                                Some(amount)
                            },
                            recurring: if is_recurring_limit {
                                Some(amount)
                            } else {
                                None
                            },
                        },
                    )),
                }
            },
            (LimitKind::Destination, None) => unreachable!(),
        }
        cursor = data_end;
    }

    // Per destination key, the debit must fit within both present limit types,
    // so a pair's window capacity is whichever twin is smaller; defaulting the
    // absent twin to u64::MAX keeps that minimum equal to whichever exists.
    let destination = if destination_groups.is_empty() {
        None
    } else {
        Some(
            destination_groups
                .iter()
                .map(|(_, group)| {
                    group
                        .one_shot
                        .unwrap_or(u64::MAX)
                        .min(group.recurring.unwrap_or(u64::MAX))
                })
                .fold(0u64, |total, cap| total.saturating_add(cap)),
        )
    };

    // A general one-shot and a general recurring limit for the same mint are
    // also a pair: SignV2 charges both, so the general window capacity is
    // whichever twin is smaller (defaulting the absent twin to u64::MAX).
    let general = match (one_shot, recurring) {
        (Some(one), Some(recur)) => Some(one.min(recur)),
        (one, recur) => one.or(recur),
    };

    Ok(match (general, destination) {
        (Some(g), Some(d)) => g.min(d),
        (Some(g), None) => g,
        (None, Some(d)) => d,
        (None, None) => 0,
    })
}

/// Mirrors the recurring limits' `run`: the allowance refreshes once more than
/// `window` slots have passed since `last_reset`. A zero window never permits
/// spending.
fn recurring_remaining(window: u64, last_reset: u64, full: u64, current: u64, slot: u64) -> u64 {
    if window == 0 {
        0
    } else if slot.saturating_sub(last_reset) > window {
        full
    } else {
        current
    }
}

/// Fails when the role's active locks on any mint exceed what its limits still
/// let it spend. SignV2 runs this after charging the role's limits, so a role
/// can neither spend the allowance backing its reservations nor keep locks its
/// limits can no longer cover.
#[inline(never)]
pub(crate) fn check_role_locks_within_limits(
    tail: &[u8],
    role_id: u32,
    actions: &[u8],
    slot: u64,
) -> Result<(), ProgramError> {
    let Some(entry) = authorization_locks::read(tail)? else {
        return Ok(());
    };
    let mut checked: Vec<[u8; 32]> = Vec::new();
    for lock in entry
        .iter()
        .filter(|lock| lock.role_id == role_id && lock.is_active(slot))
    {
        if checked.contains(&lock.mint) {
            continue;
        }
        checked.push(lock.mint);
        let reserved = sum_active(entry.iter(), slot, |other| {
            other.role_id == role_id && other.mint == lock.mint
        })?;
        if reserved > remaining_spend_capacity(actions, &lock.mint, slot)? {
            return Err(SwigError::AuthorizationLockExceedsSpendLimit.into());
        }
    }
    Ok(())
}

enum LimitKind {
    OneShot,
    Recurring,
    Destination,
}

/// Identifies the destination a destination-limit action reserves capacity
/// for: the destination pubkey for SOL limits, or the mint + destination
/// token account pair for token limits. Keys are only compared within one
/// capacity call, which is scoped to a single mint (native or one token), so
/// a collision between the two families cannot happen.
#[derive(PartialEq)]
enum DestinationKey {
    Sol([u8; 32]),
    Token {
        mint: [u8; 32],
        destination: [u8; 32],
    },
}

/// The first regular (one-shot) and recurring destination-limit amounts for
/// one destination key, mirroring which actions SignV2 charges.
struct DestinationPair {
    one_shot: Option<u64>,
    recurring: Option<u64>,
}

fn load<T: Transmutable>(data: &[u8]) -> Result<&T, ProgramError> {
    if data.len() != T::LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    unsafe { T::load_unchecked(data) }
}

/// Sums active lock amounts matching `filter`.
pub(crate) fn sum_active<F>(
    locks: impl Iterator<Item = AuthorizationLock>,
    slot: u64,
    filter: F,
) -> Result<u64, ProgramError>
where
    F: Fn(&AuthorizationLock) -> bool,
{
    let mut total = 0u64;
    for lock in locks.filter(|lock| lock.is_active(slot) && filter(lock)) {
        total = total
            .checked_add(lock.amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }
    Ok(total)
}

struct GuardedAccount {
    index: usize,
    native: bool,
    mint: [u8; 32],
    reserved: u64,
    before: u64,
}

/// Pre-CPI snapshot of every writable account that carries an active lock.
pub(crate) struct LockGuard {
    accounts: Vec<GuardedAccount>,
}

impl LockGuard {
    /// Captures the locked accounts present and writable in this transaction.
    /// Read-only and absent accounts cannot change, so they need no check.
    #[inline(never)]
    pub(crate) fn capture(
        tail: &[u8],
        all_accounts: &[AccountInfo],
        wallet: &AccountInfo,
        slot: u64,
    ) -> Result<Option<Self>, ProgramError> {
        let Some(entry) = authorization_locks::read(tail)? else {
            return Ok(None);
        };
        let mut accounts: Vec<GuardedAccount> = Vec::new();
        for lock in entry.iter().filter(|lock| lock.is_active(slot)) {
            if let Some(guarded) = accounts
                .iter_mut()
                .find(|g| all_accounts[g.index].key() == &lock.asset_account)
            {
                guarded.reserved = guarded
                    .reserved
                    .checked_add(lock.amount)
                    .ok_or(ProgramError::ArithmeticOverflow)?;
                continue;
            }
            let Some(index) = all_accounts
                .iter()
                .position(|account| account.key() == &lock.asset_account)
            else {
                continue;
            };
            if !all_accounts[index].is_writable() {
                continue;
            }
            let native = lock.is_native_sol();
            let before = Self::balance(&all_accounts[index], native, &lock.mint, wallet)?;
            accounts.push(GuardedAccount {
                index,
                native,
                mint: lock.mint,
                reserved: lock.amount,
                before,
            });
        }
        if accounts.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self { accounts }))
    }

    /// Verifies that no locked account lost reserved funds or its identity.
    #[inline(never)]
    pub(crate) fn validate(
        &self,
        all_accounts: &[AccountInfo],
        wallet: &AccountInfo,
    ) -> Result<(), ProgramError> {
        for guarded in &self.accounts {
            let after = Self::balance(
                &all_accounts[guarded.index],
                guarded.native,
                &guarded.mint,
                wallet,
            )?;
            if after < guarded.before.min(guarded.reserved) {
                return Err(SwigError::AuthorizationLockViolated.into());
            }
        }
        Ok(())
    }

    fn balance(
        account: &AccountInfo,
        native: bool,
        mint: &[u8; 32],
        wallet: &AccountInfo,
    ) -> Result<u64, ProgramError> {
        if native {
            if account.key() != wallet.key() {
                return Err(SwigError::AuthorizationLockViolated.into());
            }
            return lockable_lamports(account);
        }
        lockable_token_balance(account, mint, wallet.key(), true)
            .ok_or_else(|| SwigError::AuthorizationLockViolated.into())
    }
}
