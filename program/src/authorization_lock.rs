//! Authorization lock validation and enforcement.
//!
//! A lock reserves part of one wallet asset account: the swig wallet address
//! for native SOL, or one token account whose authority is the wallet address.
//! Locks follow card-authorization semantics:
//!
//! - Every role other than the lock's creator, including `All`, is held off
//!   the reserved funds. [`LockGuard`] enforces this around SignV2: an account
//!   may receive funds freely, but may not end a transaction below
//!   `min(balance_before, reserved by locks the signing role does not hold)`.
//! - The creating role may spend its own reserved funds. SignV2 then captures
//!   its locks on that account: their amounts drop by the account's net
//!   outflow, oldest lock first, never below zero. A lock captured to zero is
//!   inactive and may be pruned.
//! - Limits are charged when funds are spent, not when they are locked. After
//!   charging and capturing, a limited role's remaining locks must still fit
//!   what its limits let it spend ([`check_role_locks_within_limits`]).
//!
//! Every locked account in a SignV2, whoever signs, must keep the wallet as
//! its token authority with no delegate or foreign close authority.

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

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
    tail::authorization_locks::{
        self, record_at, AuthorizationLock, LockRecord, LOCK_LEN, MAX_AUTHORIZATION_LOCKS,
    },
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
/// A role's active locks must always fit within this amount, so it cannot hold
/// a reservation it could never spend.
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

        let (kind, amount) = match action.permission()? {
            Permission::SolLimit if native => (LimitKind::OneShot, load::<SolLimit>(data)?.amount),
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
                )
            },
            Permission::SolDestinationLimit if native => {
                let limit = load::<SolDestinationLimit>(data)?;
                (
                    LimitKind::Destination {
                        key: DestinationKey::Sol(limit.destination),
                        recurring: false,
                    },
                    limit.amount,
                )
            },
            Permission::SolRecurringDestinationLimit if native => {
                let limit = load::<SolRecurringDestinationLimit>(data)?;
                (
                    LimitKind::Destination {
                        key: DestinationKey::Sol(limit.destination),
                        recurring: true,
                    },
                    recurring_remaining(
                        limit.window,
                        limit.last_reset,
                        limit.recurring_amount,
                        limit.current_amount,
                        slot,
                    ),
                )
            },
            Permission::TokenLimit if !native => {
                let limit = load::<TokenLimit>(data)?;
                if &limit.token_mint != mint {
                    cursor = data_end;
                    continue;
                }
                (LimitKind::OneShot, limit.current_amount)
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
                )
            },
            Permission::TokenDestinationLimit if !native => {
                let limit = load::<TokenDestinationLimit>(data)?;
                if &limit.token_mint != mint {
                    cursor = data_end;
                    continue;
                }
                (
                    LimitKind::Destination {
                        key: DestinationKey::Token {
                            mint: limit.token_mint,
                            destination: limit.destination,
                        },
                        recurring: false,
                    },
                    limit.amount,
                )
            },
            Permission::TokenRecurringDestinationLimit if !native => {
                let limit = load::<TokenRecurringDestinationLimit>(data)?;
                if &limit.token_mint != mint {
                    cursor = data_end;
                    continue;
                }
                (
                    LimitKind::Destination {
                        key: DestinationKey::Token {
                            mint: limit.token_mint,
                            destination: limit.destination,
                        },
                        recurring: true,
                    },
                    recurring_remaining(
                        limit.window,
                        limit.last_reset,
                        limit.recurring_amount,
                        limit.current_amount,
                        slot,
                    ),
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
        match kind {
            LimitKind::OneShot => {
                one_shot.get_or_insert(amount);
            },
            LimitKind::Recurring => {
                recurring.get_or_insert(amount);
            },
            LimitKind::Destination { key, recurring } => {
                match destination_groups
                    .iter_mut()
                    .find(|(existing, _)| existing == &key)
                {
                    Some((_, group)) if recurring => {
                        group.recurring.get_or_insert(amount);
                    },
                    Some((_, group)) => {
                        group.one_shot.get_or_insert(amount);
                    },
                    None => destination_groups.push((
                        key,
                        DestinationPair {
                            one_shot: (!recurring).then_some(amount),
                            recurring: recurring.then_some(amount),
                        },
                    )),
                }
            },
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
/// let it spend. Callers run this after charging the role's limits (and, in
/// SignV2, after capturing its locks), so a role cannot keep reservations its
/// limits can no longer cover.
pub(crate) fn check_role_locks_within_limits(
    tail: &[u8],
    role_id: u32,
    actions: &[u8],
    slot: u64,
) -> Result<(), ProgramError> {
    let Some(range) = authorization_locks::records_range(tail)? else {
        return Ok(());
    };
    check_records_within_limits(&tail[range], role_id, actions, slot)
}

/// [`check_role_locks_within_limits`] over the packed lock records, in one
/// pass and without allocating.
#[inline(never)]
fn check_records_within_limits(
    records: &[u8],
    role_id: u32,
    actions: &[u8],
    slot: u64,
) -> Result<(), ProgramError> {
    // Per distinct mint: the record holding it and the role's active total.
    let mut mint_records = [0usize; MAX_AUTHORIZATION_LOCKS];
    let mut totals = [0u64; MAX_AUTHORIZATION_LOCKS];
    let mut mints = 0usize;
    for (index, bytes) in records.chunks_exact(LOCK_LEN).enumerate() {
        let lock = LockRecord::new(bytes).ok_or(ProgramError::InvalidAccountData)?;
        if lock.role_id() != role_id || !lock.is_active(slot) {
            continue;
        }
        let mint = lock.mint();
        let known = (0..mints).find(|&m| {
            record_at(records, mint_records[m]).is_some_and(|other| other.mint() == mint)
        });
        let m = match known {
            Some(m) => m,
            None => {
                if mints == MAX_AUTHORIZATION_LOCKS {
                    return Err(ProgramError::InvalidAccountData);
                }
                mint_records[mints] = index;
                mints += 1;
                mints - 1
            },
        };
        totals[m] = totals[m]
            .checked_add(lock.amount())
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }
    for m in 0..mints {
        let mint = record_at(records, mint_records[m])
            .ok_or(ProgramError::InvalidAccountData)?
            .mint();
        if totals[m] > remaining_spend_capacity(actions, mint, slot)? {
            return Err(SwigError::AuthorizationLockExceedsSpendLimit.into());
        }
    }
    Ok(())
}

enum LimitKind {
    OneShot,
    Recurring,
    /// A destination-scoped limit, keyed by what SignV2 matches it against.
    Destination {
        key: DestinationKey,
        recurring: bool,
    },
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

#[derive(Clone, Copy)]
struct GuardedAccount {
    /// Balance before execution, then the net outflow during settlement.
    before: u64,
    /// Sum of active locks held by roles other than the signer.
    reserved_by_others: u64,
    /// Id of the first lock seen on this account, stored at `record`.
    lock_id: u32,
    /// Index of the account in the instruction's accounts.
    index: u16,
    /// Index of that first lock among the packed records.
    record: u8,
    native: bool,
}

impl GuardedAccount {
    const EMPTY: Self = Self {
        before: 0,
        reserved_by_others: 0,
        lock_id: 0,
        index: 0,
        record: 0,
        native: false,
    };
}

/// One of the signer's active locks on a guarded account, in storage order.
#[derive(Clone, Copy)]
struct SignerLock {
    lock_id: u32,
    record: u8,
    /// Slot of the account in [`LockGuard::guarded`].
    account: u8,
}

impl SignerLock {
    const EMPTY: Self = Self {
        lock_id: 0,
        record: 0,
        account: 0,
    };
}

/// Pre-CPI snapshot of the active locks that matter to one SignV2: those on
/// writable accounts in the transaction, and whether the signer holds any.
/// Uses fixed-size arrays (a wallet stores at most
/// [`MAX_AUTHORIZATION_LOCKS`] locks) and keeps only the records' location in
/// the tail, so it parses the tail once and allocates at most once, only when
/// a lock matters to the transaction.
pub(crate) struct LockGuard {
    /// Byte range of the packed lock records within the config account data.
    records: core::ops::Range<usize>,
    /// Config account length at the snapshot. Settlement writes through the
    /// pre-CPI view of the config, so the account must not have been resized.
    config_len: usize,
    signer_has_active_locks: bool,
    guarded_len: usize,
    guarded: [GuardedAccount; MAX_AUTHORIZATION_LOCKS],
    signer_locks_len: usize,
    signer_locks: [SignerLock; MAX_AUTHORIZATION_LOCKS],
}

impl LockGuard {
    /// Snapshots the active locks on accounts that are present and writable
    /// in this transaction. Read-only and absent accounts cannot change, so
    /// they need no check. `signer_role_id` is the role SignV2 authenticated
    /// as: its own locks do not restrict it, and its spending captures them.
    ///
    /// Returns `None`, having done no further work, when the tail has no lock
    /// entry, or when no active lock is on a writable account here and the
    /// signer holds no active lock.
    #[inline(never)]
    pub(crate) fn snapshot(
        tail: &[u8],
        config: &AccountInfo,
        all_accounts: &[AccountInfo],
        wallet: &AccountInfo,
        slot: u64,
        signer_role_id: u32,
    ) -> Result<Option<&'static mut Self>, ProgramError> {
        let Some(range) = authorization_locks::records_range(tail)? else {
            return Ok(None);
        };
        let records = &tail[range.clone()];
        // Locate the records within the config account, so settlement needs
        // nothing from SignV2 but the account.
        let tail_start = (tail.as_ptr() as usize)
            .checked_sub(unsafe { config.borrow_data_unchecked() }.as_ptr() as usize)
            .ok_or(ProgramError::InvalidAccountData)?;
        // Built in this frame and moved to the heap only when needed: SignV2's
        // own frame has no room for it.
        let mut guard = Self {
            records: tail_start + range.start..tail_start + range.end,
            config_len: config.data_len(),
            signer_has_active_locks: false,
            guarded_len: 0,
            guarded: [GuardedAccount::EMPTY; MAX_AUTHORIZATION_LOCKS],
            signer_locks_len: 0,
            signer_locks: [SignerLock::EMPTY; MAX_AUTHORIZATION_LOCKS],
        };
        // Records whose asset account is absent or read-only here, so later
        // locks on the same asset skip the account scan.
        let mut skipped = [0usize; MAX_AUTHORIZATION_LOCKS];
        let mut skipped_len = 0usize;
        for (record, bytes) in records.chunks_exact(LOCK_LEN).enumerate() {
            let lock = LockRecord::new(bytes).ok_or(ProgramError::InvalidAccountData)?;
            let amount = lock.amount();
            if amount == 0 || lock.expiry_slot() <= slot {
                continue;
            }
            let is_signer = lock.role_id() == signer_role_id;
            guard.signer_has_active_locks |= is_signer;
            let asset = lock.asset_account();
            let account = match guard.guarded[..guard.guarded_len]
                .iter()
                .position(|g| all_accounts[g.index as usize].key() == asset)
            {
                Some(account) => account,
                None => {
                    if skipped[..skipped_len].iter().any(|&other| {
                        record_at(records, other).is_some_and(|o| o.asset_account() == asset)
                    }) {
                        continue;
                    }
                    let found = all_accounts
                        .iter()
                        .position(|account| account.key() == asset)
                        .filter(|&index| all_accounts[index].is_writable());
                    let Some(index) = found else {
                        skipped[skipped_len] = record;
                        skipped_len += 1;
                        continue;
                    };
                    let native = lock.is_native_sol();
                    let before = Self::balance(&all_accounts[index], native, lock.mint(), wallet)?;
                    guard.guarded[guard.guarded_len] = GuardedAccount {
                        before,
                        reserved_by_others: 0,
                        lock_id: lock.lock_id(),
                        index: u16::try_from(index).map_err(|_| ProgramError::InvalidArgument)?,
                        record: record as u8,
                        native,
                    };
                    guard.guarded_len += 1;
                    guard.guarded_len - 1
                },
            };
            if is_signer {
                guard.signer_locks[guard.signer_locks_len] = SignerLock {
                    lock_id: lock.lock_id(),
                    record: record as u8,
                    account: account as u8,
                };
                guard.signer_locks_len += 1;
            } else {
                let guarded = &mut guard.guarded[account];
                guarded.reserved_by_others = guarded
                    .reserved_by_others
                    .checked_add(amount)
                    .ok_or(ProgramError::ArithmeticOverflow)?;
            }
        }
        if guard.guarded_len == 0 && !guard.signer_has_active_locks {
            return Ok(None);
        }
        // Leaked rather than boxed: the program's bump allocator never frees,
        // and a plain reference adds no drop glue to SignV2's many exits.
        Ok(Some(Box::leak(Box::new(guard))))
    }

    /// Verifies that no locked account lost its identity or funds reserved by
    /// other roles, then captures the signer's locks in place in the config.
    ///
    /// Each account's net outflow (`before - after`, never negative; lamports
    /// for the wallet address) is taken off the signer's locks on it, oldest
    /// first, never below zero. Outflow beyond the signer's locks came from
    /// unreserved funds; the floor check already guarantees it did not touch
    /// other roles' reservations. Inflows never raise a lock. Only lowered
    /// amounts are written: the config is never resized, no lamports move, and
    /// inactive locks are left for RemoveAuthorizationLockV1 to prune.
    #[inline(never)]
    pub(crate) fn settle(
        &mut self,
        config: &AccountInfo,
        all_accounts: &[AccountInfo],
        wallet: &AccountInfo,
    ) -> Result<(), ProgramError> {
        if config.data_len() != self.config_len {
            return Err(SwigError::AccountDataModifiedUnexpectedly.into());
        }
        // SAFETY: SignV2 holds no other live borrow of the config's lock
        // records; it only reads them through this guard.
        let records = unsafe { config.borrow_mut_data_unchecked() }
            .get_mut(self.records.clone())
            .ok_or(SwigError::AccountDataModifiedUnexpectedly)?;
        let mut wallet_rent: Option<u64> = None;
        for guarded in &mut self.guarded[..self.guarded_len] {
            let lock = record_at(records, guarded.record as usize)
                .filter(|lock| lock.lock_id() == guarded.lock_id)
                .ok_or(SwigError::AccountDataModifiedUnexpectedly)?;
            let after = Self::balance(
                &all_accounts[guarded.index as usize],
                guarded.native,
                lock.mint(),
                wallet,
            )?;
            // Only an outflow can breach the floor, and only other roles'
            // locks set one, so most accounts need no further work.
            if after < guarded.before && guarded.reserved_by_others != 0 {
                let (after, before) = if guarded.native {
                    // Lamports above the rent-exempt minimum are what locks
                    // reserve; read the rent sysvar at most once.
                    let rent = match wallet_rent {
                        Some(rent) => rent,
                        None => *wallet_rent.insert(Rent::get()?.minimum_balance(0)),
                    };
                    (
                        after.saturating_sub(rent),
                        guarded.before.saturating_sub(rent),
                    )
                } else {
                    (after, guarded.before)
                };
                if after < before.min(guarded.reserved_by_others) {
                    return Err(SwigError::AuthorizationLockViolated.into());
                }
            }
            guarded.before = guarded.before.saturating_sub(after);
        }
        for signer_lock in &self.signer_locks[..self.signer_locks_len] {
            let outflow = &mut self.guarded[signer_lock.account as usize].before;
            if *outflow == 0 {
                continue;
            }
            let start = signer_lock.record as usize * LOCK_LEN;
            let record: &mut [u8; LOCK_LEN] = records
                .get_mut(start..start + LOCK_LEN)
                .and_then(|record| record.try_into().ok())
                .ok_or(SwigError::AccountDataModifiedUnexpectedly)?;
            let mut lock_id = [0u8; 4];
            lock_id.copy_from_slice(&record[authorization_locks::LOCK_ID]);
            if u32::from_le_bytes(lock_id) != signer_lock.lock_id {
                return Err(SwigError::AccountDataModifiedUnexpectedly.into());
            }
            let mut amount_bytes = [0u8; 8];
            amount_bytes.copy_from_slice(&record[authorization_locks::AMOUNT]);
            let amount = u64::from_le_bytes(amount_bytes);
            let take = amount.min(*outflow);
            if take == 0 {
                continue;
            }
            *outflow -= take;
            record[authorization_locks::AMOUNT].copy_from_slice(&(amount - take).to_le_bytes());
        }
        Ok(())
    }

    /// Fails when the signer's remaining active locks exceed what its limits
    /// still let it spend. Run after charging limits and [`Self::settle`],
    /// which has already written the captured amounts to the config.
    pub(crate) fn check_signer_within_limits(
        &self,
        config: &AccountInfo,
        signer_role_id: u32,
        actions: &[u8],
        slot: u64,
    ) -> Result<(), ProgramError> {
        if !self.signer_has_active_locks {
            return Ok(());
        }
        let records = unsafe { config.borrow_data_unchecked() }
            .get(self.records.clone())
            .ok_or(SwigError::AccountDataModifiedUnexpectedly)?;
        check_records_within_limits(records, signer_role_id, actions, slot)
    }

    /// The account's balance: raw lamports for the wallet address (the rent
    /// reserve is applied only where a floor needs it), or the token amount.
    /// Fails when the account no longer has the identity a lock requires.
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
            return Ok(account.lamports());
        }
        lockable_token_balance(account, mint, wallet.key(), true)
            .ok_or_else(|| SwigError::AuthorizationLockViolated.into())
    }
}
