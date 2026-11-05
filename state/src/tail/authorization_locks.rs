//! Authorization-lock tail entry.
//!
//! An authorization lock reserves `amount` of one wallet asset account until
//! `expiry_slot`, like a card authorization hold. The asset account is either
//! the swig wallet address (native SOL, `mint == NATIVE_SOL_MINT`) or one SPL
//! Token / Token-2022 account owned by the swig wallet address. While a lock is
//! active, SignV2 rejects transactions by any other role that move that
//! account's balance below the amount reserved by locks that role does not
//! hold, regardless of its permissions. The creating role may spend its own
//! reserved funds; SignV2 then captures its locks by lowering `amount` by the
//! account's net outflow, oldest lock first. A lock captured down to zero
//! stays stored, inactive, until it is removed.
//!
//! The entry is a single typed tail record whose value is a packed array of
//! [`AuthorizationLock`] records. The header's 4-byte payload stores the next
//! lock id, so ids are never reused within a wallet. Records are parsed by
//! value because the tail starts at the (unaligned) end of the roles region.

use core::convert::TryInto;

use pinocchio::program_error::ProgramError;

use crate::{
    tail::{
        read_first_of, AnyTailEntry, TailDescriptor, TailHeader, TailKind, TailReadError,
        TAIL_HEADER_LEN,
    },
    SwigStateError,
};

extern crate alloc;
use alloc::vec::Vec;

pub const VERSION: u8 = 1;
/// Serialized size of one [`AuthorizationLock`].
pub const LOCK_LEN: usize = 88;
/// Maximum number of locks, active or expired, stored on one wallet.
pub const MAX_AUTHORIZATION_LOCKS: usize = 32;
pub const MAX_VALUE_LEN: usize = LOCK_LEN * MAX_AUTHORIZATION_LOCKS;
pub const MAX_ENTRY_LEN: usize = TAIL_HEADER_LEN + MAX_VALUE_LEN;
/// Mint value used by locks on the wallet address's native SOL balance.
pub const NATIVE_SOL_MINT: [u8; 32] = [0u8; 32];

/// Field byte ranges within one serialized lock record.
pub const ASSET_ACCOUNT: core::ops::Range<usize> = 0..32;
pub const MINT: core::ops::Range<usize> = 32..64;
pub const AMOUNT: core::ops::Range<usize> = 64..72;
pub const EXPIRY_SLOT: core::ops::Range<usize> = 72..80;
pub const ROLE_ID: core::ops::Range<usize> = 80..84;
pub const LOCK_ID: core::ops::Range<usize> = 84..88;

/// A reservation of `amount` in `asset_account`, created by `role_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationLock {
    /// Swig wallet address (native SOL) or a token account it owns.
    pub asset_account: [u8; 32],
    /// Token mint, or [`NATIVE_SOL_MINT`] for native SOL.
    pub mint: [u8; 32],
    /// Reserved amount in base units.
    pub amount: u64,
    /// First slot at which the lock no longer applies.
    pub expiry_slot: u64,
    /// Role that created the lock and may release it early.
    pub role_id: u32,
    /// Wallet-unique, never-reused lock identifier.
    pub lock_id: u32,
}

impl AuthorizationLock {
    /// A lock is enforced through `expiry_slot - 1` while it still reserves a
    /// non-zero amount. A fully captured lock (amount 0) is inactive and may
    /// be pruned like an expired one.
    pub fn is_active(&self, slot: u64) -> bool {
        self.amount != 0 && self.expiry_slot > slot
    }

    pub fn is_native_sol(&self) -> bool {
        self.mint == NATIVE_SOL_MINT
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProgramError> {
        if bytes.len() != LOCK_LEN {
            return Err(SwigStateError::InvalidAuthorizationLockLayout.into());
        }
        let read_u64 = |range: core::ops::Range<usize>| {
            u64::from_le_bytes(bytes[range].try_into().expect("fixed-size field"))
        };
        let read_u32 = |range: core::ops::Range<usize>| {
            u32::from_le_bytes(bytes[range].try_into().expect("fixed-size field"))
        };
        Ok(Self {
            asset_account: bytes[ASSET_ACCOUNT].try_into().expect("fixed-size field"),
            mint: bytes[MINT].try_into().expect("fixed-size field"),
            amount: read_u64(AMOUNT),
            expiry_slot: read_u64(EXPIRY_SLOT),
            role_id: read_u32(ROLE_ID),
            lock_id: read_u32(LOCK_ID),
        })
    }

    pub fn to_bytes(&self) -> [u8; LOCK_LEN] {
        let mut buf = [0u8; LOCK_LEN];
        buf[ASSET_ACCOUNT].copy_from_slice(&self.asset_account);
        buf[MINT].copy_from_slice(&self.mint);
        buf[AMOUNT].copy_from_slice(&self.amount.to_le_bytes());
        buf[EXPIRY_SLOT].copy_from_slice(&self.expiry_slot.to_le_bytes());
        buf[ROLE_ID].copy_from_slice(&self.role_id.to_le_bytes());
        buf[LOCK_ID].copy_from_slice(&self.lock_id.to_le_bytes());
        buf
    }
}

/// Zero-copy view of one stored lock record, for hot paths that only need a
/// few fields of each lock.
#[derive(Debug, Clone, Copy)]
pub struct LockRecord<'a>(&'a [u8; LOCK_LEN]);

impl<'a> LockRecord<'a> {
    /// Views `bytes`, which must be exactly [`LOCK_LEN`] long.
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        bytes.try_into().ok().map(Self)
    }

    pub fn asset_account(&self) -> &'a [u8; 32] {
        self.0[ASSET_ACCOUNT].try_into().expect("fixed-size field")
    }

    pub fn mint(&self) -> &'a [u8; 32] {
        self.0[MINT].try_into().expect("fixed-size field")
    }

    pub fn amount(&self) -> u64 {
        u64::from_le_bytes(self.0[AMOUNT].try_into().expect("fixed-size field"))
    }

    pub fn expiry_slot(&self) -> u64 {
        u64::from_le_bytes(self.0[EXPIRY_SLOT].try_into().expect("fixed-size field"))
    }

    pub fn role_id(&self) -> u32 {
        u32::from_le_bytes(self.0[ROLE_ID].try_into().expect("fixed-size field"))
    }

    pub fn lock_id(&self) -> u32 {
        u32::from_le_bytes(self.0[LOCK_ID].try_into().expect("fixed-size field"))
    }

    /// Same rule as [`AuthorizationLock::is_active`].
    pub fn is_active(&self, slot: u64) -> bool {
        self.amount() != 0 && self.expiry_slot() > slot
    }

    pub fn is_native_sol(&self) -> bool {
        self.mint() == &NATIVE_SOL_MINT
    }
}

/// Returns the [`LockRecord`] at `index` of a packed records slice.
pub fn record_at(records: &[u8], index: usize) -> Option<LockRecord<'_>> {
    let start = index.checked_mul(LOCK_LEN)?;
    LockRecord::new(records.get(start..start.checked_add(LOCK_LEN)?)?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationLocksEntry<'a> {
    pub header: TailHeader,
    value: &'a [u8],
}

impl<'a> AuthorizationLocksEntry<'a> {
    /// Id that the next created lock will receive.
    pub fn next_lock_id(&self) -> u32 {
        u32::from_le_bytes(self.header.payload)
    }

    /// Number of stored locks, including expired ones.
    pub fn len(&self) -> usize {
        self.value.len() / LOCK_LEN
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// The packed lock records.
    pub fn records(&self) -> &'a [u8] {
        self.value
    }

    pub fn get(&self, index: usize) -> Option<AuthorizationLock> {
        let start = index.checked_mul(LOCK_LEN)?;
        let bytes = self.value.get(start..start.checked_add(LOCK_LEN)?)?;
        AuthorizationLock::from_bytes(bytes).ok()
    }

    pub fn iter(&self) -> impl Iterator<Item = AuthorizationLock> + 'a {
        self.value
            .chunks_exact(LOCK_LEN)
            .filter_map(|bytes| AuthorizationLock::from_bytes(bytes).ok())
    }

    /// Validates the version, size bound, and lock-id uniqueness.
    ///
    /// Locks are appended with the next id and removed in place, so stored ids
    /// are strictly increasing and below the counter. Checking that ordering
    /// proves uniqueness in one pass. A zero amount is valid: it marks a lock
    /// that SignV2 captured in full.
    pub fn validate(&self) -> Result<(), ProgramError> {
        if self.header.version != VERSION
            || !self.value.len().is_multiple_of(LOCK_LEN)
            || self.value.len() > MAX_VALUE_LEN
        {
            return Err(SwigStateError::InvalidAuthorizationLockLayout.into());
        }
        let mut previous: Option<u32> = None;
        for record in self.value.chunks_exact(LOCK_LEN) {
            let lock_id = u32::from_le_bytes(record[LOCK_ID].try_into().expect("fixed-size field"));
            if previous.is_some_and(|previous| lock_id <= previous) {
                return Err(SwigStateError::InvalidAuthorizationLockLayout.into());
            }
            previous = Some(lock_id);
        }
        if previous.is_some_and(|last| last >= self.next_lock_id()) {
            return Err(SwigStateError::InvalidAuthorizationLockLayout.into());
        }
        Ok(())
    }
}

impl<'a> TailDescriptor<'a> for AuthorizationLocksEntry<'a> {
    const KIND: TailKind = TailKind::AuthorizationLocks;

    fn from_parts(header: TailHeader, value: &'a [u8]) -> Result<Self, TailReadError> {
        if !value.len().is_multiple_of(LOCK_LEN) || value.len() > MAX_VALUE_LEN {
            return Err(TailReadError::InvalidValueLen {
                expected: LOCK_LEN,
                found: value.len(),
            });
        }
        Ok(Self { header, value })
    }
}

/// Returns the lock entry, if any. Callers that act on locks must also have
/// validated the full tail with [`super::validate_strict`].
pub fn read(tail_data: &[u8]) -> Result<Option<AuthorizationLocksEntry<'_>>, ProgramError> {
    Ok(read_first_of::<AuthorizationLocksEntry<'_>>(tail_data)?)
}

/// Strict variant of [`read`] that validates the full heterogeneous tail.
pub fn read_strict(tail_data: &[u8]) -> Result<Option<AuthorizationLocksEntry<'_>>, ProgramError> {
    super::validate_strict(tail_data)?;
    read(tail_data)
}

/// True when any lock created by `role_id` is still active at `slot`.
pub fn role_has_active_locks(
    tail_data: &[u8],
    role_id: u32,
    slot: u64,
) -> Result<bool, ProgramError> {
    if tail_data.is_empty() {
        return Ok(false);
    }
    Ok(read_strict(tail_data)?.is_some_and(|entry| {
        entry
            .iter()
            .any(|l| l.role_id == role_id && l.is_active(slot))
    }))
}

/// True when any lock is still active at `slot`.
pub fn has_active_locks(tail_data: &[u8], slot: u64) -> Result<bool, ProgramError> {
    if tail_data.is_empty() {
        return Ok(false);
    }
    Ok(read_strict(tail_data)?.is_some_and(|entry| entry.iter().any(|l| l.is_active(slot))))
}

/// True when any active lock reserves funds in `asset_account`.
pub fn account_has_active_locks(
    tail_data: &[u8],
    asset_account: &[u8; 32],
    slot: u64,
) -> Result<bool, ProgramError> {
    Ok(read_strict(tail_data)?.is_some_and(|entry| {
        entry
            .iter()
            .any(|l| &l.asset_account == asset_account && l.is_active(slot))
    }))
}

/// Serializes a complete lock entry.
pub fn entry(next_lock_id: u32, locks: &[AuthorizationLock]) -> Result<Vec<u8>, ProgramError> {
    if locks.len() > MAX_AUTHORIZATION_LOCKS {
        return Err(SwigStateError::AuthorizationLockLimitReached.into());
    }
    let value_len = locks.len() * LOCK_LEN;
    let mut buf = Vec::with_capacity(TAIL_HEADER_LEN + value_len);
    buf.push(TailKind::AuthorizationLocks.as_u8());
    buf.push(VERSION);
    buf.extend_from_slice(&(value_len as u16).to_le_bytes());
    buf.extend_from_slice(&next_lock_id.to_le_bytes());
    for lock in locks {
        buf.extend_from_slice(&lock.to_bytes());
    }
    Ok(buf)
}

/// Returns the byte range of the packed lock records within `tail_data`, or
/// `None` when the tail has no lock entry. Like [`read`], callers that act on
/// locks must also have validated the full tail.
pub fn records_range(tail_data: &[u8]) -> Result<Option<core::ops::Range<usize>>, ProgramError> {
    Ok(read(tail_data)?.map(|entry| {
        let start = entry.value.as_ptr() as usize - tail_data.as_ptr() as usize;
        start..start + entry.value.len()
    }))
}

/// Bytes the tail grows by when one lock is appended: a record, plus an entry
/// header when the wallet has no lock entry yet.
pub fn append_growth(tail_data: &[u8]) -> Result<usize, ProgramError> {
    Ok(match records_range(tail_data)? {
        Some(_) => LOCK_LEN,
        None => TAIL_HEADER_LEN + LOCK_LEN,
    })
}

/// Appends `lock` in place to the validated tail held in `buf[..tail_len]`,
/// where `buf` has room for [`append_growth`] more bytes: the record goes at
/// the end of the lock entry (later entries move up), the entry's length
/// grows, and its counter becomes `lock.lock_id + 1`. A wallet without a lock
/// entry gets one at the end of the tail. Returns the new tail length.
pub fn append_in_place(
    buf: &mut [u8],
    tail_len: usize,
    lock: &AuthorizationLock,
) -> Result<usize, ProgramError> {
    let tail = buf
        .get(..tail_len)
        .ok_or(SwigStateError::InvalidAuthorizationLockLayout)?;
    let next_lock_id = lock
        .lock_id
        .checked_add(1)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    match records_range(tail)? {
        Some(records) => {
            let value_len = records.len() + LOCK_LEN;
            if value_len > MAX_VALUE_LEN {
                return Err(SwigStateError::AuthorizationLockLimitReached.into());
            }
            let new_len = tail_len + LOCK_LEN;
            if buf.len() < new_len {
                return Err(SwigStateError::InvalidAuthorizationLockLayout.into());
            }
            let record_end = records.end + LOCK_LEN;
            buf.copy_within(records.end..tail_len, record_end);
            buf[records.end..record_end].copy_from_slice(&lock.to_bytes());
            let header = records.start - TAIL_HEADER_LEN;
            buf[header + 2..header + 4].copy_from_slice(&(value_len as u16).to_le_bytes());
            buf[header + 4..header + 8].copy_from_slice(&next_lock_id.to_le_bytes());
            Ok(new_len)
        },
        None => {
            let added = entry(next_lock_id, core::slice::from_ref(lock))?;
            let new_len = tail_len + added.len();
            buf.get_mut(tail_len..new_len)
                .ok_or(SwigStateError::InvalidAuthorizationLockLayout)?
                .copy_from_slice(&added);
            Ok(new_len)
        },
    }
}

/// Removes the record at `index` in place from the validated tail in
/// `buf[..tail_len]`: later records and entries move down, the entry shrinks,
/// and the freed bytes at the end are zeroed. The counter is unchanged.
/// Returns the new tail length.
pub fn remove_in_place(
    buf: &mut [u8],
    tail_len: usize,
    index: usize,
) -> Result<usize, ProgramError> {
    let tail = buf
        .get(..tail_len)
        .ok_or(SwigStateError::InvalidAuthorizationLockLayout)?;
    let records = records_range(tail)?.ok_or(SwigStateError::InvalidAuthorizationLockLayout)?;
    let start = index
        .checked_mul(LOCK_LEN)
        .map(|offset| records.start + offset)
        .filter(|&start| start + LOCK_LEN <= records.end)
        .ok_or(SwigStateError::InvalidAuthorizationLockLayout)?;
    buf.copy_within(start + LOCK_LEN..tail_len, start);
    let new_len = tail_len - LOCK_LEN;
    buf[new_len..tail_len].fill(0);
    let header = records.start - TAIL_HEADER_LEN;
    let value_len = (records.len() - LOCK_LEN) as u16;
    buf[header + 2..header + 4].copy_from_slice(&value_len.to_le_bytes());
    Ok(new_len)
}

/// Whether `role_id` holds any stored lock, and any active one at `slot`, in
/// one pass over the raw records. Callers must have validated the tail.
pub fn role_lock_state(
    tail_data: &[u8],
    role_id: u32,
    slot: u64,
) -> Result<(bool, bool), ProgramError> {
    if tail_data.is_empty() {
        return Ok((false, false));
    }
    let Some(records) = records_range(tail_data)? else {
        return Ok((false, false));
    };
    let mut stored = false;
    for bytes in tail_data[records].chunks_exact(LOCK_LEN) {
        let lock = LockRecord::new(bytes).ok_or(SwigStateError::InvalidAuthorizationLockLayout)?;
        if lock.role_id() == role_id {
            if lock.is_active(slot) {
                return Ok((true, true));
            }
            stored = true;
        }
    }
    Ok((stored, false))
}

/// Drops every lock of `role_id` in place from a validated tail held in a
/// `Vec`, keeping all other bytes, entries and the counter. Returns how many
/// bytes the tail shrank by. Callers must first ensure none of the role's
/// locks is active.
pub fn prune_role_locks(tail: &mut Vec<u8>, role_id: u32) -> Result<usize, ProgramError> {
    let Some(records) = records_range(tail)? else {
        return Ok(0);
    };
    let mut kept = records.start;
    let mut cursor = records.start;
    while cursor < records.end {
        let lock = LockRecord::new(&tail[cursor..cursor + LOCK_LEN])
            .ok_or(SwigStateError::InvalidAuthorizationLockLayout)?;
        if lock.role_id() != role_id {
            if kept != cursor {
                tail.copy_within(cursor..cursor + LOCK_LEN, kept);
            }
            kept += LOCK_LEN;
        }
        cursor += LOCK_LEN;
    }
    let removed = records.end - kept;
    if removed == 0 {
        return Ok(0);
    }
    tail.drain(kept..records.end);
    let header = records.start - TAIL_HEADER_LEN;
    let value_len = (kept - records.start) as u16;
    tail[header + 2..header + 4].copy_from_slice(&value_len.to_le_bytes());
    Ok(removed)
}

/// Rebuilds a validated tail with its lock entry replaced, preserving every
/// other entry and its order. A wallet without a lock entry gets one appended.
pub fn rebuild_tail(
    tail_data: &[u8],
    next_lock_id: u32,
    locks: &[AuthorizationLock],
) -> Result<Vec<u8>, ProgramError> {
    super::validate_strict(tail_data)?;
    let replacement = entry(next_lock_id, locks)?;
    let mut rebuilt = Vec::with_capacity(tail_data.len() + replacement.len());
    let mut replaced = false;
    let mut rest = tail_data;
    while !rest.is_empty() {
        let (parsed, consumed) = AnyTailEntry::read(rest)?;
        if matches!(parsed, AnyTailEntry::AuthorizationLocks(_)) {
            rebuilt.extend_from_slice(&replacement);
            replaced = true;
        } else {
            rebuilt.extend_from_slice(&rest[..consumed]);
        }
        rest = &rest[consumed..];
    }
    if !replaced {
        rebuilt.extend_from_slice(&replacement);
    }
    Ok(rebuilt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tail::{active_sub_account_count, rent_claimer, validate_strict};

    fn lock(lock_id: u32, role_id: u32, expiry_slot: u64) -> AuthorizationLock {
        AuthorizationLock {
            asset_account: [lock_id as u8 + 1; 32],
            mint: NATIVE_SOL_MINT,
            amount: 1_000 + lock_id as u64,
            expiry_slot,
            role_id,
            lock_id,
        }
    }

    #[test]
    fn lock_round_trips() {
        let original = AuthorizationLock {
            asset_account: [3; 32],
            mint: [4; 32],
            amount: u64::MAX,
            expiry_slot: 99,
            role_id: 7,
            lock_id: 11,
        };
        let bytes = original.to_bytes();
        assert_eq!(AuthorizationLock::from_bytes(&bytes).unwrap(), original);
        assert!(AuthorizationLock::from_bytes(&bytes[..LOCK_LEN - 1]).is_err());
    }

    #[test]
    fn entry_round_trips_through_read() {
        let locks = [lock(0, 1, 50), lock(1, 2, 60)];
        let tail = entry(2, &locks).unwrap();
        validate_strict(&tail).unwrap();
        let parsed = read(&tail).unwrap().unwrap();
        assert_eq!(parsed.next_lock_id(), 2);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.iter().collect::<Vec<_>>(), locks.to_vec());
        assert_eq!(parsed.get(1), Some(locks[1]));
        assert_eq!(parsed.get(2), None);
    }

    #[test]
    fn empty_entry_is_valid_and_keeps_counter() {
        let tail = entry(9, &[]).unwrap();
        validate_strict(&tail).unwrap();
        let parsed = read(&tail).unwrap().unwrap();
        assert!(parsed.is_empty());
        assert_eq!(parsed.next_lock_id(), 9);
    }

    #[test]
    fn activity_is_exclusive_of_expiry_slot() {
        let l = lock(0, 0, 100);
        assert!(l.is_active(99));
        assert!(!l.is_active(100));
        assert!(!l.is_active(101));
    }

    #[test]
    fn helpers_ignore_expired_locks() {
        let locks = [lock(0, 1, 50), lock(1, 2, 200)];
        let tail = entry(2, &locks).unwrap();
        assert!(!role_has_active_locks(&tail, 1, 50).unwrap());
        assert!(role_has_active_locks(&tail, 1, 49).unwrap());
        assert!(role_has_active_locks(&tail, 2, 100).unwrap());
        assert!(has_active_locks(&tail, 100).unwrap());
        assert!(!has_active_locks(&tail, 200).unwrap());
        assert!(account_has_active_locks(&tail, &locks[1].asset_account, 100).unwrap());
        assert!(!account_has_active_locks(&tail, &locks[0].asset_account, 100).unwrap());
        assert!(!has_active_locks(&[], 0).unwrap());
    }

    #[test]
    fn validate_rejects_bad_entries() {
        // Wrong version.
        let mut tail = entry(1, &[lock(0, 0, 10)]).unwrap();
        tail[1] = VERSION + 1;
        assert!(validate_strict(&tail).is_err());

        // Lock id not below the counter.
        let tail = entry(0, &[lock(0, 0, 10)]).unwrap();
        assert!(validate_strict(&tail).is_err());

        // Duplicate lock id.
        let tail = entry(5, &[lock(1, 0, 10), lock(1, 0, 20)]).unwrap();
        assert!(validate_strict(&tail).is_err());

        // Out-of-order ids.
        let tail = entry(5, &[lock(2, 0, 10), lock(1, 0, 20)]).unwrap();
        assert!(validate_strict(&tail).is_err());
        let tail = entry(5, &[lock(1, 0, 10), lock(3, 0, 20)]).unwrap();
        assert!(validate_strict(&tail).is_ok());

        // A zero amount marks a fully captured lock and is valid.
        let mut zero = lock(0, 0, 10);
        zero.amount = 0;
        assert!(validate_strict(&entry(1, &[zero]).unwrap()).is_ok());

        // Value not a multiple of the record size.
        let mut tail = entry(1, &[lock(0, 0, 10)]).unwrap();
        tail.pop();
        tail[2..4].copy_from_slice(&((LOCK_LEN - 1) as u16).to_le_bytes());
        assert!(validate_strict(&tail).is_err());

        // Two lock entries.
        let mut tail = entry(1, &[lock(0, 0, 10)]).unwrap();
        tail.extend_from_slice(&entry(1, &[]).unwrap());
        assert!(validate_strict(&tail).is_err());
    }

    #[test]
    fn captured_locks_are_inactive() {
        let mut l = lock(0, 0, 100);
        l.amount = 0;
        assert!(!l.is_active(0));
        let tail = entry(1, &[l]).unwrap();
        assert!(!has_active_locks(&tail, 0).unwrap());
        assert!(!role_has_active_locks(&tail, 0, 0).unwrap());
    }

    #[test]
    fn records_are_located_and_viewed_and_zero_amounts_validate() {
        let rent = rent_claimer::entry(&[7u8; 32]);
        let locks = [lock(0, 1, 50), lock(1, 2, 60), lock(2, 1, 70)];
        let count = active_sub_account_count::entry(3);
        let mut tail = [
            rent.as_slice(),
            entry(3, &locks).unwrap().as_slice(),
            count.as_slice(),
        ]
        .concat();
        let len = tail.len();
        let range = records_range(&tail).unwrap().unwrap();
        assert_eq!(range.len(), 3 * LOCK_LEN);
        for (index, expected) in locks.iter().enumerate() {
            let record = record_at(&tail[range.clone()], index).unwrap();
            assert_eq!(record.asset_account(), &expected.asset_account);
            assert_eq!(record.mint(), &expected.mint);
            assert_eq!(record.amount(), expected.amount);
            assert_eq!(record.expiry_slot(), expected.expiry_slot);
            assert_eq!(record.role_id(), expected.role_id);
            assert_eq!(record.lock_id(), expected.lock_id);
            assert_eq!(record.is_active(49), expected.is_active(49));
        }
        assert!(record_at(&tail[range.clone()], 3).is_none());

        let records = &mut tail[range.clone()];
        records[AMOUNT].copy_from_slice(&0u64.to_le_bytes());
        records[2 * LOCK_LEN + AMOUNT.start..2 * LOCK_LEN + AMOUNT.end]
            .copy_from_slice(&5u64.to_le_bytes());
        assert_eq!(tail.len(), len);
        validate_strict(&tail).unwrap();
        let stored: Vec<_> = read(&tail).unwrap().unwrap().iter().collect();
        assert_eq!(stored[0].amount, 0);
        assert!(!stored[0].is_active(0));
        assert_eq!(stored[1], locks[1]);
        assert_eq!(stored[2].amount, 5);
        assert_eq!(rent_claimer::read(&tail).unwrap(), Some(&[7u8; 32]));
        assert_eq!(active_sub_account_count::read(&tail).unwrap(), Some(3));
        assert_eq!(records_range(&rent).unwrap(), None);
        assert_eq!(records_range(&[]).unwrap(), None);
    }

    #[test]
    fn in_place_edits_match_a_rebuild() {
        let rent = rent_claimer::entry(&[7u8; 32]);
        let count = active_sub_account_count::entry(3);
        let locks = [lock(0, 1, 50), lock(1, 2, 60), lock(2, 1, 70)];
        let tail = [
            rent.as_slice(),
            entry(3, &locks).unwrap().as_slice(),
            count.as_slice(),
        ]
        .concat();

        // Append, with a later entry to move.
        let added = lock(3, 2, 80);
        assert_eq!(append_growth(&tail).unwrap(), LOCK_LEN);
        let mut buf = tail.clone();
        buf.resize(tail.len() + LOCK_LEN, 0);
        let len = append_in_place(&mut buf, tail.len(), &added).unwrap();
        assert_eq!(len, buf.len());
        let all = [locks[0], locks[1], locks[2], added];
        assert_eq!(buf, rebuild_tail(&tail, 4, &all).unwrap());

        // Append to a tail without a lock entry.
        let plain = [rent.as_slice(), count.as_slice()].concat();
        assert_eq!(append_growth(&plain).unwrap(), TAIL_HEADER_LEN + LOCK_LEN);
        let mut buf = plain.clone();
        buf.resize(plain.len() + TAIL_HEADER_LEN + LOCK_LEN, 0);
        let first = lock(0, 1, 50);
        append_in_place(&mut buf, plain.len(), &first).unwrap();
        assert_eq!(buf, rebuild_tail(&plain, 1, &[first]).unwrap());

        // Remove from the middle; the counter stays.
        let mut buf = tail.clone();
        let len = remove_in_place(&mut buf, tail.len(), 1).unwrap();
        assert_eq!(
            &buf[..len],
            rebuild_tail(&tail, 3, &[locks[0], locks[2]]).unwrap()
        );
        assert!(buf[len..].iter().all(|&byte| byte == 0));
        assert!(remove_in_place(&mut tail.clone(), tail.len(), 3).is_err());

        // A full entry cannot grow.
        let full: Vec<_> = (0..MAX_AUTHORIZATION_LOCKS as u32)
            .map(|id| lock(id, 0, 10))
            .collect();
        let full_tail = entry(40, &full).unwrap();
        let mut buf = full_tail.clone();
        buf.resize(full_tail.len() + LOCK_LEN, 0);
        assert!(append_in_place(&mut buf, full_tail.len(), &lock(40, 0, 10)).is_err());

        // Role state and pruning.
        assert_eq!(role_lock_state(&tail, 1, 0).unwrap(), (true, true));
        assert_eq!(role_lock_state(&tail, 1, 70).unwrap(), (true, false));
        assert_eq!(role_lock_state(&tail, 9, 0).unwrap(), (false, false));
        assert_eq!(role_lock_state(&[], 1, 0).unwrap(), (false, false));
        let mut pruned = tail.clone();
        assert_eq!(prune_role_locks(&mut pruned, 1).unwrap(), 2 * LOCK_LEN);
        assert_eq!(pruned, rebuild_tail(&tail, 3, &[locks[1]]).unwrap());
        assert_eq!(prune_role_locks(&mut pruned, 9).unwrap(), 0);
        // The last lock goes; the entry and its counter stay.
        assert_eq!(prune_role_locks(&mut pruned, 2).unwrap(), LOCK_LEN);
        validate_strict(&pruned).unwrap();
        let emptied = read(&pruned).unwrap().unwrap();
        assert!(emptied.is_empty());
        assert_eq!(emptied.next_lock_id(), 3);
        assert_eq!(active_sub_account_count::read(&pruned).unwrap(), Some(3));
        assert_eq!(prune_role_locks(&mut rent.to_vec(), 1).unwrap(), 0);
    }

    #[test]
    fn entry_rejects_too_many_locks() {
        let locks: Vec<_> = (0..=MAX_AUTHORIZATION_LOCKS as u32)
            .map(|id| lock(id, 0, 10))
            .collect();
        assert!(entry(100, &locks).is_err());
        assert!(entry(100, &locks[..MAX_AUTHORIZATION_LOCKS]).is_ok());
    }

    #[test]
    fn rebuild_preserves_other_entries_in_place() {
        let rent = rent_claimer::entry(&[7u8; 32]);
        let count = active_sub_account_count::entry(3);
        let locks_v1 = entry(1, &[lock(0, 0, 10)]).unwrap();
        let tail = [rent.as_slice(), locks_v1.as_slice(), count.as_slice()].concat();
        validate_strict(&tail).unwrap();

        let new_locks = [lock(0, 0, 10), lock(1, 2, 20)];
        let rebuilt = rebuild_tail(&tail, 2, &new_locks).unwrap();
        validate_strict(&rebuilt).unwrap();
        let expected = [
            rent.as_slice(),
            entry(2, &new_locks).unwrap().as_slice(),
            count.as_slice(),
        ]
        .concat();
        assert_eq!(rebuilt, expected);
        assert_eq!(rent_claimer::read(&rebuilt).unwrap(), Some(&[7u8; 32]));
        assert_eq!(active_sub_account_count::read(&rebuilt).unwrap(), Some(3));
    }

    #[test]
    fn rebuild_appends_when_missing() {
        let rent = rent_claimer::entry(&[1u8; 32]);
        let rebuilt = rebuild_tail(&rent, 1, &[lock(0, 0, 10)]).unwrap();
        assert_eq!(&rebuilt[..rent.len()], rent.as_slice());
        assert_eq!(read_strict(&rebuilt).unwrap().unwrap().len(), 1);

        let rebuilt = rebuild_tail(&[], 1, &[lock(0, 0, 10)]).unwrap();
        assert_eq!(read_strict(&rebuilt).unwrap().unwrap().len(), 1);
    }
}
