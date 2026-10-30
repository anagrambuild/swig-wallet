//! Authorization-lock tail entry.
//!
//! An authorization lock reserves `amount` of one wallet asset account until
//! `expiry_slot`. The asset account is either the swig wallet address (native
//! SOL, `mint == NATIVE_SOL_MINT`) or one SPL Token / Token-2022 account owned
//! by the swig wallet address. While any lock on an account is active, SignV2
//! rejects transactions that move that account's balance below the total
//! reserved amount, regardless of the signing role's permissions.
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

const ASSET_ACCOUNT: core::ops::Range<usize> = 0..32;
const MINT: core::ops::Range<usize> = 32..64;
const AMOUNT: core::ops::Range<usize> = 64..72;
const EXPIRY_SLOT: core::ops::Range<usize> = 72..80;
const ROLE_ID: core::ops::Range<usize> = 80..84;
const LOCK_ID: core::ops::Range<usize> = 84..88;

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
    /// A lock is enforced through `expiry_slot - 1`.
    pub fn is_active(&self, slot: u64) -> bool {
        self.expiry_slot > slot
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
    /// proves uniqueness in one pass.
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
            if previous.is_some_and(|previous| lock_id <= previous) || record[AMOUNT] == [0u8; 8] {
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
    Ok(read_strict(tail_data)?.is_some_and(|entry| {
        entry
            .iter()
            .any(|l| l.role_id == role_id && l.is_active(slot))
    }))
}

/// True when any lock is still active at `slot`.
pub fn has_active_locks(tail_data: &[u8], slot: u64) -> Result<bool, ProgramError> {
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
