use std::u64;

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use crate::{
    action::{Actionable, Permission},
    IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut,
};

/// Represents an individual authorization lock on tokens or SOL.
///
/// This struct represents a single authorization lock that follows the
/// ManageAuthorizationLocks header. Multiple instances can exist per role.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct AuthorizationLock {
    /// The token mint address (32 bytes). Use zero for SOL locks.
    pub mint: [u8; 32],
    /// The amount of tokens/SOL locked (in smallest units)
    pub amount: u64,
    /// The slot when this lock expires
    pub expires_at: u64,
}

impl AuthorizationLock {
    /// Creates a new authorization lock.
    ///
    /// # Arguments
    /// * `mint` - The token mint address (use zero for SOL)
    /// * `amount` - The amount to lock
    /// * `expires_at` - The slot when this lock expires
    ///
    /// # Returns
    /// * `Self` - The new authorization lock
    pub fn new(mint: [u8; 32], amount: u64, expires_at: u64) -> Self {
        Self {
            mint,
            amount,
            expires_at,
        }
    }

    /// Checks if this lock has expired.
    ///
    /// # Arguments
    /// * `current_slot` - The current slot number
    ///
    /// # Returns
    /// * `bool` - True if the lock has expired
    pub fn is_expired(&self, current_slot: u64) -> bool {
        current_slot >= self.expires_at
    }

    /// Reduces the locked amount by the specified amount.
    ///
    /// # Arguments
    /// * `amount` - The amount to reduce by
    ///
    /// # Returns
    /// * `Result<(), ProgramError>` - Success or error if insufficient amount
    pub fn modify_amount(&mut self, amount: i64) {
        if amount > 0 {
            self.amount = self.amount.saturating_add(amount as u64);
        } else {
            self.amount = self.amount.saturating_sub(amount as u64);
        }
    }

    /// Update the authorization lock with the new values
    ///
    /// # Arguments
    /// * `existing_lock` - The existing authorization lock
    ///
    /// # Returns
    /// * `Result<(), ProgramError>` - Success or error if insufficient amount
    pub fn update(&mut self, amount: u64, expires_at: u64) {
        self.amount = amount;
        self.expires_at = expires_at;
    }

    /// Update the cache with the new authorization lock
    ///
    /// # Arguments
    /// * `cache_auth_locks` - The cache of authorization locks
    ///
    /// # Returns
    /// * `Result<(), ProgramError>` - Success or error if insufficient amount
    pub fn update_cache(&self, cache_lock: &mut AuthorizationLock, current_slot: u64) -> bool {
        if self.is_expired(current_slot) {
            return false;
        }
        cache_lock.update_for_global(self.amount, self.expires_at);
        return true;
    }

    /// Compare and update the values to be used for the global config file
    ///
    ///
    ///
    pub fn update_for_global(&mut self, amount: u64, expires_at: u64) {
        self.amount += amount;
        if expires_at < self.expires_at {
            self.expires_at = expires_at;
        }
    }

    pub fn run(&mut self, current_balance: u64) -> Result<(), ProgramError> {
        if current_balance < self.amount {
            return Err(SwigAuthenticateError::PermissionDeniedAuthorizationLockExceeded.into());
        }
        Ok(())
    }
}

impl Transmutable for AuthorizationLock {
    /// Size of the AuthorizationLock struct in bytes
    /// 32 (mint) + 8 (amount) + 8 (expires_at) = 48
    const LEN: usize = 48;
}

impl TransmutableMut for AuthorizationLock {}

impl IntoBytes for AuthorizationLock {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> Actionable<'a> for AuthorizationLock {
    /// This action represents the AuthorizationLock permission type
    const TYPE: Permission = Permission::AuthorizationLock;
    /// Multiple authorization locks can exist per role
    const REPEATABLE: bool = true;

    /// Checks if this authorization lock matches the provided data.
    ///
    /// # Arguments
    /// * `data` - The data to check against (first 32 bytes)
    fn match_data(&self, data: &[u8]) -> bool {
        data[0..32] == self.mint
    }
}
