//! Authorization lock action type.
//!
//! This module defines the AuthorizationLock action type which places
//! temporary locks on token amounts to prevent transfers that would reduce
//! the wallet balance below the locked amount during the lock period.

use no_padding::NoPadding;
use pinocchio::{msg, program_error::ProgramError};

use super::{Actionable, Permission};
use crate::{IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut};

/// Represents a temporary authorization lock on a specific token mint.
///
/// This struct tracks a locked amount of tokens that cannot be transferred
/// out of the wallet until the expiry slot is reached. This is useful for
/// implementing authorization holds like those used by card companies.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct AuthorizationLock {
    /// The mint address of the token this lock applies to
    pub token_mint: [u8; 32],
    /// The amount of tokens locked (minimum balance required)
    pub locked_amount: u64,
    /// The slot when this lock expires
    pub expiry_slot: u64,
    /// The role ID of the authority that created this lock
    pub creator_role_id: u32,
    /// Padding to maintain 8-byte alignment
    _padding: u32,
}

impl AuthorizationLock {
    /// Creates a new authorization lock.
    ///
    /// # Arguments
    /// * `token_mint` - The mint address of the token
    /// * `locked_amount` - The amount to lock
    /// * `expiry_slot` - When the lock expires
    /// * `creator_role_id` - The role ID of the authority creating this lock
    pub fn new(
        token_mint: [u8; 32],
        locked_amount: u64,
        expiry_slot: u64,
        creator_role_id: u32,
    ) -> Self {
        Self {
            token_mint,
            locked_amount,
            expiry_slot,
            creator_role_id,
            _padding: 0,
        }
    }

    /// Checks if this authorization lock has expired.
    ///
    /// # Arguments
    /// * `current_slot` - The current slot number
    ///
    /// # Returns
    /// * `bool` - True if the lock has expired
    pub fn is_expired(&self, current_slot: u64) -> bool {
        current_slot >= self.expiry_slot
    }

    /// Checks if a transfer would violate this authorization lock.
    ///
    /// # Arguments
    /// * `current_balance` - The current token balance
    /// * `transfer_amount` - The amount being transferred out
    /// * `current_slot` - The current slot number
    ///
    /// # Returns
    /// * `Ok(())` - If the transfer is allowed
    /// * `Err(ProgramError)` - If the transfer would violate the lock
    pub fn check_authorization(
        &self,
        current_balance: &u64,
        transfer_amount: u64,
        current_slot: u64,
    ) -> Result<(), ProgramError> {
        msg!("lock.is_expired: {:?}", self.is_expired(current_slot));
        // If the lock has expired, allow the transfer
        if self.is_expired(current_slot) {
            return Ok(());
        }

        // Check if the transfer would reduce balance below locked amount
        let remaining_balance = current_balance.saturating_sub(transfer_amount);
        msg!("transfer_amount: {:?}", remaining_balance);
        msg!("current_balance: {:?}", current_balance);
        msg!("transfer_amount: {:?}", transfer_amount);
        msg!("locked_amount: {:?}", self.locked_amount);
        if remaining_balance < self.locked_amount {
            msg!("PermissionDeniedAuthorizationLockViolation");
            return Err(SwigAuthenticateError::PermissionDeniedAuthorizationLockViolation.into());
        }

        Ok(())
    }

    /// Updates the locked amount for this authorization.
    ///
    /// # Arguments
    /// * `new_amount` - The new amount to lock
    pub fn update_locked_amount(&mut self, new_amount: u64) {
        self.locked_amount = new_amount;
    }

    /// Extends the expiry slot for this authorization.
    ///
    /// # Arguments
    /// * `new_expiry_slot` - The new expiry slot
    pub fn extend_expiry(&mut self, new_expiry_slot: u64) {
        if new_expiry_slot > self.expiry_slot {
            self.expiry_slot = new_expiry_slot;
        }
    }
}

impl Transmutable for AuthorizationLock {
    /// Size of the AuthorizationLock struct in bytes (32 bytes for mint + 8
    /// bytes for amount + 8 bytes for expiry + 4 bytes for creator_role_id
    /// + 4 bytes padding)
    const LEN: usize = 56;
}

impl TransmutableMut for AuthorizationLock {}

impl IntoBytes for AuthorizationLock {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

impl<'a> Actionable<'a> for AuthorizationLock {
    /// This action represents the AuthorizationLock permission type
    const TYPE: Permission = Permission::AuthorizationLock;
    /// Multiple authorization locks can exist per role (one per token mint)
    const REPEATABLE: bool = true;

    /// Checks if this authorization lock matches the provided token mint.
    ///
    /// # Arguments
    /// * `data` - The token mint to check against (first 32 bytes)
    fn match_data(&self, data: &[u8]) -> bool {
        data[0..32] == self.token_mint
    }
}
