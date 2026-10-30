//! Manage authorization locks action type.
//!
//! An authorization lock reserves part of one wallet asset account until an
//! expiry slot. While a lock is active, no role (including `All`) may spend
//! that account below the reserved amount, and the wallet cannot strip the
//! creating role of the permissions it needs to capture the reservation.
//!
//! Every lock requires this action, and no lock may outlast
//! `max_duration_slots`. Because a lock constrains every other role, a role
//! that cannot spend everything may only lock funds within the spending
//! allowance it already holds for that asset. A role may not set or change its
//! own `max_duration_slots`; another manager grants it (the root, which no
//! other role may manage, is the exception).

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Permission to create authorization locks of at most `max_duration_slots`,
/// bounded by the role's own spending limits unless it may spend everything.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct ManageAuthorizationLocks {
    /// Maximum number of slots between lock creation and lock expiry.
    pub max_duration_slots: u64,
}

impl ManageAuthorizationLocks {
    pub const fn new(max_duration_slots: u64) -> Self {
        Self { max_duration_slots }
    }
}

impl Transmutable for ManageAuthorizationLocks {
    const LEN: usize = 8;
}

impl TransmutableMut for ManageAuthorizationLocks {}

impl IntoBytes for ManageAuthorizationLocks {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> Actionable<'a> for ManageAuthorizationLocks {
    const TYPE: Permission = Permission::ManageAuthorizationLocks;
    const REPEATABLE: bool = false;

    fn match_data(&self, _data: &[u8]) -> bool {
        true
    }

    /// A zero duration could never produce a valid lock.
    fn valid_layout(data: &'a [u8]) -> Result<bool, ProgramError> {
        if data.len() != Self::LEN {
            return Ok(false);
        }
        Ok(data != [0u8; 8])
    }
}
