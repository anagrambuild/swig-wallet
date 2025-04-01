use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

static_assertions::const_assert!(core::mem::size_of::<TokenRecurringLimit>() % 8 == 0);
#[repr(C)]
pub struct TokenRecurringLimit {
  pub token_mint: [u8; 32],
  pub window: u64,
  pub limit: u64,
  pub current: u64,
  pub last_reset: u64,
}

impl Transmutable for TokenRecurringLimit {
    const LEN: usize = 64; // Since this is just a marker with no data
}

impl TransmutableMut for TokenRecurringLimit {}

impl<'a> IntoBytes<'a> for TokenRecurringLimit {
    fn into_bytes(&'a self) -> Result<&'a [u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> Actionable<'a> for TokenRecurringLimit {
    const TYPE: Permission = Permission::TokenRecurringLimit;

    fn validate(&mut self) {
        // No validation needed for a marker type
    }
}
