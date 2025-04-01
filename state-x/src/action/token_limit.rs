use core::ptr::slice_from_raw_parts;

use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

static_assertions::const_assert!(core::mem::size_of::<TokenLimit>() % 8 == 0);
#[repr(C)]
pub struct TokenLimit {
    pub token_mint: [u8; 32],
    pub current_amount: u64,
}

impl Transmutable for TokenLimit {
    const LEN: usize = 40; // Since this is just a marker with no data
}

impl TransmutableMut for TokenLimit {}

impl<'a> IntoBytes<'a> for TokenLimit {
    fn into_bytes(&'a self) -> Result<&'a [u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

impl<'a> Actionable<'a> for TokenLimit {
    const TYPE: Permission = Permission::TokenLimit;

    fn validate(&mut self) {
        // No validation needed for a marker type
    }
}
