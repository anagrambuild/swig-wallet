use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut};
use no_padding::NoPadding;

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct TokenLimit {
    pub token_mint: [u8; 32],
    pub current_amount: u64,
}

impl TokenLimit {
    pub fn run(&mut self, amount: u64) -> Result<(), ProgramError> {
        if amount > self.current_amount {
            return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
        }
        self.current_amount -= amount;
        Ok(())
    }
}
impl Transmutable for TokenLimit {
    const LEN: usize = 40; // Since this is just a marker with no data
}

impl TransmutableMut for TokenLimit {}

impl IntoBytes for TokenLimit {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

impl<'a> Actionable<'a> for TokenLimit {
    const TYPE: Permission = Permission::TokenLimit;
    const REPEATABLE: bool = true;

    fn match_data(&self, data: &[u8]) -> bool {
        data[0..32] == self.token_mint
    }
}
