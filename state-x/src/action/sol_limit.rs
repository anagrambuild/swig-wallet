use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut};

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct SolLimit {
    pub amount: u64,
}

impl SolLimit {
    pub fn run(&mut self, lamport_diff: u64) -> Result<(), ProgramError> {
        if lamport_diff > self.amount {
            return Err(SwigAuthenticateError::PermissionDeniedInsufficientBalance.into());
        }
        self.amount -= lamport_diff;
        Ok(())
    }
}

impl Transmutable for SolLimit {
    const LEN: usize = core::mem::size_of::<SolLimit>();
}

impl TransmutableMut for SolLimit {}

impl IntoBytes for SolLimit {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> Actionable<'a> for SolLimit {
    const TYPE: Permission = Permission::SolLimit;
    const REPEATABLE: bool = false;
}
