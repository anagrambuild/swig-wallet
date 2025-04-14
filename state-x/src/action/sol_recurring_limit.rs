use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct SolRecurringLimit {
    pub recurring_amount: u64,
    pub window: u64,
    pub last_reset: u64,
    pub current_amount: u64,
}

impl SolRecurringLimit {
    pub fn run(&mut self, lamport_diff: u64, current_slot: u64) -> Result<(), ProgramError> {
        if current_slot - self.last_reset > self.window && lamport_diff <= self.recurring_amount {
            self.current_amount = self.recurring_amount;
            self.last_reset = current_slot;
        }
        if lamport_diff > self.current_amount {
            return Err(ProgramError::InsufficientFunds);
        }
        self.current_amount -= lamport_diff;
        Ok(())
    }
}
impl Transmutable for SolRecurringLimit {
    const LEN: usize = core::mem::size_of::<SolRecurringLimit>();
}

impl IntoBytes for SolRecurringLimit {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl TransmutableMut for SolRecurringLimit {}

impl<'a> Actionable<'a> for SolRecurringLimit {
    const TYPE: Permission = Permission::SolRecurringLimit;
    const REPEATABLE: bool = false;
}
