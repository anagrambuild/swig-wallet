use pinocchio::program_error::ProgramError;

use crate::{IntoBytes, Transmutable, TransmutableMut};

use super::{Actionable, Permission};

static_assertions::const_assert!(core::mem::size_of::<SolRecurringLimit>() % 8 == 0);
#[repr(C)]
pub struct SolRecurringLimit {
    pub recurring_amount: u64,
    pub window: u64,
    pub last_reset: u64,
    pub current_amount: u64,
}

impl Transmutable for SolRecurringLimit {
    const LEN: usize = core::mem::size_of::<SolRecurringLimit>();
}

impl<'a> IntoBytes<'a> for SolRecurringLimit {
    fn into_bytes(&'a self) -> Result<&'a [u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl TransmutableMut for SolRecurringLimit {}

impl<'a> Actionable<'a> for SolRecurringLimit {
    const TYPE: Permission = Permission::SolRecurringLimit;

    /// TODO
    fn validate(&mut self) {
        todo!()
    }
}
