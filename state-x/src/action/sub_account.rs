use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::IntoBytes;
use crate::Transmutable;
use crate::TransmutableMut;
pub struct SubAccount {
  pub sub_account: [u8; 32],
}

impl Transmutable for SubAccount {
    const LEN: usize = 32; // Since this is just a marker with no data
}

impl TransmutableMut for SubAccount {}

impl<'a> IntoBytes<'a> for SubAccount {
    fn into_bytes(&'a self) -> Result<&'a [u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}


impl<'a> Actionable<'a> for SubAccount {
    const TYPE: Permission = Permission::SubAccount;



    fn validate(&mut self) {
        // No validation needed for a marker type
    }
}
