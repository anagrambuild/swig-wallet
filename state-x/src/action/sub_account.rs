use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::IntoBytes;
use crate::Transmutable;
use crate::TransmutableMut;
use no_padding::NoPadding;

#[repr(C,align(8))]
#[derive(Debug,NoPadding)]
pub struct SubAccount {
  pub sub_account: [u8; 32],
}

impl Transmutable for SubAccount {
    const LEN: usize = 32; // Since this is just a marker with no data
}

impl TransmutableMut for SubAccount {}

impl IntoBytes for SubAccount {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}


impl<'a> Actionable<'a> for SubAccount {
    const TYPE: Permission = Permission::SubAccount;
    const REPEATABLE: bool = true;

    fn match_data(&self, data: &[u8]) -> bool {
        data[0..32] == self.sub_account
    }
}
