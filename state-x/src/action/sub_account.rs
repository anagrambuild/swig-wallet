use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct SubAccount {
    pub sub_account: [u8; 32], // this will be 0 until the sub-account is created
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
        true
    }

    fn valid_layout(data: &'a [u8]) -> Result<bool, ProgramError> {
        Ok(data.len() == Self::LEN && data[0..32] == [0u8; 32])
    }
}
