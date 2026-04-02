//! Rent destination action type.
//!
//! This module defines the RentDestination action type which marks an authority
//! as a valid rent destination for close instructions.

use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Marker action designating an authority as a valid rent destination.
///
/// This action contains no payload. Its presence alone indicates that the
/// authority is allowed to receive rent refunds during close operations.
#[repr(C)]
pub struct RentDestination;

impl Transmutable for RentDestination {
    const LEN: usize = 0;
}

impl TransmutableMut for RentDestination {}

impl IntoBytes for RentDestination {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(&[])
    }
}

impl<'a> Actionable<'a> for RentDestination {
    const TYPE: Permission = Permission::RentDestination;
    const REPEATABLE: bool = false;

    fn match_data(&self, _data: &[u8]) -> bool {
        true
    }
}
