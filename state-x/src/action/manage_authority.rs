use super::{Actionable, Permission};

use crate::{AsBytes, Transmutable, TransmutableMut};

// SANITY CHECK: Make sure the type size is a multiple of 8 bytes.
static_assertions::const_assert!(core::mem::size_of::<ManageAuthority>() % 8 == 0);

#[repr(C)]
pub struct ManageAuthority;

impl Transmutable for ManageAuthority {
    // Marker with no data.
    const LEN: usize = 0;
}

impl TransmutableMut for ManageAuthority {}

impl<'a> AsBytes<'a> for ManageAuthority {}

impl<'a> Actionable<'a> for ManageAuthority {
    const TYPE: Permission = Permission::ManageAuthority;

    fn validate(&mut self) {
        // No validation needed for a marker type.
    }
}
