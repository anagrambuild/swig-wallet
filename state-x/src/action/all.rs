use super::{Actionable, Permission};

use crate::{AsBytes, Transmutable, TransmutableMut};

// SANITY CHECK: Make sure the type size is a multiple of 8 bytes.
static_assertions::const_assert!(core::mem::size_of::<All>() % 8 == 0);

pub struct All;

impl Transmutable for All {
    /// Marker type with no data.
    const LEN: usize = 0;
}

impl TransmutableMut for All {}

impl<'a> AsBytes<'a> for All {}

impl<'a> Actionable<'a> for All {
    const TYPE: Permission = Permission::All;

    fn validate(&mut self) {
        // No validation needed for a marker type.
    }
}
