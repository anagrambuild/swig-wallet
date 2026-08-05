//! Replace authority action type.
//!
//! This scoped permission grants access only to the dedicated authority
//! replacement instruction for one target role. It is intentionally narrower
//! than ManageAuthority.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Permission to replace one role's signer without changing its type or
/// actions.
#[repr(C, align(8))]
#[derive(Debug, NoPadding)]
pub struct ReplaceAuthority {
    /// The role whose signer may be replaced.
    pub role_id: u32,
    pub _padding: [u8; 4],
}

impl ReplaceAuthority {
    pub const fn new(role_id: u32) -> Self {
        Self {
            role_id,
            _padding: [0; 4],
        }
    }
}

impl Transmutable for ReplaceAuthority {
    const LEN: usize = 8;
}

impl TransmutableMut for ReplaceAuthority {}

impl IntoBytes for ReplaceAuthority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) })
    }
}

impl<'a> Actionable<'a> for ReplaceAuthority {
    const TYPE: Permission = Permission::ReplaceAuthority;
    const REPEATABLE: bool = true;

    fn match_data(&self, data: &[u8]) -> bool {
        data.len() == 4 && self.role_id.to_le_bytes() == data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_matches_only_its_target_role() {
        let permission = ReplaceAuthority::new(7);

        assert_eq!(ReplaceAuthority::LEN, 8);
        assert!(permission.match_data(&7u32.to_le_bytes()));
        assert!(!permission.match_data(&6u32.to_le_bytes()));
        assert!(!permission.match_data(&[]));
    }
}
