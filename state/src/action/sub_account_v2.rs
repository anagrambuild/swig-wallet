//! V2 sub-account action types.
//!
//! These are the flattened, scoped permissions a role can hold for V2
//! sub-accounts. Unlike V1's single `SubAccount` action, access is expressed as
//! separate permission types so presence grants and absence denies — there is
//! no bundled grant object and no per-action enabled flag.
//!
//! - [`SubAccountV2Create`] — a zero-length, non-repeatable marker granting the
//!   ability to create V2 sub-accounts.
//! - [`SubAccountV2All`] / [`SubAccountV2Sign`] / [`SubAccountV2Withdraw`] /
//!   [`SubAccountV2Toggle`] — repeatable, each scoped to a single `subacc_id`.
//!
//! The scoped types share an identical 8-byte body and match on `subacc_id`,
//! reusing the same repeatable-action mechanism as V1's `SubAccount`.

use no_padding::NoPadding;
use pinocchio::program_error::ProgramError;

use super::{Actionable, Permission};
use crate::{IntoBytes, Transmutable, TransmutableMut};

/// Zero-length marker granting permission to create V2 sub-accounts.
pub struct SubAccountV2Create;

impl Transmutable for SubAccountV2Create {
    const LEN: usize = 0;
}

impl TransmutableMut for SubAccountV2Create {}

impl IntoBytes for SubAccountV2Create {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        Ok(&[])
    }
}

impl<'a> Actionable<'a> for SubAccountV2Create {
    const TYPE: Permission = Permission::SubAccountV2Create;
    /// A role needs at most one create marker.
    const REPEATABLE: bool = false;

    fn match_data(&self, _data: &[u8]) -> bool {
        true
    }
}

/// Defines a scoped V2 sub-account permission: an 8-byte body carrying a
/// `subacc_id`, repeatable, matched on that id.
macro_rules! scoped_v2_permission {
    ($name:ident, $permission:expr, $doc:literal) => {
        #[doc = $doc]
        #[repr(C, align(8))]
        #[derive(Debug, NoPadding)]
        pub struct $name {
            /// The sub-account this permission is scoped to.
            pub subacc_id: u32,
            pub _padding: [u8; 4],
        }

        impl $name {
            /// Creates a new scoped permission for `subacc_id`.
            pub fn new(subacc_id: u32) -> Self {
                Self {
                    subacc_id,
                    _padding: [0; 4],
                }
            }
        }

        impl Transmutable for $name {
            /// 4 (subacc_id) + 4 (padding) = 8
            const LEN: usize = 8;
        }

        impl TransmutableMut for $name {}

        impl IntoBytes for $name {
            fn into_bytes(&self) -> Result<&[u8], ProgramError> {
                Ok(unsafe {
                    core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN)
                })
            }
        }

        impl<'a> Actionable<'a> for $name {
            const TYPE: Permission = $permission;
            const REPEATABLE: bool = true;

            /// Matches when `data` is the little-endian `subacc_id` this
            /// permission is scoped to.
            fn match_data(&self, data: &[u8]) -> bool {
                data.len() == 4 && self.subacc_id.to_le_bytes() == data
            }
        }
    };
}

scoped_v2_permission!(
    SubAccountV2All,
    Permission::SubAccountV2All,
    "Scoped umbrella permission for sign/withdraw/toggle on one `subacc_id`."
);
scoped_v2_permission!(
    SubAccountV2Sign,
    Permission::SubAccountV2Sign,
    "Scoped permission to sign as one V2 sub-account."
);
scoped_v2_permission!(
    SubAccountV2Withdraw,
    Permission::SubAccountV2Withdraw,
    "Scoped permission to withdraw from one V2 sub-account."
);
scoped_v2_permission!(
    SubAccountV2Toggle,
    Permission::SubAccountV2Toggle,
    "Scoped permission to toggle one V2 sub-account."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scoped_layout() {
        assert_eq!(SubAccountV2All::LEN, 8);
        assert_eq!(core::mem::size_of::<SubAccountV2Sign>(), 8);
        assert_eq!(core::mem::align_of::<SubAccountV2Withdraw>(), 8);
        assert_eq!(SubAccountV2Create::LEN, 0);
    }

    #[test]
    fn test_match_data_on_subacc_id() {
        let action = SubAccountV2Sign::new(5);
        assert!(action.match_data(&5u32.to_le_bytes()));
        assert!(!action.match_data(&6u32.to_le_bytes()));
        assert!(!action.match_data(&[])); // empty never matches a scoped id
        assert!(!action.match_data(&5u64.to_le_bytes())); // wrong length
    }

    #[test]
    fn test_roundtrip() {
        let action = SubAccountV2All::new(42);
        let bytes = action.into_bytes().unwrap();
        assert_eq!(bytes.len(), 8);
        let loaded = unsafe { SubAccountV2All::load_unchecked(bytes).unwrap() };
        assert_eq!(loaded.subacc_id, 42);
    }

    /// Builds an `[Action header][data]` byte buffer for a scoped V2 action.
    fn scoped_action_bytes(permission: super::Permission, subacc_id: u32) -> Vec<u8> {
        use crate::action::Action;
        let mut buf = Vec::new();
        // header: type(u16), length(u16)=8, boundary(u32) — boundary unused by the
        // sequential dedup walk.
        buf.extend_from_slice(&(permission as u16).to_le_bytes());
        buf.extend_from_slice(&8u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(buf.len(), Action::LEN);
        buf.extend_from_slice(&subacc_id.to_le_bytes());
        buf.extend_from_slice(&[0u8; 4]);
        buf
    }

    #[test]
    fn test_reject_duplicate_v2_scoped() {
        use crate::action::{ActionLoader, Permission};

        // Same type + same id twice → rejected.
        let mut dup = scoped_action_bytes(Permission::SubAccountV2Sign, 3);
        dup.extend(scoped_action_bytes(Permission::SubAccountV2Sign, 3));
        assert!(ActionLoader::reject_duplicate_v2_scoped(&dup).is_err());

        // Same type, different id → allowed (one role, many sub-accounts).
        let mut diff_id = scoped_action_bytes(Permission::SubAccountV2Sign, 3);
        diff_id.extend(scoped_action_bytes(Permission::SubAccountV2Sign, 4));
        assert!(ActionLoader::reject_duplicate_v2_scoped(&diff_id).is_ok());

        // Same id, different type → allowed (Sign and Withdraw for one sub-account).
        let mut diff_type = scoped_action_bytes(Permission::SubAccountV2Sign, 3);
        diff_type.extend(scoped_action_bytes(Permission::SubAccountV2Withdraw, 3));
        assert!(ActionLoader::reject_duplicate_v2_scoped(&diff_type).is_ok());
    }
}
