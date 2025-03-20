use super::{AuthorityData, AuthorityType};

pub struct ED25519 {}

impl<'a> AuthorityData<'a> for ED25519 {
    const TYPE: AuthorityType = AuthorityType::Ed25519;

    fn from_bytes(bytes: &'a [u8]) -> &'a Self {
        unsafe { &*(bytes.as_ptr() as *const Self) }
    }

    fn length(&self) -> usize {
        0
    }
}
