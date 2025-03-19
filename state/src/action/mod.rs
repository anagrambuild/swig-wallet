#[macro_use]
mod marker;
pub mod sol;
pub mod tokens;
use bytemuck::{Pod, Zeroable};
use sol::SolLimit;

use crate::swig::SwigStateError;

pub trait Actionable<'a>: Sized {
    const TYPE: PermissionType;
    fn size(&self) -> usize;
    fn load_from_bytes(data: &'a [u8]) -> Result<Self, SwigStateError>;
    fn load_from_bytes_mut(data: &'a mut [u8]) -> Result<Self, SwigStateError>;
    fn into_bytes(self) -> Vec<u8>;
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
#[repr(C)]
pub enum PermissionType {
    #[default]
    None,
    SolLimit,
    SolRecurringLimit,
    Program,
    TokenLimit,
    TokenRecurringLimit,
    TokensLimit,
    TokensRecurringLimit,
    All,
    ManageAuthority,
    SubAccount,
}

impl PermissionType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::SolLimit,
            2 => Self::SolRecurringLimit,
            3 => Self::Program,
            4 => Self::TokenLimit,
            5 => Self::TokenRecurringLimit,
            6 => Self::TokensLimit,
            7 => Self::TokensRecurringLimit,
            8 => Self::All,
            9 => Self::ManageAuthority,
            10 => Self::SubAccount,
            _ => Self::None,
        }
    }
}

unsafe impl Pod for PermissionType {}
unsafe impl Zeroable for PermissionType {}

impl_permission_marker!(All, PermissionType::All);
impl_permission_marker!(ManageAuthority, PermissionType::ManageAuthority);

pub struct Action<'a> {
    pub permission_type: PermissionType,
    pub size: u16,
    pub data: &'a [u8],
}

impl<'a> Action<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, SwigStateError> {
        Ok(Self {
            permission_type: PermissionType::from_u8(data[0]),
            size: u16::from_le_bytes(data[1..3].try_into().unwrap()),
            data: &data[3..],
        })
    }

    pub fn into_actionable(&self) -> Result<impl Actionable<'a>, SwigStateError> {
        match self.permission_type {
            PermissionType::All => All::load_from_bytes(self.data),
            _ => panic!("Unsupported action type"),
        }
    }
}
