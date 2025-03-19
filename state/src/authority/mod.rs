use std::ops::Deref;

use ed25519::{Ed25519Authority, Ed25519AuthorityBuilder};

pub mod ed25519;
pub mod secp256k1;
#[derive(PartialEq, Debug, Clone, Copy, Default)]
#[repr(u8)]
pub enum AuthorityType {
    #[default]
    None,
    Ed25519,
    Ed25519Session,
    Secp256k1,
    Secp256k1Session,
    Secp256r1Session, //Syscall
    R1PasskeySession, //Groth16
}

impl AuthorityType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Ed25519,
            2 => Self::Ed25519Session,
            3 => Self::Secp256k1,
            4 => Self::Secp256k1Session,
            5 => Self::Secp256r1Session,
            6 => Self::R1PasskeySession,
            _ => Self::None,
        }
    }
}

unsafe impl bytemuck::Zeroable for AuthorityType {}
unsafe impl bytemuck::Pod for AuthorityType {}

pub trait AuthorityData<'a> {
    const TYPE: AuthorityType;
    fn size(&self) -> usize;
    fn load_from_bytes(data: &'a [u8]) -> Self;
}

pub trait AuthorityDataMut<'a> {
    const TYPE: AuthorityType;
    fn load_from_bytes_mut(data: &'a mut [u8]) -> Self;
}

pub trait AuthorityDataBuilder<'a> {
    type Authority: AuthorityData<'a>;

    fn build(&'a self) -> Self::Authority;
    fn size(&self) -> usize;
    fn bytes(&self) -> Vec<u8>;
    fn into_bytes(&mut self) -> Vec<u8> {
        [
            &[Self::Authority::TYPE as u8],
            (self.size() as u16).to_le_bytes().as_slice(),
            self.bytes().as_slice(),
        ]
        .concat()
    }
}

pub struct Authority<'a> {
    pub authority_type: AuthorityType,
    pub authority_size: u16,
    pub authority_data: &'a [u8],
}

impl<'a> Authority<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Self {
        Self {
            authority_type: AuthorityType::from_u8(data[0]),
            authority_size: u16::from_le_bytes(data[1..3].try_into().unwrap()),
            authority_data: &data[3..],
        }
    }

    pub fn into_authority_data(&self) -> impl AuthorityData<'a> {
        match self.authority_type {
            AuthorityType::Ed25519 => Ed25519Authority::load_from_bytes(self.authority_data),
            _ => panic!("Unsupported authority type"),
        }
    }
}
