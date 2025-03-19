use std::ops::Deref;

use super::{AuthorityData, AuthorityDataBuilder, AuthorityDataMut, AuthorityType};

#[repr(C)]
pub struct Ed25519Authority<'a> {
    pub public_key: &'a [u8; 32],
}

#[repr(C)]
pub struct Ed25519AuthorityMut<'a> {
    pub public_key: &'a mut [u8; 32],
}

#[derive(Default)]
pub struct Ed25519AuthorityBuilder {
    pub public_key: [u8; 32],
}

impl Ed25519AuthorityBuilder {
    pub fn new(public_key: [u8; 32]) -> Self {
        Self { public_key }
    }
}

impl Deref for Ed25519AuthorityBuilder {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.public_key
    }
}

impl<'a> AuthorityDataBuilder<'a> for Ed25519AuthorityBuilder {
    type Authority = Ed25519Authority<'a>;

    fn size(&self) -> usize {
        std::mem::size_of::<[u8; 32]>() + 1
    }

    fn build(&'a self) -> Ed25519Authority<'a> {
        Ed25519Authority::load_from_bytes(&self.public_key)
    }

    fn bytes(&self) -> Vec<u8> {
        self.public_key.to_vec()
    }
}

impl<'a> AuthorityData<'a> for Ed25519Authority<'a> {
    const TYPE: AuthorityType = AuthorityType::Ed25519;

    fn size(&self) -> usize {
        std::mem::size_of::<[u8; 32]>() + 1
    }

    fn load_from_bytes(data: &'a [u8]) -> Self {
        //ignore type byte
        Self {
            public_key: bytemuck::from_bytes(&data[1..33]),
        }
    }
}

impl<'a> AuthorityDataMut<'a> for Ed25519AuthorityMut<'a> {
    const TYPE: AuthorityType = AuthorityType::Ed25519;

    fn load_from_bytes_mut(data: &'a mut [u8]) -> Self {
        Self {
            public_key: bytemuck::from_bytes_mut(&mut data[0..32]),
        }
    }
}

#[repr(C)]
pub struct Ed25519SessionAuthority<'a> {
    pub public_key: &'a [u8; 32],
    pub session_public_key: &'a [u8; 32],
    //todo: question, do we need bloomfilter to ensure no key resuse iwth recent keys, how many ?
    pub expires_at: &'a u64,
}

#[repr(C)]
pub struct Ed25519SessionAuthorityMut<'a> {
    pub public_key: &'a mut [u8; 32],
    pub session_public_key: &'a mut [u8; 32],
    //todo: question, do we need bloomfilter to ensure no key resuse iwth recent keys, how many ?
    pub expires_at: &'a mut u64,
}

impl<'a> AuthorityData<'a> for Ed25519SessionAuthority<'a> {
    const TYPE: AuthorityType = AuthorityType::Ed25519Session;

    fn size(&self) -> usize {
        (std::mem::size_of::<[u8; 32]>() * 2) + std::mem::size_of::<u64>()
    }

    fn load_from_bytes(data: &'a [u8]) -> Self {
        let (public_key, rest) = data.split_at(std::mem::size_of::<[u8; 32]>());
        let (session_public_key, rest) = rest.split_at(std::mem::size_of::<[u8; 32]>());

        Self {
            public_key: bytemuck::from_bytes(public_key),
            session_public_key: bytemuck::from_bytes(session_public_key),
            expires_at: bytemuck::from_bytes(rest),
        }
    }
}

impl<'a> AuthorityDataMut<'a> for Ed25519SessionAuthorityMut<'a> {
    const TYPE: AuthorityType = AuthorityType::Ed25519Session;

    fn load_from_bytes_mut(data: &'a mut [u8]) -> Self {
        let (public_key, rest) = data.split_at_mut(std::mem::size_of::<[u8; 32]>());
        let (session_public_key, rest) = rest.split_at_mut(std::mem::size_of::<[u8; 32]>());

        Self {
            public_key: bytemuck::from_bytes_mut(public_key),
            session_public_key: bytemuck::from_bytes_mut(session_public_key),
            expires_at: bytemuck::from_bytes_mut(rest),
        }
    }
}

#[derive(Default)]
pub struct Ed25519SessionAuthorityBuilder {
    pub public_key: [u8; 32],
    pub session_public_key: [u8; 32],
    pub expires_at: u64,
}

impl<'a> AuthorityDataBuilder<'a> for Ed25519SessionAuthorityBuilder {
    type Authority = Ed25519SessionAuthority<'a>;

    fn size(&self) -> usize {
        std::mem::size_of::<[u8; 32]>() + 1
    }

    fn build(&'a self) -> Ed25519SessionAuthority<'a> {
        Ed25519SessionAuthority::load_from_bytes(&self.public_key)
    }
    fn into_bytes(&mut self) -> Vec<u8> {
        [
            &[Ed25519SessionAuthority::TYPE as u8],
            self.public_key.as_slice(),
            self.session_public_key.as_slice(),
            self.expires_at.to_le_bytes().as_slice(),
        ]
        .concat()
    }

    fn bytes(&self) -> Vec<u8> {
        [
            self.public_key.as_slice(),
            self.session_public_key.as_slice(),
            self.expires_at.to_le_bytes().as_slice(),
        ]
        .concat()
    }
}
