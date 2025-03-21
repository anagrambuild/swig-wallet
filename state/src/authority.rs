use pinocchio::msg;

use crate::{AuthorityType, SwigStateError};

pub struct Ed25519SessionAuthorityData<'a> {
    pub authority_pubkey: &'a [u8; 32],
    pub current_session_pubkey: &'a [u8; 32],
    pub role_max_duration: &'a u64,
    pub session_expires_at: &'a u64,
}

#[derive(Debug)]
pub struct Ed25519SessionAuthorityDataMut<'a> {
    pub authority_pubkey: &'a mut [u8; 32],
    pub current_session_pubkey: &'a mut [u8; 32],
    pub role_max_duration: &'a mut u64,
    pub session_expires_at: &'a mut u64,
}

pub struct Ed25519SessionAuthorityDataCreate<'a> {
    pub authority_pubkey: &'a [u8; 32],
    pub role_max_duration: &'a u64,
}

impl<'a> Ed25519SessionAuthorityDataCreate<'a> {
    const SIZE: usize = 32 + 8;
    pub fn new(authority_pubkey: &'a [u8; 32], role_max_duration: &'a u64) -> Self {
        Self {
            authority_pubkey,
            role_max_duration,
        }
    }

    pub fn into_bytes(self) -> [u8; Ed25519SessionAuthorityDataCreate::SIZE] {
        let mut data = [0u8; Ed25519SessionAuthorityDataCreate::SIZE];
        data[..32].copy_from_slice(self.authority_pubkey);
        data[32..40].copy_from_slice(&self.role_max_duration.to_le_bytes());
        data
    }

    pub fn load(data: &'a [u8]) -> Result<Self, SwigStateError> {
        if data.len() != Ed25519SessionAuthorityDataCreate::SIZE {
            return Err(SwigStateError::InvalidAuthority);
        }
        let (authority_pubkey, rest) = data.split_at(32);
        let (role_max_duration, _) = rest.split_at(8);
        Ok(Self {
            authority_pubkey: authority_pubkey
                .try_into()
                .map_err(|_| SwigStateError::InvalidAuthority)?,
            role_max_duration: bytemuck::from_bytes(role_max_duration),
        })
    }
}

impl<'a> Ed25519SessionAuthorityData<'a> {
    const SIZE: usize = 80;

    pub fn new(authority_pubkey: &'a [u8; 32], role_max_duration: &'a u64) -> Self {
        let current_session_pubkey = &[0u8; 32];
        let session_expires_at = &0u64;
        Self {
            authority_pubkey,
            current_session_pubkey,
            role_max_duration,
            session_expires_at,
        }
    }

    pub fn into_bytes(self) -> [u8; Ed25519SessionAuthorityData::SIZE] {
        let mut data = [0u8; Ed25519SessionAuthorityData::SIZE];
        data[..32].copy_from_slice(self.authority_pubkey);
        data[32..64].copy_from_slice(self.current_session_pubkey);
        data[64..72].copy_from_slice(&self.role_max_duration.to_le_bytes());
        data[72..80].copy_from_slice(&self.session_expires_at.to_le_bytes());
        data
    }

    pub fn load(data: &'a [u8]) -> Result<Self, SwigStateError> {
        if data.len() != Ed25519SessionAuthorityData::SIZE {
            return Err(SwigStateError::InvalidAuthority);
        }
        let (authority_pubkey, rest) = data.split_at(32);
        let (current_session_pubkey, rest) = rest.split_at(32);
        let (role_max_duration, rest) = rest.split_at(8);
        let (session_expires_at, _) = rest.split_at(8);
        Ok(Self {
            authority_pubkey: authority_pubkey
                .try_into()
                .map_err(|_| SwigStateError::InvalidAuthority)?,
            current_session_pubkey: current_session_pubkey
                .try_into()
                .map_err(|_| SwigStateError::InvalidAuthority)?,
            role_max_duration: bytemuck::from_bytes(role_max_duration),
            session_expires_at: bytemuck::from_bytes(session_expires_at),
        })
    }
}

impl<'a> Ed25519SessionAuthorityDataMut<'a> {
    pub fn into_bytes(self) -> [u8; Ed25519SessionAuthorityData::SIZE] {
        let mut data = [0u8; Ed25519SessionAuthorityData::SIZE];
        data[..32].copy_from_slice(self.authority_pubkey);
        data[32..64].copy_from_slice(self.current_session_pubkey);
        data[64..72].copy_from_slice(&self.role_max_duration.to_le_bytes());
        data[72..80].copy_from_slice(&self.session_expires_at.to_le_bytes());
        data
    }

    pub fn load(data: &'a mut [u8]) -> Result<Self, SwigStateError> {
        if data.len() != Ed25519SessionAuthorityData::SIZE {
            return Err(SwigStateError::InvalidAuthority);
        }
        let (authority_pubkey, rest) = data.split_at_mut(32);
        let (current_session_pubkey, rest) = rest.split_at_mut(32);
        let (role_max_duration, rest) = rest.split_at_mut(8);
        let (session_expires_at, _) = rest.split_at_mut(8);
        Ok(Self {
            authority_pubkey: authority_pubkey
                .try_into()
                .map_err(|_| SwigStateError::InvalidAuthority)?,
            current_session_pubkey: current_session_pubkey
                .try_into()
                .map_err(|_| SwigStateError::InvalidAuthority)?,
            role_max_duration: bytemuck::from_bytes_mut(role_max_duration),
            session_expires_at: bytemuck::from_bytes_mut(session_expires_at),
        })
    }
}

pub struct Ed25519AuthorityData<'a> {
    pub authority_pubkey: &'a [u8; 32],
}

impl<'a> Ed25519AuthorityData<'a> {
    const SIZE: usize = 32;
    pub fn load(data: &'a [u8]) -> Result<Self, SwigStateError> {
        if data.len() != Ed25519AuthorityData::SIZE {
            return Err(SwigStateError::InvalidAuthority);
        }
        let (authority_pubkey, _) = data.split_at(32);
        Ok(Self {
            authority_pubkey: authority_pubkey
                .try_into()
                .map_err(|_| SwigStateError::InvalidAuthority)?,
        })
    }
}
