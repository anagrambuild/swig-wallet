use core::any::Any;

use no_padding::NoPadding;
use pinocchio::{account_info::AccountInfo, program_error::ProgramError};
use swig_assertions::sol_assert_bytes_eq;

use super::{Authority, AuthorityInfo, AuthorityType};
use crate::{IntoBytes, SwigAuthenticateError, SwigStateError, Transmutable, TransmutableMut};

#[cfg(feature = "client")]
use bs58;

#[repr(C, align(8))]
#[derive(Debug, PartialEq, NoPadding)]
pub struct ED25519Authority {
    pub public_key: [u8; 32],
}

impl ED25519Authority {
    pub fn from_create_bytes(bytes: &[u8]) -> Result<Self, ProgramError> {
        if bytes.len() != 32 {
            return Err(SwigStateError::InvalidRoleData.into());
        }
        let public_key = bytes.try_into().unwrap();
        Ok(Self { public_key })
    }
}

impl Authority for ED25519Authority {
    const TYPE: AuthorityType = AuthorityType::Ed25519;
    const SESSION_BASED: bool = false;

    fn set_into_bytes(create_data: &[u8], bytes: &mut [u8]) -> Result<(), ProgramError> {
        if create_data.len() != 32 {
            return Err(SwigStateError::InvalidRoleData.into());
        }
        let authority = unsafe { ED25519Authority::load_mut_unchecked(bytes)? };
        authority.public_key = create_data.try_into().unwrap();
        Ok(())
    }
}

impl AuthorityInfo for ED25519Authority {
    fn authority_type(&self) -> AuthorityType {
        Self::TYPE
    }

    fn length(&self) -> usize {
        Self::LEN
    }

    fn session_based(&self) -> bool {
        Self::SESSION_BASED
    }

    fn match_data(&self, data: &[u8]) -> bool {
        sol_assert_bytes_eq(&self.public_key, data, 32)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn identity(&self) -> Result<&[u8], ProgramError> {
        Ok(self.public_key.as_ref())
    }

    fn authenticate(
        &mut self,
        account_infos: &[AccountInfo],
        authority_payload: &[u8],
        _data_payload: &[u8],
        _slot: u64,
    ) -> Result<(), ProgramError> {
        if authority_payload.len() != 1 {
            return Err(SwigAuthenticateError::InvalidAuthorityPayload.into());
        }
        ed25519_authenticate(
            account_infos,
            authority_payload[0] as usize,
            &self.public_key,
        )
    }
}

impl Transmutable for ED25519Authority {
    const LEN: usize = core::mem::size_of::<ED25519Authority>();
}

impl TransmutableMut for ED25519Authority {}

impl IntoBytes for ED25519Authority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

#[repr(C, align(8))]
#[derive(Debug, PartialEq, NoPadding)]
pub struct CreateEd25519SessionAuthority {
    pub public_key: [u8; 32],
    pub session_key: [u8; 32],
    pub max_session_length: u64,
}

impl CreateEd25519SessionAuthority {
    pub fn new(public_key: [u8; 32], session_key: [u8; 32], max_session_length: u64) -> Self {
        Self {
            public_key,
            session_key,
            max_session_length,
        }
    }
}

impl IntoBytes for CreateEd25519SessionAuthority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

impl Transmutable for CreateEd25519SessionAuthority {
    const LEN: usize = 64 + 8;
}

#[repr(C, align(8))]
#[derive(Debug, PartialEq, NoPadding)]
pub struct Ed25519SessionAuthority {
    pub public_key: [u8; 32],
    pub session_key: [u8; 32],
    pub max_session_length: u64,
    pub current_session_expiration: u64,
}

impl Ed25519SessionAuthority {
    pub fn new(public_key: [u8; 32], session_key: [u8; 32], max_session_length: u64) -> Self {
        Self {
            public_key,
            session_key,
            max_session_length,
            current_session_expiration: 0,
        }
    }
}

impl Transmutable for Ed25519SessionAuthority {
    const LEN: usize = core::mem::size_of::<Ed25519SessionAuthority>();
}

impl TransmutableMut for Ed25519SessionAuthority {}

impl IntoBytes for Ed25519SessionAuthority {
    fn into_bytes(&self) -> Result<&[u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}

impl Authority for Ed25519SessionAuthority {
    const TYPE: AuthorityType = AuthorityType::Ed25519Session;
    const SESSION_BASED: bool = true;

    fn set_into_bytes(create_data: &[u8], bytes: &mut [u8]) -> Result<(), ProgramError> {
        let create = unsafe { CreateEd25519SessionAuthority::load_unchecked(create_data)? };
        let authority = unsafe { Ed25519SessionAuthority::load_mut_unchecked(bytes)? };
        authority.public_key = create.public_key;
        authority.session_key = create.session_key;
        authority.max_session_length = create.max_session_length;
        Ok(())
    }
}

impl AuthorityInfo for Ed25519SessionAuthority {
    fn authority_type(&self) -> AuthorityType {
        Self::TYPE
    }

    fn length(&self) -> usize {
        Self::LEN
    }

    fn session_based(&self) -> bool {
        Self::SESSION_BASED
    }

    fn identity(&self) -> Result<&[u8], ProgramError> {
        Ok(self.public_key.as_ref())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn match_data(&self, data: &[u8]) -> bool {
        sol_assert_bytes_eq(&self.public_key, data, 32)
    }

    fn start_session(
        &mut self,
        session_key: [u8; 32],
        current_slot: u64,
        duration: u64,
    ) -> Result<(), ProgramError> {
        if sol_assert_bytes_eq(&self.session_key, &session_key, 32) {
            return Err(SwigAuthenticateError::InvalidSessionKeyCannotReuseSessionKey.into());
        }
        if duration > self.max_session_length {
            return Err(SwigAuthenticateError::InvalidSessionDuration.into());
        }
        self.current_session_expiration = current_slot + duration;
        self.session_key = session_key;
        Ok(())
    }

    fn authenticate_session(
        &mut self,
        account_infos: &[AccountInfo],
        authority_payload: &[u8],
        _data_payload: &[u8],
        slot: u64,
    ) -> Result<(), ProgramError> {
        if authority_payload.len() != 1 {
            return Err(SwigAuthenticateError::InvalidAuthorityPayload.into());
        }
        if slot > self.current_session_expiration {
            return Err(SwigAuthenticateError::PermissionDeniedSessionExpired.into());
        }
        ed25519_authenticate(
            account_infos,
            authority_payload[0] as usize,
            &self.session_key,
        )
    }

    fn authenticate(
        &mut self,
        account_infos: &[AccountInfo],
        authority_payload: &[u8],
        _data_payload: &[u8],
        _slot: u64,
    ) -> Result<(), ProgramError> {
        if authority_payload.len() != 1 {
            return Err(SwigAuthenticateError::InvalidAuthorityPayload.into());
        }
        ed25519_authenticate(
            account_infos,
            authority_payload[0] as usize,
            &self.public_key,
        )
    }
}

pub fn ed25519_authenticate(
    account_infos: &[AccountInfo],
    authority_index: usize,
    public_key: &[u8],
) -> Result<(), ProgramError> {
    let auth_account = account_infos
        .get(authority_index)
        .ok_or(SwigAuthenticateError::InvalidAuthorityEd25519MissingAuthorityAccount)?;
    if sol_assert_bytes_eq(public_key, auth_account.key(), 32) && auth_account.is_signer() {
        return Ok(());
    }
    Err(SwigAuthenticateError::PermissionDenied.into())
}
