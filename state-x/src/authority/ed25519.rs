use pinocchio::{account_info::AccountInfo, program_error::ProgramError};
use swig_assertions::sol_assert_bytes_eq;

use crate::{IntoBytes, SwigAuthenticateError, Transmutable, TransmutableMut};

use super::{Authority, AuthorityType};

pub struct ED25519Authority {
    pub public_key: [u8; 32],
}

impl<'a> Authority<'a> for ED25519Authority {
    const TYPE: AuthorityType = AuthorityType::Ed25519;
    const SESSION_BASED: bool = false;
    fn length(&self) -> usize {
        Self::LEN
    }

    fn authenticate(
        &self,
        account_infos: &[AccountInfo],
        authority_payload: &[u8],
        _data_payload: &[u8],
        _slot: u64,
    ) -> Result<(), ProgramError> {
        if authority_payload.len() != 1 {
            return Err(SwigAuthenticateError::InvalidAuthorityPayload.into());
        }

        let auth_account = account_infos
            .get(authority_payload[0] as usize)
            .ok_or(SwigAuthenticateError::InvalidAuthorityPayload)?;
        if sol_assert_bytes_eq(&self.public_key, auth_account.key(), 32) && auth_account.is_signer()
        {
            return Ok(());
        }
        Err(SwigAuthenticateError::InvalidAuthorityPayload.into())
    }
}

impl Transmutable for ED25519Authority {
    const LEN: usize = core::mem::size_of::<ED25519Authority>();
}

impl TransmutableMut for ED25519Authority {}

impl<'a> IntoBytes<'a> for ED25519Authority {
    fn into_bytes(&'a self) -> Result<&'a [u8], ProgramError> {
        let bytes =
            unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::LEN) };
        Ok(bytes)
    }
}
