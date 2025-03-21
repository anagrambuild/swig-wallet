use pinocchio::{account_info::AccountInfo, msg};
use swig_state::{
    authority::{Ed25519SessionAuthorityData, Ed25519SessionAuthorityDataMut},
    AuthorityType, Role,
};

use crate::{assertions::sol_assert_bytes_eq, error::SwigError};

use super::{ed25519, StartSession, ValidSession};

impl<'a> ValidSession<'a> for Ed25519SessionAuthorityDataMut<'a> {
    fn validate_session_data(&self, duration: u64, session_key: &'a [u8]) -> Result<(), SwigError> {
        if &duration > self.role_max_duration {
            msg!("failed max duration");
            return Err(SwigError::InvalidSessionData);
        }
        if sol_assert_bytes_eq(session_key, self.current_session_pubkey, 32) {
            return Err(SwigError::InvalidSessionData);
        }
        if sol_assert_bytes_eq(session_key, self.authority_pubkey, 32) {
            return Err(SwigError::InvalidSessionData);
        }
        Ok(())
    }
}

impl<'a> StartSession<'a> for Ed25519SessionAuthorityDataMut<'a> {
    fn start_session(
        self,
        duration: u64,
        session_key: &'a [u8],
        current_slot: u64,
    ) -> Result<(), SwigError> {
        self.validate_session_data(duration, session_key)?;
        *self.session_expires_at = current_slot + duration;
        *self.current_session_pubkey = session_key.try_into().unwrap();
        Ok(())
    }
}

pub fn authenticate(
    authority_data: &[u8],
    authority_payload: &[u8],
    account_infos: &[AccountInfo],
    current_slot: u64,
    session: bool,
) -> Result<(), SwigError> {
    let authority_data = Ed25519SessionAuthorityData::load(authority_data)?;
    if session {
        if authority_data.current_session_pubkey.len() != 32 {
            return Err(SwigError::InvalidAuthority);
        }
        msg!("authority_payload: {:?}", authority_payload);
        let auth_account = account_infos
            .get(authority_payload[0] as usize)
            .ok_or(SwigError::InvalidAuthorityPayload)?;

        if &current_slot > authority_data.session_expires_at {
            return Err(SwigError::PermissionDenied("Session Expired"));
        }
        if sol_assert_bytes_eq(
            authority_data.current_session_pubkey,
            auth_account.key(),
            32,
        ) && auth_account.is_signer()
        {
            return Ok(());
        }
    } else {
        return ed25519::authenticate(
            authority_data.authority_pubkey.as_slice(),
            authority_payload,
            account_infos,
        );
    }

    Err(SwigError::InvalidAuthorityPayload)
}
