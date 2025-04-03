use swig_assertions::*;
use swig_state_x::authority::ed25519::ED25519Authority;
use crate::error::SwigError;
use pinocchio::{account_info::AccountInfo, program_error::ProgramError};

use super::Authenticate;

impl<'a> Authenticate<'a, ED25519Authority> for ED25519Authority {
    fn authenticate(
        &self,
        account_infos: &[AccountInfo],
        authority_payload: &[u8],
        _data_payload: &[u8],
    ) -> Result<(), ProgramError> {
      if authority_payload.len() != 1 {
        return Err(SwigError::InvalidAuthorityPayload.into());
    }
    
    let auth_account = account_infos
        .get(authority_payload[0] as usize)
        .ok_or(SwigError::InvalidAuthorityPayload)?;
    if sol_assert_bytes_eq(&self.public_key, auth_account.key(), 32) && auth_account.is_signer() {
        return Ok(());
    }
    Err(SwigError::InvalidAuthorityPayload.into())
  }
}