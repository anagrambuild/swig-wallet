use swig_assertions::*;
use crate::error::SwigError;
use pinocchio::{account_info::AccountInfo, msg};

pub fn authenticate(
    authority_data: &[u8],
    authority_payload: &[u8],
    account_infos: &[AccountInfo],
) -> Result<(), SwigError> {
    if authority_payload.len() != 1 {
        return Err(SwigError::InvalidAuthorityPayload);
    }
    if authority_data.len() != 32 {
        return Err(SwigError::InvalidAuthorityPayload);
    }
    let auth_account = account_infos
        .get(authority_payload[0] as usize)
        .ok_or(SwigError::InvalidAuthorityPayload)?;
    if sol_assert_bytes_eq(authority_data, auth_account.key(), 32) && auth_account.is_signer() {
        return Ok(());
    }
    Err(SwigError::InvalidAuthorityPayload)
}
