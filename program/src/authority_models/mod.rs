use pinocchio::account_info::AccountInfo;
use swig_state::AuthorityType;

use crate::error::SwigError;
mod ed25519;
mod secp256k1;

#[inline(always)]
pub fn authenticate(
    authority: AuthorityType,
    stored_authority_data: &[u8],
    authority_payload: &[u8],
    data_payload: &[u8],
    account_infos: &[AccountInfo],
) -> Result<(), SwigError> {
    match authority {
        AuthorityType::Ed25519 => {
            ed25519::authenticate(stored_authority_data, authority_payload, account_infos)
        },
        AuthorityType::Secp256k1 => {
            secp256k1::authenticate(stored_authority_data, authority_payload, data_payload)
        },
    }
}
