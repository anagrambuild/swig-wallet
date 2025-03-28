use pinocchio::account_info::AccountInfo;
use swig_state::{AuthorityType, Role};

use crate::error::SwigError;
mod ed25519;
mod ed25519_session;
mod secp256k1;

#[inline(always)]
pub fn authenticate(
    authority: AuthorityType,
    stored_authority_data: &[u8],
    authority_payload: &[u8],
    data_payload: &[u8],
    account_infos: &[AccountInfo],
    current_slot: u64,
    session: bool,
) -> Result<(), SwigError> {
    match authority {
        AuthorityType::Ed25519 => {
            ed25519::authenticate(stored_authority_data, authority_payload, account_infos)
        },
        AuthorityType::Secp256k1 => {
            secp256k1::authenticate(stored_authority_data, authority_payload, data_payload)
        },
        AuthorityType::Ed25519Session => ed25519_session::authenticate(
            stored_authority_data,
            authority_payload,
            account_infos,
            current_slot,
            session,
        ),
        AuthorityType::Secp256k1Session => {
            secp256k1::authenticate(stored_authority_data, authority_payload, data_payload)
        },
        _ => Err(SwigError::InvalidAuthorityType),
    }
}

pub trait ValidSession<'a> {
    fn validate_session_data(&self, duration: u64, session_key: &'a [u8]) -> Result<(), SwigError>;
}

pub trait StartSession<'a> {
    fn start_session(
        self,
        duration: u64,
        session_key: &'a [u8],
        current_slot: u64,
    ) -> Result<(), SwigError>;
}
