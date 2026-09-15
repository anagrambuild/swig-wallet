//! Preserve signer-controlled mint, multisig, stake, vote, nonce, and program data.

use super::{
    snapshot::{IsolationGuard, SignerSnapshot},
    token::{
        is_mint_account, is_mint_authority, is_multisig_signer, is_token_program,
        TOKEN_MINT_BASE_LEN,
    },
};
use crate::{error::SwigError, util::hash_except};
use pinocchio::{account_info::AccountInfo, pubkey::Pubkey, ProgramResult};

const STAKE_STAKER_OFF: usize = 12;
const STAKE_WITHDRAWER_OFF: usize = 44;
const VOTE_WITHDRAWER_OFF: usize = 32;
const NONCE_AUTHORITY_OFF_A: usize = 4;
const NONCE_AUTHORITY_OFF_B: usize = 40;
const NONCE_ACCOUNT_LEN: usize = 80;
const PROGRAMDATA_AUTHORITY_TAG_OFF: usize = 12;
const PROGRAMDATA_AUTHORITY_OFF: usize = 16;

#[inline(always)]
pub(super) fn any_signer_controls_frozen(
    account: &AccountInfo,
    all_accounts: &[AccountInfo],
    signers: &[SignerSnapshot],
) -> bool {
    for signer in signers {
        let key = unsafe { all_accounts.get_unchecked(signer.index as usize).key() };
        if signer_controls_frozen_account(account, key) {
            return true;
        }
    }
    false
}

#[inline(never)]
pub(super) fn signer_controls_frozen_account(
    account: &AccountInfo,
    authority_key: &Pubkey,
) -> bool {
    let owner = account.owner();
    let len = account.data_len();
    if is_token_program(owner) {
        if len < TOKEN_MINT_BASE_LEN {
            return false;
        }
        let data = unsafe { account.borrow_data_unchecked() };
        if is_mint_account(data) {
            return is_mint_authority(data, authority_key);
        }
        return is_multisig_signer(data, authority_key);
    }
    if owner == &crate::STAKING_ID && len >= STAKE_WITHDRAWER_OFF + 32 {
        let data = unsafe { account.borrow_data_unchecked() };
        return &data[STAKE_STAKER_OFF..STAKE_STAKER_OFF + 32] == authority_key.as_ref()
            || &data[STAKE_WITHDRAWER_OFF..STAKE_WITHDRAWER_OFF + 32] == authority_key.as_ref();
    }
    if owner == &crate::VOTE_PROGRAM_ID && len >= VOTE_WITHDRAWER_OFF + 32 {
        let data = unsafe { account.borrow_data_unchecked() };
        return &data[VOTE_WITHDRAWER_OFF..VOTE_WITHDRAWER_OFF + 32] == authority_key.as_ref();
    }
    if owner == &crate::SYSTEM_PROGRAM_ID && len == NONCE_ACCOUNT_LEN {
        let data = unsafe { account.borrow_data_unchecked() };
        return &data[NONCE_AUTHORITY_OFF_A..NONCE_AUTHORITY_OFF_A + 32] == authority_key.as_ref()
            || &data[NONCE_AUTHORITY_OFF_B..NONCE_AUTHORITY_OFF_B + 32] == authority_key.as_ref();
    }
    if owner == &crate::BPF_LOADER_UPGRADEABLE_ID && len >= PROGRAMDATA_AUTHORITY_OFF + 32 {
        let data = unsafe { account.borrow_data_unchecked() };
        return data[PROGRAMDATA_AUTHORITY_TAG_OFF..PROGRAMDATA_AUTHORITY_TAG_OFF + 4]
            == [1, 0, 0, 0]
            && &data[PROGRAMDATA_AUTHORITY_OFF..PROGRAMDATA_AUTHORITY_OFF + 32]
                == authority_key.as_ref();
    }
    false
}

/// Requires unchanged account data and program ownership, with no decrease in lamports.
#[inline(always)]
pub(super) fn validate_frozen_accounts(
    guard: &IsolationGuard,
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    for before in guard.frozen.as_slice() {
        let account = unsafe { all_accounts.get_unchecked(before.index as usize) };
        if account.lamports() < before.lamports {
            return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
        }
        let data = unsafe { account.borrow_data_unchecked() };
        let hash = hash_except(data, account.owner(), &[]);
        if hash != before.hash {
            return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
        }
    }
    Ok(())
}
