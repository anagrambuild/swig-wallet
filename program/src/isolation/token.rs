//! Token identity, immutable metadata, and personal balance protection.

use pinocchio::{
    account_info::AccountInfo,
    pubkey::Pubkey,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_pubkey::from_str;

use super::snapshot::{IsolationGuard, SignerSnapshot, TokenSnapshot};
use crate::{error::SwigError, util::token_integrity::hash_with_transfer_fee};

pub(super) const TOKEN_ACCOUNT_BASE_DATA_LEN: usize = 165;
pub(super) const TOKEN_MINT_BASE_LEN: usize = 82;
pub(super) const TOKEN_MULTISIG_LEN: usize = 355;
pub(super) const TOKEN_AUTHORITY_OFF: usize = 32;
pub(super) const TOKEN_AMOUNT_OFF: usize = 64;
pub(super) const TOKEN_STATE_OFF: usize = 108;
pub(super) const TOKEN_NATIVE_OPTION_OFF: usize = 109;
pub(super) const TOKEN_NATIVE_RESERVE_OFF: usize = 113;
const TOKEN_NATIVE_TAG_RANGE: core::ops::Range<usize> =
    TOKEN_NATIVE_OPTION_OFF..TOKEN_NATIVE_RESERVE_OFF;
const TOKEN_NATIVE_RESERVE_RANGE: core::ops::Range<usize> =
    TOKEN_NATIVE_RESERVE_OFF..TOKEN_NATIVE_RESERVE_OFF + 8;
// The metadata snapshot omits the eight-byte token amount.
const TOKEN_REST_RESERVE_RANGE: core::ops::Range<usize> =
    TOKEN_NATIVE_RESERVE_RANGE.start - 8..TOKEN_NATIVE_RESERVE_RANGE.end - 8;
const TOKEN_2022_ACCOUNT_TYPE_OFF: usize = 165;
const TOKEN_2022_TYPE_ACCOUNT: u8 = 2;
const TOKEN_2022_TYPE_MINT: u8 = 1;
pub(super) const WSOL_MINT: Pubkey = from_str("So11111111111111111111111111111111111111112");

#[inline(always)]
fn coption_is_key(data: &[u8], off: usize, authority_key: &Pubkey) -> bool {
    data.len() >= off + 36
        && data[off..off + 4] == [1, 0, 0, 0]
        && &data[off + 4..off + 36] == authority_key.as_ref()
}

#[inline(always)]
pub(super) fn is_token_program(owner: &Pubkey) -> bool {
    owner == &crate::SPL_TOKEN_ID || owner == &crate::SPL_TOKEN_2022_ID
}

#[inline(always)]
pub(super) fn is_token_account(data: &[u8]) -> bool {
    let len = data.len();
    (len == TOKEN_ACCOUNT_BASE_DATA_LEN)
        || (len > TOKEN_ACCOUNT_BASE_DATA_LEN
            && len != TOKEN_MULTISIG_LEN
            && data[TOKEN_2022_ACCOUNT_TYPE_OFF] == TOKEN_2022_TYPE_ACCOUNT)
}

#[inline(always)]
pub(super) fn is_mint_account(data: &[u8]) -> bool {
    let len = data.len();
    if is_token_account(data) {
        return false;
    }
    (len == TOKEN_MINT_BASE_LEN)
        || (len > TOKEN_ACCOUNT_BASE_DATA_LEN
            && len != TOKEN_MULTISIG_LEN
            && data[TOKEN_2022_ACCOUNT_TYPE_OFF] == TOKEN_2022_TYPE_MINT)
}

#[inline(never)]
pub(super) fn is_mint_authority(data: &[u8], authority_key: &Pubkey) -> bool {
    coption_is_key(data, 0, authority_key) || coption_is_key(data, 46, authority_key)
}

#[inline(never)]
pub(super) fn is_multisig_signer(data: &[u8], authority_key: &Pubkey) -> bool {
    if data.len() != TOKEN_MULTISIG_LEN || data[2] != 1 {
        return false;
    }
    let n = data[1] as usize;
    if n > 11 {
        return false;
    }
    let mut off = 3;
    for _ in 0..n {
        if &data[off..off + 32] == authority_key.as_ref() {
            return true;
        }
        off += 32;
    }
    false
}

#[inline(always)]
fn token_owner_matches_signer_or_multisig(
    owner: &[u8],
    authority_key: &Pubkey,
    all_accounts: &[AccountInfo],
) -> bool {
    if owner == authority_key.as_ref() {
        return true;
    }
    for account in all_accounts {
        // Most CPI accounts cannot be multisigs. Check their fixed size before
        // comparing keys or reading authority entries.
        if account.data_len() != TOKEN_MULTISIG_LEN {
            continue;
        }
        if account.key().as_ref() != owner {
            continue;
        }
        if !is_token_program(account.owner()) {
            return false;
        }
        let data = unsafe { account.borrow_data_unchecked() };
        return is_multisig_signer(data, authority_key);
    }
    false
}

#[inline(always)]
pub(super) fn token_owner_is_any_signer_or_multisig(
    owner: &[u8],
    all_accounts: &[AccountInfo],
    signers: &[SignerSnapshot],
) -> bool {
    for signer in signers {
        let key = unsafe { all_accounts.get_unchecked(signer.index as usize).key() };
        if token_owner_matches_signer_or_multisig(owner, key, all_accounts) {
            return true;
        }
    }
    false
}

impl IsolationGuard<'_> {
    /// Preserve token identity/control and require non-decreasing personal value.
    #[inline(never)]
    pub(super) fn validate_token_accounts(&self) -> ProgramResult {
        for before in self.tokens.as_slice() {
            let account = &self.accounts[before.index as usize];

            // Preserve the owning token program and the account's data shape.
            let owner = account.owner();
            let expected_owner = if before.is_legacy {
                &crate::SPL_TOKEN_ID
            } else {
                &crate::SPL_TOKEN_2022_ID
            };
            if owner != expected_owner
                || account.data_len() != before.data_len as usize
                || account.data_len() < TOKEN_ACCOUNT_BASE_DATA_LEN
            {
                return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
            }
            let data = unsafe { account.borrow_data_unchecked() };

            // Preserve identity and authorities. The WSOL reserve has its own rule below.
            let rest = &before.rest;
            let is_wsol = before.is_legacy && rest[..32] == WSOL_MINT;
            let metadata_matches = if is_wsol {
                data[72..TOKEN_NATIVE_RESERVE_RANGE.start]
                    == rest[64..TOKEN_REST_RESERVE_RANGE.start]
                    && data[TOKEN_NATIVE_RESERVE_RANGE.end..TOKEN_ACCOUNT_BASE_DATA_LEN]
                        == rest[TOKEN_REST_RESERVE_RANGE.end..]
            } else {
                data[72..TOKEN_ACCOUNT_BASE_DATA_LEN] == rest[64..]
            };
            if data[..64] != rest[..64] || !metadata_matches {
                return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
            }
            if let Some(previous_hash) = before.tail_hash {
                let tail = hash_with_transfer_fee(
                    &data[TOKEN_ACCOUNT_BASE_DATA_LEN..],
                    owner,
                    &[],
                    before.tail_fee_offset,
                )
                .map_err(|_| SwigError::PermissionDeniedAuthorityExternalAssetChange)?;
                if tail != previous_hash {
                    return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
                }
            }

            // Ordinary token amounts cannot decrease. WSOL also accounts for its reserve.
            let mut amount = [0u8; 8];
            amount.copy_from_slice(&data[TOKEN_AMOUNT_OFF..TOKEN_AMOUNT_OFF + 8]);
            let amount = u64::from_le_bytes(amount);
            if is_wsol {
                validate_wsol_value(before, data, amount)?;
            } else if amount < before.amount {
                return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
            }
            if account.lamports() < before.lamports {
                return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
            }
        }
        Ok(())
    }
}

/// Permit canonical SyncNative reserve refreshes without reducing total WSOL value.
#[inline(never)]
fn validate_wsol_value(before: &TokenSnapshot, data: &[u8], amount: u64) -> ProgramResult {
    if data.len() != TOKEN_ACCOUNT_BASE_DATA_LEN
        || data[TOKEN_STATE_OFF] != 1
        || data[TOKEN_NATIVE_TAG_RANGE] != [1, 0, 0, 0]
    {
        return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
    }
    let previous_reserve = u64::from_le_bytes(
        before.rest[TOKEN_REST_RESERVE_RANGE]
            .try_into()
            .map_err(|_| SwigError::PermissionDeniedAuthorityExternalAssetChange)?,
    );
    let reserve = u64::from_le_bytes(
        data[TOKEN_NATIVE_RESERVE_RANGE]
            .try_into()
            .map_err(|_| SwigError::PermissionDeniedAuthorityExternalAssetChange)?,
    );
    if reserve != previous_reserve
        && reserve != Rent::get()?.minimum_balance(TOKEN_ACCOUNT_BASE_DATA_LEN)
    {
        return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
    }
    let previous_value = before
        .amount
        .checked_add(previous_reserve)
        .ok_or(SwigError::PermissionDeniedAuthorityExternalAssetChange)?;
    let current_value = amount
        .checked_add(reserve)
        .ok_or(SwigError::PermissionDeniedAuthorityExternalAssetChange)?;
    if current_value < previous_value {
        return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
    }
    Ok(())
}
