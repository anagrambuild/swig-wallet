//! Bound outer signers' net SOL decreases by new-account rent.

use pinocchio::{
    account_info::AccountInfo,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};

use super::IsolationGuard;
use crate::error::SwigError;

#[inline(always)]
pub(super) fn validate_signer_balances(
    guard: &IsolationGuard,
    all_accounts: &[AccountInfo],
) -> ProgramResult {
    let mut spent = 0u64;
    for before in guard.signers.as_slice() {
        // Indices belong to the account list retained by this guard.
        let account = unsafe { all_accounts.get_unchecked(before.index as usize) };
        if before.system_account
            && (!account.is_owned_by(&crate::SYSTEM_PROGRAM_ID) || account.data_len() != 0)
        {
            return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
        }
        let after = account.lamports();
        if after < before.lamports {
            spent = spent
                .checked_add(before.lamports - after)
                .ok_or(SwigError::PermissionDeniedAuthorityExternalAssetChange)?;
        }
    }
    if spent == 0 {
        return Ok(());
    }
    validate_creation_rent(guard, all_accounts, spent)
}

// Rent calculation is needed only when an outer signer's SOL decreased.
#[inline(never)]
fn validate_creation_rent(
    guard: &IsolationGuard,
    all_accounts: &[AccountInfo],
    spent: u64,
) -> ProgramResult {
    let rent = Rent::get()?;
    let mut creation_rent = 0u64;
    for before in guard.creations.as_slice() {
        // Indices belong to the account list retained by this guard.
        let account = unsafe { all_accounts.get_unchecked(before.index as usize) };
        if account.is_owned_by(&crate::SYSTEM_PROGRAM_ID) || account.executable() {
            continue;
        }
        let required = rent.minimum_balance(account.data_len());
        if account.lamports() < required {
            continue;
        }
        creation_rent = creation_rent
            .checked_add(required.saturating_sub(before.lamports))
            .ok_or(SwigError::PermissionDeniedAuthorityExternalAssetChange)?;
    }
    if spent > creation_rent {
        return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
    }
    Ok(())
}
