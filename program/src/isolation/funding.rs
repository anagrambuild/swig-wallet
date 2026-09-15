//! Bound outer signers' net SOL decreases by new-account rent.

use pinocchio::{
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};

use super::IsolationGuard;
use crate::error::SwigError;

impl IsolationGuard<'_> {
    /// Preserve existing signer account control and bound net SOL decreases.
    #[inline(always)]
    pub(super) fn validate_signer_accounts(&self) -> ProgramResult {
        let mut total_decrease = 0u64;
        for before in self.signers.as_slice() {
            let account = &self.accounts[before.index as usize];
            if before.system_account
                && (!account.is_owned_by(&crate::SYSTEM_PROGRAM_ID) || account.data_len() != 0)
            {
                return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
            }
            let after = account.lamports();
            if after < before.lamports {
                total_decrease = total_decrease
                    .checked_add(before.lamports - after)
                    .ok_or(SwigError::PermissionDeniedAuthorityExternalAssetChange)?;
            }
        }
        if total_decrease == 0 {
            return Ok(());
        }
        self.validate_creation_rent(total_decrease)
    }

    // Rent calculation is needed only when an outer signer's SOL decreased.
    #[inline(never)]
    fn validate_creation_rent(&self, total_decrease: u64) -> ProgramResult {
        let rent = Rent::get()?;
        let mut allowed_rent = 0u64;
        for before in self.creations.as_slice() {
            let account = &self.accounts[before.index as usize];
            if account.is_owned_by(&crate::SYSTEM_PROGRAM_ID) || account.executable() {
                continue;
            }
            let required_rent = rent.minimum_balance(account.data_len());
            if account.lamports() < required_rent {
                continue;
            }
            allowed_rent = allowed_rent
                .checked_add(required_rent.saturating_sub(before.lamports))
                .ok_or(SwigError::PermissionDeniedAuthorityExternalAssetChange)?;
        }
        if total_decrease > allowed_rent {
            return Err(SwigError::PermissionDeniedAuthorityExternalAssetChange.into());
        }
        Ok(())
    }
}
