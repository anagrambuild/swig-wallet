use developer_account_registry_state::{DeveloperAccount, DeveloperTier};
use pinocchio::{account_info::AccountInfo, pubkey::Pubkey};
use swig_state::action::Permission;

use crate::error::SwigError;

pub fn validate_developer_account(
    developer_account: &AccountInfo,
    developer_signer: &AccountInfo,
    required_tier: DeveloperTier,
    unix_timestamp: i64,
) -> Result<(), SwigError> {
    if developer_account.is_writable() || developer_signer.is_writable() {
        return Err(SwigError::WritableDeveloperProofAccount);
    }
    if !developer_account.is_owned_by(&developer_account_registry_state::ID) {
        return Err(SwigError::InvalidDeveloperAccount);
    }
    let data = developer_account
        .try_borrow_data()
        .map_err(|_| SwigError::InvalidDeveloperAccount)?;
    let account = DeveloperAccount::load(&data)?;
    account.verify_pda(developer_account.key())?;

    check_developer_sponsorship(
        account,
        developer_signer.key(),
        developer_signer.is_signer(),
        required_tier,
        unix_timestamp,
    )
}

// Demo only: the Developer Account PDA and signer K travel as the last two
// accounts of the Swig instruction, as in the Phase 4 account contract.
pub fn require_developer_sponsorship(
    all_accounts: &[AccountInfo],
    permission: Permission,
    unix_timestamp: i64,
) -> Result<(), SwigError> {
    let Some(required_tier) = required_developer_tier(permission) else {
        return Ok(());
    };
    let [.., developer_account, developer_signer] = all_accounts else {
        return Err(SwigError::MissingDeveloperProofAccounts);
    };
    if !developer_account.is_owned_by(&developer_account_registry_state::ID) {
        return Err(SwigError::MissingDeveloperProofAccounts);
    }

    validate_developer_account(
        developer_account,
        developer_signer,
        required_tier,
        unix_timestamp,
    )
}

pub fn check_developer_sponsorship(
    account: &DeveloperAccount,
    signer_key: &Pubkey,
    signer_is_signer: bool,
    required_tier: DeveloperTier,
    unix_timestamp: i64,
) -> Result<(), SwigError> {
    if account.is_expired(unix_timestamp) {
        return Err(SwigError::DeveloperAccountExpired);
    }
    if !account.tier()?.allows(required_tier) {
        return Err(SwigError::InsufficientDeveloperTier);
    }
    if !account.signer_is_set() {
        return Err(SwigError::DeveloperSignerNotSet);
    }
    if account.signer != *signer_key {
        return Err(SwigError::DeveloperSignerMismatch);
    }
    if !signer_is_signer {
        return Err(SwigError::MissingDeveloperSignature);
    }

    Ok(())
}

pub fn required_developer_tier(permission: Permission) -> Option<DeveloperTier> {
    // Exhaustive so a new permission has to choose its tier.
    match permission {
        Permission::None
        | Permission::SolLimit
        | Permission::SolRecurringLimit
        | Permission::Program
        | Permission::ProgramScope
        | Permission::TokenRecurringLimit
        | Permission::All
        | Permission::ManageAuthority
        | Permission::SubAccount
        | Permission::StakeLimit
        | Permission::StakeRecurringLimit
        | Permission::StakeAll
        | Permission::ProgramAll
        | Permission::ProgramCurated
        | Permission::AllButManageAuthority
        | Permission::SolDestinationLimit
        | Permission::SolRecurringDestinationLimit
        | Permission::TokenDestinationLimit
        | Permission::TokenRecurringDestinationLimit
        | Permission::CloseSwigAuthority
        | Permission::ReplaceAuthority
        | Permission::SubAccountV2Create
        | Permission::SubAccountV2All
        | Permission::SubAccountV2Sign
        | Permission::SubAccountV2Withdraw
        | Permission::SubAccountV2Toggle => None,
        Permission::TokenLimit => Some(DeveloperTier::Pro),
    }
}

#[cfg(test)]
#[path = "../tests/unit/developer_account.rs"]
mod tests;
