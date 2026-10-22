pub mod create_or_update_developer_account;
pub mod update_developer_signer;

use pinocchio::{account_info::AccountInfo, program_error::ProgramError, ProgramResult};
use swig_assertions::{check_key_match, check_signer};

use self::{
    create_or_update_developer_account::create_or_update_developer_account,
    update_developer_signer::update_developer_signer,
};
use crate::{
    error::DeveloperAccountRegistryError,
    instruction::{
        accounts::{CreateOrUpdateDeveloperAccountAccounts, UpdateDeveloperSignerAccounts},
        DeveloperAccountRegistryInstruction,
    },
    REGISTRY_ADMIN,
};

#[inline(always)]
pub fn process_action(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let discriminator = u16::from_le_bytes([data[0], data[1]]);
    let ix = DeveloperAccountRegistryInstruction::try_from(discriminator)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    match ix {
        DeveloperAccountRegistryInstruction::CreateOrUpdateDeveloperAccount => {
            process_create_or_update_developer_account(accounts, data)
        },
        DeveloperAccountRegistryInstruction::UpdateDeveloperSigner => {
            process_update_developer_signer(accounts, data)
        },
    }
}

fn process_create_or_update_developer_account(
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let account_ctx = CreateOrUpdateDeveloperAccountAccounts::context(accounts)?;
    create_or_update_developer_account(account_ctx, data)
}

fn process_update_developer_signer(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = UpdateDeveloperSignerAccounts::context(accounts)?;
    update_developer_signer(account_ctx, data)
}

#[inline(always)]
pub fn require_registry_admin(registry_admin: &AccountInfo) -> ProgramResult {
    check_key_match(
        registry_admin,
        &REGISTRY_ADMIN,
        DeveloperAccountRegistryError::InvalidRegistryAdmin,
    )?;
    check_signer(
        registry_admin,
        DeveloperAccountRegistryError::MissingRegistryAdminSignature,
    )
}
