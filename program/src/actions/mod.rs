//! Action processing module for the Swig wallet program.
//!
//! This module contains the implementation of all instruction processing logic
//! for the Swig wallet program. Each action corresponds to a specific
//! instruction type and handles the validation and execution of that
//! instruction's business logic.

pub mod add_actions_to_role_v1;
pub mod add_authority_v1;
pub mod create_session_v1;
pub mod create_sub_account_v1;
pub mod create_v1;
pub mod remove_actions_from_role_v1;
pub mod remove_authority_v1;
pub mod sign_v1;
pub mod sub_account_sign_v1;
pub mod toggle_sub_account_v1;
pub mod withdraw_from_sub_account_v1;

use num_enum::FromPrimitive;
use pinocchio::{account_info::AccountInfo, msg, program_error::ProgramError, ProgramResult};

use self::{
    add_actions_to_role_v1::*, add_authority_v1::*, create_session_v1::*, create_sub_account_v1::*,
    create_v1::*, remove_actions_from_role_v1::*, remove_authority_v1::*, sign_v1::*,
    sub_account_sign_v1::*, toggle_sub_account_v1::*, withdraw_from_sub_account_v1::*,
};
use crate::{
    instruction::{
        accounts::{
            AddActionsToRoleV1Accounts, AddAuthorityV1Accounts, CreateSessionV1Accounts,
            CreateSubAccountV1Accounts, CreateV1Accounts, RemoveActionsFromRoleV1Accounts,
            RemoveAuthorityV1Accounts, SignV1Accounts, SubAccountSignV1Accounts,
            ToggleSubAccountV1Accounts, WithdrawFromSubAccountV1Accounts,
        },
        SwigInstruction,
    },
    util::AuthorizationLockCache,
    AccountClassification,
};

/// Main entry point for processing Swig wallet instructions.
///
/// This function dispatches the instruction to the appropriate handler based
/// on its discriminator. It validates the instruction data format and ensures
/// all required accounts are present.
///
/// # Arguments
/// * `accounts` - List of accounts involved in the instruction
/// * `account_classification` - Classification of each account's type and role
/// * `data` - Raw instruction data
/// * `authorization_lock_cache` - Optional cache of authorization locks
///
/// # Returns
/// * `ProgramResult` - Success or error status
#[inline(always)]
pub fn process_action(
    accounts: &[AccountInfo],
    account_classification: &[AccountClassification],
    data: &[u8],
    authorization_lock_cache: Option<&AuthorizationLockCache>,
) -> ProgramResult {
    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let discriminator = unsafe { *(data.get_unchecked(..2).as_ptr() as *const u16) };
    let ix = SwigInstruction::from_primitive(discriminator);
    match ix {
        SwigInstruction::CreateV1 => process_create_v1(accounts, data),
        SwigInstruction::SignV1 => process_sign_v1(
            accounts,
            account_classification,
            data,
            authorization_lock_cache,
        ),
        SwigInstruction::AddAuthorityV1 => process_add_authority_v1(accounts, data),
        SwigInstruction::RemoveAuthorityV1 => process_remove_authority_v1(accounts, data),
        SwigInstruction::CreateSessionV1 => process_create_session_v1(accounts, data),
        SwigInstruction::CreateSubAccountV1 => process_create_sub_account_v1(accounts, data),
        SwigInstruction::WithdrawFromSubAccountV1 => {
            process_withdraw_from_sub_account_v1(accounts, account_classification, data)
        },
        SwigInstruction::SubAccountSignV1 => {
            process_sub_account_sign_v1(accounts, account_classification, data)
        },
        SwigInstruction::ToggleSubAccountV1 => process_toggle_sub_account_v1(accounts, data),
        SwigInstruction::AddActionsToRoleV1 => process_add_actions_to_role_v1(accounts, data),
        SwigInstruction::RemoveActionsFromRoleV1 => {
            process_remove_actions_from_role_v1(accounts, data)
        },
    }
}

/// Processes a CreateV1 instruction.
///
/// Creates a new Swig wallet account with initial settings.
fn process_create_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = CreateV1Accounts::context(accounts)?;
    create_v1(account_ctx, data)
}

/// Processes a SignV1 instruction.
///
/// Signs and executes a transaction using the wallet's authority.
fn process_sign_v1(
    accounts: &[AccountInfo],
    account_classification: &[AccountClassification],
    data: &[u8],
    authorization_lock_cache: Option<&AuthorizationLockCache>,
) -> ProgramResult {
    let account_ctx = SignV1Accounts::context(accounts)?;
    sign_v1(
        account_ctx,
        accounts,
        data,
        account_classification,
        authorization_lock_cache,
    )
}

/// Processes an AddAuthorityV1 instruction.
///
/// Adds a new authority to the wallet with specified permissions.
fn process_add_authority_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = AddAuthorityV1Accounts::context(accounts)?;
    add_authority_v1(account_ctx, data, accounts)
}

/// Processes a RemoveAuthorityV1 instruction.
///
/// Removes an existing authority from the wallet.
fn process_remove_authority_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = RemoveAuthorityV1Accounts::context(accounts)?;
    remove_authority_v1(account_ctx, data, accounts)
}

/// Processes a CreateSessionV1 instruction.
///
/// Creates a new temporary session for an authority.
fn process_create_session_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = CreateSessionV1Accounts::context(accounts)?;
    create_session_v1(account_ctx, data, accounts)
}

/// Processes a CreateSubAccountV1 instruction.
///
/// Creates a new sub-account under the wallet.
fn process_create_sub_account_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = CreateSubAccountV1Accounts::context(accounts)?;
    create_sub_account_v1(account_ctx, data, accounts)
}

/// Processes a WithdrawFromSubAccountV1 instruction.
///
/// Withdraws funds from a sub-account to the main wallet.
fn process_withdraw_from_sub_account_v1(
    accounts: &[AccountInfo],
    account_classification: &[AccountClassification],
    data: &[u8],
) -> ProgramResult {
    let account_ctx = WithdrawFromSubAccountV1Accounts::context(accounts)?;
    withdraw_from_sub_account_v1(account_ctx, accounts, data, account_classification)
}

/// Processes a SubAccountSignV1 instruction.
///
/// Signs and executes a transaction from a sub-account.
fn process_sub_account_sign_v1(
    accounts: &[AccountInfo],
    account_classification: &[AccountClassification],
    data: &[u8],
) -> ProgramResult {
    let account_ctx = SubAccountSignV1Accounts::context(accounts)?;
    sub_account_sign_v1(account_ctx, accounts, data, account_classification)
}

/// Processes a ToggleSubAccountV1 instruction.
///
/// Enables or disables a sub-account.
fn process_toggle_sub_account_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = ToggleSubAccountV1Accounts::context(accounts)?;
    toggle_sub_account_v1(account_ctx, data, accounts)
}

/// Processes an AddActionsToRoleV1 instruction.
///
/// Adds actions to an existing role with specified permissions.
fn process_add_actions_to_role_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = AddActionsToRoleV1Accounts::context(accounts)?;
    add_actions_to_role_v1(account_ctx, data, accounts)
}

/// Processes a RemoveActionsFromRoleV1 instruction.
///
/// Removes actions from an existing role by their indices.
fn process_remove_actions_from_role_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = RemoveActionsFromRoleV1Accounts::context(accounts)?;
    remove_actions_from_role_v1(account_ctx, data, accounts)
}
