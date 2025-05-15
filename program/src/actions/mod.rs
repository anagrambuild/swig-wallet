pub mod add_authority_v1;
pub mod create_session_v1;
pub mod create_sub_account_v1;
pub mod create_v1;
pub mod remove_authority_v1;
pub mod sign_v1;
pub mod sub_account_sign_v1;
pub mod toggle_sub_account_v1;
pub mod withdraw_from_sub_account_v1;

use num_enum::FromPrimitive;
use pinocchio::{account_info::AccountInfo, msg, program_error::ProgramError, ProgramResult};

use self::{
    add_authority_v1::*, create_session_v1::*, create_sub_account_v1::*, create_v1::*,
    remove_authority_v1::*, sign_v1::*, sub_account_sign_v1::*, toggle_sub_account_v1::*,
    withdraw_from_sub_account_v1::*,
};
use crate::{
    instruction::{
        accounts::{
            AddAuthorityV1Accounts, CreateSessionV1Accounts, CreateSubAccountV1Accounts,
            CreateV1Accounts, RemoveAuthorityV1Accounts, SignV1Accounts, SubAccountSignV1Accounts,
            ToggleSubAccountV1Accounts, WithdrawFromSubAccountV1Accounts,
        },
        SwigInstruction,
    },
    AccountClassification,
};

#[inline(always)]
pub fn process_action(
    accounts: &[AccountInfo],
    account_classification: &[AccountClassification],
    data: &[u8],
) -> ProgramResult {
    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let discriminator = unsafe { *(data.get_unchecked(..2).as_ptr() as *const u16) };
    let ix = SwigInstruction::from_primitive(discriminator);
    match ix {
        SwigInstruction::CreateV1 => process_create_v1(accounts, data),
        SwigInstruction::SignV1 => process_sign_v1(accounts, account_classification, data),
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
    }
}

fn process_create_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = CreateV1Accounts::context(accounts)?;
    create_v1(account_ctx, data)
}

fn process_sign_v1(
    accounts: &[AccountInfo],
    account_classification: &[AccountClassification],
    data: &[u8],
) -> ProgramResult {
    let account_ctx = SignV1Accounts::context(accounts)?;
    sign_v1(account_ctx, accounts, data, account_classification)
}

fn process_add_authority_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = AddAuthorityV1Accounts::context(accounts)?;
    add_authority_v1(account_ctx, data, accounts)
}

fn process_remove_authority_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = RemoveAuthorityV1Accounts::context(accounts)?;
    remove_authority_v1(account_ctx, data, accounts)
}

fn process_create_session_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = CreateSessionV1Accounts::context(accounts)?;
    create_session_v1(account_ctx, data, accounts)
}

fn process_create_sub_account_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = CreateSubAccountV1Accounts::context(accounts)?;
    create_sub_account_v1(account_ctx, data, accounts)
}

fn process_withdraw_from_sub_account_v1(
    accounts: &[AccountInfo],
    account_classification: &[AccountClassification],
    data: &[u8],
) -> ProgramResult {
    let account_ctx = WithdrawFromSubAccountV1Accounts::context(accounts)?;
    withdraw_from_sub_account_v1(account_ctx, accounts, data, account_classification)
}

fn process_sub_account_sign_v1(
    accounts: &[AccountInfo],
    account_classification: &[AccountClassification],
    data: &[u8],
) -> ProgramResult {
    let account_ctx = SubAccountSignV1Accounts::context(accounts)?;
    sub_account_sign_v1(account_ctx, accounts, data, account_classification)
}

fn process_toggle_sub_account_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = ToggleSubAccountV1Accounts::context(accounts)?;
    toggle_sub_account_v1(account_ctx, data, accounts)
}
