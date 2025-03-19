pub mod add_authority_v1;
pub mod create_plugin_bytecode_v1;
pub mod create_v1;
pub mod execute_plugin_v1;
pub mod execute_v1;
pub mod initialize_bytecode_v1;
pub mod remove_authority_v1;
pub mod replace_authority_v1;
pub mod sign_v1;

use num_enum::FromPrimitive;
use pinocchio::{account_info::AccountInfo, msg, program_error::ProgramError, ProgramResult};

use self::{
    add_authority_v1::*, create_plugin_bytecode_v1::*, create_v1::*, execute_plugin_v1::*,
    execute_v1::*, initialize_bytecode_v1::*, remove_authority_v1::*, replace_authority_v1::*,
    sign_v1::*,
};
use crate::{
    instruction::{
        accounts::{
            AddAuthorityV1Accounts, CreatePluginBytecodeV1Accounts, CreateV1Accounts,
            ExecuteBytecodeV1Accounts, ExecutePluginBytecodeV1Accounts,
            InitializeBytecodeV1Accounts, RemoveAuthorityV1Accounts, ReplaceAuthorityV1Accounts,
            SignV1Accounts,
        },
        SwigInstruction,
    },
    AccountClassification,
};

#[inline(always)]
fn process_create_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = CreateV1Accounts::context(accounts)?;
    create_v1(account_ctx, &data[1..])
}

#[inline(always)]
fn process_sign_v1(
    accounts: &[AccountInfo],
    account_classification: &[AccountClassification],
    data: &[u8],
) -> ProgramResult {
    let account_ctx = SignV1Accounts::context(accounts)?;
    sign_v1(account_ctx, accounts, data, account_classification)
}

#[inline(always)]
fn process_add_authority_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = AddAuthorityV1Accounts::context(accounts)?;
    add_authority_v1(account_ctx, data, accounts)
}

#[inline(always)]
fn process_remove_authority_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = RemoveAuthorityV1Accounts::context(accounts)?;
    remove_authority_v1(account_ctx, data, accounts)
}

#[inline(always)]
fn process_replace_authority_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = ReplaceAuthorityV1Accounts::context(accounts)?;
    replace_authority_v1(account_ctx, data, accounts)
}

#[inline(always)]
fn process_create_plugin_bytecode_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = CreatePluginBytecodeV1Accounts::context(accounts)?;
    create_plugin_bytecode_v1(account_ctx, data)
}

#[inline(always)]
fn process_execute_plugin_bytecode_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = ExecutePluginBytecodeV1Accounts::context(accounts)?;
    execute_plugin_bytecode_v1(account_ctx, data)
}

#[inline(always)]
fn process_initialize_bytecode_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = InitializeBytecodeV1Accounts::context(accounts)?;
    initialize_bytecode_v1(account_ctx, data)
}

#[inline(always)]
fn process_execute_bytecode_v1(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account_ctx = ExecuteBytecodeV1Accounts::context(accounts)?;
    execute_bytecode_v1(account_ctx, data)
}

#[inline(always)]
pub fn process_action(
    accounts: &[AccountInfo],
    account_classification: &[AccountClassification],
    data: &[u8],
) -> ProgramResult {
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let ix = SwigInstruction::from_primitive(data[0]);
    msg!("ix: {:?}", ix);
    match ix {
        SwigInstruction::CreateV1 => process_create_v1(accounts, data),
        SwigInstruction::SignV1 => process_sign_v1(accounts, account_classification, data),
        SwigInstruction::AddAuthorityV1 => process_add_authority_v1(accounts, data),
        SwigInstruction::RemoveAuthorityV1 => process_remove_authority_v1(accounts, data),
        SwigInstruction::ReplaceAuthorityV1 => process_replace_authority_v1(accounts, data),
        SwigInstruction::CreatePluginBytecodeV1 => {
            process_create_plugin_bytecode_v1(accounts, data)
        },
        SwigInstruction::ExecutePluginBytecodeV1 => {
            process_execute_plugin_bytecode_v1(accounts, data)
        },
        SwigInstruction::ExecuteBytecodeV1 => process_execute_bytecode_v1(accounts, data),
        SwigInstruction::InitializeBytecodeV1 => process_initialize_bytecode_v1(accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
