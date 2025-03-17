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
use pinocchio::{account_info::AccountInfo, program_error::ProgramError, ProgramResult};

use self::{
    add_authority_v1::*, create_plugin_bytecode_v1::*, create_v1::*, execute_plugin_v1::*,
    execute_v1::*, initialize_bytecode_v1::*, remove_authority_v1::*, replace_authority_v1::*,
    sign_v1::*,
};
use crate::{
    instruction::{
        accounts::{
            AddAuthorityV1Accounts, CreatePluginBytecodeAccounts, CreateV1Accounts,
            ExecuteAccounts, ExecutePluginAccounts, InitializeBytecodeAccounts,
            RemoveAuthorityV1Accounts, ReplaceAuthorityV1Accounts, SignV1Accounts,
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
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let ix = SwigInstruction::from_primitive(data[0]);
    match ix {
        SwigInstruction::CreateV1 => {
            let account_ctx = CreateV1Accounts::context(accounts)?;
            create_v1(account_ctx, &data[1..])
        },
        SwigInstruction::SignV1 => {
            let account_ctx = SignV1Accounts::context(accounts)?;
            sign_v1(account_ctx, accounts, data, account_classification)
        },
        SwigInstruction::AddAuthorityV1 => {
            let account_ctx = AddAuthorityV1Accounts::context(accounts)?;
            add_authority_v1(account_ctx, data, accounts)
        },
        SwigInstruction::RemoveAuthorityV1 => {
            let account_ctx = RemoveAuthorityV1Accounts::context(accounts)?;
            remove_authority_v1(account_ctx, data, accounts)
        },
        SwigInstruction::ReplaceAuthorityV1 => {
            let account_ctx = ReplaceAuthorityV1Accounts::context(accounts)?;
            replace_authority_v1(account_ctx, data, accounts)
        },
        SwigInstruction::InitializeBytecode => {
            let account_ctx = InitializeBytecodeAccounts::context(accounts)?;
            initialize_bytecode_v1::initialize_bytecode_v1(account_ctx, data)
        },
        SwigInstruction::CreatePluginBytecode => {
            let account_ctx = CreatePluginBytecodeAccounts::context(accounts)?;
            create_plugin_bytecode_v1::create_plugin_bytecode_v1(account_ctx, data)
        },
        SwigInstruction::Execute => {
            let account_ctx = ExecuteAccounts::context(accounts)?;
            execute_v1::execute_v1(account_ctx, data)
        },
        SwigInstruction::ExecutePlugin => {
            let account_ctx = ExecutePluginAccounts::context(accounts)?;
            execute_plugin_v1::execute_plugin_v1(account_ctx, data)
        },
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
