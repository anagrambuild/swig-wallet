//pub mod add_authority_v1;
pub mod create_v1;
// pub mod remove_authority_v1;
// pub mod replace_authority_v1;
pub mod sign_v1;

use num_enum::FromPrimitive;
use pinocchio::{account_info::AccountInfo, program_error::ProgramError, ProgramResult};

use self::{create_v1::*, sign_v1::*};
use crate::{
    instruction::{
        accounts::{
            AddAuthorityV1Accounts, CreateV1Accounts, RemoveAuthorityV1Accounts,
            ReplaceAuthorityV1Accounts, SignV1Accounts,
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
            create_v1(account_ctx, &data)
        },
        // SwigInstruction::SignV1 => {
        //     let account_ctx = SignV1Accounts::context(accounts)?;
        //     sign_v1(account_ctx, accounts, data, account_classification)
        // },
        // SwigInstruction::AddAuthorityV1 => {
        //     let account_ctx = AddAuthorityV1Accounts::context(accounts)?;
        //     add_authority_v1(account_ctx, data, accounts)
        // },
        // SwigInstruction::RemoveAuthorityV1 => {
        //     let account_ctx = RemoveAuthorityV1Accounts::context(accounts)?;
        //     remove_authority_v1(account_ctx, data, accounts)
        // },
        // SwigInstruction::ReplaceAuthorityV1 => {
        //     let account_ctx = ReplaceAuthorityV1Accounts::context(accounts)?;
        //     replace_authority_v1(account_ctx, data, accounts)
        // },
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
