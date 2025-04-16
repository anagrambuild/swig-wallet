pub mod add_authority_v1;
pub mod create_session_v1;
pub mod create_v1;
pub mod remove_authority_v1;
pub mod sign_v1;

use num_enum::FromPrimitive;
use pinocchio::{account_info::AccountInfo, program_error::ProgramError, ProgramResult};

use self::{
    add_authority_v1::*, create_session_v1::*, create_v1::*, remove_authority_v1::*, sign_v1::*,
};
use crate::{
    instruction::{
        accounts::{
            AddAuthorityV1Accounts, CreateSessionV1Accounts, CreateV1Accounts,
            RemoveAuthorityV1Accounts, SignV1Accounts,
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
        SwigInstruction::CreateV1 => {
            let account_ctx = CreateV1Accounts::context(accounts)?;
            create_v1(account_ctx, data)
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
        SwigInstruction::CreateSessionV1 => {
            let account_ctx = CreateSessionV1Accounts::context(accounts)?;
            create_session_v1(account_ctx, data, accounts)
        },
    }
}
