pub mod create_v1;
pub mod sign_v1;
pub mod add_authority_v1;
use self::create_v1::*;
use self::sign_v1::*;
use self::add_authority_v1::*;
use crate::instruction::accounts::AddAuthorityV1Accounts;
use crate::instruction::{
    accounts::{CreateV1Accounts, SignV1Accounts},
    SwigInstruction,
};
use crate::AccountClassification;
use num_enum::FromPrimitive;
use pinocchio::msg;
use pinocchio::{account_info::AccountInfo, program_error::ProgramError, ProgramResult};

#[inline(always)]
pub fn process_action(
    accounts: &[AccountInfo],
    account_classification: &[AccountClassification],
    data: &[u8],
) -> ProgramResult {
    if data.len() < 1 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let ix = SwigInstruction::from_primitive(data[0]);
    match ix {
        SwigInstruction::CreateV1 => {
            let account_ctx = CreateV1Accounts::context(accounts)?;
            create_v1(account_ctx, &data[1..])
        }
        SwigInstruction::SignV1 => {
            let account_ctx = SignV1Accounts::context(accounts)?;
            sign_v1(account_ctx, accounts, data, account_classification)
        }
        SwigInstruction::AddAuthorityV1 => {
            let account_ctx = AddAuthorityV1Accounts::context(accounts)?;
            add_authority_v1(account_ctx, data, accounts)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
