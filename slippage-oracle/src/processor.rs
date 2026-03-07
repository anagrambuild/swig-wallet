use pinocchio::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

use crate::error::OracleError;

/// Instruction discriminators
pub const VALIDATE_TRADE: [u8; 8] = [0x76, 0x61, 0x6c, 0x74, 0x72, 0x61, 0x64, 0x65]; // "valtrade"

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> Result<(), ProgramError> {
    if data.len() < 8 {
        return Err(OracleError::InvalidInstruction.into());
    }

    let discriminator: [u8; 8] = data[..8].try_into().unwrap();

    match discriminator {
        VALIDATE_TRADE => process_validate_trade(accounts, &data[8..]),
        _ => Err(OracleError::InvalidInstruction.into()),
    }
}

fn process_validate_trade(
    _accounts: &[AccountInfo],
    _data: &[u8],
) -> Result<(), ProgramError> {
    // TODO: implement in Task 2
    Ok(())
}
