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
    accounts: &[AccountInfo],
    data: &[u8],
) -> Result<(), ProgramError> {
    // ProgramExec requires accounts[0] = swig_config and accounts[1] = swig_wallet.
    // The oracle does not validate these accounts itself -- ProgramExec authentication
    // on the Swig side independently verifies that these match the real Swig addresses.
    if accounts.len() < 2 {
        return Err(OracleError::InvalidAccountCount.into());
    }

    if data.len() < 18 {
        return Err(OracleError::InvalidInstruction.into());
    }

    let input_amount = u64::from_le_bytes(
        data[0..8]
            .try_into()
            .map_err(|_| OracleError::InvalidInstruction)?,
    );
    let min_output_amount = u64::from_le_bytes(
        data[8..16]
            .try_into()
            .map_err(|_| OracleError::InvalidInstruction)?,
    );
    let min_bps = u16::from_le_bytes(
        data[16..18]
            .try_into()
            .map_err(|_| OracleError::InvalidInstruction)?,
    );

    let required_min = (input_amount as u128)
        .checked_mul(min_bps as u128)
        .ok_or(OracleError::ArithmeticOverflow)?
        / 10000u128;

    if (min_output_amount as u128) < required_min {
        return Err(OracleError::SlippageExceeded.into());
    }

    Ok(())
}
