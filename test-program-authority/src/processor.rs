//! Test program instruction processor

use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::invoke,
    program_error::ProgramError,
    pubkey::Pubkey,
};

/// Instruction discriminators
pub mod instructions {
    /// Test token transfer instruction - discriminator matches what ProgramExec
    /// authority expects This instruction will call swig's sign instruction
    /// via CPI
    pub const TEST_TOKEN_TRANSFER: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    /// Invalid discriminator for testing failures
    pub const INVALID_DISCRIMINATOR: [u8; 8] = [9, 9, 9, 9, 9, 9, 9, 9];

    /// Generic proof discriminator used by ReplaceAuthority tests.
    pub const REPLACE_AUTHORITY_PROOF_V1: [u8; 8] = *b"rplauth1";

    /// Compose ordinary WSOL synchronization and transfer in one caller CPI.
    pub const SYNC_NATIVE_AND_TRANSFER: [u8; 8] = *b"syncxfer";

    /// Controlled account-data mutation for SignV2 integrity rejection tests.
    pub const WRITE_ACCOUNT_DATA: [u8; 8] = *b"writeacc";
}

/// State account data format:
/// - Byte 0: 0 = success, 1 = fail
pub const STATE_SIZE: usize = 1;

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let discriminator: [u8; 8] = instruction_data[0..8]
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let remaining_data = &instruction_data[8..];

    match discriminator {
        instructions::TEST_TOKEN_TRANSFER => process_test_token_transfer(accounts, remaining_data),
        instructions::REPLACE_AUTHORITY_PROOF_V1 => {
            process_replace_authority_proof(accounts, remaining_data)
        },
        instructions::SYNC_NATIVE_AND_TRANSFER => {
            process_sync_native_and_transfer(accounts, remaining_data)
        },
        instructions::WRITE_ACCOUNT_DATA => {
            let account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
            let mut data = account.try_borrow_mut_data()?;
            if data.len() != remaining_data.len() {
                return Err(ProgramError::InvalidInstructionData);
            }
            data.copy_from_slice(remaining_data);
            Ok(())
        },
        instructions::INVALID_DISCRIMINATOR => {
            process_invalid_instruction(accounts, remaining_data)
        },
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Accounts: writable source and destination WSOL accounts, signing token
/// authority, and the executable legacy Token program. Both operations use the
/// actual Token program; this fixture does not write token-account data itself.
fn process_sync_native_and_transfer(accounts: &[AccountInfo], amount: &[u8]) -> ProgramResult {
    if accounts.len() != 4 || amount.len() != 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let token_program = Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    if accounts[3].key != &token_program || !accounts[3].executable {
        return Err(ProgramError::IncorrectProgramId);
    }
    invoke(
        &Instruction {
            program_id: token_program,
            accounts: vec![AccountMeta::new(*accounts[0].key, false)],
            data: vec![17], // SPL TokenInstruction::SyncNative
        },
        accounts,
    )?;
    let mut transfer_data = vec![3]; // SPL TokenInstruction::Transfer
    transfer_data.extend_from_slice(amount);
    invoke(
        &Instruction {
            program_id: token_program,
            accounts: vec![
                AccountMeta::new(*accounts[0].key, false),
                AccountMeta::new(*accounts[1].key, false),
                AccountMeta::new_readonly(*accounts[2].key, true),
            ],
            data: transfer_data,
        },
        accounts,
    )
}

/// Process test token transfer - calls swig via CPI
///
/// Expected accounts:
/// 0. `[]` Swig config account (first account for ProgramExec validation)
/// 1. `[]` Swig wallet address (second account for ProgramExec validation)
/// 2. `[]` State account (owned by this program, controls success/failure)
/// 3. `[]` Swig program
/// 4+. Additional accounts needed for the inner instruction
fn process_test_token_transfer(accounts: &[AccountInfo], _data: &[u8]) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let swig_config = &accounts[0];
    let swig_wallet = &accounts[1];
    let state_account = &accounts[2];
    let _swig_program = &accounts[3];

    msg!("Test program: validating config and wallet accounts");
    msg!("Config: {}", swig_config.key);
    msg!("Wallet: {}", swig_wallet.key);

    // Check the state account to determine if we should succeed or fail
    let state_data = state_account.try_borrow_data()?;
    if state_data.is_empty() {
        msg!("State account is empty, defaulting to success");
        return Ok(());
    }

    let should_fail = state_data[0];

    if should_fail == 0 {
        msg!("State account indicates success");
        Ok(())
    } else {
        msg!("State account indicates failure");
        Err(ProgramError::Custom(999))
    }
}

fn process_replace_authority_proof(accounts: &[AccountInfo], _data: &[u8]) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    msg!("Test program: accepted ReplaceAuthority proof");
    Ok(())
}

/// Process invalid instruction - for testing failure cases
fn process_invalid_instruction(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    // Same as test_token_transfer but with invalid discriminator
    process_test_token_transfer(accounts, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discriminators() {
        assert_eq!(instructions::TEST_TOKEN_TRANSFER.len(), 8);
        assert_eq!(instructions::INVALID_DISCRIMINATOR.len(), 8);
        assert_eq!(instructions::REPLACE_AUTHORITY_PROOF_V1, *b"rplauth1");
        assert_ne!(
            instructions::TEST_TOKEN_TRANSFER,
            instructions::INVALID_DISCRIMINATOR
        );
    }
}
