use swig_compact_instructions::InstructionHolder;

use super::{wallet_shape_can_change, SPL_TOKEN_2022_ID, SPL_TOKEN_ID, SYSTEM_PROGRAM_ID};

#[test]
fn token2022_requires_wallet_integrity_checks() {
    for data in [&[3u8][..], &[12u8][..], &[9u8][..]] {
        let instruction = InstructionHolder {
            program_id: &SPL_TOKEN_2022_ID,
            cpi_accounts: Vec::new(),
            indexes: &[],
            accounts: Vec::new(),
            data,
            uses_swig_signer: true,
        };
        assert!(wallet_shape_can_change(&instruction));
    }
}

#[test]
fn legacy_token_and_plain_system_transfer_keep_the_fast_path() {
    let instruction = InstructionHolder {
        program_id: &SPL_TOKEN_ID,
        cpi_accounts: Vec::new(),
        indexes: &[],
        accounts: Vec::new(),
        data: &[3],
        uses_swig_signer: true,
    };
    assert!(!wallet_shape_can_change(&instruction));
    let transfer_data = 2u32.to_le_bytes();
    let instruction = InstructionHolder {
        program_id: &SYSTEM_PROGRAM_ID,
        data: &transfer_data,
        ..instruction
    };
    assert!(!wallet_shape_can_change(&instruction));
}
