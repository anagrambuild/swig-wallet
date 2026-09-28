#![cfg(feature = "client")]

use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
use swig_compact_instructions::{
    compact_instructions, compact_instructions_sub_account, CompactInstruction,
    CompactInstructionError, CompactInstructions, MAX_ACCOUNTS,
};

fn instruction(accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id: Pubkey::new_unique(),
        accounts,
        data,
    }
}

fn compact_instruction(account_count: usize, data_len: usize) -> CompactInstruction {
    CompactInstruction {
        program_id_index: 0,
        accounts: vec![0; account_count],
        data: vec![0; data_len],
    }
}

#[test]
fn merges_duplicate_account_privileges() {
    let swig = Pubkey::new_unique();
    let shared = Pubkey::new_unique();
    let instructions = vec![
        instruction(vec![AccountMeta::new_readonly(shared, false)], Vec::new()),
        instruction(vec![AccountMeta::new(shared, true)], Vec::new()),
    ];

    let (accounts, _) = compact_instructions(swig, Vec::new(), instructions).unwrap();
    let shared_meta = accounts
        .iter()
        .find(|account| account.pubkey == shared)
        .unwrap();

    assert!(shared_meta.is_signer);
    assert!(shared_meta.is_writable);
}

#[test]
fn keeps_swig_and_subaccount_pdas_non_signers() {
    let swig = Pubkey::new_unique();
    let sub_account = Pubkey::new_unique();
    let shared = Pubkey::new_unique();
    let accounts = vec![
        AccountMeta::new_readonly(swig, false),
        AccountMeta::new_readonly(sub_account, false),
    ];
    let instructions = vec![
        instruction(
            vec![
                AccountMeta::new_readonly(swig, true),
                AccountMeta::new_readonly(sub_account, true),
                AccountMeta::new_readonly(shared, false),
            ],
            Vec::new(),
        ),
        instruction(vec![AccountMeta::new(shared, true)], Vec::new()),
    ];

    let (accounts, _) =
        compact_instructions_sub_account(swig, sub_account, accounts, instructions).unwrap();

    assert!(
        !accounts
            .iter()
            .find(|meta| meta.pubkey == swig)
            .unwrap()
            .is_signer
    );
    assert!(
        !accounts
            .iter()
            .find(|meta| meta.pubkey == sub_account)
            .unwrap()
            .is_signer
    );
    let shared_meta = accounts.iter().find(|meta| meta.pubkey == shared).unwrap();
    assert!(shared_meta.is_signer);
    assert!(shared_meta.is_writable);
}

#[test]
fn compaction_enforces_account_limit() {
    let swig = Pubkey::new_unique();
    let accounts = (0..MAX_ACCOUNTS - 1)
        .map(|_| AccountMeta::new_readonly(Pubkey::new_unique(), false))
        .collect();
    let (accounts, _) =
        compact_instructions(swig, accounts, vec![instruction(Vec::new(), Vec::new())]).unwrap();
    assert_eq!(accounts.len(), MAX_ACCOUNTS);

    let full_accounts = (0..MAX_ACCOUNTS)
        .map(|_| AccountMeta::new_readonly(Pubkey::new_unique(), false))
        .collect();
    assert!(matches!(
        compact_instructions(
            swig,
            full_accounts,
            vec![instruction(Vec::new(), Vec::new())]
        ),
        Err(CompactInstructionError::TooManyAccounts)
    ));

    let repeated = AccountMeta::new_readonly(Pubkey::new_unique(), false);
    assert!(matches!(
        compact_instructions(
            swig,
            Vec::new(),
            vec![instruction(vec![repeated; MAX_ACCOUNTS + 1], Vec::new())]
        ),
        Err(CompactInstructionError::TooManyAccounts)
    ));
}

#[test]
fn compaction_rejects_unencodable_instruction_and_data_counts() {
    let swig = Pubkey::new_unique();
    let empty_instruction = instruction(Vec::new(), Vec::new());
    assert!(matches!(
        compact_instructions(
            swig,
            Vec::new(),
            vec![empty_instruction; usize::from(u8::MAX) + 1]
        ),
        Err(CompactInstructionError::TooManyInstructions)
    ));

    assert!(compact_instructions(
        swig,
        Vec::new(),
        vec![instruction(Vec::new(), vec![0; usize::from(u16::MAX)])]
    )
    .is_ok());
    assert!(matches!(
        compact_instructions(
            swig,
            Vec::new(),
            vec![instruction(Vec::new(), vec![0; usize::from(u16::MAX) + 1])]
        ),
        Err(CompactInstructionError::InstructionDataTooLarge)
    ));
}

#[test]
fn serialization_enforces_wire_limits() {
    let max_instructions = CompactInstructions {
        inner_instructions: (0..usize::from(u8::MAX))
            .map(|_| compact_instruction(0, 0))
            .collect(),
    };
    assert!(max_instructions.into_bytes().is_ok());

    let too_many_instructions = CompactInstructions {
        inner_instructions: (0..usize::from(u8::MAX) + 1)
            .map(|_| compact_instruction(0, 0))
            .collect(),
    };
    assert_eq!(
        too_many_instructions.into_bytes().unwrap_err(),
        CompactInstructionError::TooManyInstructions
    );

    let max_accounts = CompactInstructions {
        inner_instructions: vec![compact_instruction(MAX_ACCOUNTS, 0)],
    };
    assert!(max_accounts.into_bytes().is_ok());
    let too_many_accounts = CompactInstructions {
        inner_instructions: vec![compact_instruction(MAX_ACCOUNTS + 1, 0)],
    };
    assert_eq!(
        too_many_accounts.into_bytes().unwrap_err(),
        CompactInstructionError::TooManyAccounts
    );

    let max_data = CompactInstructions {
        inner_instructions: vec![compact_instruction(0, usize::from(u16::MAX))],
    };
    assert!(max_data.into_bytes().is_ok());
    let too_much_data = CompactInstructions {
        inner_instructions: vec![compact_instruction(0, usize::from(u16::MAX) + 1)],
    };
    assert_eq!(
        too_much_data.into_bytes().unwrap_err(),
        CompactInstructionError::InstructionDataTooLarge
    );
}

#[test]
fn serialization_rejects_unaddressable_account_indexes() {
    let max_index = u8::try_from(MAX_ACCOUNTS - 1).unwrap();
    let max_indexes = CompactInstructions {
        inner_instructions: vec![CompactInstruction {
            program_id_index: max_index,
            accounts: vec![max_index],
            data: Vec::new(),
        }],
    };
    assert!(max_indexes.into_bytes().is_ok());

    for invalid_index in [u8::try_from(MAX_ACCOUNTS).unwrap(), u8::MAX] {
        let invalid_program_index = CompactInstructions {
            inner_instructions: vec![CompactInstruction {
                program_id_index: invalid_index,
                accounts: Vec::new(),
                data: Vec::new(),
            }],
        };
        assert_eq!(
            invalid_program_index.into_bytes().unwrap_err(),
            CompactInstructionError::AccountIndexOutOfBounds
        );

        let invalid_account_index = CompactInstructions {
            inner_instructions: vec![CompactInstruction {
                program_id_index: 0,
                accounts: vec![invalid_index],
                data: Vec::new(),
            }],
        };
        assert_eq!(
            invalid_account_index.into_bytes().unwrap_err(),
            CompactInstructionError::AccountIndexOutOfBounds
        );
    }
}
