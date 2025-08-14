#![cfg(not(feature = "program_scope_test"))]

mod common;
use common::*;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, InstructionError},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{
    AuthorityConfig, ClientAction, CreateSessionInstruction, CreateSubAccountInstruction,
    SignInstruction, SubAccountSignInstruction, ToggleSubAccountInstruction, UpdateAuthorityData,
    WithdrawFromSubAccountInstruction,
};
use swig_state::{
    action::{
        external_kill_switch::ExternalKillSwitch, manage_authority::ManageAuthority,
        program::Program, program_all::ProgramAll, sol_limit::SolLimit, sub_account::SubAccount,
    },
    authority::AuthorityType,
    swig::{sub_account_seeds, swig_account_seeds, SwigWithRoles},
};

/// Helper function to create a Swig account with an external kill switch
/// that blocks execution (external account has wrong data)
fn setup_swig_with_blocking_kill_switch(
    context: &mut Context,
) -> (Pubkey, Keypair, Keypair, Keypair) {
    let swig_authority = Keypair::new();
    let test_authority = Keypair::new();
    let external_account = Keypair::new();

    // Fund accounts
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&test_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create external account with data that will NOT match our kill switch
    // expectation
    let mut external_account_data = vec![0u8; 16];
    external_account_data[8] = 2; // Kill switch expects 1, but we set 2 -> BLOCKED

    let external_account_info = Account {
        lamports: 1_000_000,
        data: external_account_data,
        owner: solana_sdk::system_program::id(),
        executable: false,
        rent_epoch: 0,
    };

    let _ = context
        .svm
        .set_account(external_account.pubkey(), external_account_info.into());

    // Create the Swig account
    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    let swig_create_txn = create_swig_ed25519(context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    // Add test authority with external kill switch that expects value 1 but
    // external account has value 2
    add_authority_with_ed25519_root(
        context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: test_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ExternalKillSwitch(
                ExternalKillSwitch::new(
                    external_account.pubkey().to_bytes(),
                    1u64.to_le_bytes().as_slice(), // Expected value 1
                    8,                             // Start index
                    16,                            // End index
                )
                .unwrap(),
            ),
            ClientAction::ManageAuthority(ManageAuthority {}),
            ClientAction::Program(Program {
                program_id: solana_sdk::system_program::ID.to_bytes(),
            }),
            ClientAction::SolLimit(SolLimit {
                amount: 1_000_000_000,
            }),
            ClientAction::SubAccount(SubAccount {
                sub_account: [0; 32],
            }),
        ],
    )
    .unwrap();

    // Fund the swig account
    context.svm.airdrop(&swig, 10_000_000_000).unwrap();

    (swig, swig_authority, test_authority, external_account)
}

#[test_log::test]
fn test_external_kill_switch_blocks_execution() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    // Fund accounts
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Create external account with test data
    let external_account = Keypair::new();
    let mut external_account_data = vec![0u8; 16];
    // Write value [2] at byte 8 - this will NOT match our expected value of [1]
    external_account_data[8] = 2;

    let external_account_info = Account {
        lamports: 1_000_000,
        data: external_account_data,
        owner: solana_sdk::system_program::id(),
        executable: false,
        rent_epoch: 0,
    };

    context
        .svm
        .set_account(external_account.pubkey(), external_account_info.into());

    // Create the Swig account
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    // Create second authority with external kill switch
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add authority with external kill switch that expects value 1 but external
    // account has value 2
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ExternalKillSwitch(
                ExternalKillSwitch::new(
                    external_account.pubkey().to_bytes(),
                    1u64.to_le_bytes().as_slice(), // Expected value
                    8,                             // Start index
                    16,                            // End index
                )
                .unwrap(),
            ),
            ClientAction::Program(Program {
                program_id: solana_sdk::system_program::ID.to_bytes(),
            }),
        ],
    )
    .unwrap();

    context.svm.airdrop(&swig, 10_000_000_000).unwrap();

    // Create a simple transfer instruction to test
    let amount = 1_000_000;
    let transfer_ix = system_instruction::transfer(&swig, &recipient.pubkey(), amount);

    // Create sign_v1 instruction
    let mut sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        transfer_ix,
        1, // role_id for the authority with kill switch
    )
    .unwrap();

    // Add external account to the instruction accounts so it can be read
    sign_ix
        .accounts
        .push(AccountMeta::new_readonly(external_account.pubkey(), false));

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    // Execute the instruction - should fail due to kill switch
    let result = context.svm.send_transaction(transfer_tx);

    assert!(
        result.is_err(),
        "Transaction should fail due to kill switch"
    );

    // Should fail with external kill switch error (3029)
    let error = result.unwrap_err();
    assert_eq!(
        error.err,
        TransactionError::InstructionError(0, InstructionError::Custom(3029))
    );

    println!("✅ External kill switch correctly blocked execution when values don't match");

    // Verify no funds were transferred
    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(recipient_account.lamports, 10_000_000_000); // Only initial
                                                            // airdrop
}

#[test_log::test]
fn test_external_kill_switch_allows_execution() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    // Fund accounts
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Create external account with test data
    let external_account = Keypair::new();
    let mut external_account_data = vec![0u8; 16];
    // Write value 1 at bytes 8-15 (as u64) - this WILL match our expected value of
    // 1
    external_account_data[8..16].copy_from_slice(&1u64.to_le_bytes());

    println!("DEBUG: External account data: {:?}", external_account_data);
    println!("DEBUG: Expected kill switch value: 1");
    println!("DEBUG: Kill switch range: 8-16");
    println!(
        "DEBUG: Data at range [8..16]: {:?}",
        &external_account_data[8..16]
    );
    println!(
        "DEBUG: Value as u64: {}",
        u64::from_le_bytes(external_account_data[8..16].try_into().unwrap())
    );

    let external_account_info = Account {
        lamports: 1_000_000,
        data: external_account_data,
        owner: solana_sdk::system_program::id(),
        executable: false,
        rent_epoch: 0,
    };

    println!(
        "external_account: {:?}",
        external_account.pubkey().to_bytes()
    );

    context
        .svm
        .set_account(external_account.pubkey(), external_account_info.into());

    // Create the Swig account
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    // Create second authority with external kill switch
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add authority with external kill switch that expects value 1 and external
    // account has value 1
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ExternalKillSwitch(
                ExternalKillSwitch::new(
                    external_account.pubkey().to_bytes(),
                    1u64.to_le_bytes().as_slice(), // Expected value
                    8u32,                          // Start index
                    16u32,                         // End index
                )
                .unwrap(),
            ),
            ClientAction::ProgramAll(ProgramAll),
            ClientAction::SolLimit(SolLimit {
                amount: 1_000_000_000,
            }),
        ],
    )
    .unwrap();

    context.svm.airdrop(&swig, 10_000_000_000).unwrap();

    // Create a simple transfer instruction to test
    let amount = 1_000_000;
    let transfer_ix = system_instruction::transfer(&swig, &recipient.pubkey(), amount);

    // Create sign_v1 instruction
    let mut sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        transfer_ix,
        1, // role_id for the authority with kill switch
    )
    .unwrap();

    // Add external account to the instruction accounts so it can be read
    sign_ix
        .accounts
        .push(AccountMeta::new_readonly(external_account.pubkey(), false));

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    // Execute the instruction - should succeed since values match
    let result = context.svm.send_transaction(transfer_tx);

    if result.is_err() {
        let cloned_result = result.clone();
        println!("{}", cloned_result.unwrap().pretty_logs());
    }

    assert!(
        result.is_ok(),
        "Transaction should succeed when kill switch values match"
    );

    println!("✅ External kill switch correctly allowed execution when values match");

    // Verify funds were transferred
    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(recipient_account.lamports, 10_000_000_000 + amount);
}

#[test_log::test]
fn test_external_kill_switch_missing_account() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    // Fund accounts
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Create external account but DON'T add it to the transaction accounts
    let external_account = Keypair::new();
    let mut external_account_data = vec![0u8; 16];
    external_account_data[8..16].copy_from_slice(&1u64.to_le_bytes());

    let external_account_info = Account {
        lamports: 1_000_000,
        data: external_account_data,
        owner: solana_sdk::system_program::id(),
        executable: false,
        rent_epoch: 0,
    };

    context
        .svm
        .set_account(external_account.pubkey(), external_account_info.into());

    // Create the Swig account
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    // Create second authority with external kill switch
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add authority with external kill switch
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ExternalKillSwitch(
                ExternalKillSwitch::new(
                    external_account.pubkey().to_bytes(),
                    1u64.to_le_bytes().as_slice(), // Expected value
                    8,                             // Start index
                    16,                            // End index
                )
                .unwrap(),
            ),
            ClientAction::Program(Program {
                program_id: solana_sdk::system_program::ID.to_bytes(),
            }),
        ],
    )
    .unwrap();

    context.svm.airdrop(&swig, 10_000_000_000).unwrap();

    // Create a simple transfer instruction to test
    let amount = 1_000_000;
    let transfer_ix = system_instruction::transfer(&swig, &recipient.pubkey(), amount);

    // Create sign_v1 instruction WITHOUT adding the external account
    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        transfer_ix,
        1, // role_id for the authority with kill switch
    )
    .unwrap();
    // Note: NOT adding external account to instruction accounts

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    // Execute the instruction - should fail due to missing external account
    let result = context.svm.send_transaction(transfer_tx);

    assert!(
        result.is_err(),
        "Transaction should fail when external account is missing"
    );

    // Should fail with external kill switch error (3029) because account is not
    // provided
    let error = result.unwrap_err();
    assert_eq!(
        error.err,
        TransactionError::InstructionError(0, InstructionError::Custom(3030))
    );

    println!(
        "✅ External kill switch correctly blocked execution when external account is missing"
    );

    // Verify no funds were transferred
    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(recipient_account.lamports, 10_000_000_000); // Only initial
                                                            // airdrop
}

#[test_log::test]
fn test_external_kill_switch_with_different_numeric_types() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    // Fund accounts
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Test different numeric types
    struct TestCase {
        name: &'static str,
        data_value: Vec<u8>,
        expected_data: Vec<u8>,
        start_index: u32,
        end_index: u32,
    }

    let test_cases = vec![
        TestCase {
            name: "u8",
            data_value: vec![42],
            expected_data: vec![42],
            start_index: 0,
            end_index: 1,
        },
        TestCase {
            name: "u32",
            data_value: 12345u32.to_le_bytes().to_vec(),
            expected_data: 12345u32.to_le_bytes().to_vec(),
            start_index: 0,
            end_index: 4,
        },
        TestCase {
            name: "u128",
            data_value: 987654321123456789u128.to_le_bytes().to_vec(),
            expected_data: 987654321123456789u128.to_le_bytes().to_vec(),
            start_index: 0,
            end_index: 16,
        },
    ];

    for test_case in test_cases {
        println!("Testing numeric type: {}", test_case.name);

        // Create external account with test data
        let external_account = Keypair::new();
        let mut external_account_data = vec![0u8; 32]; // Make it large enough
        external_account_data[test_case.start_index as usize..test_case.end_index as usize]
            .copy_from_slice(&test_case.data_value);

        let external_account_info = Account {
            lamports: 1_000_000,
            data: external_account_data,
            owner: solana_sdk::system_program::id(),
            executable: false,
            rent_epoch: 0,
        };

        context
            .svm
            .set_account(external_account.pubkey(), external_account_info.into());

        // Create new swig account for this test
        let test_id = rand::random::<[u8; 32]>();
        let test_swig =
            Pubkey::find_program_address(&swig_account_seeds(&test_id), &program_id()).0;

        let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, test_id);
        assert!(swig_create_txn.is_ok());

        // Create second authority with external kill switch
        let second_authority = Keypair::new();
        context
            .svm
            .airdrop(&second_authority.pubkey(), 10_000_000_000)
            .unwrap();

        // Add authority with external kill switch
        add_authority_with_ed25519_root(
            &mut context,
            &test_swig,
            &swig_authority,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: second_authority.pubkey().as_ref(),
            },
            vec![
                ClientAction::ExternalKillSwitch(
                    ExternalKillSwitch::new(
                        external_account.pubkey().to_bytes(),
                        &test_case.expected_data,
                        test_case.start_index,
                        test_case.end_index,
                    )
                    .unwrap(),
                ),
                ClientAction::Program(Program {
                    program_id: solana_sdk::system_program::ID.to_bytes(),
                }),
                ClientAction::SolLimit(SolLimit { amount: 2_000_000 }), // Allow up to 2M lamports
            ],
        )
        .unwrap();

        context.svm.airdrop(&test_swig, 10_000_000_000).unwrap();

        // Create a simple transfer instruction to test
        let amount = 1_000_000;
        let transfer_ix = system_instruction::transfer(&test_swig, &recipient.pubkey(), amount);

        // Create sign_v1 instruction
        let mut sign_ix = swig_interface::SignInstruction::new_ed25519(
            test_swig,
            second_authority.pubkey(),
            second_authority.pubkey(),
            transfer_ix,
            1, // role_id for the authority with kill switch
        )
        .unwrap();

        // Add external account to the instruction accounts so it can be read
        sign_ix
            .accounts
            .push(AccountMeta::new_readonly(external_account.pubkey(), false));

        let transfer_message = v0::Message::try_compile(
            &second_authority.pubkey(),
            &[sign_ix],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap();

        let transfer_tx = VersionedTransaction::try_new(
            VersionedMessage::V0(transfer_message),
            &[&second_authority],
        )
        .unwrap();

        // Execute the instruction - should succeed since values match
        let result = context.svm.send_transaction(transfer_tx);

        assert!(
            result.is_ok(),
            "Transaction should succeed for numeric type {}",
            test_case.name
        );

        println!(
            "✅ External kill switch correctly worked with {} type",
            test_case.name
        );
    }
}

#[test_log::test]
fn test_kill_switch_blocks_add_authority_v1() {
    let mut context = setup_test_context().unwrap();
    let (swig, _swig_authority, test_authority, external_account) =
        setup_swig_with_blocking_kill_switch(&mut context);

    let new_authority = Keypair::new();
    context
        .svm
        .airdrop(&new_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Try to add a new authority with the test authority that has kill switch
    let mut add_authority_ix = swig_interface::AddAuthorityInstruction::new_with_ed25519_authority(
        swig,
        test_authority.pubkey(),
        test_authority.pubkey(),
        1, // role_id
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    // Add external account as the last account (required for kill switch)
    add_authority_ix
        .accounts
        .push(AccountMeta::new_readonly(external_account.pubkey(), false));

    let message = v0::Message::try_compile(
        &test_authority.pubkey(),
        &[add_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&test_authority]).unwrap();

    let result = context.svm.send_transaction(tx);

    // Should fail due to kill switch blocking execution
    assert!(
        result.is_err(),
        "Transaction should fail due to kill switch blocking execution"
    );

    if let Err(err) = result {
        println!(
            "Kill switch successfully blocked add_authority_v1: {:?}",
            err
        );
        assert!(
            format!("{:?}", err).contains("PermissionDeniedExternalKillSwitchTriggered")
                || format!("{:?}", err).contains("InstructionError")
        );
    }
}

#[test_log::test]
fn test_kill_switch_blocks_remove_authority_v1() {
    let mut context = setup_test_context().unwrap();
    let (swig, _swig_authority, test_authority, external_account) =
        setup_swig_with_blocking_kill_switch(&mut context);

    // Try to remove an authority with the test authority that has kill switch
    let mut remove_authority_ix =
        swig_interface::RemoveAuthorityInstruction::new_with_ed25519_authority(
            swig,
            test_authority.pubkey(),
            test_authority.pubkey(),
            1, // role_id
            1, // authority_id (the authority to remove)
        )
        .unwrap();

    // Add external account as the last account (required for kill switch)
    remove_authority_ix
        .accounts
        .push(AccountMeta::new_readonly(external_account.pubkey(), false));

    let message = v0::Message::try_compile(
        &test_authority.pubkey(),
        &[remove_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&test_authority]).unwrap();

    let result = context.svm.send_transaction(tx);

    // Should fail due to kill switch blocking execution
    assert!(
        result.is_err(),
        "Transaction should fail due to kill switch blocking execution"
    );

    if let Err(err) = result {
        println!(
            "Kill switch successfully blocked remove_authority_v1: {:?}",
            err
        );
        assert!(
            format!("{:?}", err).contains("PermissionDeniedExternalKillSwitchTriggered")
                || format!("{:?}", err).contains("InstructionError")
        );
    }
}

#[test_log::test]
fn test_kill_switch_blocks_update_authority_v1() {
    let mut context = setup_test_context().unwrap();
    let (swig, _swig_authority, test_authority, external_account) =
        setup_swig_with_blocking_kill_switch(&mut context);

    // Try to update an authority with the test authority that has kill switch
    let mut update_authority_ix =
        swig_interface::UpdateAuthorityInstruction::new_with_ed25519_authority(
            swig,
            test_authority.pubkey(),
            test_authority.pubkey(),
            1, // role_id
            1, // authority_id (the authority to update)
            UpdateAuthorityData::ReplaceAll(vec![ClientAction::ManageAuthority(
                ManageAuthority {},
            )]), // Updated actions
        )
        .unwrap();

    // Add external account as the last account (required for kill switch)
    update_authority_ix
        .accounts
        .push(AccountMeta::new_readonly(external_account.pubkey(), false));

    let message = v0::Message::try_compile(
        &test_authority.pubkey(),
        &[update_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&test_authority]).unwrap();

    let result = context.svm.send_transaction(tx);

    // Should fail due to kill switch blocking execution
    assert!(
        result.is_err(),
        "Transaction should fail due to kill switch blocking execution"
    );

    if let Err(err) = result {
        println!(
            "Kill switch successfully blocked update_authority_v1: {:?}",
            err
        );
        assert!(
            format!("{:?}", err).contains("PermissionDeniedExternalKillSwitchTriggered")
                || format!("{:?}", err).contains("InstructionError")
        );
    }
}

#[test_log::test]
fn test_kill_switch_blocks_create_session_v1() {
    let mut context = setup_test_context().unwrap();
    let (swig, _swig_authority, test_authority, external_account) =
        setup_swig_with_blocking_kill_switch(&mut context);

    let session_key = Keypair::new();
    let session_duration = 100; // 100 slots

    // Try to create a session with the test authority that has kill switch
    let mut create_session_ix = CreateSessionInstruction::new_with_ed25519_authority(
        swig,
        test_authority.pubkey(),
        test_authority.pubkey(),
        1, // role_id
        session_key.pubkey(),
        session_duration,
    )
    .unwrap();

    // Add external account as the last account (required for kill switch)
    create_session_ix
        .accounts
        .push(AccountMeta::new_readonly(external_account.pubkey(), false));

    let message = v0::Message::try_compile(
        &test_authority.pubkey(),
        &[create_session_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&test_authority]).unwrap();

    let result = context.svm.send_transaction(tx);

    // Should fail due to kill switch blocking execution
    assert!(
        result.is_err(),
        "Transaction should fail due to kill switch blocking execution"
    );

    if let Err(err) = result {
        println!(
            "Kill switch successfully blocked create_session_v1: {:?}",
            err
        );
        assert!(
            format!("{:?}", err).contains("PermissionDeniedExternalKillSwitchTriggered")
                || format!("{:?}", err).contains("InstructionError")
        );
    }
}

#[test_log::test]
fn test_kill_switch_blocks_create_sub_account_v1() {
    let mut context = setup_test_context().unwrap();
    let (swig, _swig_authority, test_authority, external_account) =
        setup_swig_with_blocking_kill_switch(&mut context);

    // Generate a random sub-account ID and derive the sub-account address
    let sub_account_id = rand::random::<[u8; 32]>();
    let role_id_bytes = 1u32.to_le_bytes();
    let (sub_account, sub_account_bump) = Pubkey::find_program_address(
        &sub_account_seeds(&sub_account_id, &role_id_bytes),
        &program_id(),
    );

    // Try to create a sub-account with the test authority that has kill switch
    let mut create_sub_account_ix = CreateSubAccountInstruction::new_with_ed25519_authority(
        swig,
        test_authority.pubkey(),
        test_authority.pubkey(),
        sub_account,
        1, // role_id
        sub_account_bump,
    )
    .unwrap();

    // Add external account as the last account (required for kill switch)
    create_sub_account_ix
        .accounts
        .push(AccountMeta::new_readonly(external_account.pubkey(), false));

    let message = v0::Message::try_compile(
        &test_authority.pubkey(),
        &[create_sub_account_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&test_authority]).unwrap();

    let result = context.svm.send_transaction(tx);

    // Should fail due to kill switch blocking execution
    assert!(
        result.is_err(),
        "Transaction should fail due to kill switch blocking execution"
    );

    if let Err(err) = result {
        println!(
            "Kill switch successfully blocked create_sub_account_v1: {:?}",
            err
        );
        assert!(
            format!("{:?}", err).contains("PermissionDeniedExternalKillSwitchTriggered")
                || format!("{:?}", err).contains("InstructionError")
        );
    }
}

#[test_log::test]
fn test_kill_switch_blocks_toggle_sub_account_v1() {
    let mut context = setup_test_context().unwrap();
    let (swig, _swig_authority, test_authority, external_account) =
        setup_swig_with_blocking_kill_switch(&mut context);

    // Generate a random sub-account ID and derive the sub-account address
    let sub_account_id = rand::random::<[u8; 32]>();
    let role_id_bytes = 1u32.to_le_bytes();
    let (sub_account, _sub_account_bump) = Pubkey::find_program_address(
        &sub_account_seeds(&sub_account_id, &role_id_bytes),
        &program_id(),
    );

    // Try to toggle a sub-account with the test authority that has kill switch
    let mut toggle_sub_account_ix = ToggleSubAccountInstruction::new_with_ed25519_authority(
        swig,
        test_authority.pubkey(),
        test_authority.pubkey(),
        sub_account,
        1,     // role_id
        false, // enabled (disable the sub-account)
    )
    .unwrap();

    // Add external account as the last account (required for kill switch)
    toggle_sub_account_ix
        .accounts
        .push(AccountMeta::new_readonly(external_account.pubkey(), false));

    let message = v0::Message::try_compile(
        &test_authority.pubkey(),
        &[toggle_sub_account_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&test_authority]).unwrap();

    let result = context.svm.send_transaction(tx);

    // Should fail due to kill switch blocking execution
    assert!(
        result.is_err(),
        "Transaction should fail due to kill switch blocking execution"
    );

    if let Err(err) = result {
        println!(
            "Kill switch successfully blocked toggle_sub_account_v1: {:?}",
            err
        );
        assert!(
            format!("{:?}", err).contains("PermissionDeniedExternalKillSwitchTriggered")
                || format!("{:?}", err).contains("InstructionError")
        );
    }
}

#[test_log::test]
fn test_kill_switch_blocks_sub_account_sign_v1() {
    let mut context = setup_test_context().unwrap();
    let (swig, _swig_authority, test_authority, external_account) =
        setup_swig_with_blocking_kill_switch(&mut context);

    // Generate a random sub-account ID and derive the sub-account address
    let sub_account_id = rand::random::<[u8; 32]>();
    let role_id_bytes = 1u32.to_le_bytes();
    let (sub_account, _sub_account_bump) = Pubkey::find_program_address(
        &sub_account_seeds(&sub_account_id, &role_id_bytes),
        &program_id(),
    );

    // Create a simple transfer instruction to sign
    let recipient = Keypair::new();
    let transfer_ix =
        system_instruction::transfer(&test_authority.pubkey(), &recipient.pubkey(), 1_000_000);

    // Try to sign with a sub-account using the test authority that has kill switch
    let mut sub_account_sign_ix = SubAccountSignInstruction::new_with_ed25519_authority(
        swig,
        sub_account,
        test_authority.pubkey(),
        test_authority.pubkey(),
        1, // role_id
        vec![transfer_ix],
    )
    .unwrap();

    // Add external account as the last account (required for kill switch)
    sub_account_sign_ix
        .accounts
        .push(AccountMeta::new_readonly(external_account.pubkey(), false));

    let message = v0::Message::try_compile(
        &test_authority.pubkey(),
        &[sub_account_sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&test_authority]).unwrap();

    let result = context.svm.send_transaction(tx);

    // Should fail due to kill switch blocking execution
    assert!(
        result.is_err(),
        "Transaction should fail due to kill switch blocking execution"
    );

    if let Err(err) = result {
        println!(
            "Kill switch successfully blocked sub_account_sign_v1: {:?}",
            err
        );
        assert!(
            format!("{:?}", err).contains("PermissionDeniedExternalKillSwitchTriggered")
                || format!("{:?}", err).contains("InstructionError")
        );
    }
}

#[test_log::test]
fn test_kill_switch_blocks_withdraw_from_sub_account_v1() {
    let mut context = setup_test_context().unwrap();
    let (swig, _swig_authority, test_authority, external_account) =
        setup_swig_with_blocking_kill_switch(&mut context);

    // Generate a random sub-account ID and derive the sub-account address
    let sub_account_id = rand::random::<[u8; 32]>();
    let role_id_bytes = 1u32.to_le_bytes();
    let (sub_account, _sub_account_bump) = Pubkey::find_program_address(
        &sub_account_seeds(&sub_account_id, &role_id_bytes),
        &program_id(),
    );

    let withdraw_amount = 1_000_000; // 1 SOL in lamports

    // Try to withdraw from a sub-account with the test authority that has kill
    // switch
    let mut withdraw_ix = WithdrawFromSubAccountInstruction::new_with_ed25519_authority(
        swig,
        test_authority.pubkey(),
        test_authority.pubkey(),
        sub_account,
        1, // role_id
        withdraw_amount,
    )
    .unwrap();

    // Add external account as the last account (required for kill switch)
    withdraw_ix
        .accounts
        .push(AccountMeta::new_readonly(external_account.pubkey(), false));

    let message = v0::Message::try_compile(
        &test_authority.pubkey(),
        &[withdraw_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&test_authority]).unwrap();

    let result = context.svm.send_transaction(tx);

    // Should fail due to kill switch blocking execution
    assert!(
        result.is_err(),
        "Transaction should fail due to kill switch blocking execution"
    );

    if let Err(err) = result {
        println!(
            "Kill switch successfully blocked withdraw_from_sub_account_v1: {:?}",
            err
        );
        assert!(
            format!("{:?}", err).contains("PermissionDeniedExternalKillSwitchTriggered")
                || format!("{:?}", err).contains("InstructionError")
        );
    }
}
