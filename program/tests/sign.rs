mod common;
use borsh::BorshDeserialize;
use common::*;
use litesvm_token::spl_token::{self, instruction::TokenInstruction};
use pinocchio_pubkey::from_str;
use solana_sdk::{
    instruction::{AccountMeta, Instruction, InstructionError},
    message::{v0, VersionedMessage},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction, system_program,
    transaction::{TransactionError, VersionedTransaction},
};
use swig::actions::sign_v1::SYSTEM_PROGRAM_ID;
use swig_interface::AuthorityConfig;
use swig_state::{
    swig_account_seeds, Action, AuthorityType, SolAction, Swig, TokenAction, VMInstruction,
};

#[test_log::test]
fn test_transfer_sol_with_additional_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 13]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig,
        &context.default_payer,
    )
    .unwrap();
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        1000,
    )
    .unwrap();

    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, &id);
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![Action::Sol {
            action: SolAction::Manage(1000000000),
        }],
        0,
        0,
    )
    .unwrap();
    context.svm.airdrop(&swig, 10_000_000_000).unwrap();
    assert!(swig_create_txn.is_ok());
    let amount = 100000;
    let ixd = system_instruction::transfer(&swig, &recipient.pubkey(), amount);
    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        ixd,
        1, // new authority role id
    )
    .unwrap();
    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[second_authority])
            .unwrap();
    let res = context.svm.send_transaction(transfer_tx);
    if res.is_err() {
        println!("{:?}", res.err());
        assert!(false);
    } else {
        println!("Sign Transfer CU {:?}", res.unwrap().compute_units_consumed);
    }
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig = Swig::try_from_slice(&swig_account.data).unwrap();
    let role = swig.roles.last().unwrap();

    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(swig.roles.len(), 2);
    assert_eq!(
        role.actions[0],
        Action::Sol {
            action: SolAction::Manage(1000000000 - amount)
        }
    );
    assert_eq!(recipient_account.lamports, 10_000_000_000 + amount);
}

#[test_log::test]
fn test_transfer_sol_all_with_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 13]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, &id);

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![Action::Sol {
            action: SolAction::All,
        }],
        0,
        0,
    )
    .unwrap();
    let swig_lamports_balance = context.svm.get_account(&swig).unwrap().lamports;
    let initial_swig_balance = 10_000_000_000;
    context.svm.airdrop(&swig, initial_swig_balance).unwrap();
    assert!(swig_create_txn.is_ok());

    let amount = 5_000_000_000; // 5 SOL
    let ixd = system_instruction::transfer(&swig, &recipient.pubkey(), amount);
    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        ixd,
        1,
    )
    .unwrap();

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

    let res = context.svm.send_transaction(transfer_tx);
    assert!(res.is_ok());
    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    let swig_account_after = context.svm.get_account(&swig).unwrap();
    assert_eq!(recipient_account.lamports, 10_000_000_000 + amount);

    assert_eq!(
        swig_account_after.lamports,
        swig_lamports_balance + initial_swig_balance - amount
    );
    let swig_state = Swig::try_from_slice(&swig_account_after.data).unwrap();
    let role = swig_state.roles.last().unwrap();
    assert_eq!(
        role.actions[0],
        Action::Sol {
            action: SolAction::All
        }
    );
}

#[test_log::test]
fn test_transfer_sol_and_tokens_with_mixed_permissions() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 13]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    context.svm.warp_to_slot(10);
    // Setup token infrastructure
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        1000,
    )
    .unwrap();

    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, &id);
    assert!(swig_create_txn.is_ok());

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            Action::Sol {
                action: SolAction::Manage(100),
            },
            Action::Tokens {
                action: TokenAction::All,
            },
        ],
        0,
        0,
    )
    .unwrap();

    context.svm.airdrop(&swig, 10_000_000_000).unwrap();
    let sol_amount = 50;
    let token_amount = 500;

    context.svm.warp_to_slot(100);
    let sol_ix = system_instruction::transfer(&swig, &recipient.pubkey(), sol_amount);
    let token_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer {
            amount: token_amount,
        }
        .pack(),
    };

    let account = context.svm.get_account(&swig_ata).unwrap();
    let token_account = spl_token::state::Account::unpack(&account.data).unwrap();

    let raccount = context.svm.get_account(&recipient_ata).unwrap();
    let rtoken_account = spl_token::state::Account::unpack(&raccount.data).unwrap();

    println!("pk: {} account: {:?}", swig_ata, token_account);
    println!("pk: {} account: {:?}", recipient_ata, rtoken_account);
    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix,
        1,
    )
    .unwrap();

    let sign_ix2 = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        sol_ix,
        1,
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix, sign_ix2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    let res = context.svm.send_transaction(transfer_tx);
    if res.is_err() {
        let e = res.unwrap_err();
        println!("Logs {} - {:?}", e.err, e.meta.logs);
    }
    // assert!(res.is_ok());
    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(recipient_account.lamports, 10_000_000_000 + sol_amount);
    let recipient_token_account = context.svm.get_account(&recipient_ata).unwrap();
    let token_account = spl_token::state::Account::unpack(&recipient_token_account.data).unwrap();
    assert_eq!(token_account.amount, token_amount);
    let swig_token_account = context.svm.get_account(&swig_ata).unwrap();
    let swig_token_balance = spl_token::state::Account::unpack(&swig_token_account.data).unwrap();
    assert_eq!(swig_token_balance.amount, 1000 - token_amount);
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = Swig::try_from_slice(&swig_account.data).unwrap();
    let role = swig_state.roles.last().unwrap();
    assert_eq!(
        role.actions[0],
        Action::Sol {
            action: SolAction::Manage(100 - sol_amount)
        }
    );
    assert_eq!(
        role.actions[1],
        Action::Tokens {
            action: TokenAction::All
        }
    );
}

#[test_log::test]
fn test_fail_transfer_sol_with_additional_authority_not_enough() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 13]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, &id);
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![Action::Sol {
            action: SolAction::Manage(1000),
        }],
        0,
        0,
    )
    .unwrap();
    context.svm.airdrop(&swig, 10_000_000_000).unwrap();
    assert!(swig_create_txn.is_ok());
    let amount = 1001;
    let ixd = system_instruction::transfer(&swig, &recipient.pubkey(), amount);
    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        ixd,
        1, // new authority role id
    )
    .unwrap();
    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[second_authority])
            .unwrap();
    let res = context.svm.send_transaction(transfer_tx);
    assert!(res.is_err());
    assert_eq!(
        res.unwrap_err().err,
        TransactionError::InstructionError(0, InstructionError::Custom(15))
    );
}

#[test_log::test]
fn fail_not_correct_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 13]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, &id);
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![Action::Sol {
            action: SolAction::Manage(1000),
        }],
        0,
        0,
    )
    .unwrap();
    context.svm.airdrop(&swig, 10_000_000_000).unwrap();
    assert!(swig_create_txn.is_ok());
    let amount = 1001;
    let fake_authority = Keypair::new();
    context
        .svm
        .airdrop(&fake_authority.pubkey(), 10_000_000_000)
        .unwrap();
    let ixd = system_instruction::transfer(&swig, &recipient.pubkey(), amount);
    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        fake_authority.pubkey(),
        fake_authority.pubkey(),
        ixd,
        1, // new authority role id
    )
    .unwrap();
    let transfer_message = v0::Message::try_compile(
        &fake_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[fake_authority])
            .unwrap();
    let res = context.svm.send_transaction(transfer_tx);
    assert!(res.is_err());
    assert_eq!(
        res.unwrap_err().err,
        TransactionError::InstructionError(0, InstructionError::Custom(10))
    );
}

#[test_log::test]
fn fail_not_wrong_resource() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 13]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &recipient.pubkey(),
        &recipient,
    )
    .unwrap();
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        1000,
    )
    .unwrap();

    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, &id);
    assert!(swig_create_txn.is_ok());
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![Action::Sol {
            action: SolAction::All,
        }],
        0,
        0,
    )
    .unwrap();

    let ixd = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer { amount: 100 }.pack(),
    };

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        ixd,
        1,
    )
    .unwrap();

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
    let res = context.svm.send_transaction(transfer_tx);

    assert_eq!(
        res.unwrap_err().err,
        TransactionError::InstructionError(0, InstructionError::Custom(15))
    );
    let account = context.svm.get_account(&swig_ata).unwrap();
    let token_account = spl_token::state::Account::unpack(&account.data).unwrap();
    assert_eq!(token_account.amount, 1000);
}

#[test_log::test]
fn test_sol_transfer_with_plugin_validation() {
    let mut context = setup_test_context().unwrap();

    // Create keypairs for our test
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    let second_authority = Keypair::new();

    // Airdrop SOL to accounts
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create Swig account
    let id = rand::random::<[u8; 13]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, &id);
    assert!(
        swig_create_txn.is_ok(),
        "Failed to create Swig: {:?}",
        swig_create_txn.err()
    );
    println!("Created Swig wallet: {}", swig);

    // Add second authority with SOL management permissions
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![Action::Sol {
            action: SolAction::Manage(1000000000),
        }],
        0,
        0,
    )
    .unwrap();

    // Fund the Swig account
    context.svm.airdrop(&swig, 10_000_000_000).unwrap();

    // Derive a PDA for the plugin bytecode account using "swig-pim" seed and the
    // correct system program id (since we're validating SOL transfers)
    let system_program_bytes = [
        5, 135, 132, 191, 20, 139, 164, 40, 47, 176, 18, 87, 72, 136, 169, 241, 83, 160, 125, 173,
        247, 101, 192, 69, 92, 154, 151, 3, 128, 0, 0, 0,
    ];

    let target_program_id = Pubkey::new_from_array(SYSTEM_PROGRAM_ID);
    let seeds = &[b"swig-pim", target_program_id.as_ref()];
    let (plugin_bytecode_account, _) = Pubkey::find_program_address(seeds, &program_id());
    println!("Using target program ID: {}", target_program_id);
    println!("Plugin bytecode PDA: {}", plugin_bytecode_account);

    // Create a plugin that validates the recipient pubkey
    // This plugin will check if the recipient pubkey matches our expected recipient
    // If it matches, it returns 1 (success), otherwise returns 0 (failure)
    println!("Creating plugin to validate recipient account");

    // Create VM instructions for plugin bytecode
    let mut validation_instructions = Vec::new();

    // Start with value 1 (assume success)
    validation_instructions.push(VMInstruction::PushValue { value: 1 });

    // Compare each 8-byte chunk of the recipient's pubkey
    // According to the transaction logs:
    // Index 1 is the expected recipient
    // Index 3 is the actual recipient
    // We need to load from their pubkey bytes using 0xFF00+ offsets

    // First chunk (bytes 0-7)
    validation_instructions.push(VMInstruction::LoadField {
        account_index: 1,     // Expected recipient
        field_offset: 0xFF00, // Public key bytes offset 0
        padding: [0; 4],
    });
    validation_instructions.push(VMInstruction::LoadField {
        account_index: 2,     // Actual recipient
        field_offset: 0xFF00, // Public key bytes offset 0
        padding: [0; 4],
    });
    validation_instructions.push(VMInstruction::Equal);
    validation_instructions.push(VMInstruction::And);

    // Second chunk (bytes 8-15)
    validation_instructions.push(VMInstruction::LoadField {
        account_index: 1,     // Expected recipient
        field_offset: 0xFF08, // Public key bytes offset 8
        padding: [0; 4],
    });
    validation_instructions.push(VMInstruction::LoadField {
        account_index: 2,     // Actual recipient
        field_offset: 0xFF08, // Public key bytes offset 8
        padding: [0; 4],
    });
    validation_instructions.push(VMInstruction::Equal);
    validation_instructions.push(VMInstruction::And);

    // Third chunk (bytes 16-23)
    validation_instructions.push(VMInstruction::LoadField {
        account_index: 1,     // Expected recipient
        field_offset: 0xFF10, // Public key bytes offset 16
        padding: [0; 4],
    });
    validation_instructions.push(VMInstruction::LoadField {
        account_index: 2,     // Actual recipient
        field_offset: 0xFF10, // Public key bytes offset 16
        padding: [0; 4],
    });
    validation_instructions.push(VMInstruction::Equal);
    validation_instructions.push(VMInstruction::And);

    // Fourth chunk (bytes 24-31)
    validation_instructions.push(VMInstruction::LoadField {
        account_index: 1,     // Expected recipient
        field_offset: 0xFF18, // Public key bytes offset 24
        padding: [0; 4],
    });
    validation_instructions.push(VMInstruction::LoadField {
        account_index: 2,     // Actual recipient
        field_offset: 0xFF18, // Public key bytes offset 24
        padding: [0; 4],
    });
    validation_instructions.push(VMInstruction::Equal);
    validation_instructions.push(VMInstruction::And);

    // Return result - 1 means success (all chunks matched), 0 means failure
    validation_instructions.push(VMInstruction::Return);

    // Create a plugin bytecode account
    let create_plugin_ix = swig_interface::CreatePluginBytecodeInstruction::new(
        plugin_bytecode_account,
        target_program_id,
        target_program_id, // Using target_program_id as program_data for simplicity
        swig_authority.pubkey(),
        system_program::ID,
        &validation_instructions,
    );

    let create_plugin_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[create_plugin_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let create_plugin_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(create_plugin_message),
        &[&swig_authority],
    )
    .unwrap();

    let create_plugin_result = context.svm.send_transaction(create_plugin_tx);
    assert!(
        create_plugin_result.is_ok(),
        "Failed to create plugin bytecode account: {:?}",
        create_plugin_result.err()
    );

    println!(
        "Created plugin bytecode account: CU = {:?}",
        create_plugin_result.unwrap().compute_units_consumed
    );

    // First perform a normal SOL transfer without plugin to benchmark
    let amount = 100000;
    let sol_ix = system_instruction::transfer(&swig, &recipient.pubkey(), amount);

    let sign_ix_no_plugin = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        sol_ix.clone(),
        1, // new authority role id
    )
    .unwrap();

    let transfer_message_no_plugin = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix_no_plugin],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx_no_plugin = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message_no_plugin),
        &[&second_authority],
    )
    .unwrap();

    let res_no_plugin = context.svm.send_transaction(transfer_tx_no_plugin);
    assert!(
        res_no_plugin.is_ok(),
        "Transfer without plugin failed: {:?}",
        res_no_plugin.err()
    );
    let cu_no_plugin = res_no_plugin.unwrap().compute_units_consumed;
    println!("SOL Transfer WITHOUT plugin CU: {:?}", cu_no_plugin);

    // Now perform the same transfer but with plugin validation
    let sign_ix_with_plugin = swig_interface::SignInstruction::new_ed25519_with_plugin_targets(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        sol_ix,
        1,       // authority role id
        &[1, 2], // Index of recipient account to validate
    )
    .unwrap();

    // Include the plugin bytecode account and recipient account as additional
    // accounts
    let mut sign_ix_mut = sign_ix_with_plugin.clone();
    sign_ix_mut
        .accounts
        .push(AccountMeta::new(recipient.pubkey(), false)); // Add recipient account
    sign_ix_mut
        .accounts
        .push(AccountMeta::new_readonly(plugin_bytecode_account, false));

    // Print the accounts as they'll appear in the transaction for debugging
    println!("\nTransaction account ordering:");
    println!("0: payer/fee payer - {}", second_authority.pubkey());
    println!("1: recipient (expected) - {}", recipient.pubkey());
    println!(
        "2: second_authority (signer) - {}",
        second_authority.pubkey()
    );
    println!("3: recipient (actual) - {}", recipient.pubkey());
    println!("4: plugin account - {}", plugin_bytecode_account);

    let transfer_message_with_plugin = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix_mut],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx_with_plugin = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message_with_plugin),
        &[&second_authority],
    )
    .unwrap();

    let res_with_plugin = context.svm.send_transaction(transfer_tx_with_plugin);
    assert!(
        res_with_plugin.is_ok(),
        "Transfer with plugin failed: {:?}",
        res_with_plugin.err()
    );
    if let Ok(result) = res_with_plugin {
        let cu_with_plugin = result.compute_units_consumed;
        println!("SOL Transfer WITH plugin CU: {:?}", cu_with_plugin);

        // Output program logs if available
        println!("Program logs for transfer with plugin:");
        for (idx, log) in result.logs.iter().enumerate() {
            println!("  {}: {}", idx, log);
        }

        // Calculate the overhead
        let plugin_overhead = cu_with_plugin - cu_no_plugin;
        println!(
            "Plugin validation overhead: {} CU ({:.2}% increase)",
            plugin_overhead,
            (plugin_overhead as f64 / cu_no_plugin as f64) * 100.0
        );
    }

    // Verify the SOL transfer was successful (role's remaining allowance decrements
    // properly)
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = Swig::try_from_slice(&swig_account.data).unwrap();
    let role = swig_state.roles.last().unwrap();

    // We now use a variable to hold the cu_with_plugin value
    assert_eq!(
        role.actions[0],
        Action::Sol {
            action: SolAction::Manage(1000000000 - amount * 2) // 2 transfers happened
        }
    );

    // Verify recipient received the SOL
    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(recipient_account.lamports, 10_000_000_000 + amount * 2);

    // Now try with an incorrect recipient to verify plugin rejection
    let incorrect_recipient = Keypair::new();
    context
        .svm
        .airdrop(&incorrect_recipient.pubkey(), 10_000_000_000)
        .unwrap();

    println!(
        "\nTesting with incorrect recipient: {}",
        incorrect_recipient.pubkey()
    );

    // Create transfer instruction to incorrect recipient
    let incorrect_sol_ix =
        system_instruction::transfer(&swig, &incorrect_recipient.pubkey(), amount);

    let sign_ix_incorrect = swig_interface::SignInstruction::new_ed25519_with_plugin_targets(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        incorrect_sol_ix,
        1,       // authority role id
        &[1, 3], // Index of recipient account to validate
    )
    .unwrap();

    // Include the plugin bytecode account and incorrect recipient account
    let mut sign_ix_incorrect_mut = sign_ix_incorrect.clone();
    sign_ix_incorrect_mut
        .accounts
        .push(AccountMeta::new(recipient.pubkey(), false)); // Expected recipient
    sign_ix_incorrect_mut
        .accounts
        .push(AccountMeta::new(incorrect_recipient.pubkey(), false)); // Actual recipient
    sign_ix_incorrect_mut
        .accounts
        .push(AccountMeta::new_readonly(plugin_bytecode_account, false));

    println!("\nTransaction account ordering for incorrect recipient test:");
    println!("0: payer/fee payer - {}", second_authority.pubkey());
    println!("1: recipient (expected) - {}", recipient.pubkey());
    println!(
        "2: second_authority (signer) - {}",
        second_authority.pubkey()
    );
    println!(
        "3: incorrect_recipient (actual) - {}",
        incorrect_recipient.pubkey()
    );
    println!("4: plugin account - {}", plugin_bytecode_account);

    let transfer_message_incorrect = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix_incorrect_mut],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx_incorrect = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message_incorrect),
        &[&second_authority],
    )
    .unwrap();

    let res_incorrect = context.svm.send_transaction(transfer_tx_incorrect);
    println!("res_incorrect: {:?}", res_incorrect);

    // This transaction should be rejected by the plugin
    assert!(
        res_incorrect.is_err(),
        "Transaction with incorrect recipient should have been rejected by
    plugin"
    );

    if let Err(err) = res_incorrect {
        println!(
            "Correctly rejected transaction with incorrect recipient: {:?}",
            err
        );

        // The error should be our custom error code 406 (ValidationFailed)
        assert_eq!(
            err.err,
            TransactionError::InstructionError(0, InstructionError::Custom(406))
        );
    } else {
        // panic!("Expected transaction to fail with ValidationFailed error
        // (406)");
    }
}

#[test_log::test]
fn test_stake_account_withdraw_authority_validation() {
    let mut context = setup_test_context().unwrap();

    // Create keypairs for our test
    let swig_authority = Keypair::new();
    let stake_authority = Keypair::new();
    let withdraw_authority = Keypair::new();
    let second_authority = Keypair::new();
    let new_withdraw_authority = Keypair::new();

    // Airdrop SOL to accounts
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&stake_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&withdraw_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&new_withdraw_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create Swig account
    let id = rand::random::<[u8; 13]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, &id);
    assert!(
        swig_create_txn.is_ok(),
        "Failed to create Swig: {:?}",
        swig_create_txn.err()
    );
    println!("Created Swig wallet: {}", swig);

    // Add second authority with SOL management permissions
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![Action::Sol {
            action: SolAction::Manage(1000000000),
        }],
        0,
        0,
    )
    .unwrap();

    // Fund the Swig account
    context.svm.airdrop(&swig, 10_000_000_000).unwrap();

    // Get stake program ID
    let stake_program_id = solana_sdk::stake::program::id();
    println!("Stake program ID: {}", stake_program_id);

    // Create and initialize a stake account
    // Get the stake program ID
    let stake_program_id = solana_sdk::stake::program::id();
    println!("Stake program ID: {}", stake_program_id);

    // Calculate minimum balance for rent exemption
    let stake_account_size = solana_sdk::stake::state::StakeState::size_of() as usize;
    println!("Stake account size: {} bytes", stake_account_size);
    let rent = context
        .svm
        .minimum_balance_for_rent_exemption(stake_account_size);
    let stake_amount = 1_000_000_000;

    // Create a keypair for the stake account
    let stake_account_keypair = Keypair::new();

    // Use the stake program's create_account instruction directly
    // This creates and initializes the stake account in one step
    let create_stake_ix = solana_sdk::stake::instruction::create_account(
        &stake_authority.pubkey(),
        &stake_account_keypair.pubkey(),
        &solana_sdk::stake::state::Authorized {
            staker: stake_authority.pubkey(),
            withdrawer: withdraw_authority.pubkey(),
        },
        &solana_sdk::stake::state::Lockup::default(),
        stake_amount + rent,
    );

    // Create transaction to create and initialize stake account
    let create_stake_message = v0::Message::try_compile(
        &stake_authority.pubkey(),
        &create_stake_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let create_stake_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(create_stake_message),
        &[&stake_authority, &stake_account_keypair],
    )
    .unwrap();

    let create_stake_res = context.svm.send_transaction(create_stake_tx);
    assert!(
        create_stake_res.is_ok(),
        "Failed to create stake account: {:?}",
        create_stake_res.err()
    );
    println!("Created stake account: {}", stake_account_keypair.pubkey());

    // Verify stake account was properly initialized
    let stake_account = context
        .svm
        .get_account(&stake_account_keypair.pubkey())
        .unwrap();
    println!("Stake account owner: {}", stake_account.owner);
    println!("Stake program ID: {}", stake_program_id);
    println!("Stake account data length: {}", stake_account.data.len());

    // Check if the stake account is properly owned by the stake program
    if stake_account.owner != stake_program_id {
        println!("WARNING: Stake account is not owned by the stake program!");
        println!("Current owner: {}", stake_account.owner);
        println!("Expected owner: {}", stake_program_id);
    }

    assert_eq!(
        stake_account.owner, stake_program_id,
        "Stake account not owned by stake program"
    );

    // Print more detailed stake account analysis to determine structure and offsets
    if !stake_account.data.is_empty() {
        println!("DETAILED STAKE ACCOUNT STRUCTURE ANALYSIS:");
        println!("----------------------------------------");
        println!("Full stake account data (all bytes):");
        for (i, chunk) in stake_account.data.chunks(16).enumerate() {
            println!("{:02x}: {:02x?}", i * 16, chunk);
        }

        println!("\nSearching for withdraw authority pubkey pattern...");
        let auth_bytes = withdraw_authority.pubkey().to_bytes();
        println!("Withdraw authority pubkey bytes: {:02x?}", auth_bytes);

        // Search for authority in the stake account data
        for i in 0..stake_account.data.len() - 31 {
            let data_slice = &stake_account.data[i..i + 32];
            if data_slice == auth_bytes {
                println!("FOUND EXACT MATCH at offset {}", i);
                break;
            }
        }

        // Check if the authority might be stored in reverse byte order
        let mut reversed_auth = auth_bytes.clone();
        reversed_auth.reverse();
        println!("Reversed authority pubkey bytes: {:02x?}", reversed_auth);

        for i in 0..stake_account.data.len() - 31 {
            let data_slice = &stake_account.data[i..i + 32];
            if data_slice == reversed_auth {
                println!("FOUND REVERSED MATCH at offset {}", i);
                break;
            }
        }

        // Try to locate key pattern bytes sequence from different offsets
        for (offset, _) in [44, 52, 60, 68, 76, 84].iter().enumerate() {
            let offset_val = 44 + offset * 8;
            if offset_val + 8 <= stake_account.data.len() {
                let chunk = &stake_account.data[offset_val..offset_val + 8];
                println!("Offset {}: {:02x?}", offset_val, chunk);
            }
        }
    }

    // Derive a PDA for the plugin bytecode account using "swig-pim" seed and stake
    // program ID
    let seeds = &[b"swig-pim", stake_program_id.as_ref()];
    let (plugin_bytecode_account, _) = Pubkey::find_program_address(seeds, &program_id());
    println!("Plugin bytecode PDA: {}", plugin_bytecode_account);

    // Create a plugin that validates the withdraw authority
    // This plugin dynamically compares the withdraw authority in the stake account
    // with the authority that signed the transaction.
    // If they match, it returns a non-zero value (success), otherwise returns 0
    // (fail).

    // Let's print the withdraw authority pubkey to verify
    let wa_pubkey = withdraw_authority.pubkey();
    println!(
        "Withdraw authority pubkey for plugin validation: {}",
        wa_pubkey
    );
    let wa_bytes = wa_pubkey.to_bytes();
    println!("Withdraw authority bytes for plugin:");
    for (i, chunk) in wa_bytes.chunks(8).enumerate() {
        println!("Chunk {}: {:02x?}", i, chunk);
    }

    // Create VM instructions for plugin bytecode
    let mut validation_instructions = Vec::new();

    // Start with value 1 (assume success)
    validation_instructions.push(VMInstruction::PushValue { value: 1 });

    // Print the actual indices used in the transaction
    println!("Withdraw authority is signer index: 6");
    println!("Stake account is at index: 4");

    // In a stake account, the withdraw authority is stored at offsets 44-76
    // We need to check each 8-byte segment against the signer pubkey

    // Step 1: First chunk of withdraw authority from stake account
    validation_instructions.push(VMInstruction::LoadField {
        account_index: 0, // Primary account (stake account)
        field_offset: 44, // First 8 bytes of withdraw authority in stake account
        padding: [0; 4],
    });

    // Load from the actual withdraw authority account's pubkey (at index 6)
    // The special offset 0xFF00+ is used to load from pubkey bytes
    validation_instructions.push(VMInstruction::LoadField {
        account_index: 2,     // Third account in indices array (corresponds to index 6)
        field_offset: 0xFF00, // Public key bytes offset 0
        padding: [0; 4],
    });

    validation_instructions.push(VMInstruction::Equal);
    validation_instructions.push(VMInstruction::And);

    // Step 2: Second chunk
    validation_instructions.push(VMInstruction::LoadField {
        account_index: 0, // Primary account (stake account)
        field_offset: 52, // Next 8 bytes
        padding: [0; 4],
    });

    validation_instructions.push(VMInstruction::LoadField {
        account_index: 2,     // Third account in indices array (corresponds to index 6)
        field_offset: 0xFF08, // Public key bytes offset 8
        padding: [0; 4],
    });

    validation_instructions.push(VMInstruction::Equal);
    validation_instructions.push(VMInstruction::And);

    // Step 3: Third chunk
    validation_instructions.push(VMInstruction::LoadField {
        account_index: 0, // Primary account (stake account)
        field_offset: 60, // Next 8 bytes
        padding: [0; 4],
    });

    validation_instructions.push(VMInstruction::LoadField {
        account_index: 2,     // Third account in indices array (corresponds to index 6)
        field_offset: 0xFF10, // Public key bytes offset 16
        padding: [0; 4],
    });

    validation_instructions.push(VMInstruction::Equal);
    validation_instructions.push(VMInstruction::And);

    // Step 4: Fourth chunk
    validation_instructions.push(VMInstruction::LoadField {
        account_index: 0, // Primary account (stake account)
        field_offset: 68, // Final 8 bytes
        padding: [0; 4],
    });

    validation_instructions.push(VMInstruction::LoadField {
        account_index: 2,     // Third account in indices array (corresponds to index 6)
        field_offset: 0xFF18, // Public key bytes offset 24
        padding: [0; 4],
    });

    validation_instructions.push(VMInstruction::Equal);
    validation_instructions.push(VMInstruction::And);

    // Return result directly - 1 means success, 0 means failure
    validation_instructions.push(VMInstruction::Return);

    // Create the plugin bytecode account
    let create_plugin_ix = swig_interface::CreatePluginBytecodeInstruction::new(
        plugin_bytecode_account,
        stake_program_id,
        stake_program_id, // Using stake_program_id as program_data for simplicity
        swig_authority.pubkey(),
        system_program::ID,
        &validation_instructions,
    );

    let create_plugin_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[create_plugin_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let create_plugin_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(create_plugin_message),
        &[&swig_authority],
    )
    .unwrap();

    let create_plugin_result = context.svm.send_transaction(create_plugin_tx);
    assert!(
        create_plugin_result.is_ok(),
        "Failed to create plugin bytecode account: {:?}",
        create_plugin_result.err()
    );

    println!(
        "Created plugin bytecode account: CU = {:?}",
        create_plugin_result.unwrap().compute_units_consumed
    );

    // First perform a stake account authority change WITHOUT plugin to benchmark
    // This will change the withdraw authority from withdraw_authority to
    // new_withdraw_authority
    let change_auth_ix = solana_sdk::stake::instruction::authorize(
        &stake_account_keypair.pubkey(),
        &withdraw_authority.pubkey(),
        &new_withdraw_authority.pubkey(),
        solana_sdk::stake::state::StakeAuthorize::Withdrawer,
        None,
    );

    // Create the sign instruction without plugin validation
    let sign_ix_no_plugin = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        change_auth_ix.clone(),
        1, // authority role id
    )
    .unwrap();

    let auth_message_no_plugin = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix_no_plugin],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let auth_tx_no_plugin = VersionedTransaction::try_new(
        VersionedMessage::V0(auth_message_no_plugin),
        &[&second_authority, &withdraw_authority],
    )
    .unwrap();

    let res_no_plugin = context.svm.send_transaction(auth_tx_no_plugin);
    assert!(
        res_no_plugin.is_ok(),
        "Authority change without plugin failed: {:?}",
        res_no_plugin.err()
    );
    let cu_no_plugin = res_no_plugin.unwrap().compute_units_consumed;
    println!(
        "Stake authority change WITHOUT plugin CU: {:?}",
        cu_no_plugin
    );

    // Creating another stake account for testing with plugin
    // Create a keypair for the second stake account
    let stake_account2_keypair = Keypair::new();

    // Use the stake program's create_account instruction directly
    let create_stake2_ix = solana_sdk::stake::instruction::create_account(
        &stake_authority.pubkey(),
        &stake_account2_keypair.pubkey(),
        &solana_sdk::stake::state::Authorized {
            staker: stake_authority.pubkey(),
            withdrawer: withdraw_authority.pubkey(),
        },
        &solana_sdk::stake::state::Lockup::default(),
        stake_amount + rent,
    );

    // Create transaction to create and initialize stake account 2
    let create_stake2_message = v0::Message::try_compile(
        &stake_authority.pubkey(),
        &create_stake2_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let create_stake2_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(create_stake2_message),
        &[&stake_authority, &stake_account2_keypair],
    )
    .unwrap();

    let create_stake2_res = context.svm.send_transaction(create_stake2_tx);
    assert!(
        create_stake2_res.is_ok(),
        "Failed to create stake account 2: {:?}",
        create_stake2_res.err()
    );
    println!(
        "Created stake account 2: {}",
        stake_account2_keypair.pubkey()
    );

    // Now perform the same authority change but with plugin validation
    let change_auth_ix2 = solana_sdk::stake::instruction::authorize(
        &stake_account2_keypair.pubkey(),
        &withdraw_authority.pubkey(),
        &new_withdraw_authority.pubkey(),
        solana_sdk::stake::state::StakeAuthorize::Withdrawer,
        None,
    );

    println!("Using withdraw_authority: {}", withdraw_authority.pubkey());

    // Print stake account data to debug the withdraw authority location
    let stake_account2 = context
        .svm
        .get_account(&stake_account2_keypair.pubkey())
        .unwrap();
    if !stake_account2.data.is_empty() {
        println!("Stake account 2 data (first 128 bytes):");
        for (i, chunk) in stake_account2.data.chunks(16).take(8).enumerate() {
            println!("{:02x}: {:02x?}", i * 16, chunk);
        }

        // Check for withdraw authority in the expected location
        if stake_account2.data.len() >= 76 {
            println!("\nWithdraw authority in stake account (bytes 44-76):");
            let auth_in_stake = &stake_account2.data[44..76];
            println!("{:02x?}", auth_in_stake);

            // Get full withdraw authority pubkey bytes
            let withdraw_auth_bytes = withdraw_authority.pubkey().to_bytes();
            println!("\nFull withdraw_authority pubkey bytes:");
            println!("{:02x?}", withdraw_auth_bytes);

            // Compare parts to see what's matching and what's not
            if auth_in_stake.len() >= 32 {
                println!("\nComparing pubkey parts:");
                for i in 0..4 {
                    let start = i * 8;
                    let end = start + 8;
                    println!(
                        "Part {}: Stake Account[{}:{}] = {:02x?}",
                        i,
                        44 + start,
                        44 + end,
                        &auth_in_stake[start..end]
                    );
                    println!(
                        "Part {}: Auth Pubkey[{}:{}] = {:02x?}",
                        i,
                        start,
                        end,
                        &withdraw_auth_bytes[start..end]
                    );
                    println!(
                        "Match: {}",
                        &auth_in_stake[start..end] == &withdraw_auth_bytes[start..end]
                    );
                }
            }
        }
    }

    // Create the sign instruction with plugin validation
    let sign_ix_with_plugin = swig_interface::SignInstruction::new_ed25519_with_plugin_targets(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        change_auth_ix2,
        1,
        &[4, 6], // Explicitly pass indices 4 (stake account) and 6 (withdraw authority)
    )
    .unwrap();

    // Include the plugin bytecode account as an additional account
    let mut sign_ix_mut = sign_ix_with_plugin.clone();
    sign_ix_mut
        .accounts
        .push(AccountMeta::new_readonly(plugin_bytecode_account, false));

    println!("sign_ix_mut accounts: {:?}", sign_ix_mut.accounts);
    println!("Plugin account indices passed to VM: [4, 6]"); // Print for clarity

    // Print the accounts as they'll appear in the transaction
    println!("Transaction account ordering:");
    println!("0: payer/fee payer - {}", second_authority.pubkey());
    println!("1: swig - {}", swig);
    println!(
        "2: second_authority (signer) - {}",
        second_authority.pubkey()
    );
    println!("3: stake program - {}", stake_program_id);
    println!("4: stake account - {}", stake_account2_keypair.pubkey());
    println!("5: sysvar clock - SysvarC1ock11111111111111111111111111111111");
    println!(
        "6: withdraw_authority (signer) - {}",
        withdraw_authority.pubkey()
    );
    println!("7: plugin account - {}", plugin_bytecode_account);

    let auth_message_with_plugin = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix_mut],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let auth_tx_with_plugin = VersionedTransaction::try_new(
        VersionedMessage::V0(auth_message_with_plugin),
        &[&second_authority, &withdraw_authority],
    )
    .unwrap();

    let res_with_plugin = context.svm.send_transaction(auth_tx_with_plugin);
    assert!(
        res_with_plugin.is_ok(),
        "Authority change with plugin failed: {:?}",
        res_with_plugin.err()
    );

    if let Ok(result) = res_with_plugin {
        let cu_with_plugin = result.compute_units_consumed;
        println!(
            "Stake authority change WITH plugin CU: {:?}",
            cu_with_plugin
        );

        // Output program logs
        println!("Program logs for stake authority change with plugin:");
        for (idx, log) in result.logs.iter().enumerate() {
            println!("  {}: {}", idx, log);
        }

        // Calculate the overhead
        let plugin_overhead = cu_with_plugin - cu_no_plugin;
        println!(
            "Plugin validation overhead: {} CU ({:.2}% increase)",
            plugin_overhead,
            (plugin_overhead as f64 / cu_no_plugin as f64) * 100.0
        );
    }

    // Now try with an incorrect authority to verify plugin rejection
    // Creating another stake account with incorrect authority for testing plugin
    // rejection
    let stake_account3_keypair = Keypair::new();
    let incorrect_withdraw_authority = Keypair::new();
    context
        .svm
        .airdrop(&incorrect_withdraw_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Use the stake program's create_account instruction directly
    let create_stake3_ix = solana_sdk::stake::instruction::create_account(
        &stake_authority.pubkey(),
        &stake_account3_keypair.pubkey(),
        &solana_sdk::stake::state::Authorized {
            staker: stake_authority.pubkey(),
            withdrawer: second_authority.pubkey(),
        },
        &solana_sdk::stake::state::Lockup::default(),
        stake_amount + rent,
    );

    // Create transaction to create and initialize stake account 3
    let create_stake3_message = v0::Message::try_compile(
        &stake_authority.pubkey(),
        &create_stake3_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let create_stake3_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(create_stake3_message),
        &[&stake_authority, &stake_account3_keypair],
    )
    .unwrap();

    let create_stake3_res = context.svm.send_transaction(create_stake3_tx);
    assert!(
        create_stake3_res.is_ok(),
        "Failed to create stake account 3: {:?}",
        create_stake3_res.err()
    );
    println!(
        "Created stake account 3: {}",
        stake_account3_keypair.pubkey()
    );

    // Verify stake account 3 was properly initialized with incorrect authority
    let stake_account3 = context
        .svm
        .get_account(&stake_account3_keypair.pubkey())
        .unwrap();
    assert_eq!(
        stake_account3.owner, stake_program_id,
        "Stake account 3 not owned by stake program"
    );
    println!("Stake account 3 owner: {}", stake_account3.owner);
    println!("Stake account 3 data length: {}", stake_account3.data.len());

    // Print stake account data to debug the withdraw authority location
    let stake_account3 = context
        .svm
        .get_account(&stake_account3_keypair.pubkey())
        .unwrap();
    if !stake_account3.data.is_empty() {
        println!("Stake account 3 data (first 128 bytes):");
        for (i, chunk) in stake_account3.data.chunks(16).take(8).enumerate() {
            println!("{:02x}: {:02x?}", i * 16, chunk);
        }

        // If the withdraw authority is at offset 72, let's verify it
        if stake_account3.data.len() >= 104 {
            let withdraw_bytes = &stake_account3.data[72..104];
            println!("Withdraw authority bytes from stake account 3:");
            println!("{:02x?}", withdraw_bytes);
            println!("Expected incorrect withdraw authority bytes:");
            println!("{:02x?}", incorrect_withdraw_authority.pubkey().to_bytes());
            println!("Previous withdraw authority bytes for comparison:");
            println!("{:02x?}", withdraw_authority.pubkey().to_bytes());
        }
    }

    // More detailed analysis of stake account 3
    println!("\nDETAILED STAKE ACCOUNT 3 ANALYSIS:");
    println!("----------------------------------------");
    println!("Full stake account 3 data (all bytes):");
    for (i, chunk) in stake_account3.data.chunks(16).enumerate() {
        println!("{:02x}: {:02x?}", i * 16, chunk);
    }

    // We need to find where the withdraw authority is really stored
    println!("\nSearching for incorrect_withdraw_authority pubkey pattern in stake account 3:");
    let incorrect_auth_bytes = incorrect_withdraw_authority.pubkey().to_bytes();
    println!(
        "Incorrect withdraw authority pubkey bytes: {:02x?}",
        incorrect_auth_bytes
    );

    // Search for authority in the stake account data
    for i in 0..stake_account3.data.len() - 31 {
        let data_slice = &stake_account3.data[i..i + 32];
        if data_slice == incorrect_auth_bytes {
            println!("FOUND EXACT MATCH at offset {}", i);

            // Verify all 32 bytes match in detail
            println!("VERIFYING MATCH:");
            println!("Stake account data at offset {}: {:02x?}", i, data_slice);
            println!(
                "Incorrect authority pubkey:     {:02x?}",
                incorrect_auth_bytes
            );
            break;
        }
    }

    // Inspect offsets 44-76 in detail which is where we expect the withdraw
    // authority to be
    if stake_account3.data.len() >= 76 {
        println!("\nInspecting bytes at offsets 44-76 in stake account 3:");
        let bytes_at_offset = &stake_account3.data[44..76];
        println!("Bytes[44:76]: {:02x?}", bytes_at_offset);
        println!(
            "Incorrect withdraw authority: {:02x?}",
            incorrect_auth_bytes
        );

        // Compare bytes one by one for detailed analysis
        println!("\nDetailed byte comparison at offsets 44-76:");
        for (i, (a, b)) in bytes_at_offset
            .iter()
            .zip(incorrect_auth_bytes.iter())
            .enumerate()
        {
            println!(
                "Byte[{}]: stake account: {:02x}, authority pubkey: {:02x}, match: {}",
                i,
                a,
                b,
                a == b
            );
        }
    }

    // Create and try to use the incorrect authority's transaction
    let change_auth_ix3 = solana_sdk::stake::instruction::authorize(
        &stake_account3_keypair.pubkey(),
        &incorrect_withdraw_authority.pubkey(),
        &new_withdraw_authority.pubkey(),
        solana_sdk::stake::state::StakeAuthorize::Withdrawer,
        None,
    );

    let sign_ix_with_plugin3 = swig_interface::SignInstruction::new_ed25519_with_plugin_targets(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        change_auth_ix3,
        1,
        &[4, 6], // Explicitly pass indices 4 (stake account) and 6 (incorrect authority)
    )
    .unwrap();

    // Include the plugin bytecode account as an additional account
    let mut sign_ix_mut3 = sign_ix_with_plugin3.clone();
    sign_ix_mut3
        .accounts
        .push(AccountMeta::new_readonly(plugin_bytecode_account, false));

    println!("Plugin account indices passed to VM for incorrect authority test: [4, 6]"); // Print for clarity

    // Print transaction account ordering for debugging
    println!("Transaction account ordering for incorrect authority test:");
    println!("0: payer/fee payer - {}", second_authority.pubkey());
    println!("1: swig - {}", swig);
    println!(
        "2: second_authority (signer) - {}",
        second_authority.pubkey()
    );
    println!("3: stake program - {}", stake_program_id);
    println!("4: stake account - {}", stake_account3_keypair.pubkey());
    println!("5: sysvar clock - SysvarC1ock11111111111111111111111111111111");
    println!(
        "6: incorrect_withdraw_authority (signer) - {}",
        incorrect_withdraw_authority.pubkey()
    );
    println!("7: plugin account - {}", plugin_bytecode_account);

    let auth_message_with_plugin3 = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix_mut3],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let auth_tx_with_plugin3 = VersionedTransaction::try_new(
        VersionedMessage::V0(auth_message_with_plugin3),
        &[&second_authority, &incorrect_withdraw_authority],
    )
    .unwrap();

    let res_with_plugin3 = context.svm.send_transaction(auth_tx_with_plugin3);

    // println!("res_with_plugin3 result: {:?}", res_with_plugin3);

    // This transaction should be rejected by the plugin
    assert!(
        res_with_plugin3.is_err(),
        "Transaction with incorrect authority should have been rejected by plugin"
    );

    if let Err(err) = res_with_plugin3 {
        println!(
            "Correctly rejected transaction with incorrect authority: {:?}",
            err
        );

        // The error should be our custom error code 406 (ValidationFailed)
        assert_eq!(
            err.err,
            TransactionError::InstructionError(0, InstructionError::Custom(406))
        );
    } else {
        panic!("Expected transaction to fail with ValidationFailed error (406)");
    }
}
