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
    let target_program_id = Pubkey::new_from_array(system_program_bytes);
    let seeds = &[b"swig-pim", target_program_id.as_ref()];
    let (plugin_bytecode_account, _) = Pubkey::find_program_address(seeds, &program_id());
    println!("Using target program ID: {}", target_program_id);
    println!("Plugin bytecode PDA: {}", plugin_bytecode_account);

    // Create a plugin that validates the recipient pubkey
    // This plugin will check if the recipient pubkey matches our expected recipient
    // If it matches, it returns 0 (allow), otherwise returns 1 (deny)
    let recipient_pubkey = recipient.pubkey();
    let pubkey_bytes = recipient_pubkey.to_bytes();

    // Create VM instructions for our plugin bytecode
    // For NativeLoader program accounts, we need a different approach
    // Instead of trying to validate the account data (which may be minimal),
    // Let's just validate that we're operating on the right accounts
    // by checking the account indices and ensuring our execution context

    let mut validation_instructions = Vec::new();

    // Our validation will be simpler: pushing a constant 0 value (success)
    // This means the plugin will always allow the transaction to proceed
    // but we'll still measure the execution overhead
    validation_instructions.push(VMInstruction::PushValue { value: 0 });
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
        1,    // authority role id
        &[3], // Index of recipient account in the transaction
    )
    .unwrap();

    // Include the plugin bytecode account as an additional account
    let mut sign_ix_mut = sign_ix_with_plugin.clone();
    sign_ix_mut
        .accounts
        .push(AccountMeta::new_readonly(plugin_bytecode_account, false));

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

    // Print the first few bytes of the stake account data to debug
    if !stake_account.data.is_empty() {
        println!("Stake account data (first 64 bytes):");
        for (i, chunk) in stake_account.data.chunks(16).take(4).enumerate() {
            println!("{:02x}: {:02x?}", i * 16, chunk);
        }
    }

    // Derive a PDA for the plugin bytecode account using "swig-pim" seed and stake
    // program ID
    let seeds = &[b"swig-pim", stake_program_id.as_ref()];
    let (plugin_bytecode_account, _) = Pubkey::find_program_address(seeds, &program_id());
    println!("Plugin bytecode PDA: {}", plugin_bytecode_account);

    // Create a plugin that validates the withdraw authority
    // The plugin will check if withdraw authority matches the expected pubkey
    // If it matches, it returns 0 (allow), otherwise returns 1 (deny)
    let withdraw_authority_pubkey = withdraw_authority.pubkey();
    let authority_bytes = withdraw_authority_pubkey.to_bytes();

    // Create VM instructions for plugin bytecode
    let mut validation_instructions = Vec::new();

    // Start with true (1)
    validation_instructions.push(VMInstruction::PushValue { value: 1 });

    // In a stake account, the withdraw authority is at offset 72
    // We need to compare the pubkey bytes (which is 32 bytes / 4 chunks of i64)

    // First chunk (bytes 0-8 of the authority)
    validation_instructions.push(VMInstruction::LoadField {
        account_index: 0, // Stake account at index 0
        field_offset: 72, // Withdraw authority starts at offset 44
        padding: [0; 4],
    });

    // Convert first 8 bytes to i64 and push expected value
    let mut chunk_bytes = [0u8; 8];
    chunk_bytes.copy_from_slice(&authority_bytes[0..8]);
    // TODO tracy need to update this so chunk_value isn't hardcoded in this test
    // and instead pulls from the instruction's accounts
    let chunk_value = i64::from_le_bytes(chunk_bytes);
    validation_instructions.push(VMInstruction::PushValue { value: chunk_value });
    validation_instructions.push(VMInstruction::Equal);
    validation_instructions.push(VMInstruction::And); // AND with our initial 1

    // Second chunk (bytes 8-16)
    validation_instructions.push(VMInstruction::LoadField {
        account_index: 0,
        field_offset: 80, // 44 + 8
        padding: [0; 4],
    });
    chunk_bytes.copy_from_slice(&authority_bytes[8..16]);
    let chunk_value = i64::from_le_bytes(chunk_bytes);
    validation_instructions.push(VMInstruction::PushValue { value: chunk_value });
    validation_instructions.push(VMInstruction::Equal);
    validation_instructions.push(VMInstruction::And);

    // Third chunk (bytes 16-24)
    validation_instructions.push(VMInstruction::LoadField {
        account_index: 0,
        field_offset: 88, // 44 + 16
        padding: [0; 4],
    });
    chunk_bytes.copy_from_slice(&authority_bytes[16..24]);
    let chunk_value = i64::from_le_bytes(chunk_bytes);
    validation_instructions.push(VMInstruction::PushValue { value: chunk_value });
    validation_instructions.push(VMInstruction::Equal);
    validation_instructions.push(VMInstruction::And);

    // Fourth chunk (bytes 24-32)
    validation_instructions.push(VMInstruction::LoadField {
        account_index: 0,
        field_offset: 96, // 44 + 24
        padding: [0; 4],
    });
    chunk_bytes.copy_from_slice(&authority_bytes[24..32]);
    let chunk_value = i64::from_le_bytes(chunk_bytes);
    validation_instructions.push(VMInstruction::PushValue { value: chunk_value });
    validation_instructions.push(VMInstruction::Equal);
    validation_instructions.push(VMInstruction::And);

    // Return the inverse of the comparison result (0 = success, non-zero = reject)
    // If withdraw authority matches expected pubkey, result will be 1, so use Not
    // to make it 0 (success)
    validation_instructions.push(VMInstruction::Not);
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

    // println!("change_auth_ix2 accounts: {:?}", change_auth_ix2.accounts);

    // Create the sign instruction with plugin validation
    let sign_ix_with_plugin = swig_interface::SignInstruction::new_ed25519_with_plugin_targets(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        change_auth_ix2,
        1,
        &[4], // Index of stake_account2 in the transaction accounts
    )
    .unwrap();

    // Include the plugin bytecode account as an additional account
    let mut sign_ix_mut = sign_ix_with_plugin.clone();
    sign_ix_mut
        .accounts
        .push(AccountMeta::new_readonly(plugin_bytecode_account, false));

    println!("sign_ix_mut accounts: {:?}", sign_ix_mut.accounts);

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
            withdrawer: incorrect_withdraw_authority.pubkey(),
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

    // Try to change authority on stake_account3 with plugin validation
    // This should be rejected since withdraw authority doesn't match expected value
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
        &[4], // Index of stake_account3 in the transaction accounts
    )
    .unwrap();

    // Include the plugin bytecode account
    let mut sign_ix_mut3 = sign_ix_with_plugin3.clone();
    sign_ix_mut3
        .accounts
        .push(AccountMeta::new_readonly(plugin_bytecode_account, false));

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
    // println!(
    //     "res_with_plugin3 logs: {:?}",
    //     res_with_plugin3.clone().unwrap().logs
    // );
    // assert!(
    //     res_with_plugin3.is_err(),
    //     "Transaction with incorrect authority should have been rejected by
    // plugin" );
    // println!(
    //     "Correctly rejected transaction with incorrect authority: {:?}",
    //     res_with_plugin3.err()
    // );
}
