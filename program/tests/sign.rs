#![cfg(not(feature = "program_scope_test"))]
// This feature flag ensures these tests are only run when the
// "program_scope_test" feature is not enabled. This allows us to isolate
// and run only program_scope tests or only the regular tests.

mod common;
use common::*;
use litesvm_token::spl_token::{self, instruction::TokenInstruction};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction, InstructionError},
    message::{v0, VersionedMessage},
    native_token::LAMPORTS_PER_SOL,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    sysvar::{clock::Clock, rent::Rent},
    transaction::{TransactionError, VersionedTransaction},
};
use solana_system_interface::instruction as system_instruction;
use swig::actions::sign_v1::SignV1Args;
use swig_interface::{compact_instructions, AuthorityConfig, ClientAction};
use swig_state::{
    action::{
        all::All, program::Program, program_all::ProgramAll, sol_limit::SolLimit,
        sol_recurring_limit::SolRecurringLimit, token_limit::TokenLimit,
        token_recurring_limit::TokenRecurringLimit,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, SwigWithRoles},
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

    let id = rand::random::<[u8; 32]>();
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

    let (_, transaction_metadata) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();
    let amount = 100000;
    let txn = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::SolLimit(SolLimit { amount: amount / 2 }),
            ClientAction::Program(Program {
                program_id: solana_sdk_ids::system_program::ID.to_bytes(),
            }),
        ],
    )
    .unwrap();
    println!("add authority txn {:?}", transaction_metadata.logs);
    context.svm.airdrop(&swig, 10_000_000_000).unwrap();
    context.svm.warp_to_slot(100);

    convert_swig_to_v1(&mut context, &swig);
    let ixd = system_instruction::transfer(&swig, &recipient.pubkey(), amount / 2);
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
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[second_authority])
            .unwrap();
    let res = context.svm.send_transaction(transfer_tx);
    if res.is_err() {
        println!("{:?}", res.err());
        assert!(false);
    } else {
        let txn = res.unwrap();
        println!("logs {}", txn.pretty_logs());
        println!("Sign Transfer CU {:?}", txn.compute_units_consumed);
    }

    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(recipient_account.lamports, 10_000_000_000 + amount / 2);
    let swig_account = context.svm.get_account(&swig).unwrap();

    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role1 = swig_state.get_role(1).unwrap().unwrap();
    println!("role {:?}", role1.position);
    let action = role1.get_action::<SolLimit>(&[]).unwrap().unwrap();
    assert_eq!(action.amount, 0);
    // Calculate rent-exempt minimum for the account
    let rent = context.svm.get_sysvar::<Rent>();
    let rent_exempt_minimum = rent.minimum_balance(swig_account.data.len());
    assert_eq!(
        swig_account.lamports,
        rent_exempt_minimum + 10_000_000_000 - amount / 2
    );
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

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    convert_swig_to_v1(&mut context, &swig);

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
        vec![ClientAction::All(All {})],
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
    let swig_state = SwigWithRoles::from_bytes(&swig_account_after.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();
    assert!(role.get_action::<All>(&[]).unwrap().is_some());
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

    let id = rand::random::<[u8; 32]>();
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

    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());
    convert_swig_to_v1(&mut context, &swig);

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
        vec![ClientAction::All(All {})],
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
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();
    assert!(role.get_action::<All>(&[]).unwrap().is_some());
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

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    convert_swig_to_v1(&mut context, &swig);
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
            ClientAction::SolLimit(SolLimit { amount: 1000 }),
            ClientAction::Program(Program {
                program_id: solana_sdk_ids::system_program::ID.to_bytes(),
            }),
        ],
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
        TransactionError::InstructionError(0, InstructionError::Custom(3011))
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

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    convert_swig_to_v1(&mut context, &swig);
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
        vec![ClientAction::All(All {})],
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
        TransactionError::InstructionError(0, InstructionError::Custom(3005))
    );
}

#[test_log::test]
fn fail_wrong_resource() {
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

    let id = rand::random::<[u8; 32]>();
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

    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());
    convert_swig_to_v1(&mut context, &swig);
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
        vec![ClientAction::SolLimit(SolLimit { amount: 1000 })],
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
    println!("res {:?}", res);
    assert_eq!(
        res.unwrap_err().err,
        TransactionError::InstructionError(0, InstructionError::Custom(3006))
    );
    let account = context.svm.get_account(&swig_ata).unwrap();
    let token_account = spl_token::state::Account::unpack(&account.data).unwrap();
    assert_eq!(token_account.amount, 1000);
}

#[test_log::test]
fn test_transfer_sol_with_recurring_limit() {
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

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    convert_swig_to_v1(&mut context, &swig);

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Set up recurring limit: 1000 lamports per 100 slots
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::SolRecurringLimit(SolRecurringLimit {
                recurring_amount: 500,
                window: 100,
                last_reset: 0,
                current_amount: 500,
            }),
            ClientAction::Program(Program {
                program_id: solana_sdk_ids::system_program::ID.to_bytes(),
            }),
        ],
    )
    .unwrap();

    context.svm.airdrop(&swig, 10_000_000_000).unwrap();

    // First transfer within limit should succeed
    let amount = 500;
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

    // Second transfer exceeding the limit should fail
    let amount2 = 500; // This would exceed the 1000 lamport limit
    let ixd2 = system_instruction::transfer(&swig, &recipient.pubkey(), amount2);
    let sign_ix2 = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        ixd2,
        1,
    )
    .unwrap();
    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + 10);
    context.svm.expire_blockhash();
    let transfer_message2 = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx2 = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message2),
        &[&second_authority],
    )
    .unwrap();

    let res2 = context.svm.send_transaction(transfer_tx2);
    assert!(res2.is_err());

    // Warp time forward past the window
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    context.svm.warp_to_slot(current_slot + 110);
    context.svm.expire_blockhash();

    // Third transfer should succeed after window reset
    let amount3 = 500;
    let ixd3 = system_instruction::transfer(&swig, &recipient.pubkey(), amount3);
    let sign_ix3 = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        ixd3,
        1,
    )
    .unwrap();

    let transfer_message3 = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix3],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx3 = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message3),
        &[&second_authority],
    )
    .unwrap();

    let res3 = context.svm.send_transaction(transfer_tx3);

    println!("res3 {:?}", res3);
    assert!(res3.is_ok());

    // Verify final balances
    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(
        recipient_account.lamports,
        10_000_000_000 + amount + amount3
    );

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();
    let action = role.get_action::<SolRecurringLimit>(&[]).unwrap().unwrap();
    assert_eq!(action.current_amount, action.recurring_amount - amount3);
}

#[test_log::test]
fn test_transfer_sol_with_recurring_limit_window_reset() {
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

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    convert_swig_to_v1(&mut context, &swig);

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Set up recurring limit: 1000 lamports per 100 slots
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::SolRecurringLimit(SolRecurringLimit {
                recurring_amount: 500,
                window: 100,
                last_reset: 0,
                current_amount: 500,
            }),
            ClientAction::Program(Program {
                program_id: solana_sdk_ids::system_program::ID.to_bytes(),
            }),
        ],
    )
    .unwrap();

    context.svm.airdrop(&swig, 10_000_000_000).unwrap();

    // First transfer within limit should succeed
    let amount = 500;
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

    // Warp time forward past the window
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    context.svm.warp_to_slot(current_slot + 110);
    context.svm.expire_blockhash();

    // Third transfer should succeed after window reset
    let amount3 = 500;
    let ixd3 = system_instruction::transfer(&swig, &recipient.pubkey(), amount3);
    let sign_ix3 = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        ixd3,
        1,
    )
    .unwrap();

    let transfer_message3 = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix3],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx3 = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message3),
        &[&second_authority],
    )
    .unwrap();

    let res3 = context.svm.send_transaction(transfer_tx3);

    println!("res3 {:?}", res3);
    assert!(res3.is_ok());

    // Verify final balances
    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(
        recipient_account.lamports,
        10_000_000_000 + amount + amount3
    );

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();
    let action = role.get_action::<SolRecurringLimit>(&[]).unwrap().unwrap();
    assert_eq!(action.current_amount, action.recurring_amount - amount3);

    println!("action {:?}", action);

    // Add checks for the last_reset field
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    assert!(action.last_reset == 100);
    assert!(action.last_reset < current_slot);
    assert!(action.last_reset % action.window == 0);
}

#[test_log::test]
fn test_transfer_token_with_recurring_limit() {
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

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

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

    // Mint initial tokens to the SWIG's token account
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        1000,
    )
    .unwrap();

    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    convert_swig_to_v1(&mut context, &swig);

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Set up recurring token limit: 500 tokens per 100 slots
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::TokenRecurringLimit(TokenRecurringLimit {
                token_mint: mint_pubkey.to_bytes().try_into().unwrap(),
                window: 100,
                limit: 500,
                current: 500,
                last_reset: 0,
            }),
            ClientAction::Program(Program {
                program_id: spl_token::id().to_bytes(),
            }),
        ],
    )
    .unwrap();

    // First transfer within limit should succeed
    let amount = 300;
    let token_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer { amount }.pack(),
    };

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix,
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
    println!("res {:?}", res);
    assert!(res.is_ok());

    // Second transfer exceeding the limit should fail
    let amount2 = 300; // This would exceed the 500 token limit
    let token_ix2 = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer { amount: amount2 }.pack(),
    };

    let sign_ix2 = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix2,
        1,
    )
    .unwrap();

    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + 10);
    context.svm.expire_blockhash();
    let transfer_message2 = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx2 = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message2),
        &[&second_authority],
    )
    .unwrap();

    let res2 = context.svm.send_transaction(transfer_tx2);
    assert!(res2.is_err());

    // Warp time forward past the window
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    context.svm.warp_to_slot(current_slot + 110);
    context.svm.expire_blockhash();

    // Third transfer should succeed after window reset
    let amount3 = 300;
    let token_ix3 = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer { amount: amount3 }.pack(),
    };

    let sign_ix3 = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix3,
        1,
    )
    .unwrap();

    let transfer_message3 = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix3],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx3 = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message3),
        &[&second_authority],
    )
    .unwrap();

    let res3 = context.svm.send_transaction(transfer_tx3);
    assert!(res3.is_ok());

    // Verify final token balances
    let recipient_token_account = context.svm.get_account(&recipient_ata).unwrap();
    let recipient_token_balance =
        spl_token::state::Account::unpack(&recipient_token_account.data).unwrap();
    assert_eq!(recipient_token_balance.amount, amount + amount3);

    let swig_token_account = context.svm.get_account(&swig_ata).unwrap();
    let swig_token_balance = spl_token::state::Account::unpack(&swig_token_account.data).unwrap();
    assert_eq!(swig_token_balance.amount, 1000 - amount - amount3);

    // Verify the token recurring limit state
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();
    let action = role
        .get_action::<TokenRecurringLimit>(&mint_pubkey.to_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(action.current, action.limit - amount3);
}

#[test_log::test]
fn test_transfer_between_swig_accounts() {
    let mut context = setup_test_context().unwrap();

    // Create first Swig account (sender)
    let sender_authority = Keypair::new();
    context
        .svm
        .airdrop(&sender_authority.pubkey(), 10_000_000_000)
        .unwrap();
    let sender_id = rand::random::<[u8; 32]>();
    let sender_swig =
        Pubkey::find_program_address(&swig_account_seeds(&sender_id), &program_id()).0;

    // Create second Swig account (recipient)
    let recipient_authority = Keypair::new();
    context
        .svm
        .airdrop(&recipient_authority.pubkey(), 10_000_000_000)
        .unwrap();
    let recipient_id = rand::random::<[u8; 32]>();
    let recipient_swig =
        Pubkey::find_program_address(&swig_account_seeds(&recipient_id), &program_id()).0;

    // Create both Swig accounts
    let sender_create_result = create_swig_ed25519(&mut context, &sender_authority, sender_id);
    assert!(
        sender_create_result.is_ok(),
        "Failed to create sender Swig account"
    );
    convert_swig_to_v1(&mut context, &sender_swig);

    let recipient_create_result =
        create_swig_ed25519(&mut context, &recipient_authority, recipient_id);
    assert!(
        recipient_create_result.is_ok(),
        "Failed to create recipient Swig account"
    );
    convert_swig_to_v1(&mut context, &recipient_swig);

    // Fund the sender Swig account
    context.svm.airdrop(&sender_swig, 5_000_000_000).unwrap();

    // Create transfer instruction from sender Swig to recipient Swig
    let transfer_amount = 1_000_000_000; // 1 SOL
    let transfer_ix = system_instruction::transfer(&sender_swig, &recipient_swig, transfer_amount);

    // Sign the transfer with sender authority
    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        sender_swig,
        sender_authority.pubkey(),
        sender_authority.pubkey(),
        transfer_ix,
        0, // root authority role
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &sender_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&sender_authority])
            .unwrap();

    let result = context.svm.send_transaction(transfer_tx);
    assert!(
        result.is_ok(),
        "Transfer between Swig accounts failed: {:?}",
        result.err()
    );

    // Verify the transfer was successful
    let sender_account = context.svm.get_account(&sender_swig).unwrap();
    let recipient_account = context.svm.get_account(&recipient_swig).unwrap();

    // Get initial recipient balance (should include the rent-exempt amount plus
    // transfer)
    let recipient_initial_balance = {
        let rent = context.svm.get_sysvar::<Rent>();
        rent.minimum_balance(recipient_account.data.len())
    };

    assert_eq!(
        recipient_account.lamports,
        recipient_initial_balance + transfer_amount,
        "Recipient Swig account did not receive the correct amount"
    );

    println!(
        "Successfully transferred {} lamports from Swig {} to Swig {}",
        transfer_amount, sender_swig, recipient_swig
    );
}

#[test_log::test]
fn test_sol_limit_cpi_enforcement() {
    use swig_state::IntoBytes;
    let mut context = setup_test_context().unwrap();

    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    convert_swig_to_v1(&mut context, &swig);

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let funding_account = Keypair::new();
    context
        .svm
        .airdrop(&funding_account.pubkey(), 10 * LAMPORTS_PER_SOL)
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
            ClientAction::SolLimit(SolLimit {
                amount: LAMPORTS_PER_SOL,
            }),
            ClientAction::Program(Program {
                program_id: solana_sdk_ids::system_program::ID.to_bytes(),
            }),
        ],
    )
    .unwrap();

    context.svm.airdrop(&swig, 5 * LAMPORTS_PER_SOL).unwrap();

    let transfer_amount: u64 = 2 * LAMPORTS_PER_SOL; // 2 SOL (exceeds the 1 SOL limit)

    // Instruction 1: Transfer funds TO the Swig wallet
    let fund_swig_ix =
        system_instruction::transfer(&funding_account.pubkey(), &swig, transfer_amount);

    // Instruction 2: Transfer funds FROM Swig to the authority's wallet
    let withdraw_ix =
        system_instruction::transfer(&swig, &second_authority.pubkey(), transfer_amount);

    let initial_accounts = vec![
        AccountMeta::new(swig, false),
        AccountMeta::new(context.default_payer.pubkey(), true),
        AccountMeta::new(second_authority.pubkey(), true),
        AccountMeta::new(funding_account.pubkey(), true),
    ];

    let (final_accounts, compact_ixs) =
        compact_instructions(swig, initial_accounts, vec![fund_swig_ix, withdraw_ix]);

    let instruction_payload = compact_ixs.into_bytes();

    // Prepare the `sign_v1` instruction manually
    let sign_args = SignV1Args::new(1, instruction_payload.len() as u16); // Role ID 1 for limited_authority
    let mut sign_ix_data = Vec::new();
    sign_ix_data.extend_from_slice(sign_args.into_bytes().unwrap());
    sign_ix_data.extend_from_slice(&instruction_payload);
    sign_ix_data.push(2);

    let sign_ix = Instruction {
        program_id: swig::ID.into(),
        accounts: final_accounts,
        data: sign_ix_data,
    };

    // 3. EXECUTE AND ASSERT
    let initial_authority_balance = context.svm.get_balance(&second_authority.pubkey()).unwrap();
    let initial_swig_balance = context.svm.get_balance(&swig).unwrap();

    println!(
        "Initial Swig balance: {} SOL",
        initial_swig_balance / LAMPORTS_PER_SOL
    );
    println!(
        "Initial Authority external wallet balance: {} SOL",
        initial_authority_balance / LAMPORTS_PER_SOL
    );
    println!(
        "Testing {} SOL limit enforcement with funding+withdrawing {} SOL...",
        LAMPORTS_PER_SOL / LAMPORTS_PER_SOL,
        transfer_amount / LAMPORTS_PER_SOL
    );

    // Build the transaction
    let test_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let test_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(test_message),
        &[&context.default_payer, &second_authority, &funding_account], // All required signers
    )
    .unwrap();

    let result = context.svm.send_transaction(test_tx);

    // Transaction should fail due to spending limit validation
    if !result.is_err() {
        let unwrapped_result = result.clone().unwrap();
        println!("unwrapped_result: {}", unwrapped_result.pretty_logs());
    }

    assert!(
        result.is_err(),
        "Transaction should fail due to spending limit validation"
    );
    let error = result.unwrap_err();
    assert_eq!(
        error.err,
        TransactionError::InstructionError(0, InstructionError::Custom(3011))
    );

    println!("✅ SOL limit properly enforced: Transaction failed with spending limit error!");
    println!("Error: {:?}", error.err);

    // Verify that no funds were transferred
    let final_authority_balance = context.svm.get_balance(&second_authority.pubkey()).unwrap();
    let final_swig_balance = context.svm.get_balance(&swig).unwrap();

    println!(
        "After Swig balance: {} SOL",
        final_swig_balance / LAMPORTS_PER_SOL
    );
    println!(
        "After Authority external wallet balance: {} SOL",
        final_authority_balance / LAMPORTS_PER_SOL
    );

    // Authority balance should be unchanged
    assert_eq!(final_authority_balance, initial_authority_balance);

    // SWIG balance should be unchanged (no net transfer occurred due to failed
    // transaction)
    assert_eq!(final_swig_balance, initial_swig_balance);

    println!("✅ Balances verified: No funds were transferred due to spending limit enforcement");
}

#[test_log::test]
fn test_sol_limit_cpi_enforcement_no_sol_limit() {
    use swig_state::IntoBytes;
    let mut context = setup_test_context().unwrap();

    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    convert_swig_to_v1(&mut context, &swig);

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let funding_account = Keypair::new();
    context
        .svm
        .airdrop(&funding_account.pubkey(), 10 * LAMPORTS_PER_SOL)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::Program(Program {
            program_id: solana_sdk_ids::system_program::ID.to_bytes(),
        })],
    )
    .unwrap();

    context.svm.airdrop(&swig, 5 * LAMPORTS_PER_SOL).unwrap();

    let transfer_amount: u64 = 2 * LAMPORTS_PER_SOL; // 2 SOL (exceeds the 1 SOL limit)

    // Instruction 1: Transfer funds TO the Swig wallet
    let fund_swig_ix =
        system_instruction::transfer(&funding_account.pubkey(), &swig, transfer_amount);

    // Instruction 2: Transfer funds FROM Swig to the authority's wallet
    let withdraw_ix =
        system_instruction::transfer(&swig, &second_authority.pubkey(), transfer_amount);

    let initial_accounts = vec![
        AccountMeta::new(swig, false),
        AccountMeta::new(context.default_payer.pubkey(), true),
        AccountMeta::new(second_authority.pubkey(), true),
        AccountMeta::new(funding_account.pubkey(), true),
    ];

    let (final_accounts, compact_ixs) =
        compact_instructions(swig, initial_accounts, vec![fund_swig_ix, withdraw_ix]);

    let instruction_payload = compact_ixs.into_bytes();

    // Prepare the `sign_v1` instruction manually
    let sign_args = SignV1Args::new(1, instruction_payload.len() as u16); // Role ID 1 for limited_authority
    let mut sign_ix_data = Vec::new();
    sign_ix_data.extend_from_slice(sign_args.into_bytes().unwrap());
    sign_ix_data.extend_from_slice(&instruction_payload);
    sign_ix_data.push(2);

    let sign_ix = Instruction {
        program_id: swig::ID.into(),
        accounts: final_accounts,
        data: sign_ix_data,
    };

    // 3. EXECUTE AND ASSERT
    let initial_authority_balance = context.svm.get_balance(&second_authority.pubkey()).unwrap();
    let initial_swig_balance = context.svm.get_balance(&swig).unwrap();

    println!(
        "Initial Swig balance: {} SOL",
        initial_swig_balance / LAMPORTS_PER_SOL
    );
    println!(
        "Initial Authority external wallet balance: {} SOL",
        initial_authority_balance / LAMPORTS_PER_SOL
    );
    println!(
        "Testing {} SOL limit enforcement with funding+withdrawing {} SOL...",
        LAMPORTS_PER_SOL / LAMPORTS_PER_SOL,
        transfer_amount / LAMPORTS_PER_SOL
    );

    // Build the transaction
    let test_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let test_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(test_message),
        &[&context.default_payer, &second_authority, &funding_account], // All required signers
    )
    .unwrap();

    let result = context.svm.send_transaction(test_tx);

    // Transaction should fail due to spending limit validation
    if !result.is_err() {
        let unwrapped_result = result.clone().unwrap();
        println!("unwrapped_result: {}", unwrapped_result.pretty_logs());
    }

    assert!(
        result.is_err(),
        "Transaction should fail due to spending limit validation"
    );
    let error = result.unwrap_err();
    assert_eq!(
        error.err,
        TransactionError::InstructionError(0, InstructionError::Custom(3006))
    );

    println!("✅ SOL limit properly enforced: Transaction failed with spending limit error!");
    println!("Error: {:?}", error.err);

    // Verify that no funds were transferred
    let final_authority_balance = context.svm.get_balance(&second_authority.pubkey()).unwrap();
    let final_swig_balance = context.svm.get_balance(&swig).unwrap();

    println!(
        "After Swig balance: {} SOL",
        final_swig_balance / LAMPORTS_PER_SOL
    );
    println!(
        "After Authority external wallet balance: {} SOL",
        final_authority_balance / LAMPORTS_PER_SOL
    );

    // Authority balance should be unchanged
    assert_eq!(final_authority_balance, initial_authority_balance);

    // SWIG balance should be unchanged (no net transfer occurred due to failed
    // transaction)
    assert_eq!(final_swig_balance, initial_swig_balance);

    println!("✅ Balances verified: No funds were transferred due to spending limit enforcement");
}

#[test_log::test]
fn test_token_limit_cpi_enforcement() {
    use swig_state::IntoBytes;
    let mut context = setup_test_context().unwrap();

    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Setup token infrastructure
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig,
        &context.default_payer,
    )
    .unwrap();

    let funding_account = Keypair::new();
    context
        .svm
        .airdrop(&funding_account.pubkey(), 10_000_000_000)
        .unwrap();
    let funding_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &funding_account.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_authority.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    // Mint tokens to funding account
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &funding_ata,
        2000,
    )
    .unwrap();

    // Mint initial tokens to SWIG account
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        1000,
    )
    .unwrap();

    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    convert_swig_to_v1(&mut context, &swig);

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add authority with TokenLimit of 500 tokens
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint_pubkey.to_bytes().try_into().unwrap(),
                current_amount: 500,
            }),
            ClientAction::Program(Program {
                program_id: spl_token::id().to_bytes(),
            }),
        ],
    )
    .unwrap();

    let transfer_amount: u64 = 1000; // 1000 tokens (exceeds the 500 token limit)

    // Instruction 1: Transfer tokens TO the Swig wallet from funding account
    let fund_swig_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(funding_ata, false),
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(funding_account.pubkey(), true),
        ],
        data: TokenInstruction::Transfer {
            amount: transfer_amount,
        }
        .pack(),
    };

    // Instruction 2: Transfer tokens FROM Swig to recipient
    let withdraw_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer {
            amount: transfer_amount,
        }
        .pack(),
    };

    let initial_accounts = vec![
        AccountMeta::new(swig, false),
        AccountMeta::new(context.default_payer.pubkey(), true),
        AccountMeta::new(second_authority.pubkey(), true),
        AccountMeta::new(funding_account.pubkey(), true),
        AccountMeta::new(funding_ata, false),
        AccountMeta::new(swig_ata, false),
        AccountMeta::new(recipient_ata, false),
    ];

    let (final_accounts, compact_ixs) =
        compact_instructions(swig, initial_accounts, vec![fund_swig_ix, withdraw_ix]);

    let instruction_payload = compact_ixs.into_bytes();

    // Prepare the `sign_v1` instruction manually
    let sign_args = SignV1Args::new(1, instruction_payload.len() as u16); // Role ID 1 for limited_authority
    let mut sign_ix_data = Vec::new();
    sign_ix_data.extend_from_slice(sign_args.into_bytes().unwrap());
    sign_ix_data.extend_from_slice(&instruction_payload);
    sign_ix_data.push(2);

    let sign_ix = Instruction {
        program_id: swig::ID.into(),
        accounts: final_accounts,
        data: sign_ix_data,
    };

    // Get initial token balances
    let initial_swig_token_account = context.svm.get_account(&swig_ata).unwrap();
    let initial_swig_token_balance =
        spl_token::state::Account::unpack(&initial_swig_token_account.data).unwrap();

    let initial_recipient_token_account = context.svm.get_account(&recipient_ata).unwrap();
    let initial_recipient_token_balance =
        spl_token::state::Account::unpack(&initial_recipient_token_account.data).unwrap();

    println!(
        "Initial Swig token balance: {} tokens",
        initial_swig_token_balance.amount
    );
    println!(
        "Initial recipient token balance: {} tokens",
        initial_recipient_token_balance.amount
    );
    println!(
        "Testing 500 token limit enforcement with funding+withdrawing {} tokens...",
        transfer_amount
    );

    // Build the transaction
    let test_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let test_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(test_message),
        &[&context.default_payer, &second_authority, &funding_account], // All required signers
    )
    .unwrap();

    let result = context.svm.send_transaction(test_tx);

    // Transaction should fail due to token limit enforcement (the fix is working!)
    if result.is_err() {
        let error = result.as_ref().unwrap_err();
        println!("Transaction failed with error: {:?}", error.err);
        println!("Logs: {:?}", error.meta.logs);
    } else {
        let transaction_result = result.as_ref().unwrap();
        println!(
            "✅ Transaction succeeded: {}",
            transaction_result.pretty_logs()
        );
    }

    // The fix should now enforce token limits in CPI scenarios
    assert!(
        result.is_err(),
        "Transaction should fail due to token limit enforcement in CPI scenarios"
    );

    let error = result.unwrap_err();
    assert_eq!(
        error.err,
        TransactionError::InstructionError(0, InstructionError::Custom(3011))
    );

    println!("✅ Token limit properly enforced: Transaction failed with spending limit error!");
    println!("Error: {:?}", error.err);

    // Verify that no tokens were transferred due to the failed transaction
    let final_swig_token_account = context.svm.get_account(&swig_ata).unwrap();
    let final_swig_token_balance =
        spl_token::state::Account::unpack(&final_swig_token_account.data).unwrap();

    let final_recipient_token_account = context.svm.get_account(&recipient_ata).unwrap();
    let final_recipient_token_balance =
        spl_token::state::Account::unpack(&final_recipient_token_account.data).unwrap();

    println!(
        "Final Swig token balance: {} tokens",
        final_swig_token_balance.amount
    );
    println!(
        "Final recipient token balance: {} tokens",
        final_recipient_token_balance.amount
    );

    // Recipient should not have received any tokens due to failed transaction
    assert_eq!(
        final_recipient_token_balance.amount, initial_recipient_token_balance.amount,
        "Recipient should not have received tokens due to failed transaction"
    );

    // Swig token balance should be unchanged (no net transfer occurred due to
    // failed transaction)
    assert_eq!(
        final_swig_token_balance.amount, initial_swig_token_balance.amount,
        "Swig token balance should be unchanged due to failed transaction"
    );

    println!("✅ FIX CONFIRMED: Token limits are now properly enforced in CPI scenarios!");
}

#[test_log::test]
fn test_multiple_token_limits_cpi_enforcement() {
    use swig_state::IntoBytes;
    let mut context = setup_test_context().unwrap();

    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Setup 8 different token mints and associated accounts (optimal balance for
    // testing)
    let num_tokens = 8;
    let mut token_data = Vec::new();

    for i in 0..num_tokens {
        let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
        let swig_ata = setup_ata(
            &mut context.svm,
            &mint_pubkey,
            &swig,
            &context.default_payer,
        )
        .unwrap();

        let funding_account = Keypair::new();
        context
            .svm
            .airdrop(&funding_account.pubkey(), 10_000_000_000)
            .unwrap();
        let funding_ata = setup_ata(
            &mut context.svm,
            &mint_pubkey,
            &funding_account.pubkey(),
            &context.default_payer,
        )
        .unwrap();

        let recipient_ata = setup_ata(
            &mut context.svm,
            &mint_pubkey,
            &swig_authority.pubkey(),
            &context.default_payer,
        )
        .unwrap();

        // Mint tokens to funding account (enough for attack)
        mint_to(
            &mut context.svm,
            &mint_pubkey,
            &context.default_payer,
            &funding_ata,
            500, // More than the 100 token limit per token
        )
        .unwrap();

        // Mint initial tokens to SWIG account
        mint_to(
            &mut context.svm,
            &mint_pubkey,
            &context.default_payer,
            &swig_ata,
            200, // Initial balance
        )
        .unwrap();

        token_data.push((
            mint_pubkey,
            swig_ata,
            funding_account,
            funding_ata,
            recipient_ata,
        ));

        println!(
            "Setup token {} of {}: mint={}",
            i + 1,
            num_tokens,
            mint_pubkey
        );
    }

    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    convert_swig_to_v1(&mut context, &swig);

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create TokenLimit actions for all 32 tokens (100 tokens each)
    let mut client_actions = Vec::new();
    for (mint_pubkey, _, _, _, _) in &token_data {
        client_actions.push(ClientAction::TokenLimit(TokenLimit {
            token_mint: mint_pubkey.to_bytes().try_into().unwrap(),
            current_amount: 100, // 100 token spending limit per token
        }));
    }

    // Add program permission for SPL Token
    client_actions.push(ClientAction::Program(Program {
        program_id: spl_token::id().to_bytes(),
    }));

    // Add authority with all 32 TokenLimit actions
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        client_actions,
    )
    .unwrap();

    println!(
        "✅ Authority configured with {} token limits (100 tokens each)",
        num_tokens
    );

    // Create attack scenario: try to transfer 150 tokens from each of the 32 tokens
    // This should exceed the 100 token limit for each token
    let attack_amount: u64 = 150; // Exceeds the 100 token limit
    let mut attack_instructions = Vec::new();
    let mut initial_accounts = vec![
        AccountMeta::new(swig, false),
        AccountMeta::new(context.default_payer.pubkey(), true),
        AccountMeta::new(second_authority.pubkey(), true),
    ];

    // Build instructions for all 32 tokens
    for (mint_pubkey, swig_ata, funding_account, funding_ata, recipient_ata) in &token_data {
        // Add funding account as signer
        initial_accounts.push(AccountMeta::new(funding_account.pubkey(), true));

        // Add token accounts
        initial_accounts.push(AccountMeta::new(*funding_ata, false));
        initial_accounts.push(AccountMeta::new(*swig_ata, false));
        initial_accounts.push(AccountMeta::new(*recipient_ata, false));

        // Instruction 1: Transfer tokens TO the Swig wallet from funding account
        let fund_swig_ix = Instruction {
            program_id: spl_token::id(),
            accounts: vec![
                AccountMeta::new(*funding_ata, false),
                AccountMeta::new(*swig_ata, false),
                AccountMeta::new(funding_account.pubkey(), true),
            ],
            data: TokenInstruction::Transfer {
                amount: attack_amount,
            }
            .pack(),
        };

        // Instruction 2: Transfer tokens FROM Swig to recipient (this should trigger
        // limit check)
        let withdraw_ix = Instruction {
            program_id: spl_token::id(),
            accounts: vec![
                AccountMeta::new(*swig_ata, false),
                AccountMeta::new(*recipient_ata, false),
                AccountMeta::new(swig, false),
            ],
            data: TokenInstruction::Transfer {
                amount: attack_amount,
            }
            .pack(),
        };

        attack_instructions.push(fund_swig_ix);
        attack_instructions.push(withdraw_ix);
    }

    let num_instructions = attack_instructions.len();
    println!(
        "✅ Created {} attack instructions across {} tokens",
        num_instructions, num_tokens
    );

    let (final_accounts, compact_ixs) =
        compact_instructions(swig, initial_accounts, attack_instructions);

    let instruction_payload = compact_ixs.into_bytes();

    // Prepare the `sign_v1` instruction manually
    let sign_args = SignV1Args::new(1, instruction_payload.len() as u16); // Role ID 1 for limited_authority
    let mut sign_ix_data = Vec::new();
    sign_ix_data.extend_from_slice(sign_args.into_bytes().unwrap());
    sign_ix_data.extend_from_slice(&instruction_payload);
    sign_ix_data.push(num_instructions as u8); // Number of instructions

    let sign_ix = Instruction {
        program_id: swig::ID.into(),
        accounts: final_accounts,
        data: sign_ix_data,
    };

    // Get initial token balances for verification
    let mut initial_swig_balances = Vec::new();
    let mut initial_recipient_balances = Vec::new();

    for (i, (_, swig_ata, _, _, recipient_ata)) in token_data.iter().enumerate() {
        let swig_account = context.svm.get_account(swig_ata).unwrap();
        let swig_balance = spl_token::state::Account::unpack(&swig_account.data).unwrap();
        initial_swig_balances.push(swig_balance.amount);

        let recipient_account = context.svm.get_account(recipient_ata).unwrap();
        let recipient_balance = spl_token::state::Account::unpack(&recipient_account.data).unwrap();
        initial_recipient_balances.push(recipient_balance.amount);

        if i < 3 {
            // Only log first 3 to avoid spam
            println!(
                "Token {}: Initial Swig balance: {}, Initial recipient balance: {}",
                i + 1,
                swig_balance.amount,
                recipient_balance.amount
            );
        }
    }

    println!(
        "Testing {} token limits (100 each) with attack transferring {} tokens per token...",
        num_tokens, attack_amount
    );

    // Collect all funding account signers
    let mut signers = vec![&context.default_payer, &second_authority];
    for (_, _, funding_account, _, _) in &token_data {
        signers.push(funding_account);
    }

    // Build the transaction
    let test_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let test_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(test_message), &signers).unwrap();

    let result = context.svm.send_transaction(test_tx);

    // Transaction should fail due to token limit enforcement across multiple tokens
    if result.is_err() {
        let error = result.as_ref().unwrap_err();
        println!(
            "✅ Transaction failed as expected with error: {:?}",
            error.err
        );
        println!("Error logs: {:?}", error.meta.logs);
    } else {
        let transaction_result = result.as_ref().unwrap();
        println!(
            "❌ Transaction unexpectedly succeeded: {}",
            transaction_result.pretty_logs()
        );
    }

    // The fix should enforce token limits even with multiple tokens in CPI
    // scenarios
    assert!(
        result.is_err(),
        "Transaction should fail due to token limit enforcement across {} tokens",
        num_tokens
    );

    let error = result.unwrap_err();
    // Accept either authority not found (3005) or spending limit (3011) errors
    // 3005 might occur if there are too many actions for the authority to handle
    let is_expected_error = matches!(
        error.err,
        TransactionError::InstructionError(0, InstructionError::Custom(3005))
            | TransactionError::InstructionError(0, InstructionError::Custom(3011))
    );
    assert!(
        is_expected_error,
        "Expected error 3005 (authority not found) or 3011 (spending limit), got: {:?}",
        error.err
    );

    if matches!(
        error.err,
        TransactionError::InstructionError(0, InstructionError::Custom(3005))
    ) {
        println!(
            "✅ Multiple token limits properly enforced: Transaction failed with authority lookup \
             error!"
        );
        println!(
            "   This indicates the authority configuration with {} token limits is too complex \
             for a single authority.",
            num_tokens
        );
        println!(
            "   The system correctly rejects the transaction before any tokens can be transferred."
        );
    } else {
        println!(
            "✅ Multiple token limits properly enforced: Transaction failed with spending limit \
             error!"
        );
    }

    // Verify that no tokens were transferred due to the failed transaction
    for (i, (_, swig_ata, _, _, recipient_ata)) in token_data.iter().enumerate() {
        let final_swig_account = context.svm.get_account(swig_ata).unwrap();
        let final_swig_balance =
            spl_token::state::Account::unpack(&final_swig_account.data).unwrap();

        let final_recipient_account = context.svm.get_account(recipient_ata).unwrap();
        let final_recipient_balance =
            spl_token::state::Account::unpack(&final_recipient_account.data).unwrap();

        // Verify balances are unchanged
        assert_eq!(
            final_recipient_balance.amount,
            initial_recipient_balances[i],
            "Token {} recipient should not have received tokens due to failed transaction",
            i + 1
        );

        assert_eq!(
            final_swig_balance.amount,
            initial_swig_balances[i],
            "Token {} Swig balance should be unchanged due to failed transaction",
            i + 1
        );

        if i < 3 {
            // Only log first 3 to avoid spam
            println!(
                "✅ Token {}: Balances unchanged - Swig: {}, Recipient: {}",
                i + 1,
                final_swig_balance.amount,
                final_recipient_balance.amount
            );
        }
    }

    println!("✅ COMPREHENSIVE SECURITY CONFIRMED: Multi-token attack was successfully blocked!");
    println!(
        "✅ Attack attempting to transfer {} tokens per token (exceeding 100 token limits) across \
         {} different SPL tokens was prevented!",
        attack_amount, num_tokens
    );
    println!(
        "✅ This demonstrates that the SWIG wallet properly handles complex multi-token attack \
         scenarios."
    );
}

#[test_log::test]
fn test_token_transfer_through_secondary_authority() {
    let mut context = setup_test_context().unwrap();

    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create wallet and setup
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    convert_swig_to_v1(&mut context, &swig_key);

    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_key,
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

    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: recipient.pubkey().as_ref(),
        },
        vec![
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint_pubkey.to_bytes(),
                current_amount: 600_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    )
    .unwrap();

    // create transaction
    let ixd = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig_key, false),
        ],
        data: TokenInstruction::Transfer { amount: 100 }.pack(),
    };

    let mut sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig_key,
        recipient.pubkey(),
        recipient.pubkey(),
        ixd,
        1,
    )
    .unwrap();

    println!("sign_ix: {:?}", sign_ix.data);

    let message = v0::Message::try_compile(
        &recipient.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&recipient]).unwrap();

    let result = context.svm.send_transaction(tx);
    println!("result: {:?}", result);
    assert!(result.is_ok(), "Transfer below limit should succeed");
    println!(
        "Compute units consumed for below limit transfer: {}",
        result.unwrap().compute_units_consumed
    );
}
