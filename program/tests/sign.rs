#![cfg(not(feature = "program_scope_test"))]
// This feature flag ensures these tests are only run when the
// "program_scope_test" feature is not enabled. This allows us to isolate
// and run only program_scope tests or only the regular tests.

mod common;
use common::*;
use litesvm_token::spl_token::{self, instruction::TokenInstruction};
use solana_sdk::{
    instruction::{AccountMeta, Instruction, InstructionError},
    message::{v0, VersionedMessage},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction,
    sysvar::clock::Clock,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{AuthorityConfig, ClientAction};
use swig_state::{
    action::{
        all::All, sol_limit::SolLimit, sol_recurring_limit::SolRecurringLimit,
        token_limit::TokenLimit, token_recurring_limit::TokenRecurringLimit,
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
        vec![ClientAction::SolLimit(SolLimit { amount: amount / 2 })],
    )
    .unwrap();
    println!("add authority txn {:?}", transaction_metadata.logs);
    context.svm.airdrop(&swig, 10_000_000_000).unwrap();
    context.svm.warp_to_slot(100);

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
    assert_eq!(
        swig_account.lamports,
        swig_state.state.reserved_lamports + 10_000_000_000 - amount / 2
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
        vec![ClientAction::SolRecurringLimit(SolRecurringLimit {
            recurring_amount: 500,
            window: 100,
            last_reset: 0,
            current_amount: 500,
        })],
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
        vec![ClientAction::TokenRecurringLimit(TokenRecurringLimit {
            token_mint: mint_pubkey.to_bytes().try_into().unwrap(),
            window: 100,
            limit: 500,
            current: 500,
            last_reset: 0,
        })],
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

    let recipient_create_result =
        create_swig_ed25519(&mut context, &recipient_authority, recipient_id);
    assert!(
        recipient_create_result.is_ok(),
        "Failed to create recipient Swig account"
    );

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
        let recipient_swig_state = SwigWithRoles::from_bytes(&recipient_account.data).unwrap();
        recipient_swig_state.state.reserved_lamports
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
