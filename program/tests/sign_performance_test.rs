#![cfg(not(feature = "program_scope_test"))]

mod common;
use common::*;
use litesvm_token::spl_token::{self};
use solana_sdk::{
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{AuthorityConfig, ClientAction};
use swig_state_x::{
    action::program_scope::{NumericType, ProgramScope, ProgramScopeType},
    swig::swig_account_seeds,
};

/// This test compares the baseline performance of:
/// 1. A regular token transfer (outside of swig)
/// 2. A token transfer using swig
/// It measures and compares compute units consumption and accounts used
#[test_log::test]
fn test_token_transfer_performance_comparison() {
    let mut context = setup_test_context().unwrap();

    // Setup payers and recipients
    let swig_authority = Keypair::new();
    let regular_sender = Keypair::new();
    let recipient = Keypair::new();

    // Airdrop to participants
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&regular_sender.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    // Setup token mint
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    // Setup swig account
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let swig_create_result = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_result.is_ok());

    // Setup token accounts
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig,
        &context.default_payer,
    )
    .unwrap();

    let regular_sender_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &regular_sender.pubkey(),
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

    // Mint tokens to both sending accounts
    let initial_token_amount = 1000;
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        initial_token_amount,
    )
    .unwrap();

    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &regular_sender_ata,
        initial_token_amount,
    )
    .unwrap();

    // Measure regular token transfer performance
    let transfer_amount = 100;
    let token_program_id = spl_token::ID;

    let regular_transfer_ix = spl_token::instruction::transfer(
        &token_program_id,
        &regular_sender_ata,
        &recipient_ata,
        &regular_sender.pubkey(),
        &[],
        transfer_amount,
    )
    .unwrap();

    let regular_transfer_message = v0::Message::try_compile(
        &regular_sender.pubkey(),
        &[regular_transfer_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let regular_tx_accounts = regular_transfer_message.account_keys.len();

    let regular_transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(regular_transfer_message),
        &[regular_sender],
    )
    .unwrap();

    let regular_transfer_result = context.svm.send_transaction(regular_transfer_tx).unwrap();
    let regular_transfer_cu = regular_transfer_result.compute_units_consumed;

    println!("Regular token transfer CU: {}", regular_transfer_cu);
    println!("Regular token transfer accounts: {}", regular_tx_accounts);

    // Measure swig token transfer performance
    let swig_transfer_ix = spl_token::instruction::transfer(
        &token_program_id,
        &swig_ata,
        &recipient_ata,
        &swig,
        &[],
        transfer_amount,
    )
    .unwrap();

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        swig_authority.pubkey(),
        swig_authority.pubkey(),
        swig_transfer_ix,
        0, // authority role id
    )
    .unwrap();

    let swig_transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let swig_tx_accounts = swig_transfer_message.account_keys.len();

    let swig_transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(swig_transfer_message),
        &[swig_authority],
    )
    .unwrap();

    let swig_transfer_result = context.svm.send_transaction(swig_transfer_tx).unwrap();
    let swig_transfer_cu = swig_transfer_result.compute_units_consumed;
    println!("Swig token transfer CU: {}", swig_transfer_cu);
    println!("Swig token transfer accounts: {}", swig_tx_accounts);

    // Compare results
    let cu_difference = swig_transfer_cu as i64 - regular_transfer_cu as i64;
    let account_difference = swig_tx_accounts as i64 - regular_tx_accounts as i64;

    println!("Performance comparison:");
    println!(
        "CU difference (swig - regular): {} CU ({:.2}% overhead)",
        cu_difference,
        (cu_difference as f64 / regular_transfer_cu as f64) * 100.0
    );
    println!(
        "Account difference (swig - regular): {} accounts",
        account_difference
    );
    // 3803 is the max difference in CU between the two transactions lets lower
    // this as far as possible but never increase it
    assert!(swig_transfer_cu - regular_transfer_cu <= 3803);
}

#[test_log::test]
fn test_sol_transfer_performance_comparison() {
    let mut context = setup_test_context().unwrap();

    // Setup payers and recipients
    let swig_authority = Keypair::new();
    let regular_sender = Keypair::new();
    let recipient = Keypair::new();

    // Airdrop to participants
    let initial_sol_amount = 10_000_000_000;
    context
        .svm
        .airdrop(&swig_authority.pubkey(), initial_sol_amount)
        .unwrap();
    context
        .svm
        .airdrop(&regular_sender.pubkey(), initial_sol_amount)
        .unwrap();
    context.svm.airdrop(&recipient.pubkey(), 1_000_000).unwrap();

    // Setup swig account
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let swig_create_result = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_result.is_ok());

    context.svm.airdrop(&swig, initial_sol_amount).unwrap();
    let transfer_amount = 1_000_000;

    let regular_transfer_ix = solana_sdk::system_instruction::transfer(
        &regular_sender.pubkey(),
        &recipient.pubkey(),
        transfer_amount,
    );

    let regular_transfer_message = v0::Message::try_compile(
        &regular_sender.pubkey(),
        &[regular_transfer_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let regular_tx_accounts = regular_transfer_message.account_keys.len();

    let regular_transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(regular_transfer_message),
        &[regular_sender],
    )
    .unwrap();

    let regular_transfer_result = context.svm.send_transaction(regular_transfer_tx).unwrap();
    let regular_transfer_cu = regular_transfer_result.compute_units_consumed;

    println!("Regular SOL transfer CU: {}", regular_transfer_cu);
    println!("Regular SOL transfer accounts: {}", regular_tx_accounts);

    // Measure swig SOL transfer performance
    let swig_transfer_ix =
        solana_sdk::system_instruction::transfer(&swig, &recipient.pubkey(), transfer_amount);

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        swig_authority.pubkey(),
        swig_authority.pubkey(),
        swig_transfer_ix,
        0, // authority role id
    )
    .unwrap();

    let swig_transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let swig_tx_accounts = swig_transfer_message.account_keys.len();

    let swig_transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(swig_transfer_message),
        &[swig_authority],
    )
    .unwrap();

    let swig_transfer_result = context.svm.send_transaction(swig_transfer_tx).unwrap();
    let swig_transfer_cu = swig_transfer_result.compute_units_consumed;

    println!("Swig SOL transfer CU: {}", swig_transfer_cu);
    println!("Swig SOL transfer accounts: {}", swig_tx_accounts);

    // Compare results
    let cu_difference = swig_transfer_cu as i64 - regular_transfer_cu as i64;
    let account_difference = swig_tx_accounts as i64 - regular_tx_accounts as i64;

    println!("Performance comparison:");
    println!(
        "CU difference (swig - regular): {} CU ({:.2}% overhead)",
        cu_difference,
        (cu_difference as f64 / regular_transfer_cu as f64) * 100.0
    );
    println!(
        "Account difference (swig - regular): {} accounts",
        account_difference
    );

    // Set a reasonable limit for the CU difference to avoid regressions
    // Similar to the token transfer test assertion
    assert!(swig_transfer_cu - regular_transfer_cu <= 2010);
}
