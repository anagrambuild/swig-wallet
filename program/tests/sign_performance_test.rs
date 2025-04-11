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
use swig_state_x::{action::program::ProgramScope, swig::swig_account_seeds};

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

    // Setup swig account with All action and a ProgramScope action for the token program
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());

    // Create the swig account with the All action
    let swig_create_result = create_swig_ed25519(&mut context, &swig_authority, id);
    println!("swig_create_result: {:?}", swig_create_result);
    assert!(swig_create_result.is_ok());

    // Add a role with a ProgramScope action for the token program
    // This will be used to test if our account classification logic works correctly
    let program_scope = ProgramScope {
        program_id: spl_token::ID.to_bytes(),
        actions: [
            1,  // Action 1: Greater than check
            64, // Start index 64 - Token balance field starts at byte 64
            72, // End index 72 - Token balance field ends at byte 72 (8 bytes for u64)
            0, 0, 0, 0, 0, // Padding
        ],
    };

    println!(
        "Created ProgramScope with actions: {:?}",
        program_scope.actions
    );

    let add_authority_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: swig_state_x::authority::AuthorityType::Ed25519,
            authority: swig_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ProgramScope(program_scope)],
    );
    println!("{:?}", add_authority_result);
    assert!(add_authority_result.is_ok());

    println!("Added ProgramScope action for token program");

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

    println!("Token accounts created:");
    println!("Swig ATA: {}", swig_ata);
    println!("Regular sender ATA: {}", regular_sender_ata);
    println!("Recipient ATA: {}", recipient_ata);

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
    println!("Minted {} tokens to swig ATA", initial_token_amount);

    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &regular_sender_ata,
        initial_token_amount,
    )
    .unwrap();
    println!(
        "Minted {} tokens to regular sender ATA",
        initial_token_amount
    );

    // Get the account data to verify token amounts
    let swig_ata_data = context
        .svm
        .get_account(&swig_ata)
        .expect("Failed to get swig ATA account");
    let balance_bytes = &swig_ata_data.data[64..72]; // Balance is at bytes 64-72
    let balance = u64::from_le_bytes(balance_bytes.try_into().unwrap());
    println!("Verified swig ATA balance from account data: {}", balance);

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
    // println!("Swig token transfer logs: {:?}", swig_transfer_result.logs);
    for log in swig_transfer_result.logs.iter() {
        println!("{:?}", log);
    }

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
    // 3760 is the max difference in CU between the two transactions lets lower this as far as possible but never increase it
    assert!(swig_transfer_cu - regular_transfer_cu <= 3949);
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
    assert!(swig_transfer_cu - regular_transfer_cu <= 2506);
}
