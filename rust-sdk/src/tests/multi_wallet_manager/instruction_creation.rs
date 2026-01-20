use solana_client::rpc_client::RpcClient;
use solana_program::system_instruction;
use solana_sdk::{
    clock::Clock,
    commitment_config::CommitmentConfig,
    message::{v0, VersionedMessage},
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};

use super::super::common::setup_test_context;
use super::common::create_wallets_with_dapp_authority;
use crate::{client_role::Ed25519ClientRole, multi_wallet_manager::MultiWalletManager};

/// Test creating instructions with a custom builder.
#[test_log::test]
fn test_create_instructions() {
    let mut context = setup_test_context().unwrap();
    let num_wallets = 5;
    let transfer_amount = 100_000;

    context
        .svm
        .airdrop(&context.default_payer.pubkey(), 100_000_000_000_000)
        .unwrap();

    let dapp_keypair = Keypair::new();
    let wallet_data = create_wallets_with_dapp_authority(&mut context, &dapp_keypair, num_wallets)
        .expect("Failed to create wallets");

    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    let fee_payer = &context.default_payer;
    let client_role = Box::new(Ed25519ClientRole::new(dapp_keypair.pubkey()));
    let rpc_client = RpcClient::new_with_commitment(
        "http://localhost:8899".to_string(),
        CommitmentConfig::confirmed(),
    );

    let manager = MultiWalletManager::new(
        client_role,
        fee_payer,
        Some(&dapp_keypair),
        rpc_client,
        &mut context.svm,
    );

    let recipient = Keypair::new();

    // Use the new API name
    let signed_instructions = manager
        .create_instructions(
            wallet_data.clone(),
            |_swig_id, _role_id, swig_wallet_address| {
                Ok(system_instruction::transfer(
                    &swig_wallet_address,
                    &recipient.pubkey(),
                    transfer_amount,
                ))
            },
            Some(current_slot),
        )
        .expect("Failed to create instructions");

    assert_eq!(
        signed_instructions.len(),
        num_wallets,
        "Expected {} signed instructions",
        num_wallets
    );
}

/// Test creating SOL transfer instructions.
#[test_log::test]
fn test_create_sol_transfer_instructions() {
    let mut context = setup_test_context().unwrap();
    let num_wallets = 5;
    let transfer_amount = 50_000;

    context
        .svm
        .airdrop(&context.default_payer.pubkey(), 100_000_000_000_000)
        .unwrap();

    let dapp_keypair = Keypair::new();
    let wallet_data = create_wallets_with_dapp_authority(&mut context, &dapp_keypair, num_wallets)
        .expect("Failed to create wallets");

    let recipient = Keypair::new();
    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    let fee_payer = &context.default_payer;
    let client_role = Box::new(Ed25519ClientRole::new(dapp_keypair.pubkey()));
    let rpc_client = RpcClient::new_with_commitment(
        "http://localhost:8899".to_string(),
        CommitmentConfig::confirmed(),
    );

    let manager = MultiWalletManager::new(
        client_role,
        fee_payer,
        Some(&dapp_keypair),
        rpc_client,
        &mut context.svm,
    );

    let signed_instructions = manager
        .create_sol_transfer_instructions(
            wallet_data,
            recipient.pubkey(),
            transfer_amount,
            Some(current_slot),
        )
        .expect("Failed to create SOL transfer instructions");

    assert_eq!(
        signed_instructions.len(),
        num_wallets,
        "Expected {} signed instructions",
        num_wallets
    );
}

/// Test splitting instructions into batches.
#[test_log::test]
fn test_split_into_batches() {
    let mut context = setup_test_context().unwrap();
    let num_wallets = 10;
    let transfer_amount = 100_000;

    context
        .svm
        .airdrop(&context.default_payer.pubkey(), 100_000_000_000_000)
        .unwrap();

    let dapp_keypair = Keypair::new();
    let wallet_data = create_wallets_with_dapp_authority(&mut context, &dapp_keypair, num_wallets)
        .expect("Failed to create wallets");

    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    let fee_payer = &context.default_payer;
    let client_role = Box::new(Ed25519ClientRole::new(dapp_keypair.pubkey()));
    let rpc_client = RpcClient::new_with_commitment(
        "http://localhost:8899".to_string(),
        CommitmentConfig::confirmed(),
    );

    let manager = MultiWalletManager::new(
        client_role,
        fee_payer,
        Some(&dapp_keypair),
        rpc_client,
        &mut context.svm,
    );

    let recipient = Keypair::new();

    let signed_instructions = manager
        .create_sol_transfer_instructions(
            wallet_data,
            recipient.pubkey(),
            transfer_amount,
            Some(current_slot),
        )
        .expect("Failed to create instructions");

    // Split with small limits to force multiple batches
    const MAX_ACCOUNTS_PER_TX: usize = 128;
    const MAX_TX_SIZE_BYTES: usize = 1024;

    let batches = MultiWalletManager::split_into_batches(
        signed_instructions,
        MAX_ACCOUNTS_PER_TX,
        MAX_TX_SIZE_BYTES,
    )
    .expect("Failed to split into batches");

    assert!(!batches.is_empty(), "Should have at least one batch");

    // Verify total instructions across all batches
    let total_instructions: usize = batches.iter().map(|b| b.len()).sum();
    assert_eq!(
        total_instructions, num_wallets,
        "Total instructions should match"
    );
}

/// Test the manual flow: create instructions -> split into batches -> send transactions.
#[test_log::test]
fn test_manual_batch_flow() {
    let mut context = setup_test_context().unwrap();
    let num_wallets = 10;
    let transfer_amount = 100_000;

    context
        .svm
        .airdrop(&context.default_payer.pubkey(), 100_000_000_000_000)
        .unwrap();

    let dapp_keypair = Keypair::new();
    let wallet_data = create_wallets_with_dapp_authority(&mut context, &dapp_keypair, num_wallets)
        .expect("Failed to create wallets");

    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    let fee_payer = &context.default_payer;
    let client_role = Box::new(Ed25519ClientRole::new(dapp_keypair.pubkey()));
    let rpc_client = RpcClient::new_with_commitment(
        "http://localhost:8899".to_string(),
        CommitmentConfig::confirmed(),
    );

    let manager = MultiWalletManager::new(
        client_role,
        fee_payer,
        Some(&dapp_keypair),
        rpc_client,
        &mut context.svm,
    );

    let recipient = Keypair::new();

    // Step 1: Create instructions
    let signed_instructions = manager
        .create_instructions(
            wallet_data,
            |_swig_id, _role_id, swig_wallet_address| {
                Ok(system_instruction::transfer(
                    &swig_wallet_address,
                    &recipient.pubkey(),
                    transfer_amount,
                ))
            },
            Some(current_slot),
        )
        .expect("Failed to create instructions");

    // Step 2: Split into batches
    const MAX_ACCOUNTS_PER_TX: usize = 128;
    const MAX_TX_SIZE_BYTES: usize = 1024;

    let batches = MultiWalletManager::split_into_batches(
        signed_instructions,
        MAX_ACCOUNTS_PER_TX,
        MAX_TX_SIZE_BYTES,
    )
    .expect("Failed to split into batches");

    // Step 3: Send each batch
    let mut total_sent = 0;
    for (batch_idx, batch) in batches.iter().enumerate() {
        let batch_blockhash = context.svm.latest_blockhash();
        let msg = v0::Message::try_compile(&fee_payer.pubkey(), batch, &[], batch_blockhash)
            .expect("Failed to compile message");

        let tx =
            VersionedTransaction::try_new(VersionedMessage::V0(msg), &[fee_payer, &dapp_keypair])
                .expect("Failed to create transaction");

        let result = context.svm.send_transaction(tx);
        assert!(
            result.is_ok(),
            "Failed to send batch {}: {:?}",
            batch_idx + 1,
            result.err()
        );
        total_sent += batch.len();
    }

    assert_eq!(total_sent, num_wallets, "Should have sent all instructions");

    // Verify recipient received funds
    let recipient_account = context
        .svm
        .get_account(&recipient.pubkey())
        .expect("Recipient account should exist");

    let expected_amount = transfer_amount * num_wallets as u64;
    assert_eq!(
        recipient_account.lamports, expected_amount,
        "Recipient should have received funds from all wallets"
    );
}
