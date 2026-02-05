use solana_client::rpc_client::RpcClient;
use solana_program::system_instruction;
use solana_sdk::{commitment_config::CommitmentConfig, signature::Keypair, signer::Signer};

use super::super::common::setup_test_context;
use super::common::create_wallets_with_dapp_authority;
use crate::{
    client_role::Ed25519ClientRole,
    multi_wallet_manager::{BatchConfig, BatchStrategy, MultiWalletManager},
};

/// Test execute_batch with Simple strategy.
#[tokio::test]
async fn test_execute_batch_simple_strategy() {
    let mut context = setup_test_context().unwrap();
    let num_wallets = 100;
    let transfer_amount = 100_000;

    context
        .svm
        .airdrop(&context.default_payer.pubkey(), 100_000_000_000_000)
        .unwrap();

    let dapp_keypair = Keypair::new();
    let wallet_data = create_wallets_with_dapp_authority(&mut context, &dapp_keypair, num_wallets)
        .expect("Failed to create wallets");

    let recipient = Keypair::new();

    let fee_payer = &context.default_payer;
    let client_role = Box::new(Ed25519ClientRole::new(dapp_keypair.pubkey()));
    let rpc_client = RpcClient::new_with_commitment(
        "http://localhost:8899".to_string(),
        CommitmentConfig::confirmed(),
    );

    let mut manager = MultiWalletManager::new(
        client_role,
        fee_payer,
        Some(&dapp_keypair),
        rpc_client,
        &mut context.svm,
    );

    let config = BatchConfig::new()
        .with_strategy(BatchStrategy::Simple)
        .with_max_retries(3)
        .with_retry_delay(100);

    let result = manager
        .execute_batch(
            wallet_data,
            |_swig_id, _role_id, swig_wallet_address| {
                Ok(system_instruction::transfer(
                    &swig_wallet_address,
                    &recipient.pubkey(),
                    transfer_amount,
                ))
            },
            config,
        )
        .await
        .expect("Failed to execute batch");

    assert!(
        result.is_success(),
        "Expected all transactions to succeed, but {} failed",
        result.failed_count()
    );
    assert_eq!(
        result.successful_count(),
        num_wallets,
        "Expected {} successful operations",
        num_wallets
    );

    // Verify recipient received funds
    let recipient_account = manager
        .litesvm
        .get_account(&recipient.pubkey())
        .expect("Recipient account should exist");

    let expected_amount = transfer_amount * num_wallets as u64;
    assert_eq!(
        recipient_account.lamports, expected_amount,
        "Recipient should have received funds from all wallets"
    );
}

/// Test execute_batch with BinarySearchFailures strategy.
#[tokio::test]
async fn test_execute_batch_binary_search_strategy() {
    let mut context = setup_test_context().unwrap();
    let num_wallets = 100;
    let transfer_amount = 100_000;

    context
        .svm
        .airdrop(&context.default_payer.pubkey(), 100_000_000_000_000)
        .unwrap();

    let dapp_keypair = Keypair::new();
    let wallet_data = create_wallets_with_dapp_authority(&mut context, &dapp_keypair, num_wallets)
        .expect("Failed to create wallets");

    let recipient = Keypair::new();

    let fee_payer = &context.default_payer;
    let client_role = Box::new(Ed25519ClientRole::new(dapp_keypair.pubkey()));
    let rpc_client = RpcClient::new_with_commitment(
        "http://localhost:8899".to_string(),
        CommitmentConfig::confirmed(),
    );

    let mut manager = MultiWalletManager::new(
        client_role,
        fee_payer,
        Some(&dapp_keypair),
        rpc_client,
        &mut context.svm,
    );

    let config = BatchConfig::new()
        .with_strategy(BatchStrategy::BinarySearchFailures)
        .with_max_retries(2)
        .with_retry_delay(50);

    let result = manager
        .execute_batch(
            wallet_data,
            |_swig_id, _role_id, swig_wallet_address| {
                Ok(system_instruction::transfer(
                    &swig_wallet_address,
                    &recipient.pubkey(),
                    transfer_amount,
                ))
            },
            config,
        )
        .await
        .expect("Failed to execute batch");

    assert!(
        result.is_success(),
        "Expected all transactions to succeed, but {} failed: {:?}",
        result.failed_count(),
        result.failed
    );
    assert_eq!(
        result.successful_count(),
        num_wallets,
        "Expected {} successful operations",
        num_wallets
    );

    // Verify recipient received funds
    let recipient_account = manager
        .litesvm
        .get_account(&recipient.pubkey())
        .expect("Recipient account should exist");

    let expected_amount = transfer_amount * num_wallets as u64;
    assert_eq!(
        recipient_account.lamports, expected_amount,
        "Recipient should have received funds from all wallets"
    );
}

/// Test execute_batch with num_threads > 1 for parallel execution.
///
/// Note: In test mode, parallelization is disabled due to mutable borrow constraints,
/// but this test verifies the API works correctly with the num_threads parameter.
#[tokio::test]
async fn test_execute_batch_with_num_threads() {
    let mut context = setup_test_context().unwrap();
    let num_wallets = 50;
    let transfer_amount = 100_000;

    context
        .svm
        .airdrop(&context.default_payer.pubkey(), 100_000_000_000_000)
        .unwrap();

    let dapp_keypair = Keypair::new();
    let wallet_data = create_wallets_with_dapp_authority(&mut context, &dapp_keypair, num_wallets)
        .expect("Failed to create wallets");

    let recipient = Keypair::new();

    let fee_payer = &context.default_payer;
    let client_role = Box::new(Ed25519ClientRole::new(dapp_keypair.pubkey()));
    let rpc_client = RpcClient::new_with_commitment(
        "http://localhost:8899".to_string(),
        CommitmentConfig::confirmed(),
    );

    let mut manager = MultiWalletManager::new(
        client_role,
        fee_payer,
        Some(&dapp_keypair),
        rpc_client,
        &mut context.svm,
    );

    // Use num_threads = 4 for parallel execution
    let config = BatchConfig::new()
        .with_strategy(BatchStrategy::Simple)
        .with_num_threads(4)
        .with_max_retries(3);

    let result = manager
        .execute_batch(
            wallet_data,
            |_swig_id, _role_id, swig_wallet_address| {
                Ok(system_instruction::transfer(
                    &swig_wallet_address,
                    &recipient.pubkey(),
                    transfer_amount,
                ))
            },
            config,
        )
        .await
        .expect("Failed to execute batch");

    assert!(
        result.is_success(),
        "Expected all transactions to succeed, but {} failed",
        result.failed_count()
    );
    assert_eq!(
        result.successful_count(),
        num_wallets,
        "Expected {} successful operations",
        num_wallets
    );
}

/// Test that BatchConfig builder methods work correctly.
#[test]
fn test_batch_config_builder() {
    let config = BatchConfig::new()
        .with_strategy(BatchStrategy::BinarySearchFailures)
        .with_max_accounts(32)
        .with_max_tx_size(2048)
        .with_max_retries(5)
        .with_retry_delay(1000)
        .with_num_threads(8);

    assert_eq!(config.strategy, BatchStrategy::BinarySearchFailures);
    assert_eq!(config.max_accounts_per_tx, 32);
    assert_eq!(config.max_tx_size_bytes, 2048);
    assert_eq!(config.max_retries, 5);
    assert_eq!(config.retry_delay_ms, 1000);
    assert_eq!(config.num_threads, 8);
}

/// Test that num_threads cannot be set to 0 (defaults to 1).
#[test]
fn test_batch_config_num_threads_minimum() {
    let config = BatchConfig::new().with_num_threads(0);
    assert_eq!(config.num_threads, 1, "num_threads should be at least 1");
}

/// Test BatchExecutionResult helper methods.
#[test]
fn test_batch_execution_result_helpers() {
    use crate::multi_wallet_manager::{BatchExecutionResult, FailedInstruction, SuccessfulBatch};
    use solana_sdk::signature::Signature;

    let mut result = BatchExecutionResult::default();

    // Add some successful batches
    result.successful.push(SuccessfulBatch {
        signature: Signature::new_unique(),
        swig_ids: vec![[1u8; 32], [2u8; 32]],
    });
    result.successful.push(SuccessfulBatch {
        signature: Signature::new_unique(),
        swig_ids: vec![[3u8; 32]],
    });

    // Add a failed instruction
    result.failed.push(FailedInstruction {
        swig_id: [4u8; 32],
        role_id: 1,
        error: "Test error".to_string(),
    });

    assert!(!result.is_success());
    assert_eq!(result.successful_count(), 3);
    assert_eq!(result.failed_count(), 1);

    let successful_ids = result.successful_swig_ids();
    assert_eq!(successful_ids.len(), 3);
    assert!(successful_ids.contains(&[1u8; 32]));
    assert!(successful_ids.contains(&[2u8; 32]));
    assert!(successful_ids.contains(&[3u8; 32]));

    let failed_ids = result.failed_swig_ids();
    assert_eq!(failed_ids.len(), 1);
    assert_eq!(failed_ids[0], [4u8; 32]);
}

/// Test large batch execution (1000 wallets).
#[tokio::test]
async fn test_large_batch_execution() {
    let mut context = setup_test_context().unwrap();
    let num_wallets = 1000;
    let transfer_amount = 100_000;

    context
        .svm
        .airdrop(&context.default_payer.pubkey(), 100_000_000_000_000)
        .unwrap();

    let dapp_keypair = Keypair::new();
    let wallet_data = create_wallets_with_dapp_authority(&mut context, &dapp_keypair, num_wallets)
        .expect("Failed to create wallets");

    let recipient = Keypair::new();

    let fee_payer = &context.default_payer;
    let client_role = Box::new(Ed25519ClientRole::new(dapp_keypair.pubkey()));
    let rpc_client = RpcClient::new_with_commitment(
        "http://localhost:8899".to_string(),
        CommitmentConfig::confirmed(),
    );

    let mut manager = MultiWalletManager::new(
        client_role,
        fee_payer,
        Some(&dapp_keypair),
        rpc_client,
        &mut context.svm,
    );

    let config = BatchConfig::new()
        .with_strategy(BatchStrategy::Simple)
        .with_max_accounts(64)
        .with_max_tx_size(1024)
        .with_max_retries(3);

    let result = manager
        .execute_batch(
            wallet_data,
            |_swig_id, _role_id, swig_wallet_address| {
                Ok(system_instruction::transfer(
                    &swig_wallet_address,
                    &recipient.pubkey(),
                    transfer_amount,
                ))
            },
            config,
        )
        .await
        .expect("Failed to execute batch");

    assert!(result.is_success(), "Expected all transactions to succeed");
    assert_eq!(
        result.successful_count(),
        num_wallets,
        "Expected {} successful operations",
        num_wallets
    );

    // Verify recipient received all funds
    let recipient_account = manager
        .litesvm
        .get_account(&recipient.pubkey())
        .expect("Recipient account should exist");

    let expected_amount = transfer_amount * num_wallets as u64;
    assert_eq!(recipient_account.lamports, expected_amount);
}

/// Test that BinarySearchFailures correctly identifies the failing wallet.
///
/// This test creates multiple valid wallets and one invalid wallet (with wrong role_id),
/// then verifies that only the invalid wallet is marked as failed while all valid
/// wallets succeed.
#[tokio::test]
async fn test_binary_search_identifies_failing_wallet() {
    use crate::SwigInstructionBuilder;
    use solana_sdk::pubkey::Pubkey;
    use swig_interface::program_id;
    use swig_state::swig::swig_wallet_address_seeds;

    let mut context = setup_test_context().unwrap();
    let num_valid_wallets = 10;
    let transfer_amount = 100_000;

    context
        .svm
        .airdrop(&context.default_payer.pubkey(), 100_000_000_000_000)
        .unwrap();

    let dapp_keypair = Keypair::new();

    // Create valid wallets with dapp authority
    let valid_wallet_data =
        create_wallets_with_dapp_authority(&mut context, &dapp_keypair, num_valid_wallets)
            .expect("Failed to create valid wallets");

    // Create an invalid wallet entry - use a valid swig_id but with a WRONG role_id
    // The dapp_keypair is NOT an authority on this wallet, so it will fail
    let invalid_swig_id: [u8; 32] = {
        let mut id = [0u8; 32];
        id[0..8].copy_from_slice(&(999u64).to_le_bytes()); // Different ID
        id
    };

    // Create this wallet but DON'T add the dapp_keypair as authority
    use super::super::common::create_swig_ed25519;
    let other_authority = Keypair::new();
    let (invalid_swig_key, _, _) =
        create_swig_ed25519(&mut context, &other_authority, invalid_swig_id)
            .expect("Failed to create invalid wallet");

    // Fund the invalid wallet's address PDA so it has lamports to transfer
    let (invalid_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(invalid_swig_key.as_ref()),
        &program_id(),
    );
    context
        .svm
        .airdrop(&invalid_wallet_address, 1_000_000_000)
        .unwrap();

    // Create wallet_data with valid wallets + one invalid wallet (using wrong role_id)
    // The invalid wallet uses role_id 999 which doesn't exist for the dapp_keypair
    let invalid_role_id = 999u32; // This role doesn't exist for dapp_keypair on this wallet
    let mut all_wallet_data = valid_wallet_data.clone();
    all_wallet_data.push((invalid_swig_id, invalid_role_id));

    let recipient = Keypair::new();

    let fee_payer = &context.default_payer;
    let client_role = Box::new(Ed25519ClientRole::new(dapp_keypair.pubkey()));
    let rpc_client = RpcClient::new_with_commitment(
        "http://localhost:8899".to_string(),
        CommitmentConfig::confirmed(),
    );

    let mut manager = MultiWalletManager::new(
        client_role,
        fee_payer,
        Some(&dapp_keypair),
        rpc_client,
        &mut context.svm,
    );

    // Use BinarySearchFailures to identify the failing wallet
    let config = BatchConfig::new()
        .with_strategy(BatchStrategy::BinarySearchFailures)
        .with_max_retries(1)
        .with_retry_delay(10);

    let result = manager
        .execute_batch(
            all_wallet_data,
            |_swig_id, _role_id, swig_wallet_address| {
                Ok(system_instruction::transfer(
                    &swig_wallet_address,
                    &recipient.pubkey(),
                    transfer_amount,
                ))
            },
            config,
        )
        .await
        .expect("Failed to execute batch");

    // Verify: should have exactly 1 failure (the invalid wallet)
    assert_eq!(
        result.failed_count(),
        1,
        "Expected exactly 1 failed wallet, got {}",
        result.failed_count()
    );

    // Verify: the failed wallet should be the invalid one
    let failed_ids = result.failed_swig_ids();
    assert_eq!(failed_ids.len(), 1);
    assert_eq!(
        failed_ids[0], invalid_swig_id,
        "The failed swig_id should be the invalid wallet"
    );

    // Verify: the failed instruction has the correct role_id
    assert_eq!(
        result.failed[0].role_id, invalid_role_id,
        "The failed role_id should match"
    );

    // Verify: all valid wallets should have succeeded
    assert_eq!(
        result.successful_count(),
        num_valid_wallets,
        "Expected {} successful operations",
        num_valid_wallets
    );

    // Verify: the valid swig_ids are in the successful list
    let successful_ids = result.successful_swig_ids();
    for (valid_swig_id, _) in &valid_wallet_data {
        assert!(
            successful_ids.contains(valid_swig_id),
            "Valid swig_id {:?} should be in successful list",
            valid_swig_id
        );
    }

    // Verify: recipient received funds only from valid wallets
    let recipient_account = manager
        .litesvm
        .get_account(&recipient.pubkey())
        .expect("Recipient account should exist");

    let expected_amount = transfer_amount * num_valid_wallets as u64;
    assert_eq!(
        recipient_account.lamports, expected_amount,
        "Recipient should have received funds only from valid wallets"
    );

    println!(
        "BinarySearchFailures correctly identified failing wallet: {:?}",
        invalid_swig_id
    );
    println!(
        "Successful: {}, Failed: {}",
        result.successful_count(),
        result.failed_count()
    );
}

/// Test BinarySearchFailures with multiple failing wallets scattered in the batch.
///
/// This verifies that binary search can find multiple failures, not just one.
#[tokio::test]
async fn test_binary_search_multiple_failures() {
    use crate::SwigInstructionBuilder;
    use solana_sdk::pubkey::Pubkey;
    use swig_interface::program_id;
    use swig_state::swig::swig_wallet_address_seeds;

    let mut context = setup_test_context().unwrap();
    let num_valid_wallets = 8;
    let transfer_amount = 100_000;

    context
        .svm
        .airdrop(&context.default_payer.pubkey(), 100_000_000_000_000)
        .unwrap();

    let dapp_keypair = Keypair::new();

    // Create valid wallets
    let valid_wallet_data =
        create_wallets_with_dapp_authority(&mut context, &dapp_keypair, num_valid_wallets)
            .expect("Failed to create valid wallets");

    // Create 3 invalid wallets at different positions
    use super::super::common::create_swig_ed25519;
    let mut invalid_swig_ids = Vec::new();

    for i in 0..3 {
        let invalid_swig_id: [u8; 32] = {
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&((1000 + i) as u64).to_le_bytes());
            id
        };

        let other_authority = Keypair::new();
        let (invalid_swig_key, _, _) =
            create_swig_ed25519(&mut context, &other_authority, invalid_swig_id)
                .expect("Failed to create invalid wallet");

        // Fund the wallet
        let (invalid_wallet_address, _) = Pubkey::find_program_address(
            &swig_wallet_address_seeds(invalid_swig_key.as_ref()),
            &program_id(),
        );
        context
            .svm
            .airdrop(&invalid_wallet_address, 1_000_000_000)
            .unwrap();

        invalid_swig_ids.push(invalid_swig_id);
    }

    // Interleave valid and invalid wallets
    let invalid_role_id = 999u32;
    let mut all_wallet_data = Vec::new();

    // Add first 3 valid wallets
    all_wallet_data.extend(valid_wallet_data[0..3].iter().cloned());
    // Add first invalid wallet
    all_wallet_data.push((invalid_swig_ids[0], invalid_role_id));
    // Add next 3 valid wallets
    all_wallet_data.extend(valid_wallet_data[3..6].iter().cloned());
    // Add second invalid wallet
    all_wallet_data.push((invalid_swig_ids[1], invalid_role_id));
    // Add remaining valid wallets
    all_wallet_data.extend(valid_wallet_data[6..].iter().cloned());
    // Add third invalid wallet
    all_wallet_data.push((invalid_swig_ids[2], invalid_role_id));

    let recipient = Keypair::new();

    let fee_payer = &context.default_payer;
    let client_role = Box::new(Ed25519ClientRole::new(dapp_keypair.pubkey()));
    let rpc_client = RpcClient::new_with_commitment(
        "http://localhost:8899".to_string(),
        CommitmentConfig::confirmed(),
    );

    let mut manager = MultiWalletManager::new(
        client_role,
        fee_payer,
        Some(&dapp_keypair),
        rpc_client,
        &mut context.svm,
    );

    let config = BatchConfig::new()
        .with_strategy(BatchStrategy::BinarySearchFailures)
        .with_max_retries(1)
        .with_retry_delay(10);

    let result = manager
        .execute_batch(
            all_wallet_data,
            |_swig_id, _role_id, swig_wallet_address| {
                Ok(system_instruction::transfer(
                    &swig_wallet_address,
                    &recipient.pubkey(),
                    transfer_amount,
                ))
            },
            config,
        )
        .await
        .expect("Failed to execute batch");

    // Verify: should have exactly 3 failures
    assert_eq!(
        result.failed_count(),
        3,
        "Expected exactly 3 failed wallets, got {}",
        result.failed_count()
    );

    // Verify: all 3 invalid wallets are in the failed list
    let failed_ids = result.failed_swig_ids();
    for invalid_id in &invalid_swig_ids {
        assert!(
            failed_ids.contains(invalid_id),
            "Invalid swig_id {:?} should be in failed list",
            invalid_id
        );
    }

    // Verify: all valid wallets succeeded
    assert_eq!(
        result.successful_count(),
        num_valid_wallets,
        "Expected {} successful operations",
        num_valid_wallets
    );

    // Verify: recipient received funds only from valid wallets
    let recipient_account = manager
        .litesvm
        .get_account(&recipient.pubkey())
        .expect("Recipient account should exist");

    let expected_amount = transfer_amount * num_valid_wallets as u64;
    assert_eq!(
        recipient_account.lamports, expected_amount,
        "Recipient should have received funds only from valid wallets"
    );

    println!(
        "BinarySearchFailures correctly identified {} failing wallets",
        result.failed_count()
    );
}
