use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};

use super::super::common::setup_test_context;
use super::common::create_wallets_with_dapp_authority;
use crate::{
    client_role::Ed25519ClientRole,
    multi_wallet_manager::{BatchConfig, MultiWalletManager},
};

/// Test the transfer_sol high-level helper.
#[tokio::test]
async fn test_transfer_sol_helper() {
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

    // Use the high-level helper
    let result = manager
        .transfer_sol(
            wallet_data,
            recipient.pubkey(),
            transfer_amount,
            BatchConfig::default(),
        )
        .await
        .expect("Failed to transfer SOL");

    assert!(result.is_success(), "Expected all transfers to succeed");
    assert_eq!(
        result.successful_count(),
        num_wallets,
        "Expected {} successful transfers",
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

/// Test the transfer_sol helper with parallel execution.
#[tokio::test]
async fn test_transfer_sol_helper_parallel() {
    let mut context = setup_test_context().unwrap();
    let num_wallets = 50;
    let transfer_amount = 50_000;

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

    // Use parallel execution with 4 threads
    let config = BatchConfig::new().with_num_threads(4);

    let result = manager
        .transfer_sol(wallet_data, recipient.pubkey(), transfer_amount, config)
        .await
        .expect("Failed to transfer SOL");

    assert!(result.is_success(), "Expected all transfers to succeed");
    assert_eq!(
        result.successful_count(),
        num_wallets,
        "Expected {} successful transfers",
        num_wallets
    );
}

/// Test transfer_token helper (currently ignored as token setup is complex).
#[tokio::test]
#[ignore = "Token transfer requires additional setup"]
async fn test_transfer_token_helper() {
    let mut context = setup_test_context().unwrap();
    let num_wallets = 5;
    let transfer_amount = 100u64;

    context
        .svm
        .airdrop(&context.default_payer.pubkey(), 100_000_000_000_000)
        .unwrap();

    let dapp_keypair = Keypair::new();
    let wallet_data = create_wallets_with_dapp_authority(&mut context, &dapp_keypair, num_wallets)
        .expect("Failed to create wallets");

    // Setup token infrastructure
    use crate::tests::common::{mint_to, setup_ata, setup_mint};
    use crate::SwigInstructionBuilder;
    use swig_interface::program_id;
    use swig_state::swig::swig_wallet_address_seeds;

    let payer = &context.default_payer;
    let mint_pubkey = setup_mint(&mut context.svm, payer).expect("Failed to setup mint");

    // Create recipient and recipient ATA
    let recipient = Keypair::new();
    let _recipient_ata = setup_ata(&mut context.svm, &mint_pubkey, &recipient.pubkey(), payer)
        .expect("Failed to setup recipient ATA");

    // Setup ATAs for each swig wallet and mint tokens to them
    for (swig_id, _) in &wallet_data {
        let swig_key = SwigInstructionBuilder::swig_key(swig_id);
        let (swig_wallet_address, _) = Pubkey::find_program_address(
            &swig_wallet_address_seeds(swig_key.as_ref()),
            &program_id(),
        );

        let swig_ata = setup_ata(&mut context.svm, &mint_pubkey, &swig_wallet_address, payer)
            .expect("Failed to setup swig ATA");

        mint_to(&mut context.svm, &mint_pubkey, payer, &swig_ata, 10_000)
            .expect("Failed to mint tokens");
    }

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

    let result = manager
        .transfer_token(
            wallet_data,
            mint_pubkey,
            recipient.pubkey(),
            transfer_amount,
            BatchConfig::default(),
        )
        .await
        .expect("Failed to transfer tokens");

    assert!(result.is_success(), "Expected all transfers to succeed");
    assert_eq!(
        result.successful_count(),
        num_wallets,
        "Expected {} successful transfers",
        num_wallets
    );
}
