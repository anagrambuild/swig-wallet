use alloy_primitives::B256;
use alloy_signer::SignerSync;
use litesvm_token::spl_token;
use solana_program::pubkey::Pubkey;
use solana_sdk::{clock::Clock, signature::Keypair, transaction::VersionedTransaction};

use super::*;
use crate::{client_role::Ed25519ClientRole, tests::common::*};

#[test_log::test]
#[ignore] // TODO: This test was using v1 wallets and needs updates for v2
fn should_token_transfer_with_program_scope() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let recipient = Keypair::new();
    let secondary_authority = Keypair::new();

    litesvm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Setup token mint
    let mint_pubkey = setup_mint(&mut litesvm, &main_authority).unwrap();

    // Setup token accounts
    let recipient_ata = setup_ata(
        &mut litesvm,
        &mint_pubkey,
        &recipient.pubkey(),
        &main_authority,
    )
    .unwrap();

    // Create swig wallet
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
    let swig_ata = swig_wallet.create_ata(&mint_pubkey).unwrap();

    // Setup a basic program scope
    let new_authority = Keypair::new();

    let permissions = vec![
        Permission::Program {
            program_id: spl_token::ID,
        },
        Permission::ProgramScope {
            program_id: spl_token::ID,
            target_account: swig_ata,
            numeric_type: 2, // U64
            limit: Some(1000),
            window: None,
            balance_field_start: Some(64),
            balance_field_end: Some(72),
        },
    ];

    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &new_authority.pubkey().to_bytes(),
            permissions,
        )
        .unwrap();

    let swig_pubkey = swig_wallet.get_swig_account().unwrap();
    let swig_data = swig_wallet.litesvm().get_account(&swig_pubkey).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_data.data).unwrap();

    assert_eq!(swig_with_roles.state.roles, 2);

    // Switch to the new authority
    swig_wallet
        .switch_authority(
            1,
            Box::new(Ed25519ClientRole::new(new_authority.pubkey())),
            Some(&new_authority),
        )
        .unwrap();

    // Mint initial tokens to swig wallet
    let initial_token_amount = 2000;
    mint_to(
        &mut swig_wallet.litesvm(),
        &mint_pubkey,
        &main_authority,
        &swig_ata,
        initial_token_amount,
    )
    .unwrap();

    let swig_transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig_wallet.get_swig_wallet_address().unwrap(),
        &[],
        100,
    )
    .unwrap();

    let sign_ix = swig_wallet.sign(vec![swig_transfer_ix], None).unwrap();
}

#[test_log::test]
#[ignore] // TODO: This test was using v1 wallets and needs updates for v2
fn should_token_transfer_with_recurring_limit_program_scope() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let recipient = Keypair::new();
    let secondary_authority = Keypair::new();

    litesvm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Setup token mint
    let mint_pubkey = setup_mint(&mut litesvm, &main_authority).unwrap();

    // Setup token accounts
    let recipient_ata = setup_ata(
        &mut litesvm,
        &mint_pubkey,
        &recipient.pubkey(),
        &main_authority,
    )
    .unwrap();

    // Create swig wallet
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
    let swig_ata = swig_wallet.create_ata(&mint_pubkey).unwrap();

    // Setup a RecurringLimit program scope
    // Set a limit of 500 tokens per 100 slots
    let window_size = 100;
    let transfer_limit = 500_u64;

    let new_authority = Keypair::new();

    let permissions = vec![
        Permission::Program {
            program_id: spl_token::ID,
        },
        Permission::ProgramScope {
            program_id: spl_token::ID,
            target_account: swig_ata,
            numeric_type: 2, // U64
            limit: Some(transfer_limit),
            window: Some(window_size),
            balance_field_start: Some(64),
            balance_field_end: Some(72),
        },
    ];

    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &new_authority.pubkey().to_bytes(),
            permissions,
        )
        .unwrap();

    let swig_pubkey = swig_wallet.get_swig_account().unwrap();
    let swig_data = swig_wallet.litesvm().get_account(&swig_pubkey).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_data.data).unwrap();

    assert_eq!(swig_with_roles.state.roles, 2);

    // Switch to the new authority
    swig_wallet
        .switch_authority(
            1,
            Box::new(Ed25519ClientRole::new(new_authority.pubkey())),
            Some(&new_authority),
        )
        .unwrap();

    // Mint initial tokens to swig wallet
    let initial_token_amount = 2000;
    mint_to(
        &mut swig_wallet.litesvm(),
        &mint_pubkey,
        &main_authority,
        &swig_ata,
        initial_token_amount,
    )
    .unwrap();

    // First batch of transfers - should succeed up to the limit
    let transfer_batch = 100;
    let mut transferred = 0;

    // Transfer in batches of 100 tokens up to limit (should succeed)
    while transferred + transfer_batch <= transfer_limit {
        let before_token_account = swig_wallet.litesvm().get_account(&swig_ata).unwrap();
        let before_balance = if before_token_account.data.len() >= 72 {
            // SPL token accounts have their balance at offset 64-72
            u64::from_le_bytes(before_token_account.data[64..72].try_into().unwrap())
        } else {
            0
        };
        println!("Before transfer, token balance: {}", before_balance);
        let current_slot = swig_wallet.litesvm().get_sysvar::<Clock>().slot;
        let swig_transfer_ix = spl_token::instruction::transfer(
            &spl_token::ID,
            &swig_ata,
            &recipient_ata,
            &swig_wallet.get_swig_wallet_address().unwrap(),
            &[],
            transfer_batch,
        )
        .unwrap();

        let sign_ix = swig_wallet.sign(vec![swig_transfer_ix], None).unwrap();
        transferred += transfer_batch;

        swig_wallet.litesvm().expire_blockhash();

        // Get the current token balance after the transfer
        let after_token_account = swig_wallet.litesvm().get_account(&swig_ata).unwrap();
        let after_balance = if after_token_account.data.len() >= 72 {
            // SPL token accounts have their balance at offset 64-72
            u64::from_le_bytes(after_token_account.data[64..72].try_into().unwrap())
        } else {
            0
        };
        println!("After transfer, token balance: {}", after_balance);

        // Verify transfer was successful
        assert!(sign_ix != solana_sdk::signature::Signature::default());
        assert!(after_balance < before_balance);
    }

    // Try to transfer one more batch (should fail)
    let swig_transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig_wallet.get_swig_wallet_address().unwrap(),
        &[],
        transfer_batch,
    )
    .unwrap();

    let sign_result = swig_wallet.sign(vec![swig_transfer_ix], None);
    assert!(
        sign_result.is_err(),
        "Transfer should have failed due to limit"
    );

    // Advance the clock past the window to trigger a reset
    let current_slot = swig_wallet.litesvm().get_sysvar::<Clock>().slot;
    swig_wallet
        .litesvm()
        .warp_to_slot(current_slot + window_size + 1);
    swig_wallet.litesvm().expire_blockhash();

    // After resetting the clock, we should be able to transfer again
    let swig_transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig_wallet.get_swig_wallet_address().unwrap(),
        &[],
        transfer_batch,
    )
    .unwrap();

    let sign_result = swig_wallet.sign(vec![swig_transfer_ix], None);
    assert!(
        sign_result.is_ok(),
        "Token transfer after window reset failed: {:?}",
        sign_result.err()
    );
}
