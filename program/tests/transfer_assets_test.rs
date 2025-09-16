#![cfg(not(feature = "program_scope_test"))]
// Test for transferring assets from swig account to swig wallet address

mod common;

use common::*;
use litesvm::types::TransactionMetadata;
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction,
    transaction::VersionedTransaction,
};
use swig_interface::{swig, TransferAssetsV1Instruction};
use swig_state::{
    action::all::All,
    authority::AuthorityType,
    swig::{swig_wallet_address_seeds, Swig, SwigWithRoles},
    Discriminator, IntoBytes, Transmutable,
};

/// Helper function to create a transfer assets instruction using Ed25519
/// authority
fn create_transfer_assets_instruction(
    swig_pubkey: Pubkey,
    swig_wallet_address_pubkey: Pubkey,
    authority_pubkey: Pubkey,
    payer_pubkey: Pubkey,
    role_id: u32,
) -> Instruction {
    TransferAssetsV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address_pubkey,
        payer_pubkey,
        authority_pubkey,
        role_id,
    )
    .expect("Failed to create transfer assets instruction")
}

#[test_log::test]
fn test_transfer_assets_sol_basic() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    // Create a migrated swig account (has wallet address)
    println!("Creating migrated Swig account...");
    let swig_created = create_swig_ed25519(&mut context, &authority, id);
    assert!(
        swig_created.is_ok(),
        "Failed to create swig: {:?}",
        swig_created.err()
    );
    let (swig_pubkey, _bench) = swig_created.unwrap();

    // Get the wallet address
    let (swig_wallet_address_pubkey, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    // Fund the swig account with extra lamports beyond rent
    let extra_lamports = 5_000_000u64;
    let mut swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    swig_account.lamports += extra_lamports;
    context.svm.set_account(swig_pubkey, swig_account).unwrap();

    // Record initial balances
    let initial_swig_balance = context.svm.get_account(&swig_pubkey).unwrap().lamports;
    let initial_wallet_balance = context
        .svm
        .get_account(&swig_wallet_address_pubkey)
        .unwrap()
        .lamports;

    println!("Initial swig balance: {}", initial_swig_balance);
    println!("Initial wallet balance: {}", initial_wallet_balance);

    // Create and send transfer assets instruction
    let transfer_ix = create_transfer_assets_instruction(
        swig_pubkey,
        swig_wallet_address_pubkey,
        authority.pubkey(),
        context.default_payer.pubkey(),
        0, // role_id
    );

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                transfer_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &authority]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(result.is_ok(), "Transaction failed: {:?}", result.err());

    // Verify the transfer happened
    let final_swig_balance = context.svm.get_account(&swig_pubkey).unwrap().lamports;
    let final_wallet_balance = context
        .svm
        .get_account(&swig_wallet_address_pubkey)
        .unwrap()
        .lamports;

    println!("Final swig balance: {}", final_swig_balance);
    println!("Final wallet balance: {}", final_wallet_balance);

    // The swig account should have lost the extra lamports
    assert!(
        final_swig_balance < initial_swig_balance,
        "Swig balance should have decreased"
    );

    // The wallet address should have gained lamports
    assert!(
        final_wallet_balance > initial_wallet_balance,
        "Wallet balance should have increased"
    );

    // The difference should match the extra lamports we added
    let transferred_amount = initial_swig_balance - final_swig_balance;
    let received_amount = final_wallet_balance - initial_wallet_balance;
    assert_eq!(
        transferred_amount, received_amount,
        "Transfer and receive amounts should match"
    );
}

#[test_log::test]
fn test_transfer_assets_unauthorized() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let unauthorized_authority = Keypair::new(); // Not in the swig account
    let id = rand::random::<[u8; 32]>();

    // Create a migrated swig account with the authorized authority
    println!("Creating migrated Swig account...");
    let swig_created = create_swig_ed25519(&mut context, &authority, id);
    assert!(
        swig_created.is_ok(),
        "Failed to create swig: {:?}",
        swig_created.err()
    );
    let (swig_pubkey, _bench) = swig_created.unwrap();

    // Get the wallet address
    let (swig_wallet_address_pubkey, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    // Fund the swig account with extra lamports
    let extra_lamports = 5_000_000u64;
    let mut swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    swig_account.lamports += extra_lamports;
    context.svm.set_account(swig_pubkey, swig_account).unwrap();

    // Try to transfer assets with unauthorized authority - this should fail
    let transfer_ix = TransferAssetsV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address_pubkey,
        context.default_payer.pubkey(),
        unauthorized_authority.pubkey(), // Using unauthorized authority
        0,
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                transfer_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx =
        VersionedTransaction::try_new(message, &[&context.default_payer, &unauthorized_authority])
            .unwrap();

    let result = context.svm.send_transaction(tx);
    // This should fail due to unauthorized access
    assert!(
        result.is_err(),
        "Transaction should have failed due to unauthorized access"
    );
}

#[test_log::test]
fn test_transfer_assets_unmigrated_account() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    // Create an unmigrated swig account (v1, no wallet address)
    println!("Creating unmigrated Swig account...");
    let swig_created = create_swig_ed25519(&mut context, &authority, id);
    assert!(
        swig_created.is_ok(),
        "Failed to create swig: {:?}",
        swig_created.err()
    );
    let (swig_pubkey, _bench) = swig_created.unwrap();

    // Manually set wallet_bump to 0 to simulate unmigrated account
    let mut swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    // The wallet_bump is at offset 65 in the Swig struct (after discriminator + id
    // + role_counter + roles)
    swig_account.data[65] = 0; // Set wallet_bump to 0
    context.svm.set_account(swig_pubkey, swig_account).unwrap();

    // Get the would-be wallet address (but it doesn't exist for unmigrated
    // accounts)
    let (swig_wallet_address_pubkey, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    // Create the wallet address account manually (empty system account)
    let wallet_account = solana_sdk::account::Account {
        lamports: 0,
        data: vec![],
        owner: solana_sdk::system_program::ID,
        executable: false,
        rent_epoch: u64::MAX,
    };
    context
        .svm
        .set_account(swig_wallet_address_pubkey, wallet_account)
        .unwrap();

    // Fund the swig account with extra lamports
    let extra_lamports = 5_000_000u64;
    let mut swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    swig_account.lamports += extra_lamports;
    context.svm.set_account(swig_pubkey, swig_account).unwrap();

    // Try to transfer assets from unmigrated account - this should fail
    let transfer_ix = create_transfer_assets_instruction(
        swig_pubkey,
        swig_wallet_address_pubkey,
        authority.pubkey(),
        context.default_payer.pubkey(),
        0,
    );

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                transfer_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &authority]).unwrap();

    let result = context.svm.send_transaction(tx);
    // This should fail because the account is not migrated (wallet_bump = 0)
    assert!(
        result.is_err(),
        "Transaction should have failed for unmigrated account"
    );
}

#[test_log::test]
fn test_transfer_assets_no_excess_lamports() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    // Create a migrated swig account
    println!("Creating migrated Swig account...");
    let swig_created = create_swig_ed25519(&mut context, &authority, id);
    assert!(
        swig_created.is_ok(),
        "Failed to create swig: {:?}",
        swig_created.err()
    );
    let (swig_pubkey, _bench) = swig_created.unwrap();

    // Get the wallet address
    let (swig_wallet_address_pubkey, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    // Don't add any extra lamports - account should only have minimum rent

    // Record initial balances
    let initial_swig_balance = context.svm.get_account(&swig_pubkey).unwrap().lamports;
    let initial_wallet_balance = context
        .svm
        .get_account(&swig_wallet_address_pubkey)
        .unwrap()
        .lamports;

    println!(
        "Initial swig balance: {} (should be minimum rent)",
        initial_swig_balance
    );
    println!("Initial wallet balance: {}", initial_wallet_balance);

    // Transfer assets - should succeed but transfer 0 lamports
    let transfer_ix = create_transfer_assets_instruction(
        swig_pubkey,
        swig_wallet_address_pubkey,
        authority.pubkey(),
        context.default_payer.pubkey(),
        0,
    );

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                transfer_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &authority]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Transaction should succeed even with no excess lamports: {:?}",
        result.err()
    );

    // Verify no lamports were transferred (since there were no excess lamports)
    let final_swig_balance = context.svm.get_account(&swig_pubkey).unwrap().lamports;
    let final_wallet_balance = context
        .svm
        .get_account(&swig_wallet_address_pubkey)
        .unwrap()
        .lamports;

    println!("Final swig balance: {}", final_swig_balance);
    println!("Final wallet balance: {}", final_wallet_balance);

    assert_eq!(
        final_swig_balance, initial_swig_balance,
        "Swig balance should not change"
    );
    assert_eq!(
        final_wallet_balance, initial_wallet_balance,
        "Wallet balance should not change"
    );
}
