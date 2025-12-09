#![cfg(not(feature = "program_scope_test"))]
//! Tests for CloseSwigV1 instruction.
//!
//! These tests verify closing the swig wallet and recovering all SOL.

mod common;

use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use common::*;
use litesvm_token::spl_token;

use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{
    AuthorityConfig, ClientAction, CloseSwigV1Instruction, CloseTokenAccountV1Instruction,
};
use swig_state::{
    action::{manage_authority::ManageAuthority, sol_limit::SolLimit},
    authority::{secp256k1::Secp256k1Authority, AuthorityType},
    swig::{swig_wallet_address_seeds, SwigWithRoles},
};

/// Happy path: Close swig wallet and recover all SOL (rent only)
#[test_log::test]
fn test_close_swig_ed25519() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    // Create swig wallet
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    // Record initial balances (should be rent-exempt only)
    let swig_lamports = context.svm.get_account(&swig_pubkey).unwrap().lamports;
    let wallet_lamports = context
        .svm
        .get_account(&swig_wallet_address)
        .map(|a| a.lamports)
        .unwrap_or(0);
    let total_lamports = swig_lamports + wallet_lamports;

    let destination = Keypair::new();
    context.svm.airdrop(&destination.pubkey(), 0).unwrap();

    // Close the swig wallet
    let close_ix = CloseSwigV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        authority.pubkey(),
        destination.pubkey(),
        0, // role_id
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &authority]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(result.is_ok(), "Transaction failed: {:?}", result.err());

    // Verify swig account is closed (data should be zeroed and no lamports)
    let swig_account = context.svm.get_account(&swig_pubkey);
    assert!(
        swig_account.is_none() || swig_account.as_ref().unwrap().lamports == 0,
        "Swig account should be closed"
    );

    // Verify destination received all lamports
    let destination_balance = context
        .svm
        .get_account(&destination.pubkey())
        .map(|a| a.lamports)
        .unwrap_or(0);
    assert_eq!(
        destination_balance, total_lamports,
        "Destination should have received all lamports"
    );
}

/// Test closing swig with ManageAuthority permission
#[test_log::test]
fn test_close_swig_with_manage_authority() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let manage_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    // Create swig wallet
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    // Add authority with ManageAuthority permission
    context
        .svm
        .airdrop(&manage_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: manage_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    let swig_lamports = context.svm.get_account(&swig_pubkey).unwrap().lamports;
    let wallet_lamports = context
        .svm
        .get_account(&swig_wallet_address)
        .map(|a| a.lamports)
        .unwrap_or(0);
    let total_lamports = swig_lamports + wallet_lamports;

    let destination = Keypair::new();

    // Close with ManageAuthority - should succeed
    let close_ix = CloseSwigV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        manage_authority.pubkey(),
        destination.pubkey(),
        1, // role_id for manage_authority
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &manage_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Transaction should succeed with ManageAuthority: {:?}",
        result.err()
    );

    // Verify destination received lamports
    let destination_balance = context
        .svm
        .get_account(&destination.pubkey())
        .map(|a| a.lamports)
        .unwrap_or(0);
    assert_eq!(destination_balance, total_lamports);
}

/// Error: Trying to close swig without proper permissions
#[test_log::test]
fn test_close_swig_permission_denied() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let limited_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    // Create swig wallet
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    // Add authority with only SolLimit permission
    context
        .svm
        .airdrop(&limited_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: limited_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit {
            amount: 1_000_000_000,
        })],
    )
    .unwrap();

    let destination = Keypair::new();

    // Try to close with limited authority - should fail
    let close_ix = CloseSwigV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        limited_authority.pubkey(),
        destination.pubkey(),
        1, // role_id for limited_authority
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &limited_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "Transaction should fail when authority lacks All or ManageAuthority permission"
    );
}

/// Error: Trying to close with unauthorized signer
#[test_log::test]
fn test_close_swig_unauthorized_signer() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let unauthorized = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    // Create swig wallet
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    // Fund unauthorized account
    context
        .svm
        .airdrop(&unauthorized.pubkey(), 10_000_000_000)
        .unwrap();

    let destination = Keypair::new();

    // Try to close with unauthorized signer - should fail
    let close_ix = CloseSwigV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        unauthorized.pubkey(), // Not a valid authority
        destination.pubkey(),
        0, // role_id 0 belongs to the original authority, not unauthorized
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx =
        VersionedTransaction::try_new(message, &[&context.default_payer, &unauthorized]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "Transaction should fail with unauthorized signer"
    );
}

/// Error: Trying to close swig with excess SOL balance (beyond rent)
#[test_log::test]
fn test_close_swig_with_excess_balance_fails() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    // Create swig wallet
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    // Add extra SOL to swig (beyond rent-exempt minimum)
    context.svm.airdrop(&swig_pubkey, 5_000_000_000).unwrap();

    let destination = Keypair::new();

    // Try to close with excess balance - should fail
    let close_ix = CloseSwigV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        authority.pubkey(),
        destination.pubkey(),
        0,
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &authority]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "Transaction should fail when swig has excess SOL balance"
    );
}

/// Error: Trying to close swig when wallet address has excess SOL balance
#[test_log::test]
fn test_close_swig_with_wallet_address_excess_balance_fails() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    // Create swig wallet
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    // Add extra SOL to swig_wallet_address (beyond rent-exempt minimum)
    context
        .svm
        .airdrop(&swig_wallet_address, 5_000_000_000)
        .unwrap();

    let destination = Keypair::new();

    // Try to close with excess balance in wallet address - should fail
    let close_ix = CloseSwigV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        authority.pubkey(),
        destination.pubkey(),
        0,
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &authority]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "Transaction should fail when wallet address has excess SOL balance"
    );
}

// ============================================================================
// Secp256k1 Tests
// ============================================================================

/// Helper function to get the current signature counter for a secp256k1 authority
fn get_secp256k1_counter(
    context: &SwigTestContext,
    swig_key: &Pubkey,
    wallet: &PrivateKeySigner,
) -> Result<u32, String> {
    let swig_account = context
        .svm
        .get_account(swig_key)
        .ok_or("Swig account not found")?;
    let swig = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| format!("Failed to parse swig data: {:?}", e))?;

    let eth_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();
    let authority_bytes = &eth_pubkey[1..];

    let role_id = swig
        .lookup_role_id(authority_bytes)
        .map_err(|e| format!("Failed to lookup role: {:?}", e))?
        .ok_or("Authority not found in swig account")?;

    let role = swig
        .get_role(role_id)
        .map_err(|e| format!("Failed to get role: {:?}", e))?
        .ok_or("Role not found")?;

    if matches!(role.authority.authority_type(), AuthorityType::Secp256k1) {
        let secp_authority = role
            .authority
            .as_any()
            .downcast_ref::<Secp256k1Authority>()
            .ok_or("Failed to downcast to Secp256k1Authority")?;
        Ok(secp_authority.signature_odometer)
    } else {
        Err("Authority is not a Secp256k1Authority".to_string())
    }
}

/// Happy path: Close swig wallet with Secp256k1 authority
#[test_log::test]
fn test_close_swig_secp256k1() {
    let mut context = setup_test_context().unwrap();
    let wallet = LocalSigner::random();
    let id = rand::random::<[u8; 32]>();

    // Create swig wallet with secp256k1 authority
    let (swig_pubkey, _) = create_swig_secp256k1(&mut context, &wallet, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    // Record initial balances (rent only)
    let swig_lamports = context.svm.get_account(&swig_pubkey).unwrap().lamports;
    let wallet_lamports = context
        .svm
        .get_account(&swig_wallet_address)
        .map(|a| a.lamports)
        .unwrap_or(0);
    let total_lamports = swig_lamports + wallet_lamports;

    let destination = Keypair::new();
    context.svm.airdrop(&destination.pubkey(), 0).unwrap();

    // Get the current counter
    let current_counter = get_secp256k1_counter(&context, &swig_pubkey, &wallet).unwrap();
    let next_counter = current_counter + 1;

    // Create signing function
    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    // Close the swig wallet
    let close_ix = CloseSwigV1Instruction::new_with_secp256k1_authority(
        swig_pubkey,
        swig_wallet_address,
        signing_fn,
        0, // current_slot
        next_counter,
        destination.pubkey(),
        0, // role_id
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Transaction failed with secp256k1: {:?}",
        result.err()
    );

    // Verify swig account is closed
    let swig_account = context.svm.get_account(&swig_pubkey);
    assert!(
        swig_account.is_none() || swig_account.as_ref().unwrap().lamports == 0,
        "Swig account should be closed"
    );

    // Verify destination received all lamports
    let destination_balance = context
        .svm
        .get_account(&destination.pubkey())
        .map(|a| a.lamports)
        .unwrap_or(0);
    assert_eq!(destination_balance, total_lamports);
}

/// Happy path: Close swig wallet with Secp256r1 authority
#[test_log::test]
fn test_close_swig_secp256r1() {
    let mut context = setup_test_context().unwrap();

    // Generate a random secp256r1 key
    let (signing_key, public_key) = create_test_secp256r1_keypair();

    let id = rand::random::<[u8; 32]>();

    // Create swig wallet with secp256r1 authority
    let (swig_pubkey, _) = create_swig_secp256r1(&mut context, &public_key, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    // Record initial balances (rent only)
    let swig_lamports = context.svm.get_account(&swig_pubkey).unwrap().lamports;
    let wallet_lamports = context
        .svm
        .get_account(&swig_wallet_address)
        .map(|a| a.lamports)
        .unwrap_or(0);
    let total_lamports = swig_lamports + wallet_lamports;

    let destination = Keypair::new();
    context.svm.airdrop(&destination.pubkey(), 0).unwrap();

    // Create signing function for secp256r1
    let signing_fn = |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap()
    };

    // Close the swig wallet
    let close_ixs = CloseSwigV1Instruction::new_with_secp256r1_authority(
        swig_pubkey,
        swig_wallet_address,
        signing_fn,
        0, // current_slot
        1, // counter
        destination.pubkey(),
        0, // role_id
        &public_key,
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ixs[0].clone(), // secp256r1 verify instruction
                close_ixs[1].clone(), // close swig instruction
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Transaction failed with secp256r1: {:?}",
        result.err()
    );

    // Verify swig account is closed
    let swig_account = context.svm.get_account(&swig_pubkey);
    assert!(
        swig_account.is_none() || swig_account.as_ref().unwrap().lamports == 0,
        "Swig account should be closed"
    );

    // Verify destination received all lamports
    let destination_balance = context
        .svm
        .get_account(&destination.pubkey())
        .map(|a| a.lamports)
        .unwrap_or(0);
    assert_eq!(destination_balance, total_lamports);
}
