#![cfg(not(feature = "program_scope_test"))]
//! Tests for CloseTokenAccountV1 instruction.
//!
//! These tests verify closing empty token accounts owned by the swig wallet.

mod common;

use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use common::*;
use litesvm_token::spl_token;
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    message::{v0, VersionedMessage},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{AuthorityConfig, ClientAction, CloseTokenAccountV1Instruction};
use swig_state::{
    action::{manage_authority::ManageAuthority, sol_limit::SolLimit},
    authority::{secp256k1::Secp256k1Authority, secp256r1::Secp256r1Authority, AuthorityType},
    swig::{swig_wallet_address_seeds, SwigWithRoles},
};

/// Happy path: Close an empty token account with Ed25519 authority
#[test_log::test]
fn test_close_token_account_ed25519() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    // Create swig wallet
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    // Get the swig wallet address
    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    // Create a token mint and ATA owned by swig_wallet_address (V2 style)
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_token_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    // Note: Token account is created with 0 balance, so it's already empty

    // Record initial balances
    let destination = Keypair::new();
    context.svm.airdrop(&destination.pubkey(), 0).unwrap();

    let token_account_rent = context.svm.get_account(&swig_token_ata).unwrap().lamports;

    // Close the token account
    let close_ix = CloseTokenAccountV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        authority.pubkey(),
        swig_token_ata,
        destination.pubkey(),
        spl_token::ID,
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

    // Verify the token account is closed (either doesn't exist or has 0 lamports)
    let token_account = context.svm.get_account(&swig_token_ata);
    let is_closed = token_account.is_none() || token_account.as_ref().unwrap().lamports == 0;
    assert!(is_closed, "Token account should be closed (no lamports)");

    // Verify destination received the rent
    let destination_balance = context
        .svm
        .get_account(&destination.pubkey())
        .map(|a| a.lamports)
        .unwrap_or(0);
    assert_eq!(
        destination_balance, token_account_rent,
        "Destination should have received the token account rent"
    );
}

/// Test closing token account owned by swig (V1 style - fallback path)
#[test_log::test]
fn test_close_token_account_v1_style_authority() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    // Create swig wallet
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    // Get the swig wallet address
    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    // Convert to V1 style (sets reserved_lamports to indicate V1)
    convert_swig_to_v1(&mut context, &swig_pubkey);

    // Create a token ATA owned by swig (V1 style)
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_token_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_pubkey, // V1: token owned by swig, not swig_wallet_address
        &context.default_payer,
    )
    .unwrap();

    let destination = Keypair::new();
    context.svm.airdrop(&destination.pubkey(), 0).unwrap();

    let token_account_rent = context.svm.get_account(&swig_token_ata).unwrap().lamports;

    // Close the token account
    let close_ix = CloseTokenAccountV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        authority.pubkey(),
        swig_token_ata,
        destination.pubkey(),
        spl_token::ID,
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
        result.is_ok(),
        "Transaction failed for V1 style token: {:?}",
        result.err()
    );

    // Verify the token account is closed (either doesn't exist or has 0 lamports)
    let token_account = context.svm.get_account(&swig_token_ata);
    let is_closed = token_account.is_none() || token_account.as_ref().unwrap().lamports == 0;
    assert!(is_closed, "Token account should be closed");

    // Verify destination received the rent
    let destination_balance = context
        .svm
        .get_account(&destination.pubkey())
        .map(|a| a.lamports)
        .unwrap_or(0);
    assert_eq!(destination_balance, token_account_rent);
}

/// Error: Trying to close token account with non-zero balance should fail
#[test_log::test]
fn test_close_token_account_non_zero_balance_fails() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    // Create swig wallet
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    // Create a token ATA and mint tokens to it
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_token_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    // Mint tokens to the account (non-zero balance)
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_token_ata,
        1000,
    )
    .unwrap();

    // Verify tokens were minted
    let token_data = context.svm.get_account(&swig_token_ata).unwrap().data;
    let token_account = spl_token::state::Account::unpack(&token_data).unwrap();
    assert_eq!(token_account.amount, 1000);

    let destination = Keypair::new();
    context.svm.airdrop(&destination.pubkey(), 0).unwrap();

    // Try to close the token account - should fail
    let close_ix = CloseTokenAccountV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        authority.pubkey(),
        swig_token_ata,
        destination.pubkey(),
        spl_token::ID,
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
        "Transaction should fail when token account has non-zero balance"
    );
}

/// Error: Trying to close token account with wrong authority (not owned by swig)
#[test_log::test]
fn test_close_token_account_wrong_authority_fails() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let other_owner = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    // Create swig wallet
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    // Create a token ATA owned by a different user (not the swig)
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let other_token_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &other_owner.pubkey(), // Different owner
        &context.default_payer,
    )
    .unwrap();

    let destination = Keypair::new();
    context.svm.airdrop(&destination.pubkey(), 0).unwrap();

    // Try to close a token account not owned by the swig - should fail
    let close_ix = CloseTokenAccountV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        authority.pubkey(),
        other_token_ata,
        destination.pubkey(),
        spl_token::ID,
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
        "Transaction should fail when token account is not owned by swig"
    );
}

/// Error: Trying to close token account without proper permissions
#[test_log::test]
fn test_close_token_account_permission_denied() {
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

    // Add a second authority with only SolLimit permission (not All or ManageAuthority)
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

    // Create a token ATA
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_token_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    let destination = Keypair::new();

    // Try to close token account with limited authority - should fail
    let close_ix = CloseTokenAccountV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        limited_authority.pubkey(),
        swig_token_ata,
        destination.pubkey(),
        spl_token::ID,
        1, // role_id for limited authority
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

/// Test closing token account with ManageAuthority permission (not All)
#[test_log::test]
fn test_close_token_account_with_manage_authority() {
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

    // Add a second authority with ManageAuthority permission
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

    // Create a token ATA
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_token_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    let destination = Keypair::new();
    context.svm.airdrop(&destination.pubkey(), 0).unwrap();
    let token_account_rent = context.svm.get_account(&swig_token_ata).unwrap().lamports;

    // Close token account with ManageAuthority - should succeed
    let close_ix = CloseTokenAccountV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        manage_authority.pubkey(),
        swig_token_ata,
        destination.pubkey(),
        spl_token::ID,
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
        "Transaction should succeed with ManageAuthority permission: {:?}",
        result.err()
    );

    // Verify token account is closed (either doesn't exist or has 0 lamports)
    let token_account = context.svm.get_account(&swig_token_ata);
    let is_closed = token_account.is_none() || token_account.as_ref().unwrap().lamports == 0;
    assert!(is_closed, "Token account should be closed");

    // Verify destination received rent
    let destination_balance = context
        .svm
        .get_account(&destination.pubkey())
        .map(|a| a.lamports)
        .unwrap_or(0);
    assert_eq!(destination_balance, token_account_rent);
}

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

/// Happy path: Close an empty token account with Secp256k1 authority
#[test_log::test]
fn test_close_token_account_secp256k1() {
    let mut context = setup_test_context().unwrap();
    let wallet = LocalSigner::random();
    let id = rand::random::<[u8; 32]>();

    // Create swig wallet with secp256k1 authority
    let (swig_pubkey, _) = create_swig_secp256k1(&mut context, &wallet, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    // Create a token mint and ATA owned by swig_wallet_address
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_token_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    let destination = Keypair::new();
    context.svm.airdrop(&destination.pubkey(), 0).unwrap();
    let token_account_rent = context.svm.get_account(&swig_token_ata).unwrap().lamports;

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

    // Close the token account
    let close_ix = CloseTokenAccountV1Instruction::new_with_secp256k1_authority(
        swig_pubkey,
        swig_wallet_address,
        signing_fn,
        0, // current_slot
        next_counter,
        swig_token_ata,
        destination.pubkey(),
        spl_token::ID,
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

    // Verify the token account is closed
    let token_account = context.svm.get_account(&swig_token_ata);
    let is_closed = token_account.is_none() || token_account.as_ref().unwrap().lamports == 0;
    assert!(is_closed, "Token account should be closed");

    // Verify destination received the rent
    let destination_balance = context
        .svm
        .get_account(&destination.pubkey())
        .map(|a| a.lamports)
        .unwrap_or(0);
    assert_eq!(destination_balance, token_account_rent);
}

/// Helper to generate a real secp256r1 key pair for testing
fn create_test_secp256r1_keypair() -> (openssl::ec::EcKey<openssl::pkey::Private>, [u8; 33]) {
    use openssl::{
        bn::BigNumContext,
        ec::{EcGroup, EcKey, PointConversionForm},
        nid::Nid,
    };

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let signing_key = EcKey::generate(&group).unwrap();

    let mut ctx = BigNumContext::new().unwrap();
    let pubkey_bytes = signing_key
        .public_key()
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap();

    let pubkey_array: [u8; 33] = pubkey_bytes.try_into().unwrap();
    (signing_key, pubkey_array)
}

/// Helper function to get the current signature counter for a secp256r1 authority
fn get_secp256r1_counter(
    context: &SwigTestContext,
    swig_key: &Pubkey,
    public_key: &[u8; 33],
) -> Result<u32, String> {
    let swig_account = context
        .svm
        .get_account(swig_key)
        .ok_or("Swig account not found")?;
    let swig = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| format!("Failed to parse swig data: {:?}", e))?;

    let role_id = swig
        .lookup_role_id(public_key)
        .map_err(|e| format!("Failed to lookup role: {:?}", e))?
        .ok_or("Authority not found in swig account")?;

    let role = swig
        .get_role(role_id)
        .map_err(|e| format!("Failed to get role: {:?}", e))?
        .ok_or("Role not found")?;

    if matches!(role.authority.authority_type(), AuthorityType::Secp256r1) {
        let secp_authority = role
            .authority
            .as_any()
            .downcast_ref::<Secp256r1Authority>()
            .ok_or("Failed to downcast to Secp256r1Authority")?;
        Ok(secp_authority.signature_odometer)
    } else {
        Err("Authority is not a Secp256r1Authority".to_string())
    }
}

/// Happy path: Close an empty token account with Secp256r1 authority
#[test_log::test]
fn test_close_token_account_secp256r1() {
    let mut context = setup_test_context().unwrap();

    // Create a real secp256r1 key pair for testing
    let (signing_key, public_key) = create_test_secp256r1_keypair();

    let id = rand::random::<[u8; 32]>();

    // Create swig wallet with secp256r1 authority
    let (swig_pubkey, _) = create_swig_secp256r1(&mut context, &public_key, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    // Create a token mint and ATA owned by swig_wallet_address
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_token_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    let destination = Keypair::new();
    context.svm.airdrop(&destination.pubkey(), 0).unwrap();
    let token_account_rent = context.svm.get_account(&swig_token_ata).unwrap().lamports;

    // Get the current counter
    let current_counter = get_secp256r1_counter(&context, &swig_pubkey, &public_key).unwrap();
    let next_counter = current_counter + 1;

    // Create authority function that signs the message hash
    let authority_fn = |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap()
    };

    // Close the token account
    let close_ixs = CloseTokenAccountV1Instruction::new_with_secp256r1_authority(
        swig_pubkey,
        swig_wallet_address,
        authority_fn,
        0, // current_slot
        next_counter,
        swig_token_ata,
        destination.pubkey(),
        spl_token::ID,
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
                close_ixs[1].clone(), // close token account instruction
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

    // Verify the token account is closed
    let token_account = context.svm.get_account(&swig_token_ata);
    let is_closed = token_account.is_none() || token_account.as_ref().unwrap().lamports == 0;
    assert!(is_closed, "Token account should be closed");

    // Verify destination received the rent
    let destination_balance = context
        .svm
        .get_account(&destination.pubkey())
        .map(|a| a.lamports)
        .unwrap_or(0);
    assert_eq!(destination_balance, token_account_rent);
}
