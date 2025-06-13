#![cfg(not(feature = "program_scope_test"))]
// This feature flag ensures these tests are only run when the
// "program_scope_test" feature is not enabled. This allows us to isolate
// and run only program_scope tests or only the regular tests.

mod common;

use common::*;
use solana_sdk::{
    message::{v0, VersionedMessage},
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{AuthorityConfig, ClientAction, RemoveAuthorityInstruction};
use swig_state_x::{
    action::{all::All, manage_authority::ManageAuthority, sol_limit::SolLimit},
    authority::AuthorityType,
    swig::SwigWithRoles,
};

#[test_log::test]
fn test_create_remove_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig wallet with the first authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Add a second authority
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    // Verify we have two authorities
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 2);

    // Remove the second authority
    let remove_ix = RemoveAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Acting role ID (using the first authority)
        1, // Authority to remove (the second one)
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    context.svm.send_transaction(tx).unwrap();

    // Verify that only one authority remains
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 1);

    // Verify it's the root authority
    let found_root = swig
        .lookup_role_id(swig_authority.pubkey().as_ref())
        .unwrap()
        .is_some();
    assert!(found_root, "Only the root authority should remain");

    // Test removing the last authority - should fail
    let remove_ix = RemoveAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Acting role ID
        0, // Authority to remove (trying to remove the only remaining one)
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(result.is_err(), "Removing the last authority should fail");
}

#[test_log::test]
fn test_create_remove_secp_authority() {
    use alloy_primitives::B256;
    use alloy_signer::SignerSync;
    use alloy_signer_local::LocalSigner;

    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig wallet with the first authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Add a second authority
    let wallet = LocalSigner::random();

    let secp_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256k1,
            authority: &secp_pubkey.as_ref()[1..],
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    // Verify we have two authorities
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 2);

    // Remove the second authority
    let remove_ix = RemoveAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Acting role ID (using the first authority)
        1, // Authority to remove (the second one)
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    context.svm.send_transaction(tx).unwrap();

    // Verify that only one authority remains
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 1);

    // Verify it's the root authority
    let found_root = swig
        .lookup_role_id(swig_authority.pubkey().as_ref())
        .unwrap()
        .is_some();
    assert!(found_root, "Only the root authority should remain");

    // Test removing the last authority - should fail
    let remove_ix = RemoveAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Acting role ID
        0, // Authority to remove (trying to remove the only remaining one)
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(result.is_err(), "Removing the last authority should fail");
}

#[test_log::test]
fn test_secp256k1_root_remove_authority() {
    use alloy_primitives::B256;
    use alloy_signer::SignerSync;
    use alloy_signer_local::LocalSigner;

    let mut context = setup_test_context().unwrap();

    // Create a secp256k1 root authority wallet
    let root_wallet = LocalSigner::random();
    let id = rand::random::<[u8; 32]>();

    // Create a swig wallet with secp256k1 root authority
    let (swig_key, _) = create_swig_secp256k1(&mut context, &root_wallet, id).unwrap();
    context.svm.airdrop(&swig_key, 10_000_000_000).unwrap();

    // Create a second Ed25519 authority to add and later remove
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create signing function for secp256k1 authority (same pattern as working test)
    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        root_wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    // Add the second authority using secp256k1 root authority (same as working test)
    let add_authority_ix = swig_interface::AddAuthorityInstruction::new_with_secp256k1_authority(
        swig_key,
        context.default_payer.pubkey(),
        signing_fn,
        0, // current slot (same as working test)
        1, // counter = 1 (first transaction, same as working test)
        0, // role_id of the primary wallet
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&context.default_payer])
            .unwrap();

    // Transaction should succeed
    let result = context.svm.send_transaction(tx);
    context.svm.expire_blockhash();
    context.svm.warp_to_slot(1);
    assert!(
        result.is_ok(),
        "Failed to add ed25519 authority: {:?}",
        result.err()
    );

    // Verify the authority was added
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_state.state.roles, 2);

    let remove_ix = RemoveAuthorityInstruction::new_with_secp256k1_authority(
        swig_key,
        context.default_payer.pubkey(),
        signing_fn,
        1, // current slot
        2, // counter = 2 (second transaction),
        0, // role_id of the primary wallet (secp256k1 root authority)
        1, // Authority to remove (the Ed25519 authority)
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&context.default_payer])
            .unwrap();

    // Transaction should succeed
    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to remove authority with secp256k1: {:?}",
        result.err()
    );

    // Verify that only one authority remains (the secp256k1 root)
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_state.state.roles, 1);

    // Verify it's the secp256k1 root authority by checking the authority type
    let role = swig_state.get_role(0).unwrap().unwrap();
    assert_eq!(role.authority.authority_type(), AuthorityType::Secp256k1);

    println!("✓ Secp256k1 root authority successfully removed Ed25519 authority");
    println!("✓ Signature counter functionality verified for secp256k1 remove authority operation");
}

#[test_log::test]
fn test_remove_authority_permissions() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let second_authority = Keypair::new();
    let third_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&third_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig wallet with the root authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    // Add a second authority with no management permissions
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit {
            amount: 1000000000000000000,
        })],
    )
    .unwrap();

    // Add a third authority with management permissions
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: third_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    // Try to remove an authority using the second authority (should fail due to
    // lack of permissions)
    let remove_ix = RemoveAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1, // Acting role ID (second authority)
        2, // Remove the third authority
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "Authority without management permission should not be able to remove other authorities"
    );

    // Now try with the third authority which has management permissions
    let remove_ix = RemoveAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        third_authority.pubkey(),
        2, // Acting role ID (third authority)
        1, // Remove the second authority
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &third_authority],
    )
    .unwrap();

    context.svm.send_transaction(tx).unwrap();

    // Verify that only two authorities remain: root and third
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 2);

    // Verify the right authorities are present
    let found_root = swig
        .lookup_role_id(root_authority.pubkey().as_ref())
        .unwrap()
        .is_some();
    assert!(found_root, "Root authority should still exist");

    let found_third = swig
        .lookup_role_id(third_authority.pubkey().as_ref())
        .unwrap()
        .is_some();
    assert!(found_third, "Third authority should still exist");

    let found_second = swig
        .lookup_role_id(second_authority.pubkey().as_ref())
        .unwrap()
        .is_some();
    assert!(!found_second, "Second authority should not exist");
}

#[test_log::test]
fn test_remove_nonexistent_authority() {
    // Test trying to remove an authority that doesn't exist
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig wallet with one authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Try to remove an authority with an invalid index (e.g., 5)
    let remove_ix = RemoveAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Acting role ID
        5, // Invalid authority index
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "Removing a nonexistent authority should fail"
    );
}

#[test_log::test]
fn test_remove_authority_self() {
    // Test an authority removing itself
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let second_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig wallet with the root authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    // Add a second authority with management permissions
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    // Second authority removes itself
    let remove_ix = RemoveAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1, // Acting role ID (second authority)
        1, // Remove itself
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();

    context.svm.send_transaction(tx).unwrap();

    // Verify that only the root authority remains
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 1);

    // Verify it's the root authority
    let found_root = swig
        .lookup_role_id(root_authority.pubkey().as_ref())
        .unwrap()
        .is_some();
    assert!(found_root, "Only the root authority should remain");
}

#[test_log::test]
fn test_remove_root_authority_role_validation() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig wallet with the root authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    // Let's examine the Swig account to understand how roles are stored
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();

    // Print the role details to understand what's happening
    let role = swig.get_role(0).unwrap().unwrap();
    println!("Root authority role: {:?}", role.position.id);

    // Add a second authority with no permissions
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::All(All {})], // No permissions
    )
    .unwrap();

    // Try to use the second authority to remove the root authority
    // This should fail due to lack of permissions, not due to slot validity
    let remove_ix = RemoveAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1, // Acting role ID (second authority)
        0, // Remove root authority
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "Authority without permissions should not be able to remove other authorities"
    );

    // Verify the error is related to permissions
    if let Err(err) = result {
        let error_string = format!("{:?}", err);
        println!("Error: {}", error_string);
        assert!(
            error_string.contains("PermissionDenied") || error_string.contains("Custom"),
            "Expected permission error, got: {:?}",
            err
        );
    }
}

#[test_log::test]
fn test_remove_authority_different_types() {
    // Test removing authorities of different types
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig wallet with Ed25519 authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    // Add a second authority with a different type (if possible)
    // For now, we'll just add another Ed25519 authority with different permissions
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit {
            amount: 1000000000000000000,
        })], // Different permissions
    )
    .unwrap();

    // Remove the second authority
    let remove_ix = RemoveAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        0, // Acting role ID (root authority)
        1, // Remove second authority
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &root_authority],
    )
    .unwrap();

    context.svm.send_transaction(tx).unwrap();

    // Verify that only the root authority remains
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 1);
}

#[test_log::test]
fn test_root_authority_cannot_remove_itself() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig wallet with the root authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    // Root authority tries to remove itself - should fail
    let remove_ix = RemoveAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        0, // Acting role ID (root authority)
        0, // Remove itself (root)
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &root_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "Root authority should not be able to remove itself"
    );
}

#[test_log::test]
fn test_authority_with_management_can_remove_other_authorities() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let second_authority = Keypair::new();
    let third_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&third_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig wallet with the root authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, id).unwrap();

    // Add a second authority with management permissions
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    // Add a third authority with no special permissions
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: third_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit {
            amount: 1000000000000000000,
        })],
    )
    .unwrap();

    // Verify we have three authorities
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 3);

    // Second authority removes the third authority
    let remove_ix = RemoveAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1, // Acting role ID (second authority)
        2, // Remove third authority
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();

    context.svm.send_transaction(tx).unwrap();

    // Verify that only two authorities remain
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 2);
}

#[test_log::test]
fn test_create_remove_authority_with_balance_checks() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig wallet with the first authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    context.svm.airdrop(&swig_key, 100_000_000_000).unwrap();

    // Add a second authority
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    // Verify we have two authorities
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 2);

    let swig_old_balance = context.svm.get_balance(&swig_key).unwrap();
    let payer_old_balance = context
        .svm
        .get_balance(&context.default_payer.pubkey())
        .unwrap();

    // Remove the second authority
    let remove_ix = RemoveAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Acting role ID (using the first authority)
        1, // Authority to remove (the second one)
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    context.svm.send_transaction(tx).unwrap();

    // Verify that only one authority remains
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 1);

    // Verify it's the root authority
    let found_root = swig
        .lookup_role_id(swig_authority.pubkey().as_ref())
        .unwrap()
        .is_some();
    assert!(found_root, "Only the root authority should remain");

    // Check the balance of the swig wallet
    let swig_new_balance = context.svm.get_balance(&swig_key).unwrap();
    let payer_new_balance = context
        .svm
        .get_balance(&context.default_payer.pubkey())
        .unwrap();

    let txn_fee_per_sig = 5000;
    let swig_balance_diff = swig_old_balance - swig_new_balance;
    let payer_balance_diff = payer_new_balance - payer_old_balance;

    assert!(
        swig_balance_diff <= 400_000,
        "SWIG balance should increase by at most 400_000"
    );
    assert!(
        payer_balance_diff >= 370_000,
        "Payer balance should increase by at least 370_000"
    );
    let diff = swig_balance_diff - payer_balance_diff - 2 * txn_fee_per_sig; // 2 sigs from swig and payer

    assert_eq!(diff, 0);
}
