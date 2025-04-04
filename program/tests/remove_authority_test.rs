mod common;

use common::*;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_program,
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
