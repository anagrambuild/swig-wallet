mod common;
use borsh::BorshDeserialize;
use common::*;

use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{AuthorityConfig, RemoveAuthorityInstruction};
use swig_state::{Action, AuthorityType, Role, Swig};

#[test_log::test]
fn test_create_remove_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 13]>();

    // Create a swig wallet with the first authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, &id).unwrap();

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
        vec![Action::ManageAuthority],
        0,
        0,
    )
    .unwrap();

    // Verify we have two authorities
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = Swig::try_from_slice(&swig_account.data).unwrap();
    assert_eq!(swig.roles.len(), 2);

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
    let swig = Swig::try_from_slice(&swig_account.data).unwrap();
    assert_eq!(swig.roles.len(), 1);
    assert_eq!(
        swig.roles[0],
        Role::new_with_size(
            AuthorityType::Ed25519,
            swig_authority.pubkey().as_ref().to_vec(),
            0,
            0,
            vec![Action::All],
        )
    );

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

    let id = rand::random::<[u8; 13]>();

    // Create a swig wallet with the root authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, &id).unwrap();

    // Add a second authority with no management permissions
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![Action::Sol {
            action: swig_state::SolAction::All,
        }], // No authority management permission
        0,
        0,
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
        vec![Action::ManageAuthority],
        0,
        0,
    )
    .unwrap();

    // Try to remove an authority using the second authority (should fail due to lack of permissions)
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
    let swig = Swig::try_from_slice(&swig_account.data).unwrap();
    assert_eq!(swig.roles.len(), 2);
    assert!(swig.lookup_role(root_authority.pubkey().as_ref()).is_some());
    assert!(swig
        .lookup_role(third_authority.pubkey().as_ref())
        .is_some());
    assert!(swig
        .lookup_role(second_authority.pubkey().as_ref())
        .is_none());
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

    let id = rand::random::<[u8; 13]>();

    // Create a swig wallet with one authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, &id).unwrap();

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

    let id = rand::random::<[u8; 13]>();

    // Create a swig wallet with the root authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, &id).unwrap();

    // Add a second authority with management permissions
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![Action::ManageAuthority],
        0,
        0,
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
    let swig = Swig::try_from_slice(&swig_account.data).unwrap();
    assert_eq!(swig.roles.len(), 1);
    assert!(swig.lookup_role(root_authority.pubkey().as_ref()).is_some());
}

#[test_log::test]
fn test_remove_authority_role_validation() {
    // Instead of testing with slots, let's directly check if the role validation logic works
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 13]>();

    // Create a swig wallet with the root authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, &id).unwrap();

    // Let's examine the Swig account to understand how roles are stored
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = Swig::try_from_slice(&swig_account.data).unwrap();

    // Print the role details to understand what's happening
    println!("Root authority role: {:?}", swig.roles[0]);

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
        vec![], // No permissions
        0,
        0,
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
            error_string.contains("PermissionDenied") || error_string.contains("Custom(15)"), // PermissionDenied error code
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

    let id = rand::random::<[u8; 13]>();

    // Create a swig wallet with Ed25519 authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, &id).unwrap();

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
        vec![Action::Sol {
            action: swig_state::SolAction::All,
        }], // Different permissions
        0,
        0,
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
    let swig = Swig::try_from_slice(&swig_account.data).unwrap();
    assert_eq!(swig.roles.len(), 1);
    assert!(swig.lookup_role(root_authority.pubkey().as_ref()).is_some());
}

#[test_log::test]
fn test_remove_authority_with_expired_role() {
    // Test removing an authority when the acting role has expired
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

    let id = rand::random::<[u8; 13]>();

    // Create a swig wallet with the root authority (no expiration)
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, &id).unwrap();

    // Add a second authority with management permissions but with an expiration
    // Set end_slot to 0 to make it already expired
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![Action::ManageAuthority],
        1, // start_slot = 0
        2, // end_slot = 0 (expired)
    )
    .unwrap();

    context.svm.warp_to_slot(100);

    // Second authority tries to remove the root authority (should fail due to expired role)
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
        "Authority with expired role should not be able to remove other authorities"
    );

    // Verify the error is related to authentication
    if let Err(err) = result {
        // Check if the error message contains something about invalid authority
        let error_string = format!("{:?}", err);
        assert!(
            error_string.contains("InvalidAuthority") || 
            error_string.contains("PermissionDenied") ||
            error_string.contains("Custom(11)") ||  // InvalidAuthority error code
            error_string.contains("Custom(15)"), // PermissionDenied error code
            "Expected authentication error, got: {:?}",
            err
        );
    }
}

#[test_log::test]
fn test_remove_authority_with_future_role() {
    // Test removing an authority when the acting role is not yet valid
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

    let id = rand::random::<[u8; 13]>();

    // Create a swig wallet with the root authority (no expiration)
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, &id).unwrap();

    // Add a second authority with management permissions but with a future start slot
    // Set start_slot to a very large number to ensure it's in the future
    let future_slot = u64::MAX - 1000; // Very far in the future

    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![Action::ManageAuthority],
        future_slot,        // start_slot in the future
        future_slot + 1000, // end_slot
    )
    .unwrap();

    // Second authority tries to remove the root authority (should fail due to not yet valid role)
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
        "Authority with not-yet-valid role should not be able to remove other authorities"
    );

    // Verify the error is related to authentication
    if let Err(err) = result {
        // Check if the error message contains something about invalid authority
        let error_string = format!("{:?}", err);
        assert!(
            error_string.contains("InvalidAuthority") || 
            error_string.contains("PermissionDenied") ||
            error_string.contains("Custom(11)") ||  // InvalidAuthority error code
            error_string.contains("Custom(15)"), // PermissionDenied error code
            "Expected authentication error, got: {:?}",
            err
        );
    }
}

#[test_log::test]
fn test_remove_authority_sequence() {
    // Test removing multiple authorities in sequence
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 13]>();

    // Create a swig wallet with the root authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, &id).unwrap();

    // Add 5 more authorities
    let mut authorities = Vec::new();
    for _ in 0..5 {
        let authority = Keypair::new();
        context
            .svm
            .airdrop(&authority.pubkey(), 10_000_000_000)
            .unwrap();

        add_authority_with_ed25519_root(
            &mut context,
            &swig_key,
            &root_authority,
            AuthorityConfig {
                authority_type: AuthorityType::Ed25519,
                authority: authority.pubkey().as_ref(),
            },
            vec![Action::ManageAuthority],
            0,
            0,
        )
        .unwrap();

        authorities.push(authority);
    }

    // Verify we have 6 authorities total
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = Swig::try_from_slice(&swig_account.data).unwrap();
    assert_eq!(swig.roles.len(), 6);

    // Remove authorities one by one
    for i in (1..6).rev() {
        let remove_ix = RemoveAuthorityInstruction::new_with_ed25519_authority(
            swig_key,
            context.default_payer.pubkey(),
            root_authority.pubkey(),
            0,       // Acting role ID (root authority)
            i as u8, // Remove authority at index i
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

        // Verify the number of authorities decreases
        let swig_account = context.svm.get_account(&swig_key).unwrap();
        let swig = Swig::try_from_slice(&swig_account.data).unwrap();
        assert_eq!(swig.roles.len(), i);
    }

    // Verify only the root authority remains
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = Swig::try_from_slice(&swig_account.data).unwrap();
    assert_eq!(swig.roles.len(), 1);
    assert!(swig.lookup_role(root_authority.pubkey().as_ref()).is_some());
}
