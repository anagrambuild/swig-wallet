mod common;
use borsh::BorshDeserialize;
use common::*;
use solana_sdk::{
    message::{v0, VersionedMessage},
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{AuthorityConfig, ReplaceAuthorityInstruction};
use swig_state::{Action, AuthorityType, Swig};

#[test_log::test]
fn test_replace_authority_basic() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let new_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&new_authority.pubkey(), 10_000_000_000)
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

    // Replace the second authority with a new one
    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Acting role ID (using the first authority)
        1, // Authority to replace (the second one)
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        vec![Action::ManageAuthority], // Same permissions
        0,
        0,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
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

    // Verify that we still have two authorities, but the second one is now the new
    // authority
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = Swig::try_from_slice(&swig_account.data).unwrap();
    assert_eq!(swig.roles.len(), 2);
    assert!(swig.lookup_role(swig_authority.pubkey().as_ref()).is_some());
    assert!(swig.lookup_role(new_authority.pubkey().as_ref()).is_some());
    assert!(swig
        .lookup_role(second_authority.pubkey().as_ref())
        .is_none());
}

#[test_log::test]
fn test_replace_authority_permissions() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let second_authority = Keypair::new();
    let third_authority = Keypair::new();
    let new_authority = Keypair::new();

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
    context
        .svm
        .airdrop(&new_authority.pubkey(), 10_000_000_000)
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

    // Try to replace an authority using the second authority (should fail due to
    // lack of permissions)
    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1, // Acting role ID (second authority)
        2, // Replace the third authority
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        vec![Action::ManageAuthority],
        0,
        0,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
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
        "Authority without management permission should not be able to replace other authorities"
    );

    // Now try with the third authority which has management permissions
    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        third_authority.pubkey(),
        2, // Acting role ID (third authority)
        1, // Replace the second authority
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        vec![Action::Sol {
            action: swig_state::SolAction::All,
        }],
        0,
        0,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
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

    // Verify that we still have three authorities, but the second one is now the
    // new authority
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = Swig::try_from_slice(&swig_account.data).unwrap();
    assert_eq!(swig.roles.len(), 3);
    assert!(swig.lookup_role(root_authority.pubkey().as_ref()).is_some());
    assert!(swig
        .lookup_role(third_authority.pubkey().as_ref())
        .is_some());
    assert!(swig.lookup_role(new_authority.pubkey().as_ref()).is_some());
    assert!(swig
        .lookup_role(second_authority.pubkey().as_ref())
        .is_none());
}

#[test_log::test]
fn test_replace_nonexistent_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let new_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&new_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 13]>();

    // Create a swig wallet with the first authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, &id).unwrap();

    // Try to replace a non-existent authority (index out of bounds)
    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0,  // Acting role ID
        99, // Non-existent authority to replace
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        vec![Action::ManageAuthority],
        0,
        0,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
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
        "Replacing a non-existent authority should fail"
    );
}

#[test_log::test]
fn test_replace_authority_self() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let new_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&new_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 13]>();

    // Create a swig wallet with the first authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, &id).unwrap();

    // Replace self with a new authority
    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Acting role ID
        0, // Replace self
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        vec![Action::All], // Keep all permissions
        0,
        0,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
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

    // Verify that the authority has been replaced
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = Swig::try_from_slice(&swig_account.data).unwrap();
    assert_eq!(swig.roles.len(), 1);
    assert!(swig.lookup_role(new_authority.pubkey().as_ref()).is_some());
    assert!(swig.lookup_role(swig_authority.pubkey().as_ref()).is_none());
}

#[test_log::test]
fn test_replace_authority_privilege_escalation() {
    let mut context = setup_test_context().unwrap();
    let root_authority = Keypair::new();
    let limited_authority = Keypair::new();
    let new_authority = Keypair::new();

    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&limited_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&new_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 13]>();

    // Create a swig wallet with the root authority (has Action::All)
    let (swig_key, _) = create_swig_ed25519(&mut context, &root_authority, &id).unwrap();

    // Expire the blockhash before the next transaction
    context.svm.expire_blockhash();

    // Add a limited authority with only ManageAuthority permission
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: limited_authority.pubkey().as_ref(),
        },
        vec![Action::ManageAuthority],
        0,
        0,
    )
    .unwrap();

    // Expire the blockhash before the next transaction
    context.svm.expire_blockhash();

    // Try to replace the root authority (which has Action::All) with a new
    // authority that doesn't have Action::All - this should fail as a limited
    // authority cannot downgrade a higher privileged authority
    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        limited_authority.pubkey(),
        1, // Acting role ID (limited authority)
        0, // Replace the root authority
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        vec![Action::ManageAuthority], // Downgraded permissions
        0,
        0,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &limited_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "Limited authority should not be able to downgrade a higher privileged authority"
    );

    // Expire the blockhash before the next transaction
    context.svm.expire_blockhash();

    // Now try with the root authority replacing the limited authority - this should
    // work
    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        0, // Acting role ID (root authority)
        1, // Replace the limited authority
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        vec![Action::Sol {
            action: swig_state::SolAction::All,
        }], // Different permissions
        0,
        0,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
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

    // Verify that the limited authority has been replaced
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = Swig::try_from_slice(&swig_account.data).unwrap();
    assert_eq!(swig.roles.len(), 2);
    assert!(swig.lookup_role(root_authority.pubkey().as_ref()).is_some());
    assert!(swig.lookup_role(new_authority.pubkey().as_ref()).is_some());
    assert!(swig
        .lookup_role(limited_authority.pubkey().as_ref())
        .is_none());
}

#[test_log::test]
fn test_replace_authority_duplicate_check() {
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

    // Expire the blockhash before the next transaction
    context.svm.expire_blockhash();

    // Add a second authority
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

    // Expire the blockhash before the next transaction
    context.svm.expire_blockhash();

    // Add a third authority
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

    // Expire the blockhash before the next transaction
    context.svm.expire_blockhash();

    // Try to replace the second authority with the third authority's data
    // This should fail because the third authority already exists
    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        root_authority.pubkey(),
        0, // Acting role ID (root authority)
        1, // Replace the second authority
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: third_authority.pubkey().as_ref(), // Already exists
        },
        vec![Action::ManageAuthority],
        0,
        0,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
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
        "Should not be able to replace with an authority that already exists"
    );
}

#[test_log::test]
fn test_replace_authority_self_management_permissions() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let new_authority = Keypair::new();
    let backup_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&new_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&backup_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 13]>();

    // Create a swig wallet with the first authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, &id).unwrap();

    // Try to replace self with a new authority that doesn't have management
    // permissions This should fail because it would leave the wallet without
    // any authority that can manage authorities
    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Acting role ID
        0, // Replace self
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        vec![Action::Sol {
            action: swig_state::SolAction::All,
        }], // No management permissions
        0,
        0,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
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
        "Should not be able to replace self with an authority that doesn't have management \
         permissions"
    );

    // Expire the blockhash before the next transaction
    context.svm.expire_blockhash();

    // Add a backup authority with management permissions
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: backup_authority.pubkey().as_ref(),
        },
        vec![Action::ManageAuthority],
        0,
        0,
    )
    .unwrap();

    // Expire the blockhash before the next transaction
    context.svm.expire_blockhash();

    // Now try again - this should work because there's another authority with
    // management permissions
    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Acting role ID
        0, // Replace self
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        vec![Action::Sol {
            action: swig_state::SolAction::All,
        }], // No management permissions
        0,
        0,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
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

    // Verify that the authority has been replaced
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = Swig::try_from_slice(&swig_account.data).unwrap();
    assert_eq!(swig.roles.len(), 2);
    assert!(swig
        .lookup_role(backup_authority.pubkey().as_ref())
        .is_some());
    assert!(swig.lookup_role(new_authority.pubkey().as_ref()).is_some());
    assert!(swig.lookup_role(swig_authority.pubkey().as_ref()).is_none());
}

#[test_log::test]
fn test_replace_authority_different_type() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let new_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&new_authority.pubkey(), 10_000_000_000)
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

    // Replace the second authority with a new one of a different type
    // For this test, we'll use a dummy Secp256k1 authority
    let secp_pubkey = [0u8; 20]; // Dummy Secp256k1 pubkey

    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Acting role ID
        1, // Replace second authority
        AuthorityConfig {
            authority_type: AuthorityType::Secp256k1,
            authority: &secp_pubkey,
        },
        vec![Action::ManageAuthority],
        0,
        0,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
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

    // Verify that the authority has been replaced with the new type
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = Swig::try_from_slice(&swig_account.data).unwrap();
    assert_eq!(swig.roles.len(), 2);

    // Find the role with Secp256k1 type
    let secp_role = swig
        .roles
        .iter()
        .find(|r| r.authority_type == AuthorityType::Secp256k1);
    assert!(secp_role.is_some(), "Secp256k1 authority should exist");

    // Verify the authority data matches
    let secp_role = secp_role.unwrap();
    assert_eq!(secp_role.authority_data, secp_pubkey);
}

#[test_log::test]
fn test_replace_authority_size_change() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 13]>();

    // Create a swig wallet with the first authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, &id).unwrap();

    // Add a second authority with a small set of actions
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
        vec![Action::ManageAuthority], // Small set of actions
        0,
        0,
    )
    .unwrap();

    // Get the initial account size
    let initial_account = context.svm.get_account(&swig_key).unwrap();
    let initial_size = initial_account.data.len();

    // Replace the second authority with one that has many more actions (increasing
    // size)
    let new_authority = Keypair::new();
    context
        .svm
        .airdrop(&new_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create a larger set of actions
    let many_actions = vec![
        Action::ManageAuthority,
        Action::Sol {
            action: swig_state::SolAction::All,
        },
    ];

    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Acting role ID
        1, // Replace second authority
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        many_actions,
        0,
        0,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
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

    // Verify that the account size has increased
    let new_account = context.svm.get_account(&swig_key).unwrap();
    let new_size = new_account.data.len();

    assert!(
        new_size > initial_size,
        "Account size should increase when replacing with a larger authority"
    );

    // Now replace with a smaller authority again
    let another_authority = Keypair::new();
    context
        .svm
        .airdrop(&another_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Acting role ID
        1, // Replace the new authority (now at index 1)
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: another_authority.pubkey().as_ref(),
        },
        vec![Action::ManageAuthority], // Small set of actions again
        0,
        0,
    )
    .unwrap();

    context.svm.expire_blockhash();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
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

    // Verify that the account size has decreased
    let final_account = context.svm.get_account(&swig_key).unwrap();
    let final_size = final_account.data.len();

    assert!(
        final_size < new_size,
        "Account size should decrease when replacing with a smaller authority"
    );
}

#[test_log::test]
fn test_replace_authority_invalid_acting_role() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let new_authority = Keypair::new();
    let non_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&new_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&non_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 13]>();

    // Create a swig wallet with the first authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, &id).unwrap();

    // Try to replace with a non-existent acting role ID
    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        non_authority.pubkey(), // Not an authority
        99,                     // Invalid acting role ID
        0,                      // Replace the first authority
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        vec![Action::All],
        0,
        0,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &non_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "Should not be able to replace with an invalid acting role ID"
    );
}

#[test_log::test]
fn test_replace_authority_slot_validation() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let new_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&new_authority.pubkey(), 10_000_000_000)
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

    // Try to replace with invalid slot range (start >= end)
    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Acting role ID
        1, // Replace second authority
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        vec![Action::ManageAuthority],
        100, // Start slot
        100, // End slot (equal to start)
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
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
        "Should not be able to replace with invalid slot range"
    );

    // Now try with valid slot range
    let replace_ix = ReplaceAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Acting role ID
        1, // Replace second authority
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        vec![Action::ManageAuthority],
        100, // Start slot
        200, // End slot (greater than start)
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[replace_ix],
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

    // Verify that the authority has been replaced with the correct slot range
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = Swig::try_from_slice(&swig_account.data).unwrap();

    let new_role = swig.lookup_role(new_authority.pubkey().as_ref()).unwrap();
    assert_eq!(new_role.role.start_slot, 100);
    assert_eq!(new_role.role.end_slot, 200);
}
