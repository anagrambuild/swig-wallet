#![cfg(not(feature = "program_scope_test"))]

mod common;
use common::*;
use solana_sdk::{
    clock::Clock,
    message::{v0, VersionedMessage},
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{
    AddAuthorizationLockInstruction, AuthorityConfig, ClientAction,
    RemoveAuthorizationLockInstruction,
};
use swig_state::{
    action::{manage_authorization_locks::ManageAuthorizationLocks, token_limit::TokenLimit},
    swig::SwigWithRoles,
    IntoBytes, Transmutable,
};

/// Test that validates only the role that created an authorization lock can
/// remove it.
///
/// This test:
/// 1. Creates two roles with ManageAuthorizationLocks permission
/// 2. Role A creates an authorization lock
/// 3. Role B tries to remove Role A's lock and fails
/// 4. Role A successfully removes its own lock
#[test_log::test]
fn test_remove_authorization_lock_role_ownership() {
    let mut context = setup_test_context().unwrap();

    // Setup accounts
    let root_authority = Keypair::new();
    let role_a_authority = Keypair::new();
    let role_b_authority = Keypair::new();

    // Airdrop to participants
    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&role_a_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&role_b_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Setup token mint
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    // Create swig account with root authority
    let swig_id = [1u8; 32];
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root_authority, swig_id).unwrap();

    // Add Role A with token limit and manage authorization locks permission
    let role_a_actions = vec![
        ClientAction::TokenLimit(TokenLimit {
            token_mint: mint_pubkey.to_bytes(),
            current_amount: 1000u64,
        }),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
    ];

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root_authority,
        AuthorityConfig {
            authority_type: swig_state::authority::AuthorityType::Ed25519,
            authority: role_a_authority.pubkey().as_ref(),
        },
        role_a_actions,
    )
    .unwrap();

    // Add Role B with token limit and manage authorization locks permission
    let role_b_actions = vec![
        ClientAction::TokenLimit(TokenLimit {
            token_mint: mint_pubkey.to_bytes(),
            current_amount: 1000u64,
        }),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
    ];

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root_authority,
        AuthorityConfig {
            authority_type: swig_state::authority::AuthorityType::Ed25519,
            authority: role_b_authority.pubkey().as_ref(),
        },
        role_b_actions,
    )
    .unwrap();

    // Get role IDs
    let swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();

    let role_a_id = swig_with_roles
        .lookup_role_id(role_a_authority.pubkey().as_ref())
        .unwrap()
        .unwrap();

    let role_b_id = swig_with_roles
        .lookup_role_id(role_b_authority.pubkey().as_ref())
        .unwrap()
        .unwrap();

    // Role A creates an authorization lock
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let expiry_slot = current_slot + 1000;
    let auth_lock_amount = 500u64;

    let add_auth_lock_ix = AddAuthorizationLockInstruction::new(
        swig_pubkey,
        role_a_authority.pubkey(),
        context.default_payer.pubkey(),
        role_a_id,
        mint_pubkey.to_bytes(),
        auth_lock_amount,
        expiry_slot,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_auth_lock_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[
            context.default_payer.insecure_clone(),
            role_a_authority.insecure_clone(),
        ],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Role A should successfully create authorization lock: {:?}",
        result
    );

    // Verify the lock was created
    let swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let (auth_locks, count) = swig_with_roles
        .get_authorization_locks_by_role::<10>(role_a_id)
        .unwrap();
    assert_eq!(
        count, 1,
        "Should have exactly 1 authorization lock for Role A"
    );

    // Role B tries to remove Role A's authorization lock (should fail)
    let remove_auth_lock_ix_b = RemoveAuthorizationLockInstruction::new(
        swig_pubkey,
        role_b_authority.pubkey(),
        context.default_payer.pubkey(),
        role_b_id,
        0, // First (and only) lock index
    )
    .unwrap();

    let msg_b = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_auth_lock_ix_b],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx_b = VersionedTransaction::try_new(
        VersionedMessage::V0(msg_b),
        &[
            context.default_payer.insecure_clone(),
            role_b_authority.insecure_clone(),
        ],
    )
    .unwrap();

    let result_b = context.svm.send_transaction(tx_b);
    assert!(
        result_b.is_err(),
        "Role B should NOT be able to remove Role A's authorization lock"
    );

    // Verify the lock is still there
    let swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let (auth_locks, count) = swig_with_roles
        .get_authorization_locks_by_role::<10>(role_a_id)
        .unwrap();
    assert_eq!(
        count, 1,
        "Authorization lock should still exist after failed removal"
    );

    // Role A removes its own authorization lock (should succeed)
    let remove_auth_lock_ix_a = RemoveAuthorizationLockInstruction::new(
        swig_pubkey,
        role_a_authority.pubkey(),
        context.default_payer.pubkey(),
        role_a_id,
        0, // First (and only) lock index
    )
    .unwrap();

    let msg_a = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_auth_lock_ix_a],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx_a = VersionedTransaction::try_new(
        VersionedMessage::V0(msg_a),
        &[
            context.default_payer.insecure_clone(),
            role_a_authority.insecure_clone(),
        ],
    )
    .unwrap();

    let result_a = context.svm.send_transaction(tx_a);
    assert!(
        result_a.is_ok(),
        "Role A should successfully remove its own authorization lock: {:?}",
        result_a
    );

    // Verify the lock was removed
    let final_swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    let final_swig_with_roles = SwigWithRoles::from_bytes(&final_swig_account.data).unwrap();
    let (final_locks, final_count) = final_swig_with_roles
        .get_authorization_locks_by_role::<10>(role_a_id)
        .unwrap();
    assert_eq!(final_count, 0, "Authorization lock should be removed");
}

/// Test that validates a role with All permissions can only remove
/// authorization locks they created.
///
/// This test:
/// 1. Creates a role A with limited permissions that creates an authorization
///    lock
/// 2. Creates a role B with All permissions
/// 3. Role B fails to remove Role A's lock (can only remove own locks)
#[test_log::test]
fn test_remove_authorization_lock_all_permission_override() {
    let mut context = setup_test_context().unwrap();

    // Setup accounts
    let root_authority = Keypair::new();
    let role_a_authority = Keypair::new();
    let role_b_authority = Keypair::new();

    // Airdrop to participants
    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&role_a_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&role_b_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Setup token mint
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    // Create swig account with root authority
    let swig_id = [1u8; 32];
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &root_authority, swig_id).unwrap();

    // Add Role A with limited permissions
    let role_a_actions = vec![
        ClientAction::TokenLimit(TokenLimit {
            token_mint: mint_pubkey.to_bytes(),
            current_amount: 1000u64,
        }),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
    ];

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root_authority,
        AuthorityConfig {
            authority_type: swig_state::authority::AuthorityType::Ed25519,
            authority: role_a_authority.pubkey().as_ref(),
        },
        role_a_actions,
    )
    .unwrap();

    // Add Role B with All permissions
    let role_b_actions = vec![ClientAction::All(swig_state::action::all::All {})];

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &root_authority,
        AuthorityConfig {
            authority_type: swig_state::authority::AuthorityType::Ed25519,
            authority: role_b_authority.pubkey().as_ref(),
        },
        role_b_actions,
    )
    .unwrap();

    // Get role IDs
    let swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();

    let role_a_id = swig_with_roles
        .lookup_role_id(role_a_authority.pubkey().as_ref())
        .unwrap()
        .unwrap();

    let role_b_id = swig_with_roles
        .lookup_role_id(role_b_authority.pubkey().as_ref())
        .unwrap()
        .unwrap();

    // Role A creates an authorization lock
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let expiry_slot = current_slot + 1000;
    let auth_lock_amount = 500u64;

    let add_auth_lock_ix = AddAuthorizationLockInstruction::new(
        swig_pubkey,
        role_a_authority.pubkey(),
        context.default_payer.pubkey(),
        role_a_id,
        mint_pubkey.to_bytes(),
        auth_lock_amount,
        expiry_slot,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_auth_lock_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[
            context.default_payer.insecure_clone(),
            role_a_authority.insecure_clone(),
        ],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Role A should successfully create authorization lock: {:?}",
        result
    );

    // Role B (with All permissions) tries to remove Role A's authorization lock
    // (should fail)
    let remove_auth_lock_ix_b = RemoveAuthorizationLockInstruction::new(
        swig_pubkey,
        role_b_authority.pubkey(),
        context.default_payer.pubkey(),
        role_b_id,
        0, // First (and only) lock index
    )
    .unwrap();

    let msg_b = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_auth_lock_ix_b],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx_b = VersionedTransaction::try_new(
        VersionedMessage::V0(msg_b),
        &[
            context.default_payer.insecure_clone(),
            role_b_authority.insecure_clone(),
        ],
    )
    .unwrap();

    let result_b = context.svm.send_transaction(tx_b);
    assert!(
        result_b.is_err(),
        "Role B with All permissions should NOT be able to remove Role A's authorization lock"
    );

    // Verify the lock was NOT removed
    let final_swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    let final_swig_with_roles = SwigWithRoles::from_bytes(&final_swig_account.data).unwrap();
    let (final_locks, final_count) = final_swig_with_roles
        .get_authorization_locks_by_role::<10>(role_a_id)
        .unwrap();
    assert_eq!(
        final_count, 1,
        "Authorization lock should still exist after failed removal attempt"
    );
}
