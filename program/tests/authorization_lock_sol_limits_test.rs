#![cfg(not(feature = "program_scope_test"))]

mod common;
use common::*;
use pinocchio_pubkey::pubkey;
use solana_sdk::{
    clock::Clock,
    message::{v0, VersionedMessage},
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{AddAuthorizationLockInstruction, AuthorityConfig, ClientAction};
use swig_state_x::{
    action::{manage_authorization_locks::ManageAuthorizationLocks, sol_limit::SolLimit},
    swig::{AuthorizationLock, SwigWithRoles},
    IntoBytes, Transmutable,
};

/// Test that validates authorization locks respect simple SOL limits.
///
/// This test creates a role with a SOL limit of 1000 lamports, then:
/// 1. Successfully adds an authorization lock for 800 lamports (within limit)
/// 2. Fails to add another authorization lock for 300 lamports (would exceed
///    limit: 800 + 300 = 1100 > 1000)
#[test_log::test]
fn test_authorization_lock_respects_simple_sol_limit() {
    let mut context = setup_test_context().unwrap();

    // Setup accounts
    let swig_authority = Keypair::new();

    // Airdrop to participants
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create swig account with root authority (All permissions)
    let swig_id = [1u8; 32];
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &swig_authority, swig_id).unwrap();

    // Add a SOL authority with SOL limit permission (1000 lamports)
    let sol_limit_amount = 1000u64;
    let sol_authority = Keypair::new();
    context
        .svm
        .airdrop(&sol_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let sol_authority_actions = vec![
        ClientAction::SolLimit(SolLimit {
            amount: sol_limit_amount,
        }),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
    ];

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &swig_authority,
        AuthorityConfig {
            authority_type: swig_state_x::authority::AuthorityType::Ed25519,
            authority: sol_authority.pubkey().as_ref(),
        },
        sol_authority_actions,
    )
    .unwrap();

    // Get role ID for the SOL authority
    let swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let sol_role_id = swig_with_roles
        .lookup_role_id(sol_authority.pubkey().as_ref())
        .unwrap()
        .unwrap();

    // Wrapped SOL mint address (So11111111111111111111111111111111111111112)
    let wrapped_sol_mint = pubkey!("So11111111111111111111111111111111111111112");

    // Test 1: Successfully add authorization lock for 800 lamports (within limit)
    let auth_lock_amount_1 = 800u64;
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let expiry_slot = current_slot + 1000;

    let add_auth_lock_ix_1 = AddAuthorizationLockInstruction::new(
        swig_pubkey,
        sol_authority.pubkey(),
        context.default_payer.pubkey(),
        sol_role_id,
        wrapped_sol_mint,
        auth_lock_amount_1,
        expiry_slot,
    )
    .unwrap();

    let msg_1 = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_auth_lock_ix_1],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx_1 = VersionedTransaction::try_new(
        VersionedMessage::V0(msg_1),
        &[
            context.default_payer.insecure_clone(),
            sol_authority.insecure_clone(),
        ],
    )
    .unwrap();

    let result_1 = context.svm.send_transaction(tx_1);
    assert!(
        result_1.is_ok(),
        "First authorization lock (800 lamports) should succeed: {:?}",
        result_1
    );

    // Test 2: Fail to add authorization lock for 300 lamports (would exceed limit:
    // 800 + 300 = 1100 > 1000)
    let auth_lock_amount_2 = 300u64;

    let add_auth_lock_ix_2 = AddAuthorizationLockInstruction::new(
        swig_pubkey,
        sol_authority.pubkey(),
        context.default_payer.pubkey(),
        sol_role_id,
        wrapped_sol_mint,
        auth_lock_amount_2,
        expiry_slot,
    )
    .unwrap();

    let msg_2 = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_auth_lock_ix_2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx_2 = VersionedTransaction::try_new(
        VersionedMessage::V0(msg_2),
        &[
            context.default_payer.insecure_clone(),
            sol_authority.insecure_clone(),
        ],
    )
    .unwrap();

    let result_2 = context.svm.send_transaction(tx_2);
    assert!(
        result_2.is_err(),
        "Second authorization lock (300 lamports) should fail due to exceeding limit"
    );

    // Verify final state: should have exactly 1 authorization lock for 800 lamports
    let final_swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    let final_swig_with_roles = SwigWithRoles::from_bytes(&final_swig_account.data).unwrap();

    let (auth_locks, count) = final_swig_with_roles
        .get_authorization_locks_by_role::<10>(sol_role_id)
        .unwrap();

    assert_eq!(count, 1, "Should have exactly 1 authorization lock");

    let total_locked: u64 = auth_locks
        .iter()
        .filter_map(|opt_lock| *opt_lock)
        .filter(|lock| lock.token_mint == wrapped_sol_mint)
        .map(|lock| lock.amount)
        .sum();

    assert_eq!(total_locked, 800, "Total locked amount should be 800");
}
