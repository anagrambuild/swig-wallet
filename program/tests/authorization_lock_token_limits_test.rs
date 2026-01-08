#![cfg(not(feature = "program_scope_test"))]

mod common;
use common::*;
use litesvm_token::spl_token;
use solana_sdk::{
    clock::Clock,
    message::{v0, VersionedMessage},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{AuthorityConfig, ClientAction};
use swig_state::{
    action::{manage_authorization_locks::ManageAuthorizationLocks, token_limit::TokenLimit},
    swig::{swig_account_seeds, AuthorizationLock, Swig, SwigWithRoles},
    IntoBytes, Transmutable,
};

/// Test that validates authorization locks respect simple token limits.
///
/// This test creates a role with a TokenLimit of 1000 tokens, then:
/// 1. Successfully adds an authorization lock for 800 tokens (within limit)
/// 2. Fails to add another authorization lock for 300 tokens (would exceed
///    limit: 800 + 300 = 1100 > 1000)
#[test_log::test]
fn test_authorization_lock_respects_simple_token_limit() {
    let mut context = setup_test_context().unwrap();

    // Setup accounts
    let swig_authority = Keypair::new();
    let token_authority = Keypair::new();

    // Airdrop to participants
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&token_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Setup token mint
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    // Create swig account with root authority (All permissions)
    let swig_id = [1u8; 32];
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &swig_authority, swig_id).unwrap();

    // Add a token authority with TokenLimit permission (1000 tokens)
    let token_limit_amount = 1000u64;
    let token_authority_actions = vec![
        ClientAction::TokenLimit(TokenLimit {
            token_mint: mint_pubkey.to_bytes(),
            current_amount: token_limit_amount,
        }),
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
    ];

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &swig_authority,
        AuthorityConfig {
            authority_type: swig_state::authority::AuthorityType::Ed25519,
            authority: token_authority.pubkey().as_ref(),
        },
        token_authority_actions,
    )
    .unwrap();

    // Get role ID for the token authority
    let swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let token_role_id = swig_with_roles
        .lookup_role_id(token_authority.pubkey().as_ref())
        .unwrap()
        .unwrap();

    // Test 1: Successfully add authorization lock for 800 tokens (within limit)
    let auth_lock_amount_1 = 800u64;
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let expiry_slot = current_slot + 1000;

    let add_auth_lock_ix_1 = swig_interface::AddAuthorizationLockInstruction::new(
        swig_pubkey,
        token_authority.pubkey(),
        context.default_payer.pubkey(),
        token_role_id,
        mint_pubkey.to_bytes(),
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
            token_authority.insecure_clone(),
        ],
    )
    .unwrap();

    let result_1 = context.svm.send_transaction(tx_1);
    assert!(
        result_1.is_ok(),
        "First authorization lock (800 tokens) should succeed: {:?}",
        result_1
    );

    // Test 2: Fail to add authorization lock for 300 tokens (would exceed limit:
    // 800 + 300 = 1100 > 1000)
    let auth_lock_amount_2 = 300u64;

    let add_auth_lock_ix_2 = swig_interface::AddAuthorizationLockInstruction::new(
        swig_pubkey,
        token_authority.pubkey(),
        context.default_payer.pubkey(),
        token_role_id,
        mint_pubkey.to_bytes(),
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
            token_authority.insecure_clone(),
        ],
    )
    .unwrap();

    let result_2 = context.svm.send_transaction(tx_2);
    assert!(
        result_2.is_err(),
        "Second authorization lock (300 tokens) should fail due to exceeding limit"
    );

    // Verify final state: should have exactly 1 authorization lock for 800 tokens
    let final_swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    let final_swig_with_roles = SwigWithRoles::from_bytes(&final_swig_account.data).unwrap();

    let (auth_locks, count) = final_swig_with_roles
        .get_authorization_locks_by_role::<10>(token_role_id)
        .unwrap();

    assert_eq!(count, 1, "Should have exactly 1 authorization lock");

    let total_locked: u64 = auth_locks
        .iter()
        .filter_map(|opt_lock| *opt_lock)
        .filter(|lock| lock.token_mint == mint_pubkey.to_bytes())
        .map(|lock| lock.amount)
        .sum();

    assert_eq!(total_locked, 800, "Total locked amount should be 800");
}
