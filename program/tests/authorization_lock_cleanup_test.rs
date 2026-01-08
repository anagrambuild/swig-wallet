#![cfg(not(feature = "program_scope_test"))]

mod common;
use common::*;
use solana_sdk::{
    clock::Clock,
    message::{v0, VersionedMessage},
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction,
    transaction::VersionedTransaction,
};
use swig_interface::{AuthorityConfig, ClientAction};
use swig_state::{
    action::{manage_authorization_locks::ManageAuthorizationLocks, program::Program},
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
    Transmutable,
};

/// Test that expired authorization locks can be cleaned up by authorities with All permission
/// after the cleanup threshold period has passed
#[test_log::test]
fn test_expired_authorization_lock_cleanup_by_all_permission() {
    let mut context = setup_test_context().unwrap();

    // Setup accounts
    let swig_authority = Keypair::new(); // Root with All permission
    let limited_authority = Keypair::new(); // Will create the lock
    let cleanup_authority = Keypair::new(); // Different authority with All permission

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 20_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&limited_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&cleanup_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create swig account
    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    println!("=== EXPIRED AUTHORIZATION LOCK CLEANUP TEST ===");
    create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    println!("✅ Swig account created (root has All permission)");

    // Add limited authority with ManageAuthorizationLocks permission
    println!("Adding limited authority (role 1) with ManageAuthorizationLocks permission");
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: limited_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    )
    .unwrap();
    println!("✅ Limited authority added (role ID: 1)");

    // Add cleanup authority with All permission
    println!("Adding cleanup authority (role 2) with All permission");
    use swig_state::action::all::All;
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: cleanup_authority.pubkey().as_ref(),
        },
        vec![ClientAction::All(All {})],
    )
    .unwrap();
    println!("✅ Cleanup authority added (role ID: 2)");

    // Add authorization lock that will expire soon
    let sol_mint = [0u8; 32];
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let lock_amount = 1 * LAMPORTS_PER_SOL;
    let expiry_slot = current_slot + 100; // Expires soon

    println!(
        "\nAdding authorization lock that will expire at slot {}",
        expiry_slot
    );

    let add_lock_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        limited_authority.pubkey(),
        context.default_payer.pubkey(),
        1, // Acting as role 1
        sol_mint,
        lock_amount,
        expiry_slot,
    )
    .unwrap();

    let add_lock_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &context.default_payer.pubkey(),
                &[add_lock_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&context.default_payer, &limited_authority],
    )
    .unwrap();

    context.svm.send_transaction(add_lock_tx).unwrap();
    println!("✅ Authorization lock added by role 1");

    // Verify lock was added
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_with_roles.state.authorization_locks, 1);
    println!("✅ Verified: 1 authorization lock exists");

    // TEST 1: Try to remove immediately by different role - should FAIL
    println!("\nTEST 1: Try to remove lock immediately by different role (cleanup authority)");
    println!("Expected: FAIL (lock not expired beyond threshold yet)");

    let remove_lock_ix = swig_interface::RemoveAuthorizationLockInstruction::new(
        swig,
        cleanup_authority.pubkey(),
        context.default_payer.pubkey(),
        2, // Acting as role 2 (cleanup authority)
        0, // Lock index 0
    )
    .unwrap();

    let remove_lock_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &context.default_payer.pubkey(),
                &[remove_lock_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&context.default_payer, &cleanup_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(remove_lock_tx);
    assert!(
        result.is_err(),
        "Should not be able to remove lock created by different role before threshold"
    );
    println!("✅ TEST 1 PASSED: Cannot remove before threshold");

    // TEST 2: Warp time past expiry + cleanup threshold
    let cleanup_threshold_slots = 5 * 432_000; // 5 epochs
    let target_slot = expiry_slot + cleanup_threshold_slots + 1000;
    println!(
        "\nTEST 2: Warp time to slot {} (past cleanup threshold)",
        target_slot
    );
    context.svm.warp_to_slot(target_slot);
    context.svm.expire_blockhash();

    let new_slot = context.svm.get_sysvar::<Clock>().slot;
    println!("  Current slot: {}", new_slot);
    println!("  Lock expiry slot: {}", expiry_slot);
    println!(
        "  Cleanup threshold: {} slots after expiry",
        cleanup_threshold_slots
    );
    println!("  Lock is now expired beyond cleanup threshold");

    // TEST 3: Try to remove by cleanup authority - should SUCCEED
    println!(
        "\nTEST 3: Remove expired lock by cleanup authority (different role, has All permission)"
    );
    println!("Expected: SUCCESS (expired beyond threshold, has All permission)");

    let remove_lock_ix2 = swig_interface::RemoveAuthorizationLockInstruction::new(
        swig,
        cleanup_authority.pubkey(),
        context.default_payer.pubkey(),
        2, // Acting as role 2
        0, // Lock index 0
    )
    .unwrap();

    let remove_lock_tx2 = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &context.default_payer.pubkey(),
                &[remove_lock_ix2],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&context.default_payer, &cleanup_authority],
    )
    .unwrap();

    let result2 = context.svm.send_transaction(remove_lock_tx2);
    assert!(
        result2.is_ok(),
        "Should be able to remove expired lock with All permission after threshold: {:?}",
        result2.err()
    );
    println!("✅ TEST 3 PASSED: Expired lock successfully removed by cleanup authority");

    // Verify lock was removed
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_with_roles.state.authorization_locks, 0);
    println!("✅ Verified: Authorization lock count is now 0");

    println!("\n✅ ALL TESTS PASSED!");
    println!("✅ Expired authorization locks can be cleaned up after threshold period");
    println!("======================================================");
}

/// Test that expired authorization locks cannot be cleaned up by authorities
/// without All or ManageAuthority permission, even after the cleanup threshold
#[test_log::test]
fn test_expired_authorization_lock_cleanup_requires_cleanup_permission() {
    let mut context = setup_test_context().unwrap();

    let swig_authority = Keypair::new();
    let limited_authority = Keypair::new();
    let other_limited_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 20_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&limited_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&other_limited_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    println!("=== CLEANUP PERMISSION TEST ===");
    create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Add first limited authority with ManageAuthorizationLocks
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: limited_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    )
    .unwrap();

    // Add second limited authority with only ManageAuthorizationLocks (not All)
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: other_limited_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    )
    .unwrap();

    println!(
        "✅ Two limited authorities created (both with ManageAuthorizationLocks, neither has All)"
    );

    // Add lock by first authority
    let sol_mint = [0u8; 32];
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let expiry_slot = current_slot + 100;

    let add_lock_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        limited_authority.pubkey(),
        context.default_payer.pubkey(),
        1,
        sol_mint,
        1 * LAMPORTS_PER_SOL,
        expiry_slot,
    )
    .unwrap();

    let add_lock_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &context.default_payer.pubkey(),
                &[add_lock_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&context.default_payer, &limited_authority],
    )
    .unwrap();

    context.svm.send_transaction(add_lock_tx).unwrap();
    println!("✅ Authorization lock added by role 1");

    // Warp past threshold
    let cleanup_threshold_slots = 5 * 432_000;
    let target_slot = expiry_slot + cleanup_threshold_slots + 1000;
    context.svm.warp_to_slot(target_slot);
    context.svm.expire_blockhash();
    println!("✅ Warped past cleanup threshold");

    // Try to remove by second authority (has ManageAuthorizationLocks but not All)
    println!("\nAttempting removal by role 2 (has ManageAuthorizationLocks but not All)");
    println!("Expected: FAIL (requires All permission for cleanup)");

    let remove_lock_ix = swig_interface::RemoveAuthorizationLockInstruction::new(
        swig,
        other_limited_authority.pubkey(),
        context.default_payer.pubkey(),
        2,
        0,
    )
    .unwrap();

    let remove_lock_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &context.default_payer.pubkey(),
                &[remove_lock_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&context.default_payer, &other_limited_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(remove_lock_tx);
    assert!(
        result.is_err(),
        "Should not be able to cleanup without All permission"
    );
    println!("✅ Correctly rejected: Cleanup requires All permission");

    println!("\n✅ TEST PASSED!");
    println!("✅ Cleanup of expired locks requires All or ManageAuthority permission");
    println!("======================================================");
}

/// Test that expired authorization locks can be cleaned up by authorities with ManageAuthority permission
#[test_log::test]
fn test_expired_authorization_lock_cleanup_by_manage_authority() {
    let mut context = setup_test_context().unwrap();

    let swig_authority = Keypair::new();
    let limited_authority = Keypair::new();
    let cleanup_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 20_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&limited_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&cleanup_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    println!("=== CLEANUP BY MANAGE_AUTHORITY TEST ===");
    create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Add authority that will create the lock
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: limited_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks {},
        )],
    )
    .unwrap();

    // Add cleanup authority with ManageAuthority + ManageAuthorizationLocks permissions
    // It needs ManageAuthorizationLocks to call the remove instruction, and ManageAuthority
    // to cleanup locks created by other roles
    use swig_state::action::manage_authority::ManageAuthority;
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: cleanup_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ManageAuthority(ManageAuthority {}),
            ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {}),
        ],
    )
    .unwrap();
    println!("✅ Authorities created: role 1 (lock creator), role 2 (has ManageAuthority + ManageAuthorizationLocks)");

    // Add lock
    let sol_mint = [0u8; 32];
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let expiry_slot = current_slot + 100;

    let add_lock_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        limited_authority.pubkey(),
        context.default_payer.pubkey(),
        1,
        sol_mint,
        1 * LAMPORTS_PER_SOL,
        expiry_slot,
    )
    .unwrap();

    let add_lock_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &context.default_payer.pubkey(),
                &[add_lock_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&context.default_payer, &limited_authority],
    )
    .unwrap();

    context.svm.send_transaction(add_lock_tx).unwrap();
    println!("✅ Authorization lock added by role 1");

    // Warp past threshold
    let cleanup_threshold_slots = 5 * 432_000;
    let target_slot = expiry_slot + cleanup_threshold_slots + 1000;
    context.svm.warp_to_slot(target_slot);
    context.svm.expire_blockhash();
    println!("✅ Warped past cleanup threshold");

    // Remove by cleanup authority with ManageAuthority - should SUCCEED
    println!("\nAttempting removal by role 2 (has ManageAuthority permission)");
    println!("Expected: SUCCESS (expired beyond threshold, has ManageAuthority)");

    let remove_lock_ix = swig_interface::RemoveAuthorizationLockInstruction::new(
        swig,
        cleanup_authority.pubkey(),
        context.default_payer.pubkey(),
        2,
        0,
    )
    .unwrap();

    let remove_lock_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &context.default_payer.pubkey(),
                &[remove_lock_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&context.default_payer, &cleanup_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(remove_lock_tx);
    assert!(
        result.is_ok(),
        "Should be able to cleanup with ManageAuthority permission: {:?}",
        result.err()
    );
    println!("✅ Expired lock successfully removed by authority with ManageAuthority");

    // Verify
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_with_roles.state.authorization_locks, 0);
    println!("✅ Verified: Authorization lock count is now 0");

    println!("\n✅ TEST PASSED!");
    println!("✅ ManageAuthority permission can cleanup expired locks");
    println!("======================================================");
}
