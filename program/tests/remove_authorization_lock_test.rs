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
use swig_state_x::{
    action::{
        all::All, manage_authorization_locks::ManageAuthorizationLocks, token_limit::TokenLimit,
    },
    swig::{swig_account_seeds, AuthorizationLock, Swig, SwigWithRoles},
    IntoBytes, Transmutable,
};

/// Test that validates only authorities with "All" or
/// "ManageAuthorizationLocks" permissions can remove authorization locks, while
/// others are denied.
#[test_log::test]
fn test_remove_authorization_lock_permission_enforcement() {
    let mut context = setup_test_context().unwrap();

    // Setup accounts
    let swig_authority = Keypair::new(); // Will have All permissions
    let manage_auth_locks_authority = Keypair::new(); // Will have ManageAuthorizationLocks permission
    let token_authority = Keypair::new(); // Will have only token limit permissions (should be denied)

    // Airdrop to participants
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&manage_auth_locks_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&token_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Setup token mint
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    // Create swig account
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let swig_create_result = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_result.is_ok());

    println!("=== REMOVE AUTHORIZATION LOCK PERMISSION ENFORCEMENT TEST ===");
    println!(
        "Testing that only authorities with proper permissions can remove authorization locks"
    );
    println!();

    // Add authority with ManageAuthorizationLocks permission
    let manage_auth_locks_action =
        ClientAction::ManageAuthorizationLocks(ManageAuthorizationLocks {});
    let add_manage_auth_locks_authority_ix =
        swig_interface::AddAuthorityInstruction::new_with_ed25519_authority(
            swig,
            context.default_payer.pubkey(),
            swig_authority.pubkey(),
            0, // Acting role ID (swig_authority has All permissions)
            swig_interface::AuthorityConfig {
                authority_type: swig_state_x::authority::AuthorityType::Ed25519,
                authority: &manage_auth_locks_authority.pubkey().to_bytes(),
            },
            vec![manage_auth_locks_action],
        )
        .unwrap();

    let add_manage_auth_locks_authority_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_manage_auth_locks_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_manage_auth_locks_authority_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_manage_auth_locks_authority_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let add_manage_auth_locks_authority_result = context
        .svm
        .send_transaction(add_manage_auth_locks_authority_tx);
    assert!(
        add_manage_auth_locks_authority_result.is_ok(),
        "Adding ManageAuthorizationLocks authority should succeed"
    );
    println!("✅ Added authority with ManageAuthorizationLocks permission (role ID: 1)");

    // Add authority with limited token permissions (should NOT be able to manage
    // auth locks)
    let token_action = ClientAction::TokenLimit(TokenLimit {
        token_mint: mint_pubkey.to_bytes(),
        current_amount: 1000,
    });

    let add_token_authority_ix =
        swig_interface::AddAuthorityInstruction::new_with_ed25519_authority(
            swig,
            context.default_payer.pubkey(),
            swig_authority.pubkey(),
            0, // Acting role ID (swig_authority has All permissions)
            swig_interface::AuthorityConfig {
                authority_type: swig_state_x::authority::AuthorityType::Ed25519,
                authority: &token_authority.pubkey().to_bytes(),
            },
            vec![token_action],
        )
        .unwrap();

    let add_token_authority_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_token_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_token_authority_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_token_authority_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let add_token_authority_result = context.svm.send_transaction(add_token_authority_tx);
    assert!(
        add_token_authority_result.is_ok(),
        "Adding token authority should succeed"
    );
    println!("✅ Added authority with TokenLimit permission only (role ID: 2)");
    println!();

    // Add multiple authorization locks to test with
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let expiry_slot = current_slot + 1000;

    // Add first lock using manage_auth_locks_authority (role 1)
    let add_lock1_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        manage_auth_locks_authority.pubkey(),
        context.default_payer.pubkey(),
        1, // acting_role_id: manage_auth_locks_authority
        mint_pubkey.to_bytes(),
        500,
        expiry_slot,
    )
    .unwrap();

    // Add second lock using manage_auth_locks_authority (role 1)
    let add_lock2_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        manage_auth_locks_authority.pubkey(),
        context.default_payer.pubkey(),
        1, // acting_role_id: manage_auth_locks_authority
        mint_pubkey.to_bytes(),
        300,
        expiry_slot,
    )
    .unwrap();

    // Add third lock using swig_authority (role 0)
    let add_lock3_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        0, // acting_role_id: swig_authority
        mint_pubkey.to_bytes(),
        200,
        expiry_slot,
    )
    .unwrap();

    // Add all three locks
    for (i, lock_ix) in [add_lock1_ix, add_lock2_ix, add_lock3_ix]
        .iter()
        .enumerate()
    {
        let authority = if i < 2 {
            &manage_auth_locks_authority
        } else {
            &swig_authority
        };

        let message = v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[lock_ix.clone()],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap();

        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(message),
            &[&context.default_payer, authority],
        )
        .unwrap();

        let result = context.svm.send_transaction(tx);
        assert!(
            result.is_ok(),
            "Adding authorization lock {} should succeed",
            i + 1
        );
    }
    println!("✅ Added 3 authorization locks for testing removal");

    // Expire blockhash before verification and removal operations
    context.svm.expire_blockhash();

    // Verify all locks were added
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_with_roles.state.authorization_locks, 3);

    let (auth_locks, count) = swig_with_roles
        .get_authorization_locks_for_test::<10>()
        .unwrap();
    println!();
    println!("INITIAL STATE - Authorization locks in account:");
    println!("Total authorization locks count: {}", count);
    for i in 0..count {
        if let Some(lock) = auth_locks[i] {
            println!(
                "Lock {}: mint={:?}, amount={}, expiry_slot={}",
                i, lock.token_mint, lock.amount, lock.expiry_slot
            );
        }
    }
    println!();

    println!("TEST SCENARIOS:");
    println!(
        "  1. Remove lock using authority with All permission (role 0) - removing another role's \
         lock: Should FAIL"
    );
    println!(
        "  2. Remove lock using authority with ManageAuthorizationLocks permission (role 1) - \
         removing their own lock: Should PASS"
    );
    println!(
        "  3. Remove lock using authority with TokenLimit permission only (role 2): Should FAIL"
    );
    println!();

    // Test 1: Authority with All permission should FAIL when trying to remove
    // another role's lock
    println!("EXECUTING TEST SCENARIO 1:");
    println!(
        "Attempting to remove authorization lock at index 1 using authority with All permission \
         (role 0) - removing another role's lock"
    );
    println!("Expected: FAIL (can only remove own locks)");

    let remove_lock_all_ix = swig_interface::RemoveAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        0, // acting_role_id: swig_authority (All permission)
        1, // Remove the middle lock (index 1, created by role 1)
    )
    .unwrap();

    let remove_lock_all_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_lock_all_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let remove_lock_all_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(remove_lock_all_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let remove_lock_all_result = context.svm.send_transaction(remove_lock_all_tx);
    assert!(
        remove_lock_all_result.is_err(),
        "Authority with All permission should NOT be able to remove another role's authorization \
         lock"
    );
    println!(
        "✅ Scenario 1 PASSED: Authority with All permission correctly denied from removing \
         another role's lock"
    );

    // Verify the lock was NOT removed and count remains unchanged
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_with_roles.state.authorization_locks, 3);
    println!(
        "   → Verified: Authorization lock count remains = {}",
        swig_with_roles.state.authorization_locks
    );
    println!();

    // Expire blockhash before next removal
    context.svm.expire_blockhash();

    // Test 2: Authority with ManageAuthorizationLocks permission should succeed
    println!("EXECUTING TEST SCENARIO 2:");
    println!(
        "Removing authorization lock at index 0 using authority with ManageAuthorizationLocks \
         permission (role 1) - removing their own lock"
    );

    let remove_lock_manage_ix = swig_interface::RemoveAuthorizationLockInstruction::new(
        swig,
        manage_auth_locks_authority.pubkey(),
        context.default_payer.pubkey(),
        1, // acting_role_id: manage_auth_locks_authority (ManageAuthorizationLocks permission)
        0, // Remove the first lock (index 0, created by role 1)
    )
    .unwrap();

    let remove_lock_manage_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_lock_manage_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let remove_lock_manage_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(remove_lock_manage_message),
        &[&context.default_payer, &manage_auth_locks_authority],
    )
    .unwrap();

    let remove_lock_manage_result = context.svm.send_transaction(remove_lock_manage_tx);
    assert!(
        remove_lock_manage_result.is_ok(),
        "Authority with ManageAuthorizationLocks permission should be able to remove their own \
         authorization lock"
    );
    println!(
        "✅ Scenario 2 PASSED: Authority with ManageAuthorizationLocks permission successfully \
         removed their own authorization lock"
    );

    // Verify the lock was removed
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_with_roles.state.authorization_locks, 2);
    println!(
        "   → Verified: Authorization lock count = {}",
        swig_with_roles.state.authorization_locks
    );

    // Should have locks with amounts 300 and 200 remaining (the 500 amount lock was
    // removed)
    let (final_locks, final_count) = swig_with_roles
        .get_authorization_locks_for_test::<10>()
        .unwrap();
    assert_eq!(final_count, 2);
    assert_eq!(final_locks[0].unwrap().amount, 300);
    assert_eq!(final_locks[1].unwrap().amount, 200);
    println!("   → Verified: 300 and 200 amount locks remain (500 amount lock was removed)");
    println!();

    // Expire blockhash before final test
    context.svm.expire_blockhash();

    // Test 3: Authority with only TokenLimit permission should fail
    println!("EXECUTING TEST SCENARIO 3:");
    println!(
        "Attempting to remove authorization lock using authority with TokenLimit permission only \
         (role 2)"
    );
    println!("Expected: FAIL (insufficient permissions)");

    let remove_lock_token_ix = swig_interface::RemoveAuthorizationLockInstruction::new(
        swig,
        token_authority.pubkey(),
        context.default_payer.pubkey(),
        2, // acting_role_id: token_authority (TokenLimit permission only)
        0, // Try to remove the remaining lock
    )
    .unwrap();

    let remove_lock_token_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_lock_token_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let remove_lock_token_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(remove_lock_token_message),
        &[&context.default_payer, &token_authority],
    )
    .unwrap();

    let remove_lock_token_result = context.svm.send_transaction(remove_lock_token_tx);
    assert!(
        remove_lock_token_result.is_err(),
        "Authority with only TokenLimit permission should NOT be able to remove authorization lock"
    );
    println!("✅ Scenario 3 PASSED: Authority with TokenLimit permission was correctly denied");

    // Verify the lock count didn't change
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(
        swig_with_roles.state.authorization_locks, 2,
        "Lock count should remain unchanged after failed attempt"
    );
    println!(
        "   → Verified: Authorization lock count remains = {}",
        swig_with_roles.state.authorization_locks
    );
    println!();

    println!("✅ REMOVE AUTHORIZATION LOCK PERMISSION ENFORCEMENT TEST COMPLETED SUCCESSFULLY!");
    println!("✅ Roles with All permissions can only remove their own authorization locks");
    println!(
        "✅ Roles with ManageAuthorizationLocks permissions can only remove their own \
         authorization locks"
    );
    println!("✅ Authorities with insufficient permissions are properly denied");
    println!("✅ Lock removal properly shifts remaining locks and updates count");
    println!("================================================================");
}

/// Test that validates edge cases and error conditions for remove authorization
/// lock
#[test_log::test]
fn test_remove_authorization_lock_edge_cases() {
    let mut context = setup_test_context().unwrap();

    // Setup accounts
    let swig_authority = Keypair::new();

    // Airdrop to participants
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Setup token mint
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    // Create swig account
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let swig_create_result = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_result.is_ok());

    println!("=== REMOVE AUTHORIZATION LOCK EDGE CASES TEST ===");
    println!("Testing error conditions and edge cases");
    println!();

    // Test 1: Try to remove lock when no locks exist
    println!("TEST SCENARIO 1:");
    println!("Attempting to remove authorization lock when no locks exist");
    println!("Expected: FAIL (no locks to remove)");

    let remove_empty_ix = swig_interface::RemoveAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        0, // acting_role_id
        0, // lock_index
    )
    .unwrap();

    let remove_empty_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_empty_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let remove_empty_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(remove_empty_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let remove_empty_result = context.svm.send_transaction(remove_empty_tx);
    assert!(
        remove_empty_result.is_err(),
        "Removing lock when no locks exist should fail"
    );
    println!("✅ Scenario 1 PASSED: Correctly rejected removal when no locks exist");
    println!();

    // Add a single lock for testing
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let expiry_slot = current_slot + 1000;

    let add_lock_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        0, // acting_role_id
        mint_pubkey.to_bytes(),
        100,
        expiry_slot,
    )
    .unwrap();

    let add_lock_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_lock_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_lock_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_lock_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let add_lock_result = context.svm.send_transaction(add_lock_tx);
    assert!(add_lock_result.is_ok(), "Adding single lock should succeed");
    println!("✅ Added single authorization lock for edge case testing");

    // Expire blockhash to avoid transaction replay issues
    context.svm.expire_blockhash();

    // Test 2: Try to remove lock with invalid index (out of bounds)
    println!();
    println!("TEST SCENARIO 2:");
    println!(
        "Attempting to remove authorization lock with invalid index (1 when only index 0 exists)"
    );
    println!("Expected: FAIL (index out of bounds)");

    let remove_invalid_ix = swig_interface::RemoveAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        0, // acting_role_id
        1, // Invalid index (only 0 exists)
    )
    .unwrap();

    let remove_invalid_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_invalid_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let remove_invalid_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(remove_invalid_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let remove_invalid_result = context.svm.send_transaction(remove_invalid_tx);
    assert!(
        remove_invalid_result.is_err(),
        "Removing lock with invalid index should fail"
    );
    println!("✅ Scenario 2 PASSED: Correctly rejected removal with invalid index");
    println!();

    // Expire blockhash before next transaction
    context.svm.expire_blockhash();

    // Test 3: Successfully remove the valid lock
    println!("TEST SCENARIO 3:");
    println!("Removing the valid authorization lock at index 0");
    println!("Expected: PASS (valid removal)");

    let remove_valid_ix = swig_interface::RemoveAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        0, // acting_role_id
        0, // Valid index
    )
    .unwrap();

    let remove_valid_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_valid_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let remove_valid_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(remove_valid_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let remove_valid_result = context.svm.send_transaction(remove_valid_tx);
    assert!(
        remove_valid_result.is_ok(),
        "Removing valid lock should succeed"
    );
    println!("✅ Scenario 3 PASSED: Successfully removed valid authorization lock");

    // Verify no locks remain
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_with_roles.state.authorization_locks, 0);
    println!(
        "   → Verified: No authorization locks remain (count = {})",
        swig_with_roles.state.authorization_locks
    );
    println!();

    // Test 4: Try to remove lock with non-existent role ID
    println!("TEST SCENARIO 4:");
    println!("Attempting to remove authorization lock using non-existent role ID (999)");
    println!("Expected: FAIL (role not found)");

    // First add a lock again for this test
    let add_lock_again_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        0, // acting_role_id
        mint_pubkey.to_bytes(),
        150,
        expiry_slot,
    )
    .unwrap();

    let add_lock_again_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_lock_again_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_lock_again_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_lock_again_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let add_lock_again_result = context.svm.send_transaction(add_lock_again_tx);
    assert!(
        add_lock_again_result.is_ok(),
        "Adding lock for role test should succeed"
    );

    // Expire blockhash before next transaction
    context.svm.expire_blockhash();

    let remove_bad_role_ix = swig_interface::RemoveAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        999, // Non-existent role ID
        0,   // Valid lock index
    )
    .unwrap();

    let remove_bad_role_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_bad_role_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let remove_bad_role_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(remove_bad_role_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let remove_bad_role_result = context.svm.send_transaction(remove_bad_role_tx);
    assert!(
        remove_bad_role_result.is_err(),
        "Using non-existent role ID should fail"
    );
    println!("✅ Scenario 4 PASSED: Non-existent role ID was correctly rejected");

    println!();
    println!("✅ REMOVE AUTHORIZATION LOCK EDGE CASES TEST COMPLETED SUCCESSFULLY!");
    println!("================================================================");
}
