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
/// "ManageAuthorizationLocks" permissions can add authorization locks, while
/// others are denied.
#[test_log::test]
fn test_authorization_lock_permission_enforcement() {
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

    println!("=== AUTHORIZATION LOCK PERMISSION ENFORCEMENT TEST ===");
    println!(
        "Testing that only authorities with proper permissions can manage authorization locks"
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

    // Test parameters for authorization lock
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let lock_amount = 500u64;
    let expiry_slot = current_slot + 1000;

    println!("TEST SCENARIOS:");
    println!("  1. Authority with All permission (role 0): Should PASS");
    println!("  2. Authority with ManageAuthorizationLocks permission (role 1): Should PASS");
    println!("  3. Authority with TokenLimit permission only (role 2): Should FAIL");
    println!();

    // Test 1: Authority with All permission should succeed
    println!("EXECUTING TEST SCENARIO 1:");
    println!("Adding authorization lock using authority with All permission (role 0)");

    let add_lock_all_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        0, // acting_role_id: swig_authority (All permission)
        mint_pubkey.to_bytes(),
        lock_amount,
        expiry_slot,
    )
    .unwrap();

    let add_lock_all_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_lock_all_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_lock_all_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_lock_all_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let add_lock_all_result = context.svm.send_transaction(add_lock_all_tx);
    assert!(
        add_lock_all_result.is_ok(),
        "Authority with All permission should be able to add authorization lock"
    );
    println!(
        "✅ Scenario 1 PASSED: Authority with All permission successfully added authorization lock"
    );

    // Verify the lock was added
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_with_roles.state.authorization_locks, 1);
    println!(
        "   → Verified: Authorization lock count = {}",
        swig_with_roles.state.authorization_locks
    );
    println!();

    // Test 2: Authority with ManageAuthorizationLocks permission should succeed
    println!("EXECUTING TEST SCENARIO 2:");
    println!(
        "Adding authorization lock using authority with ManageAuthorizationLocks permission (role \
         1)"
    );

    let add_lock_manage_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        manage_auth_locks_authority.pubkey(),
        context.default_payer.pubkey(),
        1, // acting_role_id: manage_auth_locks_authority (ManageAuthorizationLocks permission)
        mint_pubkey.to_bytes(),
        lock_amount + 100, // Different amount
        expiry_slot,
    )
    .unwrap();

    let add_lock_manage_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_lock_manage_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_lock_manage_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_lock_manage_message),
        &[&context.default_payer, &manage_auth_locks_authority],
    )
    .unwrap();

    let add_lock_manage_result = context.svm.send_transaction(add_lock_manage_tx);
    assert!(
        add_lock_manage_result.is_ok(),
        "Authority with ManageAuthorizationLocks permission should be able to add authorization \
         lock"
    );
    println!(
        "✅ Scenario 2 PASSED: Authority with ManageAuthorizationLocks permission successfully \
         added authorization lock"
    );

    // Verify the second lock was added
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_with_roles.state.authorization_locks, 2);
    println!(
        "   → Verified: Authorization lock count = {}",
        swig_with_roles.state.authorization_locks
    );
    println!();

    // Test 3: Authority with only TokenLimit permission should fail
    println!("EXECUTING TEST SCENARIO 3:");
    println!(
        "Attempting to add authorization lock using authority with TokenLimit permission only \
         (role 2)"
    );
    println!("Expected: FAIL (insufficient permissions)");

    let add_lock_token_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        token_authority.pubkey(),
        context.default_payer.pubkey(),
        2, // acting_role_id: token_authority (TokenLimit permission only)
        mint_pubkey.to_bytes(),
        lock_amount + 200, // Different amount
        expiry_slot,
    )
    .unwrap();

    let add_lock_token_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_lock_token_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_lock_token_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_lock_token_message),
        &[&context.default_payer, &token_authority],
    )
    .unwrap();

    let add_lock_token_result = context.svm.send_transaction(add_lock_token_tx);
    assert!(
        add_lock_token_result.is_err(),
        "Authority with only TokenLimit permission should NOT be able to add authorization lock"
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

    println!("FINAL VERIFICATION:");
    let (auth_locks, count) = swig_with_roles
        .get_authorization_locks_for_test::<10>()
        .unwrap();
    println!("Total authorization locks in account: {}", count);
    for i in 0..count {
        if let Some(lock) = auth_locks[i] {
            println!(
                "Lock {}: mint={:?}, amount={}, expiry_slot={}",
                i, lock.token_mint, lock.amount, lock.expiry_slot
            );
        }
    }

    println!();
    println!("✅ PERMISSION ENFORCEMENT TEST COMPLETED SUCCESSFULLY!");
    println!(
        "✅ Only authorities with All or ManageAuthorizationLocks permissions can manage \
         authorization locks"
    );
    println!("✅ Authorities with insufficient permissions are properly denied");
    println!("======================================================");
}

/// Test that validates role ID validation and non-existent role handling
#[test_log::test]
fn test_authorization_lock_invalid_role_handling() {
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

    println!("=== AUTHORIZATION LOCK INVALID ROLE HANDLING TEST ===");
    println!("Testing behavior with invalid role IDs");
    println!();

    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let lock_amount = 500u64;
    let expiry_slot = current_slot + 1000;

    // Test 1: Using non-existent role ID should fail
    println!("TEST SCENARIO 1:");
    println!("Attempting to add authorization lock using non-existent role ID (999)");
    println!("Expected: FAIL (role not found)");

    let add_lock_invalid_role_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        999, // Non-existent role ID
        mint_pubkey.to_bytes(),
        lock_amount,
        expiry_slot,
    )
    .unwrap();

    let add_lock_invalid_role_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_lock_invalid_role_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_lock_invalid_role_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_lock_invalid_role_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let add_lock_invalid_role_result = context.svm.send_transaction(add_lock_invalid_role_tx);
    assert!(
        add_lock_invalid_role_result.is_err(),
        "Using non-existent role ID should fail"
    );
    println!("✅ Scenario 1 PASSED: Non-existent role ID was correctly rejected");
    println!();

    // Test 2: Valid role ID (0) should succeed
    println!("TEST SCENARIO 2:");
    println!("Adding authorization lock using valid role ID (0)");
    println!("Expected: PASS (role 0 has All permissions)");

    let add_lock_valid_role_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        0, // Valid role ID
        mint_pubkey.to_bytes(),
        lock_amount,
        expiry_slot,
    )
    .unwrap();

    let add_lock_valid_role_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_lock_valid_role_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_lock_valid_role_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_lock_valid_role_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let add_lock_valid_role_result = context.svm.send_transaction(add_lock_valid_role_tx);
    assert!(
        add_lock_valid_role_result.is_ok(),
        "Using valid role ID should succeed"
    );
    println!("✅ Scenario 2 PASSED: Valid role ID successfully added authorization lock");

    // Verify the lock was added
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_with_roles.state.authorization_locks, 1);
    println!(
        "   → Verified: Authorization lock count = {}",
        swig_with_roles.state.authorization_locks
    );

    println!();
    println!("✅ INVALID ROLE HANDLING TEST COMPLETED SUCCESSFULLY!");
    println!("======================================================");
}

/// Test that validates expired authorization lock rejection
#[test_log::test]
fn test_authorization_lock_expiry_validation() {
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

    println!("=== AUTHORIZATION LOCK EXPIRY VALIDATION TEST ===");
    println!("Testing that already-expired authorization locks are rejected");
    println!();

    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let lock_amount = 500u64;

    println!("Current slot: {}", current_slot);
    println!();

    // Test 1: Try to add an authorization lock that has already expired
    let expired_slot = if current_slot > 0 {
        current_slot - 1
    } else {
        0
    };

    println!("TEST SCENARIO 1:");
    println!(
        "Attempting to add authorization lock with expired slot: {}",
        expired_slot
    );
    println!("Expected: FAIL (already expired)");

    let add_expired_lock_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        0, // acting_role_id
        mint_pubkey.to_bytes(),
        lock_amount,
        expired_slot,
    )
    .unwrap();

    let add_expired_lock_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_expired_lock_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_expired_lock_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_expired_lock_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let add_expired_lock_result = context.svm.send_transaction(add_expired_lock_tx);
    assert!(
        add_expired_lock_result.is_err(),
        "Adding expired authorization lock should fail"
    );
    println!("✅ Scenario 1 PASSED: Expired authorization lock was correctly rejected");
    println!();

    // Test 2: Add a valid authorization lock with future expiry
    let future_slot = current_slot + 1000;

    println!("TEST SCENARIO 2:");
    println!(
        "Adding authorization lock with future expiry slot: {}",
        future_slot
    );
    println!("Expected: PASS (valid expiry)");

    let add_valid_lock_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        0, // acting_role_id
        mint_pubkey.to_bytes(),
        lock_amount,
        future_slot,
    )
    .unwrap();

    let add_valid_lock_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_valid_lock_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_valid_lock_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_valid_lock_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let add_valid_lock_result = context.svm.send_transaction(add_valid_lock_tx);
    assert!(
        add_valid_lock_result.is_ok(),
        "Adding valid authorization lock should succeed"
    );
    println!("✅ Scenario 2 PASSED: Valid authorization lock successfully added");

    // Verify the lock was added
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_with_roles.state.authorization_locks, 1);
    println!(
        "   → Verified: Authorization lock count = {}",
        swig_with_roles.state.authorization_locks
    );

    println!();
    println!("✅ EXPIRY VALIDATION TEST COMPLETED SUCCESSFULLY!");
    println!("======================================================");
}
