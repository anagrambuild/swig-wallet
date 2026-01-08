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
    action::{
        all::All, manage_authorization_locks::ManageAuthorizationLocks, token_limit::TokenLimit,
    },
    swig::{swig_account_seeds, AuthorizationLock, Swig, SwigWithRoles},
    IntoBytes, Transmutable,
};

/// Test that validates authorization locks track the role ID that created them
/// and that we can retrieve locks by role ID.
#[test_log::test]
fn test_authorization_lock_role_tracking() {
    let mut context = setup_test_context().unwrap();

    // Setup accounts - simplified to test role tracking with just 2 roles
    let swig_authority = Keypair::new(); // Will have All permissions (role 0)
    let manage_auth_locks_authority = Keypair::new(); // Will have ManageAuthorizationLocks permission (role 1)

    // Airdrop to participants
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&manage_auth_locks_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Setup token mint
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    // Create swig account
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let swig_create_result = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_result.is_ok());

    println!("=== AUTHORIZATION LOCK ROLE TRACKING TEST ===");
    println!(
        "Testing that authorization locks track creator role IDs and can be retrieved by role"
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
                authority_type: swig_state::authority::AuthorityType::Ed25519,
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
    println!();

    // Test parameters for authorization locks
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let expiry_slot = current_slot + 1000;

    // Expire blockhash
    context.svm.expire_blockhash();

    // Add authorization locks from different roles
    println!("ADDING AUTHORIZATION LOCKS FROM DIFFERENT ROLES:");

    // Lock 1: Added by role 0 (swig_authority with All permission)
    println!("Adding lock 1 from role 0 (All permission): 500 tokens");
    let add_lock1_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        0, // acting_role_id: swig_authority (All permission)
        mint_pubkey.to_bytes(),
        500,
        expiry_slot,
    )
    .unwrap();

    let add_lock1_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_lock1_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_lock1_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_lock1_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let add_lock1_result = context.svm.send_transaction(add_lock1_tx);
    assert!(
        add_lock1_result.is_ok(),
        "Adding lock from role 0 should succeed"
    );

    // Expire blockhash
    context.svm.expire_blockhash();

    // Lock 2: Added by role 1 (ManageAuthorizationLocks permission)
    println!("Adding lock 2 from role 1 (ManageAuthorizationLocks permission): 300 tokens");
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

    let add_lock2_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_lock2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_lock2_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_lock2_message),
        &[&context.default_payer, &manage_auth_locks_authority],
    )
    .unwrap();

    let add_lock2_result = context.svm.send_transaction(add_lock2_tx);
    assert!(
        add_lock2_result.is_ok(),
        "Adding lock from role 1 should succeed"
    );

    // Expire blockhash
    context.svm.expire_blockhash();

    // Lock 3: Another lock from role 0
    println!("Adding lock 3 from role 0 (All permission): 100 tokens");
    let add_lock3_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        swig_authority.pubkey(),
        context.default_payer.pubkey(),
        0, // acting_role_id: swig_authority
        mint_pubkey.to_bytes(),
        100,
        expiry_slot,
    )
    .unwrap();

    let add_lock3_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_lock3_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_lock3_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_lock3_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let add_lock3_result = context.svm.send_transaction(add_lock3_tx);
    assert!(
        add_lock3_result.is_ok(),
        "Adding third lock from role 0 should succeed"
    );

    // Lock 4: Another lock from role 1
    println!("Adding lock 4 from role 1 (ManageAuthorizationLocks permission): 200 tokens");

    // Expire blockhash
    context.svm.expire_blockhash();

    let add_lock4_ix = swig_interface::AddAuthorizationLockInstruction::new(
        swig,
        manage_auth_locks_authority.pubkey(),
        context.default_payer.pubkey(),
        1, // acting_role_id: manage_auth_locks_authority
        mint_pubkey.to_bytes(),
        200,
        expiry_slot,
    )
    .unwrap();

    let add_lock4_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_lock4_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let add_lock4_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(add_lock4_message),
        &[&context.default_payer, &manage_auth_locks_authority],
    )
    .unwrap();

    let add_lock4_result = context.svm.send_transaction(add_lock4_tx);
    assert!(
        add_lock4_result.is_ok(),
        "Adding second lock from role 1 should succeed"
    );

    println!("✅ Added 4 authorization locks from different roles");
    println!();

    // Verify all locks and their role IDs
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_with_roles.state.authorization_locks, 4);

    println!("VERIFICATION - All authorization locks in account:");
    let (all_locks, total_count) = swig_with_roles
        .get_authorization_locks_for_test::<10>()
        .unwrap();
    println!("Total authorization locks: {}", total_count);
    for i in 0..total_count {
        if let Some(lock) = all_locks[i] {
            println!(
                "Lock {}: role_id={}, amount={}, mint={:?}",
                i, lock.role_id, lock.amount, lock.token_mint
            );
        }
    }
    println!();

    // Test getting locks by role ID
    println!("TESTING GET LOCKS BY ROLE ID:");

    // Get locks for role 0 (should have 2 locks: 500 and 100 tokens)
    println!("Getting locks for role 0:");
    let (role0_locks, role0_count) = swig_with_roles
        .get_authorization_locks_by_role::<10>(0)
        .unwrap();
    println!("Found {} locks for role 0", role0_count);
    assert_eq!(role0_count, 2, "Role 0 should have 2 locks");

    let mut role0_amounts = Vec::new();
    for i in 0..role0_count {
        if let Some(lock) = role0_locks[i] {
            println!("  Role 0 Lock {}: amount={}", i, lock.amount);
            assert_eq!(lock.role_id, 0, "Lock should belong to role 0");
            role0_amounts.push(lock.amount);
        }
    }
    // Should have 500 and 100 token locks
    role0_amounts.sort();
    assert_eq!(
        role0_amounts,
        vec![100, 500],
        "Role 0 should have 100 and 500 token locks"
    );

    // Get locks for role 1 (should have 2 locks: 300 and 200 tokens)
    println!("Getting locks for role 1:");
    let (role1_locks, role1_count) = swig_with_roles
        .get_authorization_locks_by_role::<10>(1)
        .unwrap();
    println!("Found {} locks for role 1", role1_count);
    assert_eq!(role1_count, 2, "Role 1 should have 2 locks");

    let mut role1_amounts = Vec::new();
    for i in 0..role1_count {
        if let Some(lock) = role1_locks[i] {
            println!("  Role 1 Lock {}: amount={}", i, lock.amount);
            assert_eq!(lock.role_id, 1, "Lock should belong to role 1");
            role1_amounts.push(lock.amount);
        }
    }
    // Should have 300 and 200 token locks
    role1_amounts.sort();
    assert_eq!(
        role1_amounts,
        vec![200, 300],
        "Role 1 should have 200 and 300 token locks"
    );

    // Get locks for role 999 (should have 0 locks)
    println!("Getting locks for role 999 (non-existent):");
    let (role999_locks, role999_count) = swig_with_roles
        .get_authorization_locks_by_role::<10>(999)
        .unwrap();
    println!("Found {} locks for role 999", role999_count);
    assert_eq!(role999_count, 0, "Role 999 should have no locks");

    println!();
    println!("✅ ROLE TRACKING VERIFICATION COMPLETE!");
    println!("✅ Authorization locks correctly track creator role IDs");
    println!("✅ get_authorization_locks_by_role function works correctly");
    println!("✅ Role 0: 2 locks (500, 100 tokens)");
    println!("✅ Role 1: 2 locks (300, 200 tokens)");
    println!("✅ Non-existent roles return 0 locks");
    println!("================================================================");
}
