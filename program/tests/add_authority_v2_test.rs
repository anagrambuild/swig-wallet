#![cfg(not(feature = "program_scope_test"))]
// This feature flag ensures these tests are only run when the
// "program_scope_test" feature is not enabled. This allows us to isolate
// and run only program_scope tests or only the regular tests.
//
// SignV2 VERSION: This is the SignV2 version of add_authority_test.rs
// The tests are functionally equivalent since add_authority operations
// don't directly use SignInstruction - any signing happens within the
// add_authority_with_ed25519_root helper function using the latest available
// signing interface.

mod common;

use common::*;
use solana_sdk::{signature::Keypair, signer::Signer};
use swig_interface::{AuthorityConfig, ClientAction};
use swig_state::{
    action::manage_authority::ManageAuthority, authority::AuthorityType, swig::SwigWithRoles,
};

#[test_log::test]
fn test_create_add_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    let (swig_key, swig_create_txn) =
        create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
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
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 2);
    assert_eq!(swig.state.role_counter, 2);
    let role_0 = swig.get_role(0).unwrap().unwrap();
    assert_eq!(role_0.authority.authority_type(), AuthorityType::Ed25519);
    assert!(!role_0.authority.session_based());
    assert_eq!(
        role_0.position.authority_type().unwrap(),
        AuthorityType::Ed25519
    );
    assert_eq!(role_0.position.authority_length(), 32);
    assert_eq!(role_0.position.num_actions(), 1);
}

#[test_log::test]
fn test_cannot_add_authority_with_zero_actions() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig wallet with the root authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Try to add a second authority with zero actions (should fail)
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let result = add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![], // Empty actions vector
    );

    // Verify the operation failed
    assert!(
        result.is_err(),
        "Adding authority with zero actions should fail"
    );

    // Verify the error is related to empty actions
    if let Err(err) = result {
        let error_string = format!("{:?}", err);
        println!("Error: {}", error_string);
        assert!(
            error_string.contains("EmptyActions") || error_string.contains("Custom"),
            "Expected empty actions error, got: {:?}",
            err
        );
    }

    // Verify no new authority was added
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(
        swig.state.roles, 1,
        "Should still have only the root authority"
    );
}

#[test_log::test]
fn test_multiple_authorities_with_different_actions() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig wallet with the root authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Add three authorities with different action combinations
    let authority1 = Keypair::new();
    let authority2 = Keypair::new();
    let authority3 = Keypair::new();

    context
        .svm
        .airdrop(&authority1.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&authority2.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&authority3.pubkey(), 10_000_000_000)
        .unwrap();

    // Add authority1 with ManageAuthority action
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: authority1.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();
    context.svm.warp_to_slot(10);
    // Add authority2 with SolLimit action (imported from remove_authority_test.rs)
    use swig_state::action::sol_limit::SolLimit;
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: authority2.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit {
            amount: 1000000000000000000,
        })],
    )
    .unwrap();
    context.svm.warp_to_slot(12);
    // Add authority3 with All action
    use swig_state::action::all::All;
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: authority3.pubkey().as_ref(),
        },
        vec![ClientAction::All(All {})],
    )
    .unwrap();
    context.svm.warp_to_slot(13);
    // Verify all authorities were added
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(
        swig.state.roles, 4,
        "Should have 4 authorities (root + 3 added)"
    );

    // Verify authority1 has ManageAuthority permission
    let role_id1 = swig
        .lookup_role_id(authority1.pubkey().as_ref())
        .unwrap()
        .unwrap();
    let role1 = swig.get_role(role_id1).unwrap().unwrap();
    assert_eq!(
        role1.position.num_actions(),
        1,
        "Authority1 should have 1 action"
    );

    // Verify authority2 has SolLimit permission
    let role_id2 = swig
        .lookup_role_id(authority2.pubkey().as_ref())
        .unwrap()
        .unwrap();
    let role2 = swig.get_role(role_id2).unwrap().unwrap();
    assert_eq!(
        role2.position.num_actions(),
        1,
        "Authority2 should have 1 action"
    );

    // Verify authority3 has All permission
    let role_id3 = swig
        .lookup_role_id(authority3.pubkey().as_ref())
        .unwrap()
        .unwrap();
    let role3 = swig.get_role(role_id3).unwrap().unwrap();
    assert_eq!(
        role3.position.num_actions(),
        1,
        "Authority3 should have 1 action"
    );
}

#[test_log::test]
fn test_recurring_action_layout_validation() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Test SOL recurring limit validation
    use swig_state::action::sol_recurring_limit::SolRecurringLimit;

    // Should succeed - current equals limit and last_reset is 0
    let result = add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolRecurringLimit(SolRecurringLimit {
            recurring_amount: 500,
            window: 100,
            last_reset: 0,
            current_amount: 500,
        })],
    );
    assert!(result.is_ok(), "Valid SOL recurring limit should succeed");

    // Should fail - current doesn't equal limit
    let result = add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolRecurringLimit(SolRecurringLimit {
            recurring_amount: 500,
            window: 100,
            last_reset: 0,
            current_amount: 400, // Different from recurring_amount
        })],
    );
    assert!(
        result.is_err(),
        "SOL recurring limit with mismatched current amount should fail"
    );

    // Should fail - last_reset is not 0
    let result = add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolRecurringLimit(SolRecurringLimit {
            recurring_amount: 500,
            window: 100,
            last_reset: 10, // Non-zero
            current_amount: 500,
        })],
    );
    assert!(
        result.is_err(),
        "SOL recurring limit with non-zero last_reset should fail"
    );

    // Test Token recurring limit validation
    use swig_state::action::token_recurring_limit::TokenRecurringLimit;
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    // Should succeed - current equals limit and last_reset is 0
    let result = add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::TokenRecurringLimit(TokenRecurringLimit {
            token_mint: mint_pubkey.to_bytes().try_into().unwrap(),
            window: 100,
            limit: 500,
            current: 500,
            last_reset: 0,
        })],
    );
    assert!(result.is_ok(), "Valid token recurring limit should succeed");

    // Should fail - current doesn't equal limit
    let result = add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::TokenRecurringLimit(TokenRecurringLimit {
            token_mint: mint_pubkey.to_bytes().try_into().unwrap(),
            window: 100,
            limit: 500,
            current: 400, // Different from limit
            last_reset: 0,
        })],
    );
    assert!(
        result.is_err(),
        "Token recurring limit with mismatched current should fail"
    );

    // Should fail - last_reset is not 0
    let result = add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::TokenRecurringLimit(TokenRecurringLimit {
            token_mint: mint_pubkey.to_bytes().try_into().unwrap(),
            window: 100,
            limit: 500,
            current: 500,
            last_reset: 10, // Non-zero
        })],
    );
    assert!(
        result.is_err(),
        "Token recurring limit with non-zero last_reset should fail"
    );

    // Test Stake recurring limit validation
    use swig_state::action::stake_recurring_limit::StakeRecurringLimit;

    // Should succeed - current equals limit and last_reset is 0
    let result = add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::StakeRecurringLimit(StakeRecurringLimit {
            recurring_amount: 500,
            window: 100,
            last_reset: 0,
            current_amount: 500,
        })],
    );
    assert!(result.is_ok(), "Valid stake recurring limit should succeed");

    // Should fail - current doesn't equal limit
    let result = add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::StakeRecurringLimit(StakeRecurringLimit {
            recurring_amount: 500,
            window: 100,
            last_reset: 0,
            current_amount: 400, // Different from recurring_amount
        })],
    );
    assert!(
        result.is_err(),
        "Stake recurring limit with mismatched current amount should fail"
    );

    // Should fail - last_reset is not 0
    let result = add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::StakeRecurringLimit(StakeRecurringLimit {
            recurring_amount: 500,
            window: 100,
            last_reset: 10, // Non-zero
            current_amount: 500,
        })],
    );
    assert!(
        result.is_err(),
        "Stake recurring limit with non-zero last_reset should fail"
    );
}