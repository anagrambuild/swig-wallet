mod common;

use common::*;
use rand::random;
use solana_program::pubkey::Pubkey;
use solana_sdk::{
    message::{v0, VersionedMessage},
    signature::{Keypair, Signer},
    transaction::VersionedTransaction,
};
use swig_interface::{AuthorityConfig, ClientAction};
use swig_state_x::{
    action::{all::All, sol_limit::SolLimit, sol_recurring_limit::SolRecurringLimit},
    authority::AuthorityType,
    swig::SwigWithRoles,
};

#[test_log::test]
fn test_authority_management() {
    // Setup test context
    let mut context = setup_test_context().unwrap();

    // Create main authority
    let main_authority = Keypair::new();
    context
        .svm
        .airdrop(&main_authority.pubkey(), 10_000_000_000)
        .unwrap();

    println!(
        "Balance of main_authority: {:?}",
        context.svm.get_balance(&main_authority.pubkey())
    );
    // Generate random ID for the wallet
    let id = random::<[u8; 32]>();

    // Create Swig wallet with main authority
    let swig_created = create_swig_ed25519(&mut context, &main_authority, id);
    assert!(
        swig_created.is_ok(),
        "Failed to create Swig wallet: {:?}",
        swig_created.err()
    );
    let (swig_pubkey, create_bench) = swig_created.unwrap();

    println!(
        "Create transaction compute units: {:?}",
        create_bench.compute_units_consumed
    );
    println!("Create transaction logs: {:?}", create_bench.logs);

    // Verify wallet creation
    let swig_account = context
        .svm
        .get_account(&swig_pubkey)
        .expect("Failed to get Swig account");
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 1, "Expected 1 role after creation");
    assert_eq!(swig.state.id, id, "Wallet ID mismatch");
    assert_eq!(swig.state.role_counter, 1, "Expected role counter to be 1");

    // Create secondary authority
    let secondary_authority = Keypair::new();

    // Define actions for secondary authority (SOL recurring limit)
    let actions = vec![ClientAction::SolRecurringLimit(SolRecurringLimit {
        recurring_amount: 1_000_000_000, // 1 SOL
        window: 86400,                   // 24 hours in slots
        last_reset: 0,
        current_amount: 1_000_000_000,
    })];

    // Add secondary authority
    let add_authority_result = add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &main_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary_authority.pubkey().as_ref(),
        },
        actions,
    );

    assert!(
        add_authority_result.is_ok(),
        "Failed to add secondary authority: {:?}",
        add_authority_result.err()
    );
    let add_auth_bench = add_authority_result.unwrap();

    println!(
        "Add authority compute units: {:?}",
        add_auth_bench.compute_units_consumed
    );
    println!("Add authority logs: {:?}", add_auth_bench.logs);

    // Verify secondary authority addition
    let updated_swig_account = context
        .svm
        .get_account(&swig_pubkey)
        .expect("Failed to get updated Swig account");
    let updated_swig = SwigWithRoles::from_bytes(&updated_swig_account.data).unwrap();
    assert_eq!(
        updated_swig.state.roles, 2,
        "Expected 2 roles after adding secondary authority"
    );
    assert_eq!(
        updated_swig.state.role_counter, 2,
        "Expected role counter to be 2"
    );

    // Verify secondary authority's role and permissions
    let secondary_role_id = updated_swig
        .lookup_role_id(secondary_authority.pubkey().as_ref())
        .unwrap()
        .expect("Secondary authority role not found");

    let secondary_role = updated_swig
        .get_role(secondary_role_id)
        .unwrap()
        .expect("Failed to get secondary role");

    // Verify SOL recurring limit action exists
    let sol_recurring_limit = secondary_role.get_action::<SolRecurringLimit>(&[]).unwrap();
    assert!(
        sol_recurring_limit.is_some(),
        "Expected SOL recurring limit action to exist"
    );
    if let Some(limit) = sol_recurring_limit {
        assert_eq!(
            limit.recurring_amount, 1_000_000_000,
            "Incorrect SOL recurring limit amount"
        );
        assert_eq!(limit.window, 86400, "Incorrect recurring window");
        assert_eq!(
            limit.current_amount, 1_000_000_000,
            "Incorrect current amount"
        );
        assert_eq!(limit.last_reset, 0, "Incorrect last reset value");
    }
}
