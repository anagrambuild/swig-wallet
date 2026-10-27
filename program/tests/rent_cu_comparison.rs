//! Deterministic management fixtures for rent-related compute costs.
#![cfg(not(feature = "program_scope_test"))]
mod common;
use common::*;
use solana_sdk::{signature::Keypair, signer::Signer};
use swig_interface::{AuthorityConfig, ClientAction};
use swig_state::{action::all::All, authority::AuthorityType};

#[test]
fn compare_management_compute_units() {
    let mut context = setup_test_context().unwrap();
    let root = Keypair::new_from_array([42; 32]);
    let secondary = Keypair::new_from_array([43; 32]);
    context.svm.airdrop(&root.pubkey(), 10_000_000_000).unwrap();
    let (swig, result) = create_swig_ed25519(&mut context, &root, [44; 32]).unwrap();
    println!("CU_COMPARE create {}", result.compute_units_consumed);
    let result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &root,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary.pubkey().as_ref(),
        },
        vec![ClientAction::All(All {})],
    )
    .unwrap();
    println!("CU_COMPARE add_role {}", result.compute_units_consumed);
    let result = remove_authority_with_ed25519_root(&mut context, &swig, &root, 1).unwrap();
    println!("CU_COMPARE remove_role {}", result.compute_units_consumed);
    let claimer = Keypair::new_from_array([45; 32]).pubkey();
    let result = set_rent_claimer_with_ed25519(&mut context, &swig, &root, 0, claimer).unwrap();
    println!(
        "CU_COMPARE set_rent_claimer {}",
        result.compute_units_consumed
    );
}
