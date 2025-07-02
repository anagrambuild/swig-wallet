#![cfg(not(feature = "program_scope_test"))]
// This feature flag ensures these tests are only run when the
// "program_scope_test" feature is not enabled. This allows us to isolate
// and run only program_scope tests or only the regular tests.

mod common;

use common::*;
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};
use swig_interface::{AuthorityConfig, ClientAction, UpdateAuthorityInstruction};
use swig_state::{
    action::{all::All, manage_authority::ManageAuthority, sol_limit::SolLimit},
    authority::AuthorityType,
    swig::SwigWithRoles,
};

/// Helper function to update authority with Ed25519 root authority
pub fn update_authority_with_ed25519_root(
    context: &mut SwigTestContext,
    swig_pubkey: &Pubkey,
    existing_ed25519_authority: &Keypair,
    authority_to_update_id: u32,
    new_actions: Vec<ClientAction>,
) -> anyhow::Result<litesvm::types::TransactionMetadata> {
    context.svm.expire_blockhash();
    let payer_pubkey = context.default_payer.pubkey();
    let swig_account = context
        .svm
        .get_account(swig_pubkey)
        .ok_or(anyhow::anyhow!("Swig account not found"))?;
    let swig = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize swig {:?}", e))?;
    let role_id = swig
        .lookup_role_id(existing_ed25519_authority.pubkey().as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to lookup role id {:?}", e))?
        .unwrap();

    let update_authority_ix = UpdateAuthorityInstruction::new_with_ed25519_authority(
        *swig_pubkey,
        context.default_payer.pubkey(),
        existing_ed25519_authority.pubkey(),
        role_id,
        authority_to_update_id,
        new_actions,
    )
    .map_err(|e| anyhow::anyhow!("Failed to create update authority instruction {:?}", e))?;

    let msg = solana_sdk::message::v0::Message::try_compile(
        &payer_pubkey,
        &[
            solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_limit(10000000),
            update_authority_ix,
        ],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = solana_sdk::transaction::VersionedTransaction::try_new(
        solana_sdk::message::VersionedMessage::V0(msg),
        &[
            context.default_payer.insecure_clone(),
            existing_ed25519_authority.insecure_clone(),
        ],
    )
    .unwrap();

    let bench = context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e))?;
    Ok(bench)
}

#[test_log::test]
fn test_update_authority_basic() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig wallet with the root authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Add a second authority with ManageAuthority permission
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

    // Verify the second authority was added
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 2);

    let role_1 = swig.get_role(1).unwrap().unwrap();
    assert_eq!(role_1.position.num_actions(), 1);

    // Update the second authority to have different permissions
    update_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        1, // Update authority with ID 1
        vec![
            ClientAction::SolLimit(SolLimit { amount: 1000000 }),
            ClientAction::ManageAuthority(ManageAuthority {}),
        ],
    )
    .unwrap();

    // Verify the authority was updated
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 2); // Still 2 roles
    assert_eq!(swig.state.role_counter, 2); // Role counter should not change

    let updated_role = swig.get_role(1).unwrap().unwrap();
    assert_eq!(updated_role.position.num_actions(), 2); // Now has 2 actions

    // Verify the authority type and data remain the same
    assert_eq!(
        updated_role.authority.authority_type(),
        AuthorityType::Ed25519
    );
    assert_eq!(
        updated_role.authority.identity().unwrap(),
        second_authority.pubkey().as_ref()
    );
}

#[test_log::test]
fn test_update_authority_cannot_update_root() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig wallet with the root authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Try to update the root authority (ID 0) - should fail
    let result = update_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        0, // Try to update root authority
        vec![ClientAction::SolLimit(SolLimit { amount: 1000000 })],
    );

    // Verify the operation failed
    assert!(result.is_err(), "Updating root authority should fail");
}

#[test_log::test]
fn test_update_authority_nonexistent_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig wallet with the root authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Try to update a non-existent authority (ID 999) - should fail
    let result = update_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        999, // Non-existent authority ID
        vec![ClientAction::SolLimit(SolLimit { amount: 1000000 })],
    );

    // Verify the operation failed
    assert!(
        result.is_err(),
        "Updating non-existent authority should fail"
    );
}

#[test_log::test]
fn test_update_authority_permission_check() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig wallet with the root authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Add a second authority without ManageAuthority permission
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
        vec![ClientAction::SolLimit(SolLimit { amount: 500000 })], /* Only SolLimit, no
                                                                    * ManageAuthority */
    )
    .unwrap();

    // Add a third authority
    let third_authority = Keypair::new();
    context
        .svm
        .airdrop(&third_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: third_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthority(ManageAuthority {})],
    )
    .unwrap();

    // Try to update the third authority using the second authority (which lacks
    // ManageAuthority permission)
    let result = update_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &second_authority, // Using second authority without ManageAuthority permission
        2,                 // Update third authority
        vec![ClientAction::SolLimit(SolLimit { amount: 1000000 })],
    );

    // Verify the operation failed due to lack of permission
    assert!(
        result.is_err(),
        "Updating authority without ManageAuthority permission should fail"
    );
}

#[test_log::test]
fn test_update_authority_with_zero_actions() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig wallet with the root authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Add a second authority
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

    // Try to update the second authority with zero actions - should fail
    let result = update_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        1,      // Update second authority
        vec![], // Empty actions vector
    );

    // Verify the operation failed
    assert!(
        result.is_err(),
        "Updating authority with zero actions should fail"
    );
}

#[test_log::test]
fn test_update_authority_size_change() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig wallet with the root authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Add a second authority with one action
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

    // Add a third authority
    let third_authority = Keypair::new();
    context
        .svm
        .airdrop(&third_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: third_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 500000 })],
    )
    .unwrap();

    // Update the second authority to have more actions (size increase)
    update_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        1, // Update second authority
        vec![
            ClientAction::ManageAuthority(ManageAuthority {}),
            ClientAction::SolLimit(SolLimit { amount: 1000000 }),
            ClientAction::All(All {}),
        ],
    )
    .unwrap();

    // Verify all authorities are still accessible and correct
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 3);

    // Check that all roles are still accessible
    let role_0 = swig.get_role(0).unwrap().unwrap();
    let role_1 = swig.get_role(1).unwrap().unwrap();
    let role_2 = swig.get_role(2).unwrap().unwrap();

    // Verify the updated role has the correct number of actions
    assert_eq!(role_1.position.num_actions(), 3);

    // Verify the third authority wasn't affected
    assert_eq!(role_2.position.num_actions(), 1);
    assert_eq!(
        role_2.authority.identity().unwrap(),
        third_authority.pubkey().as_ref()
    );
}
