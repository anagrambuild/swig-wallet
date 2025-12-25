use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use solana_program::{pubkey::Pubkey, system_instruction};
use solana_sdk::{
    message::{v0, VersionedMessage},
    signature::{Keypair, Signer},
    transaction::VersionedTransaction,
};
use swig_interface::{program_id, AddAuthorityInstruction, AuthorityConfig, ClientAction};
use swig_state::{
    action::program_all::ProgramAll,
    authority::AuthorityType,
    swig::{swig_account_seeds, SwigWithRoles},
};

use super::*;
use crate::client_role::{Ed25519ClientRole, Secp256k1ClientRole};

#[test_log::test]
fn test_add_program_all_permission_with_ed25519() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [1u8; 32];
    let authority = Keypair::new();
    let new_authority = Keypair::new();

    // Create swig account
    let (swig, swig_wallet_address, _) =
        create_swig_ed25519(&mut context, &authority, swig_id).unwrap();

    // Add a new authority with ProgramAll permission
    let add_authority_ix = AddAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        authority.pubkey(),
        1, // role_id for the root authority
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ProgramAll(ProgramAll::new())],
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(result.is_ok());

    // Verify the authority was added with ProgramAll permission
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();

    // Find the new authority's role
    let mut found_role = None;
    for i in 0..swig_with_roles.state.role_counter {
        if let Some(role) = swig_with_roles.get_role(i).unwrap() {
            if role.authority.identity().unwrap() == new_authority.pubkey().to_bytes() {
                found_role = Some(role);
                break;
            }
        }
    }

    assert!(found_role.is_some());
    let role = found_role.unwrap();

    // Check that ProgramAll permission exists
    let has_program_all = swig_state::role::Role::get_action::<ProgramAll>(&role, &[])
        .unwrap()
        .is_some();

    assert!(has_program_all);
}

#[test_log::test]
fn test_add_program_all_permission_with_secp256k1() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [2u8; 32];
    let authority = Keypair::new();
    let new_wallet = LocalSigner::random();
    let new_secp_pubkey_full = new_wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();
    let new_secp_pubkey = &new_secp_pubkey_full[1..]; // Remove the 0x04 prefix

    // Create swig account
    let (swig, swig_wallet_address, _) =
        create_swig_ed25519(&mut context, &authority, swig_id).unwrap();

    // Add a new authority with ProgramAll permission
    let add_authority_ix = AddAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        authority.pubkey(),
        1, // role_id for the root authority
        AuthorityConfig {
            authority_type: AuthorityType::Secp256k1,
            authority: &new_secp_pubkey,
        },
        vec![ClientAction::ProgramAll(ProgramAll::new())],
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(result.is_ok());

    // Verify the authority was added with ProgramAll permission
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();

    // Find the new authority's role
    let found_role = swig_with_roles.lookup_role_id(new_secp_pubkey).unwrap();
    println!("found_role {:?}", found_role);

    assert!(found_role.is_some());
    let role_id = found_role.unwrap();
    let role = swig_with_roles.get_role(role_id).unwrap().unwrap();

    // Check that ProgramAll permission exists
    let has_program_all = swig_state::role::Role::get_action::<ProgramAll>(&role, &[])
        .unwrap()
        .is_some();

    assert!(has_program_all);
}

#[test_log::test]
fn test_program_all_combines_with_other_permissions() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [3u8; 32];
    let authority = Keypair::new();
    let new_authority = Keypair::new();

    // Create swig account
    let (swig, swig_wallet_address, _) =
        create_swig_ed25519(&mut context, &authority, swig_id).unwrap();

    // Add a new authority with ProgramAll and SOL permissions
    let add_authority_ix = AddAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        authority.pubkey(),
        1, // role_id for the root authority
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ProgramAll(ProgramAll::new()),
            ClientAction::SolLimit(swig_state::action::sol_limit::SolLimit {
                amount: 1_000_000, // 0.001 SOL
            }),
        ],
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(result.is_ok());

    // Verify the authority was added with both permissions
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account.data).unwrap();

    // Find the new authority's role
    let mut found_role = None;
    for i in 0..swig_with_roles.state.role_counter {
        if let Some(role) = swig_with_roles.get_role(i).unwrap() {
            if role.authority.identity().unwrap() == new_authority.pubkey().to_bytes() {
                found_role = Some(role);
                break;
            }
        }
    }

    assert!(found_role.is_some());
    let role = found_role.unwrap();

    // Check that ProgramAll permission exists
    let has_program_all = swig_state::role::Role::get_action::<ProgramAll>(&role, &[])
        .unwrap()
        .is_some();

    assert!(has_program_all);

    // Check that SOL permission exists
    let has_sol_permission =
        swig_state::role::Role::get_action::<swig_state::action::sol_limit::SolLimit>(&role, &[])
            .unwrap()
            .is_some();

    assert!(has_sol_permission);
}
