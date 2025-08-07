use solana_program::{system_instruction, system_program};
use solana_sdk::signature::{Keypair, Signer};
use swig_state::authority::AuthorityType;

use super::*;
use crate::{
    client_role::Ed25519ClientRole,
    types::{Permission, UpdateAuthorityData},
};

#[test_log::test]
fn should_add_program_all_permission() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let secondary_authority = Keypair::new();
    litesvm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Setup secondary authority with ProgramAll and ManageAuthority permissions
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![Permission::ProgramAll, Permission::ManageAuthority],
        )
        .unwrap();

    // Verify the authority was added with ProgramAll permission
    let role_id = swig_wallet
        .get_role_id(&secondary_authority.pubkey().to_bytes())
        .unwrap();

    let role_permissions = swig_wallet.get_role_permissions(role_id).unwrap();
    let has_program_all = role_permissions
        .iter()
        .any(|p| matches!(p, Permission::ProgramAll));

    assert!(has_program_all);
}

#[test_log::test]
fn should_combine_program_all_with_other_permissions() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let secondary_authority = Keypair::new();
    litesvm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Setup secondary authority with ProgramAll and SOL permissions
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![
                Permission::ProgramAll,
                Permission::Sol {
                    amount: 1_000_000, // 0.001 SOL
                    recurring: None,
                },
            ],
        )
        .unwrap();

    // Verify the authority was added with both permissions
    let role_id = swig_wallet
        .get_role_id(&secondary_authority.pubkey().to_bytes())
        .unwrap();

    let role_permissions = swig_wallet.get_role_permissions(role_id).unwrap();
    let has_program_all = role_permissions
        .iter()
        .any(|p| matches!(p, Permission::ProgramAll));

    let has_sol_permission = role_permissions
        .iter()
        .any(|p| matches!(p, Permission::Sol { .. }));

    assert!(has_program_all);
    assert!(has_sol_permission);
}

#[test_log::test]
fn should_allow_cpi_calls_with_program_all_permission() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let secondary_authority = Keypair::new();
    let recipient = Keypair::new();

    litesvm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();
    litesvm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Setup secondary authority with ProgramAll and SOL permissions
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![
                Permission::ProgramAll,
                Permission::Sol {
                    amount: 1_000_000, // 0.001 SOL
                    recurring: None,
                },
            ],
        )
        .unwrap();

    // Switch to secondary authority
    let role_id = swig_wallet
        .get_role_id(&secondary_authority.pubkey().to_bytes())
        .unwrap();

    swig_wallet
        .switch_authority(
            role_id,
            Box::new(Ed25519ClientRole::new(secondary_authority.pubkey())),
            Some(&secondary_authority),
        )
        .unwrap();

    // Airdrop funds to swig account
    let swig_account = swig_wallet.get_swig_account().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_account, 5_000_000_000)
        .unwrap();

    // Create a transfer instruction (this will be a CPI call)
    let transfer_ix = system_instruction::transfer(
        &swig_account,
        &recipient.pubkey(),
        500_000, // 0.0005 SOL
    );

    // Execute the transfer (this should work because of ProgramAll permission)
    let signature = swig_wallet.sign(vec![transfer_ix], None).unwrap();

    assert!(signature != solana_sdk::signature::Signature::default());
}

#[test_log::test]
fn should_remove_program_all_permission() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let secondary_authority = Keypair::new();
    litesvm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Setup secondary authority with ProgramAll permission
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![Permission::ProgramAll, Permission::ManageAuthority],
        )
        .unwrap();

    // Get the role ID for the secondary authority (should be 1, not 0)
    let secondary_role_id = swig_wallet
        .get_role_id(&secondary_authority.pubkey().to_bytes())
        .unwrap();

    println!("Secondary role ID: {}", secondary_role_id);

    // Remove ProgramAll permission
    swig_wallet
        .update_authority(
            secondary_role_id,
            crate::types::UpdateAuthorityData::RemoveActionsByType(vec![Permission::ProgramAll]),
        )
        .unwrap();

    // Verify the ProgramAll permission was removed
    let role_permissions = swig_wallet.get_role_permissions(secondary_role_id).unwrap();
    let has_program_all = role_permissions
        .iter()
        .any(|p| matches!(p, Permission::ProgramAll));

    assert!(!has_program_all);
}
