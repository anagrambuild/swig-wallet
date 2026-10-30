use solana_sdk::{
    native_token::LAMPORTS_PER_SOL,
    signature::{Keypair, Signer},
};
use solana_system_interface::instruction as system_instruction;
use swig_state::tail::authorization_locks::NATIVE_SOL_MINT;

use super::*;
use crate::{client_role::Ed25519ClientRole, types::UpdateAuthorityData};

#[test_log::test]
fn should_lock_enforce_and_release_sol_through_wallet() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut wallet = create_test_wallet(litesvm, &main_authority);
    // Locking needs the explicit permission, even for the root `All` role.
    wallet
        .update_authority(
            0,
            UpdateAuthorityData::AddActions(vec![Permission::ManageAuthorizationLocks {
                max_duration_slots: 10_000,
            }]),
        )
        .unwrap();
    let wallet_address = wallet.get_swig_wallet_address().unwrap();
    wallet
        .litesvm()
        .airdrop(&wallet_address, 5 * LAMPORTS_PER_SOL)
        .unwrap();
    let slot = wallet.get_current_slot().unwrap();

    wallet
        .add_authorization_lock(
            wallet_address,
            NATIVE_SOL_MINT,
            4 * LAMPORTS_PER_SOL,
            slot + 1_000,
        )
        .unwrap();
    let locks = wallet.get_authorization_locks().unwrap();
    assert_eq!(locks.len(), 1);
    assert_eq!(locks[0].amount, 4 * LAMPORTS_PER_SOL);
    assert_eq!(locks[0].role_id, 0);

    let recipient = Keypair::new().pubkey();
    let overspend = system_instruction::transfer(&wallet_address, &recipient, 2 * LAMPORTS_PER_SOL);
    assert!(wallet.sign_v2(vec![overspend.clone()], None).is_err());

    wallet.remove_authorization_lock(locks[0].lock_id).unwrap();
    wallet.litesvm().expire_blockhash();
    assert!(wallet.get_authorization_locks().unwrap().is_empty());
    wallet.sign_v2(vec![overspend], None).unwrap();
}

#[test_log::test]
fn should_round_trip_manage_authorization_locks_permission() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut wallet = create_test_wallet(litesvm, &main_authority);
    let card = Keypair::new();
    wallet
        .add_authority(
            AuthorityType::Ed25519,
            card.pubkey().as_ref(),
            vec![
                Permission::ManageAuthorizationLocks {
                    max_duration_slots: 500,
                },
                Permission::Sol {
                    amount: LAMPORTS_PER_SOL,
                    recurring: None,
                },
            ],
        )
        .unwrap();
    wallet
        .litesvm()
        .airdrop(&card.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    wallet
        .switch_authority(
            1,
            Box::new(Ed25519ClientRole::new(card.pubkey())),
            Some(&card),
        )
        .unwrap();
    let permissions = wallet.get_role_permissions(1).unwrap();
    assert!(permissions.contains(&Permission::ManageAuthorizationLocks {
        max_duration_slots: 500
    }));

    let wallet_address = wallet.get_swig_wallet_address().unwrap();
    wallet
        .litesvm()
        .airdrop(&wallet_address, 2 * LAMPORTS_PER_SOL)
        .unwrap();
    let slot = wallet.get_current_slot().unwrap();
    // Beyond the role's duration bound.
    assert!(wallet
        .add_authorization_lock(wallet_address, NATIVE_SOL_MINT, 1, slot + 501)
        .is_err());
    // Beyond the role's SOL limit.
    assert!(wallet
        .add_authorization_lock(
            wallet_address,
            NATIVE_SOL_MINT,
            LAMPORTS_PER_SOL + 1,
            slot + 100
        )
        .is_err());
    wallet
        .add_authorization_lock(
            wallet_address,
            NATIVE_SOL_MINT,
            LAMPORTS_PER_SOL,
            slot + 100,
        )
        .unwrap();
    assert_eq!(wallet.get_authorization_locks().unwrap()[0].role_id, 1);
}
