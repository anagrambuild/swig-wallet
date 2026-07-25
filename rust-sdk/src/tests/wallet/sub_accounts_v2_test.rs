//! SDK-level integration tests for V2 sub-accounts via the `SwigWallet` API.
use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use solana_sdk::signature::{Keypair, Signer};
use swig_state::{authority::AuthorityType, swig::sub_account_v2_asset_seeds};

use super::*;
use crate::client_role::{Ed25519ClientRole, Secp256k1ClientRole};

/// Adds a creator authority (SubAccountV2Create), switches to it, and creates a
/// V2 sub-account. Returns (secondary_keypair, subacc_id, asset_pda).
fn create_v2_setup<'a>(swig_wallet: &mut SwigWallet<'a>, secondary: &'a Keypair) -> (u32, Pubkey) {
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary.pubkey().to_bytes(),
            vec![Permission::SubAccountV2Create],
        )
        .unwrap();
    swig_wallet
        .switch_authority(
            1,
            Box::new(Ed25519ClientRole::new(secondary.pubkey())),
            Some(secondary),
        )
        .unwrap();
    let (_sig, subacc_id) = swig_wallet.create_sub_account_v2().unwrap();
    let (asset, _) = Pubkey::find_program_address(
        &sub_account_v2_asset_seeds(swig_wallet.get_swig_id(), &subacc_id.to_le_bytes()),
        &swig_interface::program_id(),
    );
    (subacc_id, asset)
}

#[test_log::test]
fn test_v2_creation_and_counter() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
    let secondary = Keypair::new();

    assert_eq!(swig_wallet.get_sub_account_v2_counter().unwrap(), 0);
    let (subacc_id, _asset) = create_v2_setup(&mut swig_wallet, &secondary);
    assert_eq!(subacc_id, 0);
    assert_eq!(swig_wallet.get_sub_account_v2_counter().unwrap(), 1);
    assert!(swig_wallet.get_sub_account_v2(0).unwrap().is_some());
    assert!(swig_wallet.get_sub_account_v2(5).unwrap().is_none());
}

#[test_log::test]
fn test_v2_sign_and_withdraw() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
    let secondary = Keypair::new();
    let (subacc_id, asset) = create_v2_setup(&mut swig_wallet, &secondary);

    swig_wallet.litesvm().airdrop(&asset, 100_000_000).unwrap();
    let recipient = Keypair::new();

    // Sign a transfer out of the asset PDA.
    let transfer =
        solana_system_interface::instruction::transfer(&asset, &recipient.pubkey(), 1_000_000);
    swig_wallet
        .sign_with_sub_account_v2(subacc_id, vec![transfer], None)
        .unwrap();
    assert_eq!(
        swig_wallet
            .litesvm()
            .get_balance(&recipient.pubkey())
            .unwrap(),
        1_000_000
    );

    // Withdraw SOL back to the swig wallet address.
    let before = swig_wallet.litesvm().get_balance(&asset).unwrap();
    swig_wallet
        .withdraw_from_sub_account_v2(subacc_id, 500_000)
        .unwrap();
    let after = swig_wallet.litesvm().get_balance(&asset).unwrap();
    assert_eq!(before - after, 500_000);
}

#[test_log::test]
fn test_v2_toggle_blocks_ops() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
    let secondary = Keypair::new();
    let (subacc_id, asset) = create_v2_setup(&mut swig_wallet, &secondary);
    swig_wallet.litesvm().airdrop(&asset, 100_000_000).unwrap();

    // Disable the sub-account.
    swig_wallet.toggle_sub_account_v2(subacc_id, false).unwrap();

    // Withdrawing from a disabled sub-account must fail.
    assert!(swig_wallet
        .withdraw_from_sub_account_v2(subacc_id, 1_000)
        .is_err());

    // Re-enable and withdraw succeeds (distinct amount to avoid a duplicate tx).
    swig_wallet.toggle_sub_account_v2(subacc_id, true).unwrap();
    assert!(swig_wallet
        .withdraw_from_sub_account_v2(subacc_id, 2_000)
        .is_ok());
}

#[test_log::test]
fn test_v2_all_authority_cannot_create() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
    let secondary = Keypair::new();

    // Grant only All — not SubAccountV2Create.
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary.pubkey().to_bytes(),
            vec![Permission::All],
        )
        .unwrap();
    swig_wallet
        .switch_authority(
            1,
            Box::new(Ed25519ClientRole::new(secondary.pubkey())),
            Some(&secondary),
        )
        .unwrap();

    assert!(
        swig_wallet.create_sub_account_v2().is_err(),
        "All alone must not create a V2 sub-account"
    );
}

#[test_log::test]
fn test_v2_secp256k1_sign() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // An ed25519 creator makes sub-account 0.
    let creator = Keypair::new();
    let (subacc_id, asset) = create_v2_setup(&mut swig_wallet, &creator);

    // Grant a Secp256k1 authority scoped Sign{0} (sharing, done by root).
    swig_wallet
        .switch_authority(
            0,
            Box::new(Ed25519ClientRole::new(main_authority.pubkey())),
            Some(&main_authority),
        )
        .unwrap();
    let secp_wallet = PrivateKeySigner::random();
    let secp_pubkey = secp_wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes()
        .as_ref()[1..]
        .to_vec();
    swig_wallet
        .add_authority(
            AuthorityType::Secp256k1,
            &secp_pubkey,
            vec![Permission::SubAccountV2Sign { subacc_id }],
        )
        .unwrap();

    // Switch to the Secp256k1 authority (role 2) and sign.
    let secp_role = swig_wallet.get_role_id(&secp_pubkey).unwrap();
    let signing_fn = Box::new(move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        secp_wallet
            .sign_hash_sync(&B256::from(hash))
            .unwrap()
            .as_bytes()
    });
    swig_wallet
        .switch_authority(
            secp_role,
            Box::new(Secp256k1ClientRole::new(
                secp_pubkey.clone().into(),
                signing_fn,
            )),
            None,
        )
        .unwrap();

    swig_wallet.litesvm().airdrop(&asset, 100_000_000).unwrap();
    let recipient = Keypair::new();
    let transfer =
        solana_system_interface::instruction::transfer(&asset, &recipient.pubkey(), 1_000_000);
    swig_wallet
        .sign_with_sub_account_v2(subacc_id, vec![transfer], None)
        .unwrap();
    assert_eq!(
        swig_wallet
            .litesvm()
            .get_balance(&recipient.pubkey())
            .unwrap(),
        1_000_000
    );
}

// NOTE: A Secp256k1/r1 `create_sub_account_v2` test is intentionally omitted.
// The create instruction includes the fee payer as a signer account in the
// Secp signature's account payload, and the on-chain reconstruction of that
// payload for a signer account currently diverges from the client builder,
// causing the recovered key to mismatch. Secp runtime ops that carry no signer
// account (sign, above) verify correctly. Resolving Secp create is tracked as a
// follow-up; Ed25519 create is fully covered above.
