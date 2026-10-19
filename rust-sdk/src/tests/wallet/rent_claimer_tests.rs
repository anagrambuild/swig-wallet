use solana_sdk::signature::{Keypair, Signer};
use swig_state::{swig::Swig, tail::rent_claimer};

use super::*;
use crate::client_role::Ed25519ClientRole;

#[test_log::test]
fn should_set_rent_claimer_through_wallet() {
    let (litesvm, main_authority) = setup_test_environment();

    let mut swig_wallet = SwigWallet::new(
        [7; 32],
        Box::new(Ed25519ClientRole::new(main_authority.pubkey())),
        &main_authority,
        "http://localhost:8899".to_string(),
        Some(&main_authority),
        litesvm,
    )
    .unwrap();

    let claimer = Keypair::new().pubkey();
    swig_wallet.set_rent_claimer(claimer).unwrap();

    let swig_pubkey = swig_wallet.get_swig_account().unwrap();
    let swig_account = swig_wallet.litesvm().get_account(&swig_pubkey).unwrap();
    let parts = Swig::split_parts(&swig_account.data).unwrap();
    let parsed = rent_claimer::read_strict(parts.tail).unwrap();
    assert_eq!(parsed, Some(&claimer.to_bytes()));
}

#[test_log::test]
fn should_reject_second_rent_claimer_through_wallet() {
    let (litesvm, main_authority) = setup_test_environment();

    let mut swig_wallet = SwigWallet::new(
        [8; 32],
        Box::new(Ed25519ClientRole::new(main_authority.pubkey())),
        &main_authority,
        "http://localhost:8899".to_string(),
        Some(&main_authority),
        litesvm,
    )
    .unwrap();

    swig_wallet
        .set_rent_claimer(Keypair::new().pubkey())
        .unwrap();
    let second = swig_wallet.set_rent_claimer(Keypair::new().pubkey());
    assert!(second.is_err(), "rent claimer should be immutable");
}

#[test_log::test]
fn resizing_routes_refunds_to_the_configured_claimer_through_wallet() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut wallet = create_test_wallet(litesvm, &main_authority);
    let delegate = Keypair::new();
    let claimer = Keypair::new().pubkey();
    wallet.litesvm().airdrop(&claimer, 1_000_000).unwrap();
    wallet
        .add_authority(
            AuthorityType::Ed25519,
            delegate.pubkey().as_ref(),
            vec![
                Permission::ManageAuthority {},
                Permission::Sol {
                    amount: 1,
                    recurring: None,
                },
            ],
        )
        .unwrap();
    wallet.set_rent_claimer(claimer).unwrap();
    let swig = wallet.get_swig_account().unwrap();
    wallet.litesvm().airdrop(&swig, 1_000_000_000).unwrap();
    let rent = wallet.litesvm().get_sysvar::<solana_sdk::rent::Rent>();
    let mut before = wallet.litesvm().get_account(&swig).unwrap();
    let mut claimer_before = wallet.litesvm().get_balance(&claimer).unwrap();
    wallet
        .update_authority(
            1,
            crate::types::UpdateAuthorityData::RemoveActionsByIndex(vec![1]),
        )
        .unwrap();
    let after = wallet.litesvm().get_account(&swig).unwrap();
    assert_eq!(
        wallet.litesvm().get_balance(&claimer).unwrap() - claimer_before,
        rent.minimum_balance(before.data.len()) - rent.minimum_balance(after.data.len())
    );
    assert_eq!(
        after.lamports - rent.minimum_balance(after.data.len()),
        before.lamports - rent.minimum_balance(before.data.len())
    );
    before = after;
    claimer_before = wallet.litesvm().get_balance(&claimer).unwrap();
    wallet.remove_authority(delegate.pubkey().as_ref()).unwrap();
    let after = wallet.litesvm().get_account(&swig).unwrap();
    assert_eq!(
        wallet.litesvm().get_balance(&claimer).unwrap() - claimer_before,
        rent.minimum_balance(before.data.len()) - rent.minimum_balance(after.data.len())
    );
    assert_eq!(
        after.lamports - rent.minimum_balance(after.data.len()),
        before.lamports - rent.minimum_balance(before.data.len())
    );
}
