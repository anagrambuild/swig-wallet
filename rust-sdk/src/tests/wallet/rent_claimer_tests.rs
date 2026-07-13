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
