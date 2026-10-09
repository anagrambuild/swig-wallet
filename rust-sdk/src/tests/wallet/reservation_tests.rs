use super::*;
use crate::{
    reservation::{ReservationAddressOptions, ReservationV1},
    SwigInstructionBuilder,
};
use swig_interface::program_id;

#[test]
fn reservation_wallet_creates_signs_and_reopens_at_reserved_address() {
    let (mut svm, payer) = setup_test_environment();
    let owner = Keypair::new();
    let reservation = ReservationV1::new(
        program_id(),
        AuthorityType::Ed25519,
        owner.pubkey().as_ref(),
        ReservationAddressOptions::default(),
    )
    .unwrap();
    let a = reservation.addresses().unwrap();
    svm.airdrop(&a.wallet_address, 10_000_000).unwrap();
    let recipient = Pubkey::new_unique();
    svm.airdrop(&recipient, 1_000_000).unwrap();
    let mut wallet = SwigWallet::from_reservation(
        reservation.clone(),
        Box::new(Ed25519ClientRole::new(owner.pubkey())),
        &payer,
        "http://unused.invalid".into(),
        Some(&owner),
        svm,
    )
    .unwrap();
    assert_eq!(wallet.get_swig_account().unwrap(), a.swig_address);
    assert_eq!(wallet.get_swig_wallet_address().unwrap(), a.wallet_address);
    wallet
        .sign_v2(
            vec![solana_system_interface::instruction::transfer(
                &a.wallet_address,
                &recipient,
                1_000_000,
            )],
            None,
        )
        .unwrap();
    assert_eq!(
        wallet.litesvm().get_account(&recipient).unwrap().lamports,
        2_000_000
    );
    let before = wallet.litesvm().get_account(&a.swig_address).unwrap();
    let mut svm = wallet.litesvm().clone();
    svm.expire_blockhash();
    let mut reopened = SwigWallet::from_reservation(
        reservation,
        Box::new(Ed25519ClientRole::new(owner.pubkey())),
        &payer,
        "http://unused.invalid".into(),
        Some(&owner),
        svm,
    )
    .unwrap();
    assert_eq!(
        reopened.litesvm().get_account(&a.swig_address).unwrap(),
        before
    );
}

#[test]
fn reservation_wallet_p256_activation_sets_sufficient_compute_budget() {
    use openssl::{
        bn::BigNumContext,
        ec::{EcGroup, EcKey, PointConversionForm},
        nid::Nid,
    };
    let (svm, payer) = setup_test_environment();
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    let public: [u8; 33] = key
        .public_key()
        .to_bytes(
            &group,
            PointConversionForm::COMPRESSED,
            &mut BigNumContext::new().unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap();
    let reservation = ReservationV1::new(
        program_id(),
        AuthorityType::Secp256r1,
        &public,
        ReservationAddressOptions::default(),
    )
    .unwrap();
    let a = reservation.addresses().unwrap();
    let role = Secp256r1ClientRole::new(
        public,
        Box::new(move |hash| {
            solana_secp256r1_program::sign_message(hash, &key.private_key_to_der().unwrap())
                .unwrap()
        }),
    );
    let mut wallet = SwigWallet::from_reservation(
        reservation,
        Box::new(role),
        &payer,
        "http://unused.invalid".into(),
        None,
        svm,
    )
    .unwrap();
    assert_eq!(wallet.get_swig_account().unwrap(), a.swig_address);
    assert_eq!(wallet.get_odometer().unwrap(), 0);
    let recipient = Pubkey::new_unique();
    wallet
        .litesvm()
        .airdrop(&a.wallet_address, 5_000_000)
        .unwrap();
    wallet.litesvm().airdrop(&recipient, 1_000_000).unwrap();
    wallet
        .sign_v2(
            vec![solana_system_interface::instruction::transfer(
                &a.wallet_address,
                &recipient,
                1_000_000,
            )],
            None,
        )
        .unwrap();
    assert_eq!(
        wallet.litesvm().get_account(&recipient).unwrap().lamports,
        2_000_000
    );
    assert_eq!(wallet.get_odometer().unwrap(), 1);
}

#[test]
fn reservation_builder_rejects_wrong_program_and_modified_bytes() {
    let owner = Keypair::new();
    for wrong_program in [false, true] {
        let mut reservation = ReservationV1::new(
            if wrong_program {
                Pubkey::new_unique()
            } else {
                program_id()
            },
            AuthorityType::Ed25519,
            owner.pubkey().as_ref(),
            Default::default(),
        )
        .unwrap();
        if !wrong_program {
            reservation.package_bytes.push(0);
        }
        assert!(SwigInstructionBuilder::from_reservation(
            reservation,
            Box::new(Ed25519ClientRole::new(owner.pubkey())),
            owner.pubkey(),
            0
        )
        .is_err());
    }
}
