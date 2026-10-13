use swig_interface::program_id;

use super::*;
use crate::{
    reservation::{ReservationAddressOptions, ReservationV1},
    SwigInstructionBuilder,
};

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
    svm.airdrop(&a.swig_address, 10_000_000).unwrap();
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
    assert_eq!(
        wallet.litesvm().get_balance(&a.swig_address),
        Some(10_000_000)
    );
    assert_eq!(wallet.get_swig_id(), &a.commitment);
    let legacy_child = Pubkey::find_program_address(
        &swig_state::swig::sub_account_seeds(&a.commitment, &0u32.to_le_bytes()),
        &program_id(),
    )
    .0;
    wallet.litesvm().airdrop(&legacy_child, 1_000_000).unwrap();
    assert!(matches!(
        wallet.get_sub_account(),
        Err(SwigError::ReservedWalletRequiresSubAccountV2)
    ));
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
    let other_owner = Keypair::new();
    let add_owner = swig_interface::AddAuthorityInstruction::new_with_ed25519_authority(
        a.swig_address,
        payer.pubkey(),
        owner.pubkey(),
        0,
        swig_interface::AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: other_owner.pubkey().as_ref(),
        },
        Permission::to_client_actions(vec![Permission::All]).unwrap(),
    )
    .unwrap();
    let transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[add_owner],
        Some(&payer.pubkey()),
        &[&payer, &owner],
        wallet.litesvm().latest_blockhash(),
    );
    wallet.litesvm().send_transaction(transaction).unwrap();
    let before = wallet.litesvm().get_account(&a.swig_address).unwrap();
    let svm = wallet.litesvm().clone();
    let payer_balance = svm.get_balance(&payer.pubkey());
    let mut reopened = SwigWallet::from_reservation(
        reservation,
        Box::new(Ed25519ClientRole::new(other_owner.pubkey())),
        &payer,
        "http://unused.invalid".into(),
        Some(&other_owner),
        svm,
    )
    .unwrap();
    assert_eq!(
        reopened.litesvm().get_account(&a.swig_address).unwrap(),
        before
    );
    assert_eq!(reopened.current_role.role_id, 1);
    assert_eq!(
        reopened.litesvm().get_balance(&payer.pubkey()),
        payer_balance
    );
    reopened
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
        reopened.litesvm().get_account(&recipient).unwrap().lamports,
        3_000_000
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
    let reopen_key = key.clone();
    let role = Secp256r1ClientRole::new(
        public,
        Box::new(move |hash| {
            solana_secp256r1_program::sign_message(hash, &key.private_key_to_der().unwrap())
                .unwrap()
        }),
    );
    let mut wallet = SwigWallet::from_reservation(
        reservation.clone(),
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
    let mut svm = wallet.litesvm().clone();
    svm.expire_blockhash();
    let payer_balance = svm.get_balance(&payer.pubkey());
    let role = Secp256r1ClientRole::new(
        public,
        Box::new(move |hash| {
            solana_secp256r1_program::sign_message(hash, &reopen_key.private_key_to_der().unwrap())
                .unwrap()
        }),
    );
    let mut reopened = SwigWallet::from_reservation(
        reservation,
        Box::new(role),
        &payer,
        "http://unused.invalid".into(),
        None,
        svm,
    )
    .unwrap();
    assert_eq!(reopened.get_odometer().unwrap(), 1);
    assert_eq!(
        reopened.litesvm().get_balance(&payer.pubkey()),
        payer_balance
    );
    reopened
        .sign_v2(
            vec![solana_system_interface::instruction::transfer(
                &a.wallet_address,
                &recipient,
                1_000_000,
            )],
            None,
        )
        .unwrap();
    assert_eq!(reopened.get_odometer().unwrap(), 2);
    assert_eq!(
        reopened.litesvm().get_account(&recipient).unwrap().lamports,
        3_000_000
    );
}

#[test]
fn reservation_builder_preserves_activation_when_payer_or_authority_changes() {
    let owner = Keypair::new();
    let reservation = ReservationV1::new(
        program_id(),
        AuthorityType::Ed25519,
        owner.pubkey().as_ref(),
        Default::default(),
    )
    .unwrap();
    let payer = Pubkey::new_unique();
    let mut builder = SwigInstructionBuilder::from_reservation(
        reservation.clone(),
        Box::new(Ed25519ClientRole::new(owner.pubkey())),
        payer,
        0,
    )
    .unwrap();
    let (expected, addresses) = reservation.create_instruction(payer).unwrap();
    assert_eq!(builder.build_swig_account().unwrap(), expected);
    assert_eq!(builder.get_swig_account().unwrap(), addresses.swig_address);
    let next_payer = Pubkey::new_unique();
    builder.switch_payer(next_payer).unwrap();
    builder
        .switch_authority(1, Box::new(Ed25519ClientRole::new(Pubkey::new_unique())))
        .unwrap();
    let (expected, _) = reservation.create_instruction(next_payer).unwrap();
    assert_eq!(builder.build_swig_account().unwrap(), expected);
    assert_eq!(builder.get_swig_account().unwrap(), addresses.swig_address);
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

#[test]
fn reservation_namespace_is_distinct_and_rejects_v1_subaccount_builders() {
    let owner = Keypair::new();
    let reservation = ReservationV1::new(
        program_id(),
        AuthorityType::Ed25519,
        owner.pubkey().as_ref(),
        Default::default(),
    )
    .unwrap();
    let addresses = reservation.addresses().unwrap();
    let reserved = SwigInstructionBuilder::from_reservation(
        reservation,
        Box::new(Ed25519ClientRole::new(owner.pubkey())),
        owner.pubkey(),
        0,
    )
    .unwrap();
    let legacy = SwigInstructionBuilder::new(
        addresses.commitment,
        Box::new(Ed25519ClientRole::new(owner.pubkey())),
        owner.pubkey(),
        0,
    );
    assert!(reserved.is_reserved());
    assert!(!legacy.is_reserved());
    assert_eq!(reserved.get_swig_id(), legacy.get_swig_id());
    assert_ne!(
        reserved.get_swig_account().unwrap(),
        legacy.get_swig_account().unwrap()
    );
    assert_ne!(reserved.swig_wallet_address(), legacy.swig_wallet_address());
    assert_ne!(
        reserved.sub_account_v2_pdas(0),
        legacy.sub_account_v2_pdas(0)
    );
    let child = Pubkey::new_unique();
    for result in [
        reserved.create_sub_account(None),
        reserved.sign_instruction_with_sub_account(vec![], None),
        reserved.withdraw_from_sub_account(child, 1, None),
        reserved.withdraw_token_from_sub_account(child, child, child, child, 1, None),
        reserved.toggle_sub_account(child, 0, 0, true, None),
    ] {
        assert!(matches!(
            result,
            Err(SwigError::ReservedWalletRequiresSubAccountV2)
        ));
    }
    assert!(legacy.create_sub_account(None).is_ok());
}

#[test]
fn reservation_open_rejects_invalid_existing_accounts_without_activation() {
    use swig_state::{swig::Swig, tail::TAIL_HEADER_LEN};
    let (svm, payer) = setup_test_environment();
    let owner = Keypair::new();
    let reservation = ReservationV1::new(
        program_id(),
        AuthorityType::Ed25519,
        owner.pubkey().as_ref(),
        Default::default(),
    )
    .unwrap();
    let addresses = reservation.addresses().unwrap();
    let mut wallet = SwigWallet::from_reservation(
        reservation.clone(),
        Box::new(Ed25519ClientRole::new(owner.pubkey())),
        &payer,
        "http://unused.invalid".into(),
        Some(&owner),
        svm,
    )
    .unwrap();
    let valid = wallet
        .litesvm()
        .get_account(&addresses.swig_address)
        .unwrap();
    let roles_end = Swig::roles_end_offset(&valid.data).unwrap();
    // An unfunded payer makes accidental activation fail with a transaction
    // error. Opening a valid wallet must work without any payer funds.
    let unfunded_payer = Keypair::new();
    let mut opened = SwigWallet::from_reservation(
        reservation.clone(),
        Box::new(Ed25519ClientRole::new(owner.pubkey())),
        &unfunded_payer,
        "http://unused.invalid".into(),
        Some(&owner),
        wallet.litesvm().clone(),
    )
    .unwrap();
    assert_eq!(
        opened
            .litesvm()
            .get_account(&addresses.swig_address)
            .unwrap(),
        valid
    );
    assert!(matches!(
        opened.get_sub_account(),
        Err(SwigError::ReservedWalletRequiresSubAccountV2)
    ));
    for case in [0, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12] {
        let mut corrupted = valid.clone();
        match case {
            0 => corrupted.owner = Pubkey::new_unique(),
            1 => corrupted.owner = solana_system_interface::program::ID,
            3 => corrupted.data[0] = 255,
            4 => corrupted.data.truncate(1),
            5 => corrupted.data[1] ^= 1,
            6 => corrupted.data[2] ^= 1,
            7 => corrupted.data[40] ^= 1,
            8 => corrupted.data[41] ^= 1,
            9 => corrupted.data.truncate(roles_end),
            10 => corrupted.data[roles_end + TAIL_HEADER_LEN] ^= 1,
            11 => corrupted.data[roles_end + 1] = 2,
            _ => corrupted.data.extend_from_slice(&valid.data[roles_end..]),
        }
        let mut svm = wallet.litesvm().clone();
        svm.set_account(addresses.swig_address, corrupted).unwrap();
        let result = SwigWallet::from_reservation(
            reservation.clone(),
            Box::new(Ed25519ClientRole::new(owner.pubkey())),
            &unfunded_payer,
            "http://unused.invalid".into(),
            Some(&owner),
            svm,
        );
        assert!(
            matches!(result, Err(SwigError::InvalidSwigData)),
            "case {case}"
        );
    }
}
