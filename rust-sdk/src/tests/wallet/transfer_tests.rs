use solana_program::system_instruction;
use solana_sdk::signature::{Keypair, Signer};

use super::*;
use crate::client_role::Ed25519ClientRole;

#[test_log::test]
fn should_transfer_within_limits() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let secondary_authority = Keypair::new();
    litesvm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Setup secondary authority with permissions
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 1_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    swig_wallet
        .switch_authority(
            1,
            Box::new(Ed25519ClientRole::new(secondary_authority.pubkey())),
            None,
        )
        .unwrap();

    let swig_account = swig_wallet.get_swig_account().unwrap();
    let recipient = Keypair::new();

    // Airdrop funds to swig account
    swig_wallet
        .litesvm()
        .airdrop(&swig_account, 5_000_000_000)
        .unwrap();

    // Transfer within limits
    let transfer_ix = system_instruction::transfer(&swig_account, &recipient.pubkey(), 100_000_000);

    let signature = swig_wallet.sign(vec![transfer_ix], None).unwrap();
    println!("signature: {:?}", signature);

    swig_wallet.display_swig().unwrap();
}

#[test_log::test]
fn should_fail_transfer_beyond_limits() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let secondary_authority = Keypair::new();
    litesvm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Add secondary authority with limited SOL permission
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 1_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    swig_wallet
        .switch_authority(
            1,
            Box::new(Ed25519ClientRole::new(secondary_authority.pubkey())),
            None,
        )
        .unwrap();
    swig_wallet.switch_payer(&secondary_authority).unwrap();

    // Attempt transfer beyond limits
    let recipient = Keypair::new();
    let transfer_ix = system_instruction::transfer(
        &swig_wallet.get_swig_account().unwrap(),
        &recipient.pubkey(),
        2_000_000_000, // Amount greater than permission limit
    );

    assert!(swig_wallet.sign(vec![transfer_ix], None).is_err());
}

#[test_log::test]
fn should_get_role_id() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let authority_2 = Keypair::new();
    let authority_3 = Keypair::new();

    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &authority_2.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &authority_3.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    swig_wallet.display_swig().unwrap();
    let role_id = swig_wallet
        .get_role_id(&authority_3.pubkey().to_bytes())
        .unwrap();
    println!("role_id: {:?}", role_id);
    assert_eq!(role_id, 2);
}
