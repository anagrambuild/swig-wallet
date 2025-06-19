use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use solana_sdk::signature::{Keypair, Signer};
use swig_state_x::authority::AuthorityType;

use super::*;
use crate::client_role::{Ed25519ClientRole, Secp256k1ClientRole};

#[test_log::test]
fn should_manage_authorities_successfully() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Add secondary authority with SOL permission
    let secondary_authority = Keypair::new();
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    // Verify both authorities exist
    swig_wallet.display_swig().unwrap();

    // Remove secondary authority
    swig_wallet
        .remove_authority(&secondary_authority.pubkey().to_bytes())
        .unwrap();

    swig_wallet.display_swig().unwrap();

    // Add third authority with recurring permissions
    let third_authority = Keypair::new();

    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &third_authority.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: Some(RecurringConfig::new(100)),
            }],
        )
        .unwrap();

    swig_wallet.display_swig().unwrap();

    // Switch to third authority
    swig_wallet
        .switch_authority(
            1,
            Box::new(Ed25519ClientRole::new(third_authority.pubkey())),
            None,
        )
        .unwrap();

    swig_wallet
        .authenticate_authority(&third_authority.pubkey().to_bytes())
        .unwrap();
}

#[test_log::test]
fn should_add_secp256k1_authority() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    let wallet = LocalSigner::random();
    println!("wallet: {:?}", wallet.address());

    let secp_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();

    let sec1_bytes = wallet.credential().verifying_key().to_sec1_bytes();
    let secp1_pubkey = sec1_bytes.as_ref();

    let authority_hex = hex::encode([&[0x4].as_slice(), secp1_pubkey].concat());
    let mut hasher = solana_sdk::keccak::Hasher::default();
    hasher.hash(authority_hex.as_bytes());
    let hash = hasher.result();
    let address = format!("0x{}", hex::encode(&hash.0[12..32]));
    println!("address: {:?}", address);

    println!(
        "\t\tAuthority Public Key: 0x{} address {}",
        authority_hex, address
    );
    println!("secp_pubkey length: {:?}", secp_pubkey);
    println!("secp1_pubkey length: {:?}", secp1_pubkey);

    // Add secondary authority with SOL permission
    swig_wallet
        .add_authority(
            AuthorityType::Secp256k1,
            &secp_pubkey.as_ref()[1..],
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    // Verify both authorities exist
    swig_wallet.display_swig().unwrap();

    // Remove secondary authority
    swig_wallet
        .remove_authority(&secp_pubkey.as_ref()[1..])
        .unwrap();

    swig_wallet.display_swig().unwrap();

    // Add third authority with recurring permissions
    let third_authority = Keypair::new();

    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &third_authority.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: Some(RecurringConfig::new(100)),
            }],
        )
        .unwrap();

    swig_wallet.display_swig().unwrap();

    // Switch to third authority
    swig_wallet
        .switch_authority(
            1,
            Box::new(Ed25519ClientRole::new(third_authority.pubkey())),
            None,
        )
        .unwrap();

    swig_wallet
        .authenticate_authority(&third_authority.pubkey().to_bytes())
        .unwrap();
}

#[test_log::test]
fn should_switch_authority_and_payer() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let secondary_authority = Keypair::new();
    litesvm
        .airdrop(&secondary_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Add and switch to secondary authority
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &secondary_authority.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: Some(RecurringConfig::new(100)),
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
    swig_wallet.display_swig().unwrap();
}

#[test_log::test]
fn should_replace_authority() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
    let old_authority = Keypair::new();
    let new_authority = Keypair::new();

    println!("old authority: {:?}", old_authority.pubkey());
    println!("new authority: {:?}", new_authority.pubkey());
    // Add old authority with SOL permission
    swig_wallet
        .add_authority(
            AuthorityType::Ed25519,
            &old_authority.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    // Verify old authority exists
    swig_wallet.display_swig().unwrap();

    // Replace old authority with new authority
    swig_wallet
        .replace_authority(
            1,
            AuthorityType::Ed25519,
            &new_authority.pubkey().to_bytes(),
            vec![Permission::Sol {
                amount: 5_000_000_000, // Different amount to verify the replacement
                recurring: None,
            }],
        )
        .unwrap();

    // Verify the replacement
    swig_wallet.display_swig().unwrap();

    // Try to authenticate with new authority (should succeed)
    assert!(swig_wallet
        .authenticate_authority(&new_authority.pubkey().to_bytes())
        .is_ok());

    // Try to authenticate with old authority (should fail)
    assert!(swig_wallet
        .authenticate_authority(&old_authority.pubkey().to_bytes())
        .is_err());
}
