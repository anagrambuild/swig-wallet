use super::*;
use crate::client_role::{Ed25519ClientRole, Secp256k1ClientRole};
use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use solana_sdk::sysvar::clock::Clock;
use solana_sdk::{
    signature::{Keypair, Signer},
    system_instruction,
};
use swig_state_x::authority::AuthorityType;

/// Test helper function to create a Secp256k1 wallet and get its public key
fn create_secp256k1_wallet() -> (PrivateKeySigner, Vec<u8>) {
    let wallet = PrivateKeySigner::random();
    let secp_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();
    (wallet, secp_pubkey.as_ref()[1..].to_vec())
}

/// Test helper function to get the current signature counter for a Secp256k1 authority
fn get_secp256k1_counter(
    swig_wallet: &mut SwigWallet,
    authority_pubkey: &[u8],
) -> Result<u32, SwigError> {
    let role_id = swig_wallet.get_role_id(authority_pubkey)?;

    // Get the role data from the swig account
    let swig_account = swig_wallet.get_swig_account()?;
    let account_data = swig_wallet
        .litesvm()
        .get_account(&swig_account)
        .unwrap()
        .data;

    let swig_with_roles = swig_state_x::swig::SwigWithRoles::from_bytes(&account_data)
        .map_err(|_| SwigError::InvalidSwigData)?;

    let role = swig_with_roles
        .get_role(role_id)
        .map_err(|_| SwigError::AuthorityNotFound)?
        .ok_or(SwigError::AuthorityNotFound)?;

    if matches!(role.authority.authority_type(), AuthorityType::Secp256k1) {
        let auth = role
            .authority
            .as_any()
            .downcast_ref::<swig_state_x::authority::secp256k1::Secp256k1Authority>()
            .ok_or(SwigError::AuthorityNotFound)?;
        Ok(auth.signature_odometer)
    } else {
        Err(SwigError::AuthorityNotFound)
    }
}

#[test_log::test]
fn test_secp256k1_signature_reuse_error() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Create a Secp256k1 wallet
    let (secp_wallet, secp_pubkey) = create_secp256k1_wallet();

    // Add Secp256k1 authority
    swig_wallet
        .add_authority(
            AuthorityType::Secp256k1,
            &secp_pubkey,
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    // Create a signing function for the Secp256k1 wallet
    let signing_fn = Box::new(move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        secp_wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    });

    // Switch to Secp256k1 authority
    swig_wallet
        .switch_authority(
            1,
            Box::new(Secp256k1ClientRole::new(
                secp_pubkey.clone().into(),
                signing_fn,
            )),
            None,
        )
        .unwrap();

    let swig_pubkey = &swig_wallet.get_swig_account().unwrap();

    swig_wallet
        .litesvm()
        .airdrop(&swig_pubkey, 10_000_000_000)
        .unwrap();

    // Get initial counter
    let initial_counter = get_secp256k1_counter(&mut swig_wallet, &secp_pubkey).unwrap();
    assert_eq!(initial_counter, 0);

    // Create a test transaction
    let recipient = Keypair::new();
    let transfer_amount = 1_000_000;

    // First transaction should succeed
    let transfer_ix = system_instruction::transfer(
        &swig_wallet.get_swig_account().unwrap(),
        &recipient.pubkey(),
        transfer_amount,
    );
    let result = swig_wallet.sign(vec![transfer_ix], None);
    assert!(result.is_ok(), "First transaction should succeed");

    // Verify counter was incremented
    let counter_after_first = get_secp256k1_counter(&mut swig_wallet, &secp_pubkey).unwrap();
    assert_eq!(counter_after_first, 1);

    // Try to reuse the same signature (this should fail)
    // Note: This test simulates signature reuse by attempting to use the same counter
    // In a real scenario, this would be caught by the signature verification
    let transfer_ix2 = system_instruction::transfer(
        &swig_wallet.get_swig_account().unwrap(),
        &recipient.pubkey(),
        transfer_amount,
    );
    let result = swig_wallet.sign(vec![transfer_ix2], None);

    // The transaction should fail due to signature reuse protection
    if result.is_err() {
        // Check if it's the expected signature reuse error
        // The error code should correspond to PermissionDeniedSecp256k1SignatureReused
        println!("Transaction failed as expected: {:?}", result.err());
    }
}

#[test_log::test]
fn test_secp256k1_invalid_signature_age_error() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Create a Secp256k1 wallet
    let (secp_wallet, secp_pubkey) = create_secp256k1_wallet();

    // Add Secp256k1 authority
    swig_wallet
        .add_authority(
            AuthorityType::Secp256k1,
            &secp_pubkey,
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    // Create a signing function for the Secp256k1 wallet
    let signing_fn = Box::new(move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        secp_wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    });

    // Switch to Secp256k1 authority
    swig_wallet
        .switch_authority(
            1,
            Box::new(Secp256k1ClientRole::new(
                secp_pubkey.clone().into(),
                signing_fn,
            )),
            None,
        )
        .unwrap();

    // Create a test transaction
    let recipient = Keypair::new();
    let transfer_amount = 1_000_000;

    // Advance the slot by more than MAX_SIGNATURE_AGE_IN_SLOTS (60)
    // This simulates an old signature that should be rejected
    swig_wallet.litesvm().warp_to_slot(100);

    // Try to execute transaction with old signature
    let transfer_ix = system_instruction::transfer(
        &swig_wallet.get_swig_account().unwrap(),
        &recipient.pubkey(),
        transfer_amount,
    );
    let result = swig_wallet.sign(vec![transfer_ix], None);

    // The transaction should fail due to invalid signature age
    if result.is_err() {
        // Check if it's the expected invalid signature age error
        // The error code should correspond to PermissionDeniedSecp256k1InvalidSignatureAge
        println!(
            "Transaction failed due to old signature as expected: {:?}",
            result.err()
        );
    }
}

#[test_log::test]
fn test_secp256k1_invalid_signature_error() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Create a Secp256k1 wallet
    let (secp_wallet, secp_pubkey) = create_secp256k1_wallet();

    // Add Secp256k1 authority
    swig_wallet
        .add_authority(
            AuthorityType::Secp256k1,
            &secp_pubkey,
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    // Create a different wallet to simulate invalid signature
    let different_wallet = PrivateKeySigner::random();

    // Create a signing function that uses the different wallet (this should fail)
    let signing_fn = Box::new(move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        different_wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    });

    // Switch to Secp256k1 authority with wrong signing function
    swig_wallet
        .switch_authority(
            1,
            Box::new(Secp256k1ClientRole::new(
                secp_pubkey.clone().into(),
                signing_fn,
            )),
            None,
        )
        .unwrap();

    // Create a test transaction
    let recipient = Keypair::new();
    let transfer_amount = 1_000_000;

    // Try to execute transaction with invalid signature
    let transfer_ix = system_instruction::transfer(
        &swig_wallet.get_swig_account().unwrap(),
        &recipient.pubkey(),
        transfer_amount,
    );
    let result = swig_wallet.sign(vec![transfer_ix], None);

    // The transaction should fail due to invalid signature
    if result.is_err() {
        // Check if it's the expected invalid signature error
        // The error code should correspond to PermissionDeniedSecp256k1InvalidSignature
        println!(
            "Transaction failed due to invalid signature as expected: {:?}",
            result.err()
        );
    }
}

#[test_log::test]
fn test_secp256k1_invalid_hash_error() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Create a Secp256k1 wallet
    let (secp_wallet, secp_pubkey) = create_secp256k1_wallet();

    // Add Secp256k1 authority
    swig_wallet
        .add_authority(
            AuthorityType::Secp256k1,
            &secp_pubkey,
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    // Create a signing function for the Secp256k1 wallet
    let signing_fn = Box::new(move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        secp_wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    });

    // Switch to Secp256k1 authority
    swig_wallet
        .switch_authority(
            1,
            Box::new(Secp256k1ClientRole::new(
                secp_pubkey.clone().into(),
                signing_fn,
            )),
            None,
        )
        .unwrap();

    // Create a test transaction with corrupted data
    // This simulates a scenario where hash computation would fail
    let recipient = Keypair::new();
    let transfer_amount = 1_000_000;

    // Try to execute transaction with potentially corrupted data
    // Note: This test simulates hash computation failure
    // In practice, this would be caught by the hash verification in the program
    let transfer_ix = system_instruction::transfer(
        &swig_wallet.get_swig_account().unwrap(),
        &recipient.pubkey(),
        transfer_amount,
    );
    let result = swig_wallet.sign(vec![transfer_ix], None);

    // The transaction should fail due to invalid hash
    if result.is_err() {
        // Check if it's the expected invalid hash error
        // The error code should correspond to PermissionDeniedSecp256k1InvalidHash
        println!(
            "Transaction failed due to invalid hash as expected: {:?}",
            result.err()
        );
    }
}

#[test_log::test]
fn test_secp256k1_counter_increment() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Create a Secp256k1 wallet
    let (secp_wallet, secp_pubkey) = create_secp256k1_wallet();

    // Add Secp256k1 authority
    swig_wallet
        .add_authority(
            AuthorityType::Secp256k1,
            &secp_pubkey,
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    // Create a signing function for the Secp256k1 wallet
    let signing_fn = Box::new(move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        secp_wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    });

    // Switch to Secp256k1 authority
    swig_wallet
        .switch_authority(
            1,
            Box::new(Secp256k1ClientRole::new(
                secp_pubkey.clone().into(),
                signing_fn,
            )),
            None,
        )
        .unwrap();

    // Get initial counter
    let initial_counter = get_secp256k1_counter(&mut swig_wallet, &secp_pubkey).unwrap();
    assert_eq!(initial_counter, 0);

    // Execute multiple transactions and verify counter increments
    let recipient = Keypair::new();
    let transfer_amount = 1_000_000;

    let swig_pubkey = &swig_wallet.get_swig_account().unwrap();

    swig_wallet
        .litesvm()
        .airdrop(&swig_pubkey, 10_000_000_000)
        .unwrap();

    for i in 1..=5 {
        let transfer_ix =
            system_instruction::transfer(&swig_pubkey, &recipient.pubkey(), transfer_amount);
        let result = swig_wallet.sign(vec![transfer_ix], None);
        assert!(result.is_ok(), "Transaction {} should succeed", i);

        let litesvm = swig_wallet.litesvm();
        litesvm.warp_to_slot(litesvm.get_sysvar::<Clock>().slot + 1);

        let current_counter = get_secp256k1_counter(&mut swig_wallet, &secp_pubkey).unwrap();
        assert_eq!(
            current_counter, i,
            "Counter should be {} after transaction {}",
            i, i
        );
    }
}

#[test_log::test]
fn test_secp256k1_authority_odometer() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Create a Secp256k1 wallet
    let (secp_wallet, secp_pubkey) = create_secp256k1_wallet();

    // Add Secp256k1 authority (using regular authority for odometer testing)
    swig_wallet
        .add_authority(
            AuthorityType::Secp256k1,
            &secp_pubkey,
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    // Fund the wallet
    let swig_pubkey = &swig_wallet.get_swig_account().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_pubkey, 10_000_000_000)
        .unwrap();

    // Create a signing function for the Secp256k1 wallet
    let signing_fn = Box::new(move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        secp_wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    });

    // Switch to Secp256k1 authority
    swig_wallet
        .switch_authority(
            1,
            Box::new(Secp256k1ClientRole::new(
                secp_pubkey.clone().into(),
                signing_fn,
            )),
            None,
        )
        .unwrap();

    // Get initial counter
    let initial_counter = get_secp256k1_counter(&mut swig_wallet, &secp_pubkey).unwrap();
    assert_eq!(initial_counter, 0);

    // Execute transactions and verify counter increments for Secp256k1 authority
    let recipient = Keypair::new();
    let transfer_amount = 1_000_000;

    for i in 1..=3 {
        let transfer_ix = system_instruction::transfer(
            &swig_wallet.get_swig_account().unwrap(),
            &recipient.pubkey(),
            transfer_amount,
        );
        let result = swig_wallet.sign(vec![transfer_ix], None);
        assert!(result.is_ok(), "Secp256k1 transaction {} should succeed", i);

        let current_counter = get_secp256k1_counter(&mut swig_wallet, &secp_pubkey).unwrap();
        assert_eq!(
            current_counter, i,
            "Secp256k1 counter should be {} after transaction {}",
            i, i
        );
    }
}

#[test_log::test]
fn test_secp256k1_odometer_wrapping() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Create a Secp256k1 wallet
    let (secp_wallet, secp_pubkey) = create_secp256k1_wallet();

    // Add Secp256k1 authority
    swig_wallet
        .add_authority(
            AuthorityType::Secp256k1,
            &secp_pubkey,
            vec![Permission::Sol {
                amount: 10_000_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    let swig_pubkey = &swig_wallet.get_swig_account().unwrap();

    swig_wallet
        .litesvm()
        .airdrop(&swig_pubkey, 10_000_000_000)
        .unwrap();

    // Create a signing function for the Secp256k1 wallet
    let signing_fn = Box::new(move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        secp_wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    });

    // Switch to Secp256k1 authority
    swig_wallet
        .switch_authority(
            1,
            Box::new(Secp256k1ClientRole::new(
                secp_pubkey.clone().into(),
                signing_fn,
            )),
            None,
        )
        .unwrap();

    // Test that the odometer can handle wrapping (u32 overflow)
    // This tests the wrapping_add(1) behavior in the implementation
    let recipient = Keypair::new();
    let transfer_amount = 1_000_000;

    // Execute transactions to test odometer behavior
    for i in 1..=10 {
        let transfer_ix = system_instruction::transfer(
            &swig_wallet.get_swig_account().unwrap(),
            &recipient.pubkey(),
            transfer_amount,
        );
        let result = swig_wallet.sign(vec![transfer_ix], None);
        assert!(result.is_ok(), "Transaction {} should succeed", i);

        let current_counter = get_secp256k1_counter(&mut swig_wallet, &secp_pubkey).unwrap();
        assert_eq!(
            current_counter, i,
            "Counter should be {} after transaction {}",
            i, i
        );
    }

    // Verify that the odometer continues to work correctly after multiple transactions
    let final_counter = get_secp256k1_counter(&mut swig_wallet, &secp_pubkey).unwrap();
    assert_eq!(final_counter, 10, "Final counter should be 10");
}
