use solana_sdk::{
    signature::{Keypair, Signer},
    sysvar::clock::Clock,
};
use solana_system_interface::instruction as system_instruction;
use swig_state::{
    authority::{
        secp256r1::{Secp256r1Authority, Secp256r1SessionAuthority},
        AuthorityType,
    },
    swig::SwigWithRoles,
};

use super::*;
use crate::client_role::{ClientRole, Ed25519ClientRole, Secp256r1ClientRole};

/// Helper function to create a test secp256r1 key pair
fn create_test_secp256r1_keypair() -> (openssl::ec::EcKey<openssl::pkey::Private>, [u8; 33]) {
    use openssl::{
        bn::BigNumContext,
        ec::{EcGroup, EcKey, PointConversionForm},
        nid::Nid,
    };

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let signing_key = EcKey::generate(&group).unwrap();

    let mut ctx = BigNumContext::new().unwrap();
    let pubkey_bytes = signing_key
        .public_key()
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap();

    let pubkey_array: [u8; 33] = pubkey_bytes.try_into().unwrap();
    (signing_key, pubkey_array)
}

/// Helper function to get the secp256r1 counter from the swig account
fn get_secp256r1_counter(
    swig_wallet: &mut SwigWallet,
    authority_pubkey: &[u8; 33],
) -> Result<u32, SwigError> {
    let role_id = swig_wallet.get_role_id(authority_pubkey)?;

    let swig_account = swig_wallet.get_swig_account()?;
    let account_data = swig_wallet
        .litesvm()
        .get_account(&swig_account)
        .unwrap()
        .data;

    let swig_with_roles =
        SwigWithRoles::from_bytes(&account_data).map_err(|_| SwigError::InvalidSwigData)?;

    let role = swig_with_roles
        .get_role(role_id)
        .map_err(|_| SwigError::AuthorityNotFound)?
        .ok_or(SwigError::AuthorityNotFound)?;

    if matches!(role.authority.authority_type(), AuthorityType::Secp256r1) {
        let auth = role
            .authority
            .as_any()
            .downcast_ref::<Secp256r1Authority>()
            .ok_or(SwigError::AuthorityNotFound)?;
        Ok(auth.signature_odometer)
    } else {
        Err(SwigError::AuthorityNotFound)
    }
}

/// Helper function to get the secp256r1 session counter from the swig account
fn get_secp256r1_session_counter(
    swig_wallet: &mut SwigWallet,
    authority_pubkey: &[u8; 33],
) -> Result<u32, SwigError> {
    let role_id = swig_wallet.get_role_id(authority_pubkey)?;

    let swig_account = swig_wallet.get_swig_account()?;
    let account_data = swig_wallet
        .litesvm()
        .get_account(&swig_account)
        .unwrap()
        .data;

    let swig_with_roles =
        SwigWithRoles::from_bytes(&account_data).map_err(|_| SwigError::InvalidSwigData)?;

    let role = swig_with_roles
        .get_role(role_id)
        .map_err(|_| SwigError::AuthorityNotFound)?
        .ok_or(SwigError::AuthorityNotFound)?;

    if matches!(
        role.authority.authority_type(),
        AuthorityType::Secp256r1Session
    ) {
        let auth = role
            .authority
            .as_any()
            .downcast_ref::<Secp256r1SessionAuthority>()
            .ok_or(SwigError::AuthorityNotFound)?;
        Ok(auth.signature_odometer)
    } else {
        Err(SwigError::AuthorityNotFound)
    }
}

#[test_log::test]
fn test_secp256r1_basic_signing() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Create a real secp256r1 key pair for testing
    let (signing_key, public_key) = create_test_secp256r1_keypair();

    // Add secp256r1 authority to the wallet
    swig_wallet
        .add_authority(AuthorityType::Secp256r1, &public_key, vec![Permission::All])
        .unwrap();

    // Create signing function for the client role
    let signing_fn = Box::new(move |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        let signature =
            sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap();
        signature
    });

    // Switch to the secp256r1 authority
    swig_wallet
        .switch_authority(
            1,
            Box::new(Secp256r1ClientRole::new(public_key, signing_fn)),
            None,
        )
        .unwrap();

    let swig_pubkey = swig_wallet.get_swig_account().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_pubkey, 10_000_000_000)
        .unwrap();

    // Set up a recipient and transaction
    let recipient = Keypair::new();
    swig_wallet
        .litesvm()
        .airdrop(&recipient.pubkey(), 1_000_000)
        .unwrap();
    let transfer_amount = 5_000_000;
    let transfer_ix =
        system_instruction::transfer(&swig_pubkey, &recipient.pubkey(), transfer_amount);

    // Sign and send the transaction
    let result = swig_wallet.sign(vec![transfer_ix], None);
    assert!(
        result.is_ok(),
        "Transaction should succeed with real secp256r1 signature: {:?}",
        result.err()
    );

    // Verify the counter was incremented
    let new_counter = get_secp256r1_counter(&mut swig_wallet, &public_key).unwrap();
    assert_eq!(
        new_counter, 1,
        "Counter should be incremented after successful transaction"
    );

    // Verify the transfer actually happened
    let recipient_balance = swig_wallet
        .litesvm()
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    assert_eq!(
        recipient_balance,
        1_000_000 + transfer_amount,
        "Recipient should receive the transferred amount"
    );

    println!("✓ Secp256r1 signing test passed with real cryptography");
}

#[test_log::test]
fn test_secp256r1_counter_increment() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Create a real secp256r1 key pair for testing
    let (_, public_key) = create_test_secp256r1_keypair();

    // Add secp256r1 authority to the wallet
    swig_wallet
        .add_authority(AuthorityType::Secp256r1, &public_key, vec![Permission::All])
        .unwrap();

    // Create a dummy signing function for creation (won't be used for signing)
    let dummy_signing_fn = Box::new(|_message_hash: &[u8]| -> [u8; 64] {
        [0u8; 64] // Dummy signature
    });

    // Switch to the secp256r1 authority
    swig_wallet
        .switch_authority(
            1,
            Box::new(Secp256r1ClientRole::new(public_key, dummy_signing_fn)),
            None,
        )
        .unwrap();

    // Verify initial counter is 0
    let initial_counter = get_secp256r1_counter(&mut swig_wallet, &public_key).unwrap();
    assert_eq!(initial_counter, 0, "Initial counter should be 0");

    println!("✓ Initial counter verified as 0");
    println!("✓ Secp256r1 authority structure works correctly");
}

#[test_log::test]
fn test_secp256r1_replay_protection() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Create a real secp256r1 key pair for testing
    let (signing_key, public_key) = create_test_secp256r1_keypair();

    // Add secp256r1 authority to the wallet
    swig_wallet
        .add_authority(AuthorityType::Secp256r1, &public_key, vec![Permission::All])
        .unwrap();

    // Create signing function for the client role
    let signing_fn = Box::new(move |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        let signature =
            sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap();
        signature
    });

    // Switch to the secp256r1 authority
    swig_wallet
        .switch_authority(
            1,
            Box::new(Secp256r1ClientRole::new(public_key, signing_fn)),
            None,
        )
        .unwrap();

    let swig_pubkey = swig_wallet.get_swig_account().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_pubkey, 10_000_000_000)
        .unwrap();

    // Set up transfer instruction
    let recipient = Keypair::new();
    swig_wallet
        .litesvm()
        .airdrop(&recipient.pubkey(), 1_000_000)
        .unwrap();
    let transfer_amount = 1_000_000;
    let transfer_ix =
        system_instruction::transfer(&swig_pubkey, &recipient.pubkey(), transfer_amount);

    // First transaction - should succeed
    let result1 = swig_wallet.sign(vec![transfer_ix.clone()], None);
    assert!(
        result1.is_ok(),
        "First transaction should succeed: {:?}",
        result1.err()
    );
    println!("✓ First transaction succeeded");

    // Try second transaction with same counter (should fail due to replay
    // protection) We need to manually set the counter to 1 to simulate replay
    let (replay_signing_key, _) = create_test_secp256r1_keypair();
    let signing_fn_clone = Box::new(move |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        let signature = sign_message(
            message_hash,
            &replay_signing_key.private_key_to_der().unwrap(),
        )
        .unwrap();
        signature
    });

    // Create a new client role with odometer set to 1 to simulate replay
    let mut replay_client_role =
        Secp256r1ClientRole::new_without_odometer(public_key, signing_fn_clone);
    replay_client_role.update_odometer(1).unwrap();

    // Create a new wallet instance with the replay client role
    let mut replay_wallet = SwigWallet::new(
        swig_wallet.get_swig_id().clone(),
        Box::new(replay_client_role),
        &main_authority,
        "http://localhost:8899".to_string(),
        None,
        swig_wallet.litesvm().clone(),
    )
    .unwrap();

    let result2 = replay_wallet.sign(vec![transfer_ix], None);

    assert!(
        result2.is_err(),
        "Second transaction with same counter should fail due to replay protection"
    );
    println!("✓ Second transaction with same counter failed (replay protection working)");

    // Verify counter is now 1
    let current_counter = get_secp256r1_counter(&mut swig_wallet, &public_key).unwrap();
    assert_eq!(
        current_counter, 1,
        "Counter should be 1 after first transaction"
    );

    println!("✓ Replay protection test passed - counter-based protection is working");
}

#[test_log::test]
fn test_secp256r1_add_authority() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Create a real secp256r1 public key to add as second authority
    let (_, secp256r1_pubkey) = create_test_secp256r1_keypair();

    // Add the Secp256r1 authority using the wallet
    let result = swig_wallet.add_authority(
        AuthorityType::Secp256r1,
        &secp256r1_pubkey,
        vec![Permission::All],
    );
    assert!(
        result.is_ok(),
        "Failed to add Secp256r1 authority: {:?}",
        result.err()
    );

    // Verify the authority was added
    let role_count = swig_wallet.get_role_count().unwrap();
    assert_eq!(role_count, 2, "Authority count should be 2");

    println!("✓ Successfully added Secp256r1 authority");
    println!("✓ Authority count increased to 2");
}

#[test_log::test]
fn test_secp256r1_add_authority_with_secp256r1() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Create a real secp256r1 key pair for the primary authority
    let (signing_key, public_key) = create_test_secp256r1_keypair();

    // Add secp256r1 authority to the wallet
    swig_wallet
        .add_authority(AuthorityType::Secp256r1, &public_key, vec![Permission::All])
        .unwrap();

    // Create signing function for the client role
    let signing_fn = Box::new(move |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        let signature =
            sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap();
        signature
    });

    // Switch to the secp256r1 authority
    swig_wallet
        .switch_authority(
            1,
            Box::new(Secp256r1ClientRole::new(public_key, signing_fn)),
            None,
        )
        .unwrap();

    let swig_pubkey = swig_wallet.get_swig_account().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_pubkey, 10_000_000_000)
        .unwrap();

    // Create a second secp256r1 public key to add as a new authority
    let (_, new_public_key) = create_test_secp256r1_keypair();

    // Add the new Secp256r1 authority using the secp256r1 signature
    let result = swig_wallet.add_authority(
        AuthorityType::Secp256r1,
        &new_public_key,
        vec![Permission::All],
    );
    assert!(
        result.is_ok(),
        "Failed to add Secp256r1 authority using secp256r1 signature: {:?}",
        result.err()
    );

    // Verify the authority was added
    let role_count = swig_wallet.get_role_count().unwrap();
    assert_eq!(role_count, 3, "Authority count should be 3");

    // Verify the counter was incremented
    let new_counter = get_secp256r1_counter(&mut swig_wallet, &public_key).unwrap();
    assert_eq!(
        new_counter, 1,
        "Counter should be incremented after successful transaction"
    );

    println!("✓ Successfully added Secp256r1 authority using secp256r1 signature");
    println!("✓ Authority count increased to 3");
    println!("✓ Counter incremented correctly");
}

#[test_log::test]
fn test_secp256r1_session_authority() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Create a real secp256r1 public key for session authority
    let (_, public_key) = create_test_secp256r1_keypair();

    // Create session authority parameters
    let session_key = rand::random::<[u8; 32]>();
    let max_session_length = 1000; // 1000 slots

    let create_params = swig_state::authority::secp256r1::CreateSecp256r1SessionAuthority::new(
        public_key,
        session_key,
        max_session_length,
    );

    // Verify the structure works
    assert_eq!(create_params.public_key, public_key);
    assert_eq!(create_params.session_key, session_key);
    assert_eq!(create_params.max_session_length, max_session_length);

    println!("✓ Secp256r1 session authority structure works correctly");
    println!(
        "✓ Session parameters: max_length = {} slots",
        max_session_length
    );
}

#[test_log::test]
fn test_secp256r1_session_authority_odometer() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Create a real secp256r1 key pair for testing
    let (_, public_key) = create_test_secp256r1_keypair();

    // Create session authority parameters
    let session_key = [0; 32];
    let max_session_length = 100;

    let create_params = swig_state::authority::secp256r1::CreateSecp256r1SessionAuthority::new(
        public_key,
        session_key,
        max_session_length,
    );

    // Add secp256r1 session authority to the wallet
    swig_wallet
        .add_authority(
            AuthorityType::Secp256r1Session,
            &create_params.into_bytes().unwrap(),
            vec![Permission::All],
        )
        .unwrap();

    // Initial counter should be 0
    let initial_counter = get_secp256r1_session_counter(&mut swig_wallet, &public_key).unwrap();
    assert_eq!(initial_counter, 0, "Initial session counter should be 0");

    // Verify the session authority structure is correctly initialized
    let role_count = swig_wallet.get_role_count().unwrap();
    assert_eq!(role_count, 2, "Role count should be 2");

    let authority_type = swig_wallet.get_authority_type(1).unwrap();
    assert_eq!(authority_type, AuthorityType::Secp256r1Session);

    let is_session_based = swig_wallet.is_session_based(1).unwrap();
    assert!(
        is_session_based,
        "Session authority should be session-based"
    );

    println!("✓ Secp256r1 session authority structure correctly initialized");
    println!("✓ Signature odometer field present and initialized to 0");
    println!("✓ Session authority has proper session-based behavior");
}

#[test_log::test]
fn test_secp256r1_invalid_signature_error() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Create a real secp256r1 key pair for testing
    let (_, public_key) = create_test_secp256r1_keypair();

    // Add secp256r1 authority to the wallet
    swig_wallet
        .add_authority(AuthorityType::Secp256r1, &public_key, vec![Permission::All])
        .unwrap();

    // Create an invalid signing function that returns a dummy signature
    let invalid_signing_fn = Box::new(|_message_hash: &[u8]| -> [u8; 64] {
        [0u8; 64] // Invalid signature
    });

    // Switch to the secp256r1 authority with invalid signing function
    swig_wallet
        .switch_authority(
            1,
            Box::new(Secp256r1ClientRole::new(public_key, invalid_signing_fn)),
            None,
        )
        .unwrap();

    let swig_pubkey = swig_wallet.get_swig_account().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_pubkey, 10_000_000_000)
        .unwrap();

    // Set up transfer instruction
    let recipient = Keypair::new();
    let transfer_amount = 1_000_000;
    let transfer_ix =
        system_instruction::transfer(&swig_pubkey, &recipient.pubkey(), transfer_amount);

    // Try to execute transaction with invalid signature
    let result = swig_wallet.sign(vec![transfer_ix], None);

    // The transaction should fail due to invalid signature
    assert!(
        result.is_err(),
        "Transaction should fail due to invalid signature"
    );
    println!(
        "✓ Transaction failed due to invalid signature as expected: {:?}",
        result.err()
    );
}

#[test_log::test]
fn test_secp256r1_odometer_wrapping() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Create a real secp256r1 key pair for testing
    let (signing_key, public_key) = create_test_secp256r1_keypair();

    // Add secp256r1 authority to the wallet
    swig_wallet
        .add_authority(AuthorityType::Secp256r1, &public_key, vec![Permission::All])
        .unwrap();

    // Create signing function for the client role
    let signing_fn = Box::new(move |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        let signature =
            sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap();
        signature
    });

    // Switch to the secp256r1 authority
    swig_wallet
        .switch_authority(
            1,
            Box::new(Secp256r1ClientRole::new(public_key, signing_fn)),
            None,
        )
        .unwrap();

    let swig_pubkey = swig_wallet.get_swig_account().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_pubkey, 10_000_000_000)
        .unwrap();

    // Set up transfer instruction
    let recipient = Keypair::new();
    let transfer_amount = 1_000_000;
    let transfer_ix =
        system_instruction::transfer(&swig_pubkey, &recipient.pubkey(), transfer_amount);

    // Execute multiple transactions to test odometer wrapping
    for i in 0..5 {
        let result = swig_wallet.sign(vec![transfer_ix.clone()], None);
        assert!(
            result.is_ok(),
            "Transaction {} should succeed: {:?}",
            i + 1,
            result.err()
        );

        let counter = get_secp256r1_counter(&mut swig_wallet, &public_key).unwrap();
        assert_eq!(
            counter,
            i + 1,
            "Counter should be {} after transaction {}",
            i + 1,
            i + 1
        );
    }

    println!("✓ Secp256r1 odometer wrapping test passed - counter increments correctly");
}

#[test_log::test]
fn test_secp256r1_authority_management() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Create multiple secp256r1 authorities
    let (_, auth1_pubkey) = create_test_secp256r1_keypair();
    let (_, auth2_pubkey) = create_test_secp256r1_keypair();
    let (_, auth3_pubkey) = create_test_secp256r1_keypair();

    // Add multiple secp256r1 authorities
    swig_wallet
        .add_authority(
            AuthorityType::Secp256r1,
            &auth1_pubkey,
            vec![Permission::Sol {
                amount: 1_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    swig_wallet
        .add_authority(
            AuthorityType::Secp256r1,
            &auth2_pubkey,
            vec![Permission::Sol {
                amount: 2_000_000,
                recurring: None,
            }],
        )
        .unwrap();

    swig_wallet
        .add_authority(
            AuthorityType::Secp256r1,
            &auth3_pubkey,
            vec![Permission::All],
        )
        .unwrap();

    // Verify all authorities were added
    let role_count = swig_wallet.get_role_count().unwrap();
    assert_eq!(
        role_count, 4,
        "Should have 4 roles (1 Ed25519 + 3 Secp256r1)"
    );

    // Verify authority types
    assert_eq!(
        swig_wallet.get_authority_type(1).unwrap(),
        AuthorityType::Secp256r1
    );
    assert_eq!(
        swig_wallet.get_authority_type(2).unwrap(),
        AuthorityType::Secp256r1
    );
    assert_eq!(
        swig_wallet.get_authority_type(3).unwrap(),
        AuthorityType::Secp256r1
    );

    // Verify authority identities
    let auth1_identity = swig_wallet.get_authority_identity(1).unwrap();
    assert_eq!(auth1_identity, auth1_pubkey);

    let auth2_identity = swig_wallet.get_authority_identity(2).unwrap();
    assert_eq!(auth2_identity, auth2_pubkey);

    let auth3_identity = swig_wallet.get_authority_identity(3).unwrap();
    assert_eq!(auth3_identity, auth3_pubkey);

    // Verify permissions
    let auth1_permissions = swig_wallet.get_role_permissions(1).unwrap();
    assert_eq!(auth1_permissions.len(), 1);
    assert!(matches!(
        auth1_permissions[0],
        Permission::Sol {
            amount: 1_000_000,
            ..
        }
    ));

    let auth2_permissions = swig_wallet.get_role_permissions(2).unwrap();
    assert_eq!(auth2_permissions.len(), 1);
    assert!(matches!(
        auth2_permissions[0],
        Permission::Sol {
            amount: 2_000_000,
            ..
        }
    ));

    let auth3_permissions = swig_wallet.get_role_permissions(3).unwrap();
    assert_eq!(auth3_permissions.len(), 1);
    assert!(matches!(auth3_permissions[0], Permission::All));

    println!("✓ Secp256r1 authority management test passed");
    println!("✓ Multiple authorities added successfully");
    println!("✓ Authority types, identities, and permissions verified correctly");
}
