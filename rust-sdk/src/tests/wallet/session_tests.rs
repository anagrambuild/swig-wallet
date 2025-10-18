use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use solana_program::system_instruction;
use solana_sdk::signature::{Keypair, Signer};
use swig_state::authority::{
    ed25519::{CreateEd25519SessionAuthority, Ed25519SessionAuthority},
    secp256k1::{CreateSecp256k1SessionAuthority, Secp256k1SessionAuthority},
    secp256r1::{CreateSecp256r1SessionAuthority, Secp256r1SessionAuthority},
    AuthorityType,
};

use super::*;
use crate::client_role::{
    Ed25519SessionClientRole, Secp256k1SessionClientRole, Secp256r1SessionClientRole,
};

#[test_log::test]
fn should_create_ed25519_session_authority() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let session_key = Keypair::new();

    let mut swig_wallet = SwigWallet::new(
        [0; 32],
        Box::new(Ed25519SessionClientRole::new(
            main_authority.pubkey(),
            session_key.pubkey(),
            100,
        )),
        &main_authority,
        "http://localhost:8899".to_string(),
        Some(&main_authority),
        litesvm,
    )
    .unwrap();

    let swig_pubkey = swig_wallet.get_swig_account().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_pubkey, 10_000_000_000)
        .unwrap();

    let new_session_key = Keypair::new();
    swig_wallet
        .create_session(new_session_key.pubkey(), 100)
        .unwrap();

    // Verify session authority was created successfully
    assert!(swig_wallet.get_swig_account().is_ok());
    assert_eq!(swig_wallet.get_role_count().unwrap(), 1);
    assert!(swig_wallet.get_balance().unwrap() > 0);
}

#[test_log::test]
fn should_create_secp256k1_session_authority() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let wallet = LocalSigner::random();
    let secp_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();

    let sign_fn = move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    let swig_wallet = SwigWallet::new(
        [0; 32],
        Box::new(Secp256k1SessionClientRole::new(
            secp_pubkey[1..].try_into().unwrap(),
            Pubkey::new_from_array([0; 32]),
            100,
            Box::new(sign_fn),
        )),
        &main_authority,
        "http://localhost:8899".to_string(),
        None,
        litesvm,
    )
    .unwrap();

    // Verify session authority was created successfully
    assert!(swig_wallet.get_swig_account().is_ok());
    assert_eq!(swig_wallet.get_role_count().unwrap(), 1);
}

#[test_log::test]
fn should_create_ed25519_session_and_transfer() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let session_key = Keypair::new();
    let recipient = Keypair::new();

    litesvm
        .airdrop(&session_key.pubkey(), 10_000_000_000)
        .unwrap();
    let mut swig_wallet = SwigWallet::new(
        [0; 32],
        Box::new(Ed25519SessionClientRole::new(
            main_authority.pubkey(),
            session_key.pubkey(),
            100,
        )),
        &main_authority,
        "http://localhost:8899".to_string(),
        None,
        litesvm,
    )
    .unwrap();

    let swig_wallet_address = swig_wallet.get_swig_wallet_address().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

    // Create a new session
    swig_wallet
        .create_session(session_key.pubkey(), 100)
        .unwrap();

    // Switch payer to session key
    swig_wallet.switch_payer(&session_key).unwrap();

    // Transfer funds using the session
    let transfer_amount = 1_000_000_000; // 1 SOL
    let initial_balance = swig_wallet.get_balance().unwrap();

    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);
    let signature = swig_wallet.sign_v2(vec![transfer_ix], None).unwrap();

    // Verify the signature was created successfully
    assert!(signature != solana_sdk::signature::Signature::default());

    // Verify the transfer was successful
    let final_balance = swig_wallet.get_balance().unwrap();
    assert_eq!(final_balance, initial_balance - transfer_amount);

    // Verify recipient received the funds
    let recipient_balance = swig_wallet
        .litesvm()
        .get_balance(&recipient.pubkey())
        .unwrap();
    assert_eq!(recipient_balance, transfer_amount);
}

#[test_log::test]
fn should_create_secp256k1_session_and_transfer() {
    let (mut litesvm, _) = setup_test_environment();
    let wallet = LocalSigner::random();
    let secp_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();

    let sign_fn = move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    let session_key = Keypair::new();
    litesvm
        .airdrop(&session_key.pubkey(), 10_000_000_000)
        .unwrap();
    let mut swig_wallet = SwigWallet::new(
        [0; 32],
        Box::new(Secp256k1SessionClientRole::new(
            secp_pubkey[1..].try_into().unwrap(),
            session_key.pubkey(),
            100,
            Box::new(sign_fn),
        )),
        &session_key,
        "http://localhost:8899".to_string(),
        None,
        litesvm,
    )
    .unwrap();

    let swig_wallet_address = swig_wallet.get_swig_wallet_address().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

    // Create a new session
    swig_wallet
        .create_session(session_key.pubkey(), 100)
        .unwrap();

    // Switch payer to session key
    swig_wallet.switch_payer(&session_key).unwrap();

    // Transfer funds using the session
    let recipient = Keypair::new();
    let transfer_amount = 1_000_000_000; // 1 SOL
    let initial_balance = swig_wallet.get_balance().unwrap();

    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);
    let signature = swig_wallet.sign_v2(vec![transfer_ix], None).unwrap();

    // Verify the transfer was successful
    let final_balance = swig_wallet.get_balance().unwrap();
    assert_eq!(final_balance, initial_balance - transfer_amount);

    // Verify recipient received the funds
    let recipient_balance = swig_wallet
        .litesvm()
        .get_balance(&recipient.pubkey())
        .unwrap();
    assert_eq!(recipient_balance, transfer_amount);

    // Check expiry of session
    swig_wallet.litesvm().warp_to_slot(101);
    swig_wallet.litesvm().expire_blockhash();

    let transfer_ix = system_instruction::transfer(
        &swig_wallet_address,
        &recipient.pubkey(),
        transfer_amount - 500,
    );

    let signature = swig_wallet.sign_v2(vec![transfer_ix], None);
    assert!(signature.is_err());

    // restart session
    swig_wallet
        .create_session(session_key.pubkey(), 100)
        .unwrap();

    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    let signature = swig_wallet.sign_v2(vec![transfer_ix], None).unwrap();

    let final_final_balance = swig_wallet.get_balance().unwrap();
    assert_eq!(final_final_balance, final_balance - transfer_amount);
}

#[test_log::test]
fn should_create_secp256r1_session_and_transfer() {
    let (mut litesvm, _) = setup_test_environment();
    let (signing_key, secp_pubkey) = create_test_secp256r1_keypair();
    use solana_secp256r1_program::sign_message;

    let sign_fn = move |message_hash: &[u8]| -> [u8; 64] {
        sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap()
    };

    let session_key = Keypair::new();
    litesvm
        .airdrop(&session_key.pubkey(), 10_000_000_000)
        .unwrap();

    let mut swig_wallet = SwigWallet::new(
        [0; 32],
        Box::new(Secp256r1SessionClientRole::new(
            secp_pubkey,
            session_key.pubkey(),
            100,
            Box::new(sign_fn),
        )),
        &session_key,
        "http://localhost:8899".to_string(),
        None,
        litesvm,
    )
    .unwrap();

    let swig_wallet_address = swig_wallet.get_swig_wallet_address().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

    // Create a new session
    swig_wallet
        .create_session(session_key.pubkey(), 100)
        .unwrap();

    swig_wallet.switch_payer(&session_key).unwrap();

    println!("session_key: {:?}", session_key.pubkey().to_bytes());
    // Transfer funds using the session
    let recipient = Keypair::new();
    let transfer_amount = 1_000_000_000; // 1 SOL
    let initial_balance = swig_wallet.get_balance().unwrap();

    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    let signature = swig_wallet.sign_v2(vec![transfer_ix], None).unwrap();

    // Verify the transfer was successful
    let final_balance = swig_wallet.get_balance().unwrap();
    assert_eq!(final_balance, initial_balance - transfer_amount);

    // Verify recipient received the funds
    let recipient_balance = swig_wallet
        .litesvm()
        .get_balance(&recipient.pubkey())
        .unwrap();
    assert_eq!(recipient_balance, transfer_amount);

    // Check expiry of session
    swig_wallet.litesvm().warp_to_slot(101);
    swig_wallet.litesvm().expire_blockhash();

    let transfer_ix = system_instruction::transfer(
        &swig_wallet_address,
        &recipient.pubkey(),
        transfer_amount - 500,
    );

    let signature = swig_wallet.sign_v2(vec![transfer_ix], None);
    assert!(signature.is_err());

    // restart session
    swig_wallet
        .create_session(session_key.pubkey(), 100)
        .unwrap();

    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    let signature = swig_wallet.sign_v2(vec![transfer_ix], None).unwrap();

    let final_final_balance = swig_wallet.get_balance().unwrap();
    assert_eq!(final_final_balance, final_balance - transfer_amount);
}

#[test_log::test]
fn should_create_ed25519_session_and_transfer_multiple_times() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let session_key = Keypair::new();
    let recipients = vec![Keypair::new(), Keypair::new(), Keypair::new()];

    litesvm
        .airdrop(&session_key.pubkey(), 10_000_000_000)
        .unwrap();
    let mut swig_wallet = SwigWallet::new(
        [0; 32],
        Box::new(Ed25519SessionClientRole::new(
            main_authority.pubkey(),
            session_key.pubkey(),
            100,
        )),
        &main_authority,
        "http://localhost:8899".to_string(),
        None,
        litesvm,
    )
    .unwrap();

    let swig_wallet_address = swig_wallet.get_swig_wallet_address().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

    // Create a new session
    swig_wallet
        .create_session(session_key.pubkey(), 100)
        .unwrap();

    // Switch payer to session key
    swig_wallet.switch_payer(&session_key).unwrap();

    // Transfer funds multiple times using the session
    let transfer_amount = 500_000_000; // 0.5 SOL each
    let initial_balance = swig_wallet.get_balance().unwrap();

    for recipient in &recipients {
        let transfer_ix = system_instruction::transfer(
            &swig_wallet_address,
            &recipient.pubkey(),
            transfer_amount,
        );
        let signature = swig_wallet.sign_v2(vec![transfer_ix], None).unwrap();
        assert!(signature != solana_sdk::signature::Signature::default());
    }

    // Verify the transfers were successful
    let final_balance = swig_wallet.get_balance().unwrap();
    let expected_final_balance = initial_balance - (transfer_amount * recipients.len() as u64);
    assert_eq!(final_balance, expected_final_balance);

    // Verify all recipients received the funds
    for recipient in &recipients {
        let recipient_balance = swig_wallet
            .litesvm()
            .get_balance(&recipient.pubkey())
            .unwrap();
        assert_eq!(recipient_balance, transfer_amount);
    }
}

// Helper function to create a test secp256r1 key pair
fn create_test_secp256r1_keypair() -> (openssl::ec::EcKey<openssl::pkey::Private>, [u8; 33]) {
    use openssl::{
        bn::BigNumContext,
        ec::{EcGroup, EcKey, PointConversionForm},
        nid::Nid,
    };

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let signing_key = EcKey::generate(&group).unwrap();

    println!(
        "signing_key der: {:?}",
        hex::encode(signing_key.private_key_to_der().unwrap())
    );
    println!(
        "signing_key pem: {:?}",
        hex::encode(signing_key.private_key_to_pem().unwrap())
    );
    let mut ctx = BigNumContext::new().unwrap();
    let pubkey_bytes = signing_key
        .public_key()
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap();

    let pubkey_array: [u8; 33] = pubkey_bytes.try_into().unwrap();
    (signing_key, pubkey_array)
}

#[test_log::test]
fn should_create_secp256r1_session_and_transfer_with_different_authority() {
    let (mut litesvm, _) = setup_test_environment();
    let (signing_key, secp_pubkey) = create_test_secp256r1_keypair();
    use solana_secp256r1_program::sign_message;

    let sign_fn = move |message_hash: &[u8]| -> [u8; 64] {
        sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap()
    };

    let session_key = Keypair::new();
    litesvm
        .airdrop(&session_key.pubkey(), 10_000_000_000)
        .unwrap();

    let mut swig_wallet = SwigWallet::new(
        [0; 32],
        Box::new(Secp256r1SessionClientRole::new(
            secp_pubkey,
            session_key.pubkey(),
            100,
            Box::new(sign_fn),
        )),
        &session_key,
        "http://localhost:8899".to_string(),
        None,
        litesvm,
    )
    .unwrap();

    let swig_wallet_address = swig_wallet.get_swig_wallet_address().unwrap();
    swig_wallet
        .litesvm()
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

    // Create a new session
    swig_wallet
        .create_session(session_key.pubkey(), 100)
        .unwrap();

    swig_wallet.switch_payer(&session_key).unwrap();

    println!("session_key: {:?}", session_key.pubkey().to_bytes());
    // Transfer funds using the session
    let recipient = Keypair::new();
    let transfer_amount = 1_000_000_000; // 1 SOL
    let initial_balance = swig_wallet.get_balance().unwrap();

    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    let signature = swig_wallet.sign_v2(vec![transfer_ix], None).unwrap();

    // Verify the transfer was successful
    let final_balance = swig_wallet.get_balance().unwrap();
    assert_eq!(final_balance, initial_balance - transfer_amount);

    // Verify recipient received the funds
    let recipient_balance = swig_wallet
        .litesvm()
        .get_balance(&recipient.pubkey())
        .unwrap();
    assert_eq!(recipient_balance, transfer_amount);

    // Check expiry of session
    swig_wallet.litesvm().warp_to_slot(101);
    swig_wallet.litesvm().expire_blockhash();

    let transfer_ix = system_instruction::transfer(
        &swig_wallet_address,
        &recipient.pubkey(),
        transfer_amount - 500,
    );

    let signature = swig_wallet.sign_v2(vec![transfer_ix], None);
    assert!(signature.is_err());

    // restart session
    swig_wallet
        .create_session(session_key.pubkey(), 100)
        .unwrap();

    let sign_fn_2 = move |message_hash: &[u8]| -> [u8; 64] { [0; 64] };
    swig_wallet
        .switch_authority(
            0,
            Box::new(Secp256r1SessionClientRole::new(
                secp_pubkey,
                session_key.pubkey(),
                100,
                Box::new(sign_fn_2),
            )),
            Some(&session_key),
        )
        .unwrap();

    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    let signature = swig_wallet.sign_v2(vec![transfer_ix], None).unwrap();

    let final_final_balance = swig_wallet.get_balance().unwrap();
    assert_eq!(final_final_balance, final_balance - transfer_amount);
}
