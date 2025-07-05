use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use solana_sdk::signature::{Keypair, Signer};
use swig_state::authority::{
    ed25519::{CreateEd25519SessionAuthority, Ed25519SessionAuthority},
    secp256k1::{CreateSecp256k1SessionAuthority, Secp256k1SessionAuthority},
    AuthorityType,
};

use super::*;
use crate::client_role::{Ed25519SessionClientRole, Secp256k1SessionClientRole};

#[test_log::test]
fn should_create_ed25519_session_authority() {
    let (mut litesvm, main_authority) = setup_test_environment();
    let session_key = Keypair::new();

    let mut swig_wallet = SwigWallet::new(
        [0; 32],
        Box::new(Ed25519SessionClientRole::new(
            CreateEd25519SessionAuthority::new(
                main_authority.pubkey().to_bytes(),
                session_key.pubkey().to_bytes(),
                100,
            ),
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
            CreateSecp256k1SessionAuthority::new(
                secp_pubkey[1..].try_into().unwrap(),
                [0; 32],
                100,
            ),
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
