use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use solana_sdk::signature::{Keypair, Signer};

use super::*;

#[test_log::test]
fn should_create_ed25519_wallet() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);

    // Verify wallet was created successfully
    assert!(swig_wallet.get_swig_config_address().is_ok());
    assert_eq!(swig_wallet.get_role_count().unwrap(), 1);
    assert_eq!(swig_wallet.get_current_role_id().unwrap(), 0);

    let swig_pubkey = swig_wallet.get_swig_config_address().unwrap();
    let swig_data = swig_wallet.litesvm().get_account(&swig_pubkey).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_data.data).unwrap();

    assert_eq!(swig_with_roles.state.id, [0; 32]);
}

#[test_log::test]
fn should_create_secp256k1_wallet() {
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
        let tsig = wallet
            .sign_hash_sync(&hash)
            .map_err(|_| SwigError::InvalidSecp256k1)
            .unwrap()
            .as_bytes();
        let mut sig = [0u8; 65];
        sig.copy_from_slice(&tsig);
        sig
    };

    let swig_wallet = SwigWallet::builder()
        .with_swig_id([0; 32])
        .with_client_role(Box::new(Secp256k1ClientRole::new(
            secp_pubkey,
            Box::new(sign_fn),
        )))
        .with_fee_payer(&main_authority)
        .with_rpc_url("http://localhost:8899".to_string())
        .with_authority_keypair(Some(&main_authority))
        .with_litesvm(litesvm)
        .create()
        .unwrap();

    // Verify wallet was created successfully
    assert!(swig_wallet.get_swig_config_address().is_ok());
    assert_eq!(swig_wallet.get_role_count().unwrap(), 1);
    assert_eq!(swig_wallet.get_current_role_id().unwrap(), 0);
}
