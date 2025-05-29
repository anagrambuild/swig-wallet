use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use solana_sdk::signature::{Keypair, Signer};

use super::*;

#[test_log::test]
fn should_create_ed25519_wallet() {
    let (litesvm, main_authority) = setup_test_environment();
    let mut swig_wallet = create_test_wallet(litesvm, &main_authority);
    swig_wallet.display_swig().unwrap();

    let swig_pubkey = swig_wallet.get_swig_account().unwrap();
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

    let swig_wallet = SwigWallet::new(
        [0; 32],
        AuthorityManager::Secp256k1(secp_pubkey, Box::new(sign_fn)),
        &main_authority,
        &main_authority,
        "http://localhost:8899".to_string(),
        litesvm,
    )
    .unwrap();

    swig_wallet.display_swig().unwrap();
}
