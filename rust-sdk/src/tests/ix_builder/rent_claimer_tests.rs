use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use solana_program::pubkey::Pubkey;
use solana_sdk::{
    message::{v0, VersionedMessage},
    signature::{Keypair, Signer},
    transaction::VersionedTransaction,
};
use swig_state::{swig::Swig, tail::rent_claimer};

use super::*;
use crate::{error::SwigError, Ed25519ClientRole, Secp256k1ClientRole};

#[test_log::test]
fn test_set_rent_claimer_with_ed25519_builder_sets_tail() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [41u8; 32];
    let authority = Keypair::new();
    let role_id = 0u32;
    let (swig_key, _, _) = create_swig_ed25519(&mut context, &authority, swig_id).unwrap();

    let builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
        context.default_payer.pubkey(),
        role_id,
    );

    let claimer = Keypair::new().pubkey();
    let set_ixs = builder.set_rent_claimer(claimer, None).unwrap();
    assert_eq!(set_ixs.len(), 1);

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &set_ixs,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &authority],
    )
    .unwrap();
    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "set rent claimer transaction failed: {:?}",
        result.err()
    );

    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let parts = Swig::split_parts(&swig_account.data).unwrap();
    let parsed = rent_claimer::read_strict(parts.tail).unwrap();
    assert_eq!(parsed, Some(&claimer.to_bytes()));
}

#[test_log::test]
fn test_set_rent_claimer_with_ed25519_builder_is_one_shot() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [42u8; 32];
    let authority = Keypair::new();
    let role_id = 0u32;
    let (_swig_key, _, _) = create_swig_ed25519(&mut context, &authority, swig_id).unwrap();

    let builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
        context.default_payer.pubkey(),
        role_id,
    );

    let first_ixs = builder
        .set_rent_claimer(Keypair::new().pubkey(), None)
        .unwrap();
    let first_msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &first_ixs,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let first_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(first_msg),
        &[&context.default_payer, &authority],
    )
    .unwrap();
    let first_result = context.svm.send_transaction(first_tx);
    assert!(first_result.is_ok(), "first set should succeed");

    let second_ixs = builder
        .set_rent_claimer(Keypair::new().pubkey(), None)
        .unwrap();
    let second_msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &second_ixs,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let second_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(second_msg),
        &[&context.default_payer, &authority],
    )
    .unwrap();
    let second_result = context.svm.send_transaction(second_tx);
    assert!(second_result.is_err(), "second set must fail (immutable)");
}

#[test_log::test]
fn test_set_rent_claimer_secp256k1_requires_current_slot() {
    let wallet = LocalSigner::random();
    let secp_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();

    let wallet_clone = wallet.clone();
    let signing_fn = move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet_clone.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    let builder = SwigInstructionBuilder::new(
        [43u8; 32],
        Box::new(Secp256k1ClientRole::new(secp_pubkey, Box::new(signing_fn))),
        Pubkey::new_unique(),
        0,
    );

    let err = builder
        .set_rent_claimer(Pubkey::new_unique(), None)
        .expect_err("secp256k1 set_rent_claimer should require current slot");
    assert!(matches!(err, SwigError::CurrentSlotNotSet));
}
