use crate::Ed25519ClientRole;
use crate::Secp256k1ClientRole;

use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use solana_program::pubkey::Pubkey;
use solana_sdk::{
    message::{v0, VersionedMessage},
    signature::{Keypair, Signer},
    transaction::VersionedTransaction,
};
use swig_interface::program_id;
use swig_state::{
    authority::AuthorityType,
    swig::{swig_account_seeds, SwigWithRoles},
};

use super::*;

#[test_log::test]
fn test_add_authority_with_ed25519_root() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [3u8; 32];
    let authority = Keypair::new();
    let role_id = 0;

    // First create the Swig account
    let (swig_key, _) = create_swig_ed25519(&mut context, &authority, swig_id).unwrap();

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
        context.default_payer.pubkey(),
        role_id,
    );

    let new_authority = Keypair::new();
    let new_authority_bytes = new_authority.pubkey().to_bytes();
    let permissions = vec![Permission::Sol {
        amount: 100000 / 2,
        recurring: None,
    }];

    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    let add_auth_ix = builder
        .add_authority_instruction(
            AuthorityType::Ed25519,
            &new_authority_bytes,
            permissions,
            Some(current_slot),
        )
        .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &add_auth_ix,
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
        "Failed to add authority: {:?}",
        result.err()
    );

    // Verify the new authority was added
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_data.state.roles, 2); // Root authority + new authority
}

#[test_log::test]
fn test_add_authority_with_secp256k1_root() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [7u8; 32];
    let payer = &context.default_payer;
    let role_id = 0;

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

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Secp256k1ClientRole::new(secp_pubkey, Box::new(signing_fn))),
        payer.pubkey(),
        role_id,
    );

    let ix = builder.build_swig_account().unwrap();
    let msg = v0::Message::try_compile(&payer.pubkey(), &[ix], &[], context.svm.latest_blockhash())
        .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to create Swig account: {:?}",
        result.err()
    );

    let swig_key = builder.get_swig_account().unwrap();

    let new_authority = LocalSigner::random();
    let secp_pubkey_bytes = new_authority
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();

    let permissions = vec![Permission::Sol {
        amount: 1_000_000_000,
        recurring: None,
    }];

    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    // Get current counter for the signing wallet (not the new authority being
    // added)
    let current_counter = get_secp256k1_counter_from_wallet(&context, &swig_key, &wallet).unwrap();

    let add_auth_ix = builder
        .add_authority_instruction(
            AuthorityType::Secp256k1,
            &secp_pubkey_bytes,
            permissions,
            Some(current_slot),
        )
        .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &add_auth_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&context.default_payer])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to add authority: {:?}",
        result.err()
    );

    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_data.state.roles, 2); // Root authority + new authority
}

#[test_log::test]
fn test_remove_authority_with_ed25519_root() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [8u8; 32];
    let authority = Keypair::new();
    let authority_pubkey = authority.pubkey();
    let role_id = 0;

    let (swig_key, _) = create_swig_ed25519(&mut context, &authority, swig_id).unwrap();

    let new_authority = Keypair::new();
    let permissions = vec![Permission::Sol {
        amount: 1_000_000_000,
        recurring: None,
    }];

    let payer = &context.default_payer;

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
        payer.pubkey(),
        role_id,
    );

    let add_auth_ix = builder
        .add_authority_instruction(
            AuthorityType::Ed25519,
            &authority_pubkey.to_bytes(),
            permissions,
            None,
        )
        .unwrap();

    let msg = v0::Message::try_compile(
        &payer.pubkey(),
        &add_auth_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&payer, &authority]).unwrap();
    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to add authority: {:?}",
        result.err()
    );

    let remove_auth_ix = builder.remove_authority(1, None).unwrap();
    let msg = v0::Message::try_compile(
        &payer.pubkey(),
        &remove_auth_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&payer, &authority]).unwrap();
    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to remove authority: {:?}",
        result.err()
    );

    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_data.state.roles, 1); // Only root authority remains
}

#[test_log::test]
fn test_switch_authority_and_payer() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [9u8; 32];
    let authority = Keypair::new();
    let payer = &context.default_payer;
    let role_id = 0;

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
        payer.pubkey(),
        role_id,
    );

    let new_authority = Keypair::new();
    let new_payer = Keypair::new();

    builder
        .switch_authority(1, Box::new(Ed25519ClientRole::new(new_authority.pubkey())))
        .unwrap();
    assert_eq!(builder.get_role_id(), 1);
    assert_eq!(
        builder.get_current_authority().unwrap(),
        new_authority.pubkey().to_bytes()
    );

    builder.switch_payer(new_payer.pubkey()).unwrap();
    let ix = builder.build_swig_account().unwrap();
    assert_eq!(ix.accounts[1].pubkey, new_payer.pubkey());
}
