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
    authority::{
        ed25519::{CreateEd25519SessionAuthority, Ed25519SessionAuthority},
        secp256k1::{CreateSecp256k1SessionAuthority, Secp256k1SessionAuthority},
        AuthorityType,
    },
    swig::{swig_account_seeds, SwigWithRoles},
};

use super::*;
use crate::client_role::{Ed25519SessionClientRole, Secp256k1SessionClientRole};

#[test_log::test]
fn test_create_ed25519_session() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = [0; 32];

    let mut swig_ix_builder = SwigInstructionBuilder::new(
        id,
        Box::new(Ed25519SessionClientRole::new(
            swig_authority.pubkey(),
            Pubkey::new_from_array([0; 32]),
            100,
        )),
        context.default_payer.pubkey(),
        0,
    );

    let create_ix = swig_ix_builder.build_swig_account().unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[create_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&context.default_payer])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to create Swig account: {:?}",
        result.err()
    );

    let swig_key = swig_ix_builder.get_swig_account().unwrap();

    context.svm.airdrop(&swig_key, 50_000_000_000).unwrap();

    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 1);
    let role = swig.get_role(0).unwrap().unwrap();

    assert_eq!(
        role.authority.authority_type(),
        AuthorityType::Ed25519Session
    );
    assert!(role.authority.session_based());
    let auth: &Ed25519SessionAuthority = role.authority.as_any().downcast_ref().unwrap();
    assert_eq!(auth.max_session_length, 100);
    assert_eq!(auth.public_key, swig_authority.pubkey().to_bytes());
    assert_eq!(auth.current_session_expiration, 0);
    assert_eq!(auth.session_key, [0; 32]);

    // Create a session
    let session_authority = Keypair::new();
    let create_session_ix = swig_ix_builder
        .create_session_instruction(session_authority.pubkey(), 100, None, None)
        .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &create_session_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to create session: {:?}",
        result.err()
    );

    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_data = swig_account.data;

    let swig_with_roles = SwigWithRoles::from_bytes(&swig_data)
        .map_err(|e| SwigError::InvalidSwigData)
        .unwrap();

    let role = swig_with_roles.get_role(0).unwrap().unwrap();
    let auth: &Ed25519SessionAuthority = role.authority.as_any().downcast_ref().unwrap();
}

#[test_log::test]
fn test_create_secp256k1_session() {
    let mut context = setup_test_context().unwrap();

    let wallet = LocalSigner::random();

    let id = [0; 32];

    let secp_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();

    let wallet = wallet.clone();
    let payer = &context.default_payer;

    let signing_fn = move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    let mut swig_ix_builder = SwigInstructionBuilder::new(
        id,
        Box::new(Secp256k1SessionClientRole::new(
            secp_pubkey[1..].try_into().unwrap(),
            Pubkey::new_from_array([0; 32]),
            100,
            Box::new(signing_fn),
        )),
        context.default_payer.pubkey(),
        0,
    );

    let create_ix = swig_ix_builder.build_swig_account().unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[create_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&context.default_payer])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to create Swig account: {:?}",
        result.err()
    );

    display_swig(
        swig_ix_builder.get_swig_account().unwrap(),
        &context
            .svm
            .get_account(&swig_ix_builder.get_swig_account().unwrap())
            .unwrap(),
    )
    .unwrap();

    let swig_key = swig_ix_builder.get_swig_account().unwrap();

    context.svm.airdrop(&swig_key, 50_000_000_000).unwrap();

    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 1);
    let role = swig.get_role(0).unwrap().unwrap();

    assert_eq!(
        role.authority.authority_type(),
        AuthorityType::Secp256k1Session
    );
    assert!(role.authority.session_based());
    let auth: &Secp256k1SessionAuthority = role.authority.as_any().downcast_ref().unwrap();

    assert_eq!(auth.max_session_age, 100);
    assert_eq!(auth.current_session_expiration, 0);
    assert_eq!(auth.session_key, [0; 32]);

    // Create a session
    let session_authority = Keypair::new();

    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let counter = 1;
    let create_session_ix = swig_ix_builder
        .create_session_instruction(
            session_authority.pubkey(),
            100,
            Some(current_slot),
            Some(counter),
        )
        .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &create_session_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&context.default_payer])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to create session: {:?}",
        result.err()
    );

    display_swig(
        swig_ix_builder.get_swig_account().unwrap(),
        &context
            .svm
            .get_account(&swig_ix_builder.get_swig_account().unwrap())
            .unwrap(),
    )
    .unwrap();

    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_data = swig_account.data;

    let swig_with_roles = SwigWithRoles::from_bytes(&swig_data)
        .map_err(|e| SwigError::InvalidSwigData)
        .unwrap();

    let role = swig_with_roles.get_role(0).unwrap().unwrap();
    let auth: &Secp256k1SessionAuthority = role.authority.as_any().downcast_ref().unwrap();
}
