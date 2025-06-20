use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use solana_program::{pubkey::Pubkey, system_instruction};
use solana_sdk::{
    message::{v0, VersionedMessage},
    signature::{Keypair, Signer},
    transaction::VersionedTransaction,
};
use swig_interface::program_id;
use swig_state_x::{
    authority::AuthorityType,
    swig::{swig_account_seeds, SwigWithRoles},
};

use super::*;
use crate::client_role::{Ed25519ClientRole, Secp256k1ClientRole};

#[test_log::test]
fn test_sign_instruction_with_ed25519_authority() {
    // First create the Swig account
    let mut context = setup_test_context().unwrap();
    let swig_id = [1u8; 32];
    let authority = Keypair::new();
    let payer = &context.default_payer;
    let role_id = 0;

    let builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
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

    // Fund the Swig account
    context.svm.airdrop(&swig_key, 1_000_000_000).unwrap();

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
        context.default_payer.pubkey(),
        role_id,
    );

    // Create a transfer instruction to test signing
    let recipient = Keypair::new();
    let transfer_amount = 100_000;
    let transfer_ix = solana_program::system_instruction::transfer(
        &swig_key,
        &recipient.pubkey(),
        transfer_amount,
    );

    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    let sign_ix = builder
        .sign_instruction(vec![transfer_ix], Some(current_slot))
        .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &sign_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &authority],
    );

    assert!(tx.is_ok(), "Failed to create transaction {:?}", tx.err());

    let result = context.svm.send_transaction(tx.unwrap());
    assert!(
        result.is_ok(),
        "Failed to execute signed instruction: {:?}",
        result.err()
    );

    // Verify the transfer was successful
    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(recipient_account.lamports, transfer_amount);
}

#[test_log::test]
fn test_sign_instruction_with_secp256k1_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [6u8; 32];
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
    context.svm.airdrop(&swig_key, 1_000_000_000).unwrap();

    let recipient = Keypair::new();
    let transfer_amount = 100_000;
    let transfer_ix = solana_program::system_instruction::transfer(
        &swig_key,
        &recipient.pubkey(),
        transfer_amount,
    );

    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    // Get current counter and calculate next counter
    let current_counter = get_secp256k1_counter_from_wallet(&context, &swig_key, &wallet).unwrap();

    let sign_ix = builder
        .sign_instruction(vec![transfer_ix], Some(current_slot))
        .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &sign_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&context.default_payer]);
    assert!(tx.is_ok(), "Failed to create transaction {:?}", tx.err());

    let result = context.svm.send_transaction(tx.unwrap());
    assert!(
        result.is_ok(),
        "Failed to execute signed instruction: {:?}",
        result.err()
    );

    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(recipient_account.lamports, transfer_amount);
}
