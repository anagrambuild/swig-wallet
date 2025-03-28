mod common;
use borsh::BorshDeserialize;
use common::*;
use solana_sdk::{
    clock::Clock,
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction,
    transaction::VersionedTransaction,
};
use swig_interface::{CreateSessionInstruction, SignInstruction};
use swig_state::{authority::Ed25519SessionAuthorityData, Action, AuthorityType, Role, Swig};

#[test_log::test]
fn test_create_session() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 13]>();

    // Create a swig with ed25519session authority type
    let (swig_key, _) = create_swig_ed25519_session(&mut context, &swig_authority, &id).unwrap();

    // Airdrop funds to the swig account so it can transfer SOL
    context.svm.airdrop(&swig_key, 50_000_000_000).unwrap();

    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = Swig::try_from_slice(&swig_account.data).unwrap();
    assert_eq!(swig.roles[0].authority_type, AuthorityType::Ed25519Session);
    assert_eq!(swig.roles[0].authority_data.len(), 80);
    let authority_data = Ed25519SessionAuthorityData::load(&swig.roles[0].authority_data).unwrap();
    assert_eq!(
        authority_data.authority_pubkey,
        &swig_authority.pubkey().to_bytes()
    );
    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + 1);

    // Create a session key
    let session_key = Keypair::new();

    // Create a session with the session key
    let session_duration = 100; // 100 slots
    let create_session_ix = CreateSessionInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Role ID 0 is the root authority
        session_key.pubkey(),
        session_duration,
    )
    .unwrap();

    // Send the create session transaction
    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[create_session_ix],
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

    // Verify that the session was created
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = Swig::try_from_slice(&swig_account.data).unwrap();
    assert_eq!(swig.roles.len(), 1);

    // Create a receiver keypair
    let receiver = Keypair::new();

    // Create a real SOL transfer instruction with swig_key as sender
    let dummy_ix = system_instruction::transfer(
        &swig_key,
        &receiver.pubkey(),
        1000000, // 0.001 SOL in lamports
    );

    // Create a sign instruction using the session key
    let sign_ix = SignInstruction::new_ed25519(
        swig_key,
        context.default_payer.pubkey(),
        session_key.pubkey(),
        dummy_ix,
        0, // Role ID 0
    )
    .unwrap();

    let sign_msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let sign_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(sign_msg),
        &[&context.default_payer, &session_key],
    )
    .unwrap();

    let sign_result = context.svm.send_transaction(sign_tx);
    assert!(
        sign_result.is_ok(),
        "Failed to sign with session key: {:?}",
        sign_result.err()
    );
}

#[test_log::test]
fn test_expired_session() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 13]>();

    // Create a swig with ed25519session authority type
    let (swig_key, _) = create_swig_ed25519_session(&mut context, &swig_authority, &id).unwrap();

    // Airdrop funds to the swig account so it can transfer SOL
    context.svm.airdrop(&swig_key, 50_000_000_000).unwrap();

    // Create a session key
    let session_key = Keypair::new();

    // Create a session with a very short duration
    let session_duration = 1; // 1 slot
    let create_session_ix = CreateSessionInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Role ID 0 is the root authority
        session_key.pubkey(),
        session_duration,
    )
    .unwrap();

    // Send the create session transaction
    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[create_session_ix],
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

    // Wait for session to expire by advancing slots
    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + 2);

    // Create a receiver keypair
    let receiver = Keypair::new();

    // Create a real SOL transfer instruction with swig_key as sender
    let dummy_ix = system_instruction::transfer(
        &swig_key,
        &receiver.pubkey(),
        1000000, // 0.001 SOL in lamports
    );

    // Try to use the expired session key
    let sign_ix = SignInstruction::new_ed25519(
        swig_key,
        context.default_payer.pubkey(),
        session_key.pubkey(),
        dummy_ix,
        0, // Role ID 0
    )
    .unwrap();

    let sign_msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let sign_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(sign_msg),
        &[&context.default_payer, &session_key],
    )
    .unwrap();

    let sign_result = context.svm.send_transaction(sign_tx);
    assert!(
        sign_result.is_err(),
        "Expected error for expired session but got success"
    );
}

#[test_log::test]
fn test_reuse_session_key() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 13]>();

    // Create a swig with ed25519session authority type
    let (swig_key, _) = create_swig_ed25519_session(&mut context, &swig_authority, &id).unwrap();

    // Airdrop funds to the swig account so it can transfer SOL
    context.svm.airdrop(&swig_key, 50_000_000_000).unwrap();

    // Create a session key
    let session_key = Keypair::new();

    // Try to create a session with a key that will be reused
    let create_session_ix1 = CreateSessionInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Role ID 0
        session_key.pubkey(),
        100, // 100 slots
    )
    .unwrap();

    // Send the first create session transaction
    let msg1 = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[create_session_ix1],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx1 = VersionedTransaction::try_new(
        VersionedMessage::V0(msg1),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let result1 = context.svm.send_transaction(tx1);
    assert!(
        result1.is_ok(),
        "Failed to create first session: {:?}",
        result1.err()
    );

    // Try to create another session with the same session key
    let create_session_ix2 = CreateSessionInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0, // Role ID 0
        session_key.pubkey(),
        100, // 100 slots
    )
    .unwrap();

    // Process the next block to get a new blockhash
    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + 1);

    // Send the second create session transaction
    let msg2 = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[create_session_ix2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx2 = VersionedTransaction::try_new(
        VersionedMessage::V0(msg2),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let result2 = context.svm.send_transaction(tx2);
    assert!(
        result2.is_err(),
        "Expected error for reuse of session key but got success"
    );
}
