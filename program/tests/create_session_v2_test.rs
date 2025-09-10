#![cfg(not(feature = "program_scope_test"))]
// This feature flag ensures these tests are only run when the
// "program_scope_test" feature is not enabled. This allows us to isolate
// and run only program_scope tests or only the regular tests.

mod common;

use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use common::*;
use solana_sdk::{
    clock::Clock,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction,
    sysvar::rent::Rent,
    transaction::VersionedTransaction,
};
use swig_interface::{CreateSessionInstruction, SignV2Instruction};
use swig_state::{
    authority::{
        ed25519::Ed25519SessionAuthority, secp256k1::Secp256k1SessionAuthority, AuthorityType,
    },
    swig::{swig_wallet_address_seeds, SwigWithRoles},
};

#[test_log::test]
fn test_create_session_v2() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig with ed25519session authority type
    let (swig_key, res) =
        create_swig_ed25519_session(&mut context, &swig_authority, id, 100, [0; 32]).unwrap();

    println!("res: {:?}", res.logs);

    // Get swig_wallet_address for SignV2
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id())
            .0;

    // Airdrop funds to the swig_wallet_address so it can transfer SOL
    context
        .svm
        .airdrop(&swig_wallet_address, 50_000_000_000)
        .unwrap();

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
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
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

    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig.get_role(0).unwrap().unwrap();
    assert_eq!(
        role.authority.authority_type(),
        AuthorityType::Ed25519Session
    );
    assert!(role.authority.session_based());
    let auth: &Ed25519SessionAuthority = role.authority.as_any().downcast_ref().unwrap();
    assert_eq!(auth.max_session_length, 100);
    assert_eq!(
        auth.current_session_expiration,
        current_slot + session_duration
    );
    assert_eq!(auth.session_key, session_key.pubkey().to_bytes());
    // Create a receiver keypair
    let receiver = Keypair::new();

    // Create a real SOL transfer instruction with swig_wallet_address as sender
    // (SignV2)
    let dummy_ix = system_instruction::transfer(
        &swig_wallet_address,
        &receiver.pubkey(),
        1000000, // 0.001 SOL in lamports
    );

    // Create a sign instruction using the session key (SignV2)
    let sign_ix = SignV2Instruction::new_ed25519(
        swig_key,
        swig_wallet_address,
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
fn test_expired_session_v2() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig with ed25519session authority type
    let (swig_key, _) =
        create_swig_ed25519_session(&mut context, &swig_authority, id, 100, [0; 32]).unwrap();

    // Get swig_wallet_address for SignV2
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id())
            .0;

    // Airdrop funds to the swig_wallet_address so it can transfer SOL
    context
        .svm
        .airdrop(&swig_wallet_address, 50_000_000_000)
        .unwrap();

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

    // Create a real SOL transfer instruction with swig_wallet_address as sender
    // (SignV2)
    let dummy_ix = system_instruction::transfer(
        &swig_wallet_address,
        &receiver.pubkey(),
        1000000, // 0.001 SOL in lamports
    );

    // Try to use the expired session key (SignV2)
    let sign_ix = SignV2Instruction::new_ed25519(
        swig_key,
        swig_wallet_address,
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
fn test_session_key_refresh_ed25519_v2() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig with ed25519session authority type
    let (swig_key, _) =
        create_swig_ed25519_session(&mut context, &swig_authority, id, 100, [0; 32]).unwrap();

    // Get swig_wallet_address for SignV2
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id())
            .0;

    // Airdrop funds to the swig_wallet_address so it can transfer SOL
    context
        .svm
        .airdrop(&swig_wallet_address, 50_000_000_000)
        .unwrap();

    // Create a session key
    let session_key = Keypair::new();

    // Get the role ID for the authority
    let swig_account_initial = context.svm.get_account(&swig_key).unwrap();
    let swig_initial = SwigWithRoles::from_bytes(&swig_account_initial.data).unwrap();
    let role_id = swig_initial
        .lookup_role_id(swig_authority.pubkey().as_ref())
        .unwrap()
        .expect("Role should exist");

    // Create initial session
    let create_session_ix1 = CreateSessionInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        role_id, // Use the actual role ID
        session_key.pubkey(),
        50, // 50 slots
    )
    .unwrap();

    let current_slot_before = context.svm.get_sysvar::<Clock>().slot;

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

    // Verify the initial session was created correctly
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig.get_role(role_id).unwrap().unwrap();
    let auth: &Ed25519SessionAuthority = role.authority.as_any().downcast_ref().unwrap();
    assert_eq!(auth.session_key, session_key.pubkey().to_bytes());
    assert_eq!(auth.current_session_expiration, current_slot_before + 50);

    // Advance time by a few slots
    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + 10);

    // Refresh the session with the SAME session key but new duration
    let create_session_ix2 = CreateSessionInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        role_id,              // Use the same role ID
        session_key.pubkey(), // Same session key
        80,                   // New duration: 80 slots
    )
    .unwrap();

    let current_slot_refresh = context.svm.get_sysvar::<Clock>().slot;

    // Send the session refresh transaction
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
        result2.is_ok(),
        "Session refresh should succeed, but got error: {:?}",
        result2.err()
    );

    // Verify the session was refreshed with new expiration
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig.get_role(role_id).unwrap().unwrap();
    let auth: &Ed25519SessionAuthority = role.authority.as_any().downcast_ref().unwrap();
    assert_eq!(auth.session_key, session_key.pubkey().to_bytes());
    assert_eq!(auth.current_session_expiration, current_slot_refresh + 80);

    // Test that the refreshed session is still functional
    let receiver = Keypair::new();
    let dummy_ix = system_instruction::transfer(
        &swig_wallet_address,
        &receiver.pubkey(),
        1000000, // 0.001 SOL in lamports
    );

    let sign_ix = SignV2Instruction::new_ed25519(
        swig_key,
        swig_wallet_address,
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
        "Failed to use refreshed session: {:?}",
        sign_result.err()
    );
}

#[test_log::test]
fn test_transfer_sol_with_session_v2() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig with ed25519session authority type
    let (swig_key, _) =
        create_swig_ed25519_session(&mut context, &swig_authority, id, 100, [0; 32]).unwrap();

    // Get swig_wallet_address for SignV2
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id())
            .0;

    // Airdrop funds to the swig_wallet_address so it can transfer SOL
    let initial_swig_wallet_address_balance = 50_000_000_000;
    context
        .svm
        .airdrop(&swig_wallet_address, initial_swig_wallet_address_balance)
        .unwrap();

    // Create a session key
    let session_key = Keypair::new();
    let session_duration = 100; // 100 slots

    // Create a session with the session key
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

    // Create a receiver keypair and check initial balance
    let receiver = Keypair::new();
    let transfer_amount = 1_000_000; // 0.001 SOL in lamports

    let receiver_initial_balance = context
        .svm
        .get_account(&receiver.pubkey())
        .map(|acc| acc.lamports)
        .unwrap_or(0);

    // Create a SOL transfer instruction from swig_wallet_address to receiver
    // (SignV2)
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &receiver.pubkey(), transfer_amount);

    // Create a sign instruction using the session key (SignV2)
    let sign_ix = SignV2Instruction::new_ed25519(
        swig_key,
        swig_wallet_address,
        context.default_payer.pubkey(),
        session_key.pubkey(),
        transfer_ix,
        0, // Role ID 0
    )
    .unwrap();

    // Send the transfer transaction
    let transfer_msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_msg),
        &[&context.default_payer, &session_key],
    )
    .unwrap();

    let transfer_result = context.svm.send_transaction(transfer_tx);
    assert!(
        transfer_result.is_ok(),
        "Failed to transfer SOL: {:?}",
        transfer_result.err()
    );

    // Verify the transfer was successful by checking balances
    let receiver_final_balance = context
        .svm
        .get_account(&receiver.pubkey())
        .map(|acc| acc.lamports)
        .unwrap_or(0);

    let swig_wallet_address_account = context.svm.get_account(&swig_wallet_address).unwrap();
    let swig_wallet_address_final_balance = swig_wallet_address_account.lamports;

    assert_eq!(
        receiver_final_balance,
        receiver_initial_balance + transfer_amount,
        "Receiver balance did not increase by the correct amount"
    );

    // Calculate rent-exempt minimum for the swig_wallet_address account
    let rent = context.svm.get_sysvar::<Rent>();
    let rent_exempt_minimum = rent.minimum_balance(swig_wallet_address_account.data.len());
    assert_eq!(
        swig_wallet_address_final_balance - rent_exempt_minimum,
        initial_swig_wallet_address_balance - transfer_amount,
        "Swig wallet address balance did not decrease by the correct amount"
    );
}

#[test_log::test]
fn test_secp256k1_session_v2() {
    let mut context = setup_test_context().unwrap();

    // Generate a random Ethereum wallet
    let wallet = LocalSigner::random();

    let id = rand::random::<[u8; 32]>();

    // Create a swig with secp256k1 session authority type
    let (swig_key, res) =
        create_swig_secp256k1_session(&mut context, &wallet, id, 100, [0; 32]).unwrap();

    println!("res: {:?}", res.logs);

    // Get swig_wallet_address for SignV2
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id())
            .0;

    // Airdrop funds to the swig_wallet_address so it can transfer SOL
    context
        .svm
        .airdrop(&swig_wallet_address, 50_000_000_000)
        .unwrap();

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
    let compressed_eth_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(true)
        .to_bytes();
    assert_eq!(auth.public_key, compressed_eth_pubkey.as_ref());
    assert_eq!(auth.current_session_expiration, 0);
    assert_eq!(auth.session_key, [0; 32]);
    assert_eq!(auth.signature_odometer, 0, "Initial odometer should be 0");

    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + 1);

    // Create a session key
    let session_key = Keypair::new();

    // Create a session with the session key
    let session_duration = 100; // 100 slots
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    let create_session_ix = CreateSessionInstruction::new_with_secp256k1_authority(
        swig_key,
        context.default_payer.pubkey(),
        signing_fn,
        current_slot,
        1, // Counter for session authorities (starting from 1)
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

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&context.default_payer])
        .unwrap();
    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to create session: {:?}",
        result.err()
    );

    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig.get_role(0).unwrap().unwrap();
    assert_eq!(
        role.authority.authority_type(),
        AuthorityType::Secp256k1Session
    );
    assert!(role.authority.session_based());
    let auth: &Secp256k1SessionAuthority = role.authority.as_any().downcast_ref().unwrap();
    assert_eq!(auth.max_session_age, 100);
    assert_eq!(
        auth.current_session_expiration,
        current_slot + session_duration
    );
    assert_eq!(auth.session_key, session_key.pubkey().to_bytes());
    assert_eq!(
        auth.signature_odometer, 1,
        "Odometer should be 1 after session creation"
    );

    // Create a receiver keypair
    let receiver = Keypair::new();

    // Create a real SOL transfer instruction with swig_wallet_address as sender
    // (SignV2)
    let dummy_ix = system_instruction::transfer(
        &swig_wallet_address,
        &receiver.pubkey(),
        1000000, // 0.001 SOL in lamports
    );

    // Create a sign instruction using the session key (SignV2)
    let sign_ix = SignV2Instruction::new_ed25519(
        swig_key,
        swig_wallet_address,
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
fn test_session_key_refresh_secp256k1_v2() {
    let mut context = setup_test_context().unwrap();

    // Generate a random Ethereum wallet
    let wallet = LocalSigner::random();
    let id = rand::random::<[u8; 32]>();

    // Create a swig with secp256k1 session authority type
    let (swig_key, _) =
        create_swig_secp256k1_session(&mut context, &wallet, id, 100, [0; 32]).unwrap();

    // Get swig_wallet_address for SignV2
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id())
            .0;

    // Airdrop funds to the swig_wallet_address
    context
        .svm
        .airdrop(&swig_wallet_address, 50_000_000_000)
        .unwrap();

    // Create a session key
    let session_key = Keypair::new();

    // Create initial session
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    let create_session_ix1 = CreateSessionInstruction::new_with_secp256k1_authority(
        swig_key,
        context.default_payer.pubkey(),
        signing_fn,
        current_slot,
        1, // Counter starts at 1
        0, // Role ID 0
        session_key.pubkey(),
        50, // 50 slots
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

    let tx1 = VersionedTransaction::try_new(VersionedMessage::V0(msg1), &[&context.default_payer])
        .unwrap();

    let result1 = context.svm.send_transaction(tx1);
    assert!(
        result1.is_ok(),
        "Failed to create first session: {:?}",
        result1.err()
    );

    // Verify initial session
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig.get_role(0).unwrap().unwrap();
    let auth: &Secp256k1SessionAuthority = role.authority.as_any().downcast_ref().unwrap();
    assert_eq!(auth.session_key, session_key.pubkey().to_bytes());
    assert_eq!(auth.signature_odometer, 1);

    // Advance time and refresh session with same session key
    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + 10);

    let refresh_slot = context.svm.get_sysvar::<Clock>().slot;
    let create_session_ix2 = CreateSessionInstruction::new_with_secp256k1_authority(
        swig_key,
        context.default_payer.pubkey(),
        signing_fn,
        refresh_slot,
        2,                    // Increment counter for second signature
        0,                    // Role ID 0
        session_key.pubkey(), // Same session key - this should work now
        80,                   // New duration: 80 slots
    )
    .unwrap();

    // Send the session refresh transaction
    let msg2 = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[create_session_ix2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx2 = VersionedTransaction::try_new(VersionedMessage::V0(msg2), &[&context.default_payer])
        .unwrap();

    let result2 = context.svm.send_transaction(tx2);
    assert!(
        result2.is_ok(),
        "Session refresh should succeed, but got error: {:?}",
        result2.err()
    );

    // Verify the session was refreshed
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig.get_role(0).unwrap().unwrap();
    let auth: &Secp256k1SessionAuthority = role.authority.as_any().downcast_ref().unwrap();
    assert_eq!(auth.session_key, session_key.pubkey().to_bytes());
    assert_eq!(auth.signature_odometer, 2); // Should increment
    assert_eq!(auth.current_session_expiration, refresh_slot + 80);
}

#[test_log::test]
fn test_session_extension_before_expiration_v2() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig with ed25519session authority type
    let (swig_key, _) =
        create_swig_ed25519_session(&mut context, &swig_authority, id, 100, [0; 32]).unwrap();

    // Get swig_wallet_address for SignV2
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id())
            .0;

    context
        .svm
        .airdrop(&swig_wallet_address, 50_000_000_000)
        .unwrap();

    let session_key = Keypair::new();

    // Create initial session with short duration
    let create_session_ix1 = CreateSessionInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0,
        session_key.pubkey(),
        10, // Very short duration
    )
    .unwrap();

    let initial_slot = context.svm.get_sysvar::<Clock>().slot;

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
    assert!(result1.is_ok(), "Failed to create initial session");

    // Advance close to expiration but not past it
    context.svm.warp_to_slot(initial_slot + 8); // 8 < 10, so still valid

    // Extend the session before it expires
    let create_session_ix2 = CreateSessionInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        swig_authority.pubkey(),
        0,
        session_key.pubkey(), // Same session key
        50,                   // Much longer duration
    )
    .unwrap();

    let extension_slot = context.svm.get_sysvar::<Clock>().slot;

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
        result2.is_ok(),
        "Session extension should succeed: {:?}",
        result2.err()
    );

    // Verify the session has new expiration
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig.get_role(0).unwrap().unwrap();
    let auth: &Ed25519SessionAuthority = role.authority.as_any().downcast_ref().unwrap();
    assert_eq!(auth.current_session_expiration, extension_slot + 50);

    // Verify session still works after original expiration time
    context.svm.warp_to_slot(initial_slot + 15); // Past original expiration

    let receiver = Keypair::new();
    let dummy_ix = system_instruction::transfer(&swig_wallet_address, &receiver.pubkey(), 1000000);

    let sign_ix = SignV2Instruction::new_ed25519(
        swig_key,
        swig_wallet_address,
        context.default_payer.pubkey(),
        session_key.pubkey(),
        dummy_ix,
        0,
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
        "Extended session should still be usable: {:?}",
        sign_result.err()
    );
}

#[test_log::test]
fn test_multiple_session_refreshes_v2() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) =
        create_swig_ed25519_session(&mut context, &swig_authority, id, 100, [0; 32]).unwrap();

    // Get swig_wallet_address for SignV2
    let swig_wallet_address =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id())
            .0;

    context
        .svm
        .airdrop(&swig_wallet_address, 50_000_000_000)
        .unwrap();

    let session_key = Keypair::new();

    // Function to create session with given duration
    let create_session = |context: &mut SwigTestContext, duration: u64| {
        let create_session_ix = CreateSessionInstruction::new_with_ed25519_authority(
            swig_key,
            context.default_payer.pubkey(),
            swig_authority.pubkey(),
            0,
            session_key.pubkey(),
            duration,
        )
        .unwrap();

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

        context.svm.send_transaction(tx).unwrap();
    };

    // Create initial session
    create_session(&mut context, 20);

    // Refresh multiple times with different durations
    for i in 1..=5 {
        context
            .svm
            .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + 3);

        create_session(&mut context, 30 + (i * 10));

        // Verify the session expiration updated correctly
        let current_slot = context.svm.get_sysvar::<Clock>().slot;
        let swig_account = context.svm.get_account(&swig_key).unwrap();
        let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
        let role = swig.get_role(0).unwrap().unwrap();
        let auth: &Ed25519SessionAuthority = role.authority.as_any().downcast_ref().unwrap();
        assert_eq!(
            auth.current_session_expiration,
            current_slot + 30 + (i * 10),
            "Session refresh #{} didn't update expiration correctly",
            i
        );
    }

    // Verify the session is still functional after all refreshes
    let receiver = Keypair::new();
    let dummy_ix = system_instruction::transfer(&swig_wallet_address, &receiver.pubkey(), 1000000);

    let sign_ix = SignV2Instruction::new_ed25519(
        swig_key,
        swig_wallet_address,
        context.default_payer.pubkey(),
        session_key.pubkey(),
        dummy_ix,
        0,
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
        "Session should still be functional after multiple refreshes: {:?}",
        sign_result.err()
    );
}
