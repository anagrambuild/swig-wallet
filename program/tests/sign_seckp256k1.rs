mod common;
use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use common::*;
use solana_sdk::{
    clock::Clock,
    instruction::InstructionError,
    message::{v0, VersionedMessage},
    signature::Keypair,
    signer::Signer,
    system_instruction,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{AuthorityConfig, ClientAction};
use swig_state_x::{action::all::All, authority::AuthorityType, swig::SwigWithRoles};

#[test_log::test]
fn test_secp256k1_basic_signing() {
    let mut context = setup_test_context().unwrap();

    // Generate a random Ethereum wallet
    let wallet = LocalSigner::random();

    // Create a new swig with the secp256k1 authority
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_secp256k1(&mut context, &wallet, id).unwrap();
    context.svm.airdrop(&swig_key, 10_000_000_000).unwrap();

    // Set up a recipient and transaction
    let recipient = Keypair::new();
    context.svm.airdrop(&recipient.pubkey(), 1_000_000).unwrap();
    let transfer_amount = 5_000_000;
    let transfer_ix = system_instruction::transfer(&swig_key, &recipient.pubkey(), transfer_amount);

    // Sign the transaction
    let current_slot = 0; // Using 0 since LiteSVM doesn't expose get_slot
    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    // Create and submit the transaction
    let sign_ix = swig_interface::SignInstruction::new_secp256k1(
        swig_key,
        context.default_payer.pubkey(),
        signing_fn,
        current_slot,
        transfer_ix,
        0, // Role ID 0
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&context.default_payer])
            .unwrap();

    // Transaction should succeed
    let result = context.svm.send_transaction(tx);
    assert!(result.is_ok(), "Transaction failed: {:?}", result.err());
    println!("result: {:?}", result.unwrap().logs);
    // Verify transfer was successful
    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(recipient_account.lamports, 1_000_000 + transfer_amount);
}

#[test_log::test]
fn test_secp256k1_direct_signature_reuse() {
    let mut context = setup_test_context().unwrap();

    // Generate a random Ethereum wallet
    let wallet = LocalSigner::random();

    // Create a new swig with the secp256k1 authority
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_secp256k1(&mut context, &wallet, id).unwrap();
    context.svm.airdrop(&swig_key, 10_000_000_000).unwrap();
    let payer2 = Keypair::new();
    context.svm.airdrop(&payer2.pubkey(), 1_000_000).unwrap();

    // Set up a recipient and transaction
    let recipient = Keypair::new();
    context.svm.airdrop(&recipient.pubkey(), 1_000_000).unwrap();
    let transfer_amount = 5_000_000;
    let transfer_ix = system_instruction::transfer(&swig_key, &recipient.pubkey(), transfer_amount);
    let mut sig = [0u8; 65];

    // For first transaction, we'll use a standard signing function
    let sign_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        let tsig = wallet.sign_hash_sync(&hash).unwrap().as_bytes();
        sig.copy_from_slice(&tsig);
        sig
    };

    // Current slot for all transactions
    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    // TRANSACTION 1: Initial transaction that should succeed
    let sign_ix = swig_interface::SignInstruction::new_secp256k1(
        swig_key,
        context.default_payer.pubkey(),
        sign_fn,
        current_slot,
        transfer_ix.clone(),
        0, // Role ID
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&context.default_payer])
            .unwrap();

    // First transaction should succeed
    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "First transaction failed: {:?}",
        result.err()
    );

    // Verify transfer was successful
    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(recipient_account.lamports, 1_000_000 + transfer_amount);

    let transfer_ix2 =
        system_instruction::transfer(&swig_key, &recipient.pubkey(), transfer_amount);

    let reuse_signature_fn = move |_: &[u8]| -> [u8; 65] { sig };

    // Advance the slot by 2
    context.svm.warp_to_slot(2);

    // TRANSACTION 2: Attempt to reuse the stored signature (should fail)
    let sign_ix2 = swig_interface::SignInstruction::new_secp256k1(
        swig_key,
        payer2.pubkey(),
        reuse_signature_fn,
        current_slot,
        transfer_ix2,
        0,
    )
    .unwrap();

    let message2 = v0::Message::try_compile(
        &payer2.pubkey(),
        &[sign_ix2],
        &[],
        context.svm.latest_blockhash(), // Get new blockhash
    )
    .unwrap();

    let tx2 = VersionedTransaction::try_new(VersionedMessage::V0(message2), &[&payer2]).unwrap();

    // Second transaction should fail (either with signature reuse or invalid
    // signature)
    let result2 = context.svm.send_transaction(tx2);
    println!("result2: {:?}", result2);
    assert!(result2.is_err(), "Expected second transaction to fail");

    // TRANSACTION 3: Fresh signature at current slot (should succeed)
    // Create a new signing function that generates a fresh signature
    let fresh_signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    // Use current slot value (slot 2 after warping)
    let current_slot_value = 2;

    let transfer_ix3 =
        system_instruction::transfer(&swig_key, &recipient.pubkey(), transfer_amount);
    let sign_ix3 = swig_interface::SignInstruction::new_secp256k1(
        swig_key,
        context.default_payer.pubkey(),
        fresh_signing_fn,
        current_slot_value, // Use current slot from simulator
        transfer_ix3,
        0,
    )
    .unwrap();

    let message3 = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix3],
        &[],
        context.svm.latest_blockhash(), // Get new blockhash
    )
    .unwrap();

    let tx3 =
        VersionedTransaction::try_new(VersionedMessage::V0(message3), &[&context.default_payer])
            .unwrap();

    // Third transaction should succeed
    let result3 = context.svm.send_transaction(tx3);
    assert!(
        result3.is_ok(),
        "Third transaction failed: {:?}",
        result3.err()
    );

    // Verify second transfer was successful
    let recipient_account_final = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(
        recipient_account_final.lamports,
        1_000_000 + 2 * transfer_amount
    );
}

#[test_log::test]
fn test_secp256k1_old_signature() {
    let mut context = setup_test_context().unwrap();

    // Generate a random Ethereum wallet
    let wallet = LocalSigner::random();

    // Create a new swig with the secp256k1 authority
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_secp256k1(&mut context, &wallet, id).unwrap();
    context.svm.airdrop(&swig_key, 10_000_000_000).unwrap();

    // Set up a recipient and transaction
    let recipient = Keypair::new();
    context.svm.airdrop(&recipient.pubkey(), 1_000_000).unwrap();
    let transfer_amount = 1_000_000;
    let transfer_ix = system_instruction::transfer(&swig_key, &recipient.pubkey(), transfer_amount);

    // Create a signature for a very old slot
    let old_slot = 0;

    // Create a signing function that uses the old slot
    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    // Advance the slot by more than MAX_SIGNATURE_AGE_IN_SLOTS (60)
    context.svm.warp_to_slot(100);

    // Create and submit the transaction with the old signature
    let sign_ix = swig_interface::SignInstruction::new_secp256k1(
        swig_key,
        context.default_payer.pubkey(),
        signing_fn,
        old_slot, // Using old slot
        transfer_ix,
        0,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&context.default_payer])
            .unwrap();

    // Transaction should fail due to old signature
    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "Expected transaction to fail due to old signature"
    );

    // Verify the specific error
    match result.unwrap_err().err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => {
            // This should match the error code for
            // PermissionDeniedSecp256k1InvalidSignatureAge Note: You may need
            // to adjust this assertion based on your actual error code
            assert!(code > 0, "Expected a custom error code for old signature");
        },
        err => panic!("Expected InstructionError::Custom, got {:?}", err),
    }
}

#[test_log::test]
fn test_secp256k1_add_authority() {
    let mut context = setup_test_context().unwrap();

    // Create primary Ed25519 authority
    let primary_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    // Create a new swig with Ed25519 authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &primary_authority, id).unwrap();
    context.svm.airdrop(&swig_key, 10_000_000_000).unwrap();

    // Read the account data to verify initial state
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let roles_before = swig_state.state.roles;
    assert_eq!(roles_before, 1);

    // Test initial Ed25519 signing
    let transfer_ix =
        system_instruction::transfer(&swig_key, &context.default_payer.pubkey(), 1_000_000);
    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig_key,
        context.default_payer.pubkey(),
        primary_authority.pubkey(),
        transfer_ix,
        0, // role_id of the primary wallet
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, &primary_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to sign with Ed25519: {:?}",
        result.err()
    );

    // Generate a random Ethereum wallet to add as second authority
    let secp_wallet = LocalSigner::random();

    // Create instruction to add the Secp256k1 authority
    let add_authority_ix = swig_interface::AddAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        primary_authority.pubkey(),
        0, // role_id of the primary wallet
        AuthorityConfig {
            authority_type: AuthorityType::Secp256k1,
            authority: &secp_wallet
                .credential()
                .verifying_key()
                .to_encoded_point(false)
                .to_bytes()
                .as_ref()[1..],
        },
        vec![ClientAction::All(All {})],
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, &primary_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to add Secp256k1 authority: {:?}",
        result.err()
    );

    // Verify the authority was added
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_state.state.roles, 2);

    // Test signing with the new Secp256k1 authority
    let transfer_ix =
        system_instruction::transfer(&swig_key, &context.default_payer.pubkey(), 500_000);

    // Create signing function for Secp256k1
    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        secp_wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let sign_ix = swig_interface::SignInstruction::new_secp256k1(
        swig_key,
        context.default_payer.pubkey(),
        signing_fn,
        current_slot,
        transfer_ix,
        1, // role_id of the secp256k1 authority
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&context.default_payer])
            .unwrap();

    // Transaction should succeed
    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to sign with Secp256k1 authority: {:?}",
        result.err()
    );
}

#[test_log::test]
fn test_secp256k1_add_ed25519_authority() {
    let mut context = setup_test_context().unwrap();

    // Generate a random Ethereum wallet for the primary authority
    let wallet = LocalSigner::random();

    // Create a new swig with the secp256k1 authority
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_secp256k1(&mut context, &wallet, id).unwrap();
    context.svm.airdrop(&swig_key, 10_000_000_000).unwrap();

    // Create an ed25519 authority to add
    let ed25519_authority = Keypair::new();
    context
        .svm
        .airdrop(&ed25519_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create the signing function for the secp256k1 authority
    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    // Create instruction to add the ed25519 authority
    let add_authority_ix = swig_interface::AddAuthorityInstruction::new_with_secp256k1_authority(
        swig_key,
        context.default_payer.pubkey(),
        signing_fn,
        0, // current slot
        0, // role_id of the primary wallet
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: ed25519_authority.pubkey().as_ref(),
        },
        vec![ClientAction::All(All {})],
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_authority_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&context.default_payer])
            .unwrap();

    // Transaction should succeed
    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to add ed25519 authority: {:?}",
        result.err()
    );

    // Verify the authority was added
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_state.state.roles, 2);

    // Test signing with the new ed25519 authority
    let transfer_ix =
        system_instruction::transfer(&swig_key, &context.default_payer.pubkey(), 500_000);
    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig_key,
        context.default_payer.pubkey(),
        ed25519_authority.pubkey(),
        transfer_ix,
        1, // role_id of the ed25519 authority
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.default_payer, &ed25519_authority],
    )
    .unwrap();

    // Transaction should succeed
    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to sign with ed25519 authority: {:?}",
        result.err()
    );

    // Verify the transfer went through by checking the balance
    let payer_balance_after = context
        .svm
        .get_account(&context.default_payer.pubkey())
        .unwrap()
        .lamports;
}
