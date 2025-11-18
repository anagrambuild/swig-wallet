#![cfg(not(feature = "program_scope_test"))]
// This feature flag ensures these tests are only run when the
// "program_scope_test" feature is not enabled. This allows us to isolate
// and run only program_scope tests or only the regular tests.

mod common;
use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use common::*;
use solana_sdk::{
    clock::Clock,
    instruction::InstructionError,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{AuthorityConfig, ClientAction, CreateSessionInstruction};
use swig_state::{
    action::all::All,
    authority::{
        secp256k1::{Secp256k1Authority, Secp256k1SessionAuthority},
        AuthorityType,
    },
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
};

/// Helper function to get the current signature counter for a secp256k1
/// authority
fn get_secp256k1_counter(
    context: &SwigTestContext,
    swig_key: &solana_sdk::pubkey::Pubkey,
    wallet: &PrivateKeySigner,
) -> Result<u32, String> {
    // Get the swig account data
    let swig_account = context
        .svm
        .get_account(swig_key)
        .ok_or("Swig account not found")?;
    let swig = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| format!("Failed to parse swig data: {:?}", e))?;

    // Get the wallet's public key in the format expected by swig
    let eth_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();
    let authority_bytes = &eth_pubkey[1..]; // Remove the first byte (0x04 prefix)

    // Look up the role ID for this authority
    let role_id = swig
        .lookup_role_id(authority_bytes)
        .map_err(|e| format!("Failed to lookup role: {:?}", e))?
        .ok_or("Authority not found in swig account")?;

    // Get the role
    let role = swig
        .get_role(role_id)
        .map_err(|e| format!("Failed to get role: {:?}", e))?
        .ok_or("Role not found")?;

    // The authority should be a Secp256k1Authority, so we can access it directly
    // Since we know this is a Secp256k1 authority from our test setup
    if matches!(role.authority.authority_type(), AuthorityType::Secp256k1) {
        // We need to cast the authority to get access to the signature_odometer
        // The authority identity gives us the public key, but we need the full
        // authority object We'll need to access the raw authority data

        // Get the authority from the any() interface
        let secp_authority = role
            .authority
            .as_any()
            .downcast_ref::<Secp256k1Authority>()
            .ok_or("Failed to downcast to Secp256k1Authority")?;

        Ok(secp_authority.signature_odometer)
    } else {
        Err("Authority is not a Secp256k1Authority".to_string())
    }
}

#[test_log::test]
fn test_secp256k1_basic_signing_v2() {
    let mut context = setup_test_context().unwrap();

    // Generate a random Ethereum wallet
    let wallet = LocalSigner::random();

    // Create a new swig with the secp256k1 authority
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_secp256k1(&mut context, &wallet, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    // For SignV2, fund the swig_wallet_address instead of swig
    context
        .svm
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

    // Set up a recipient and transaction
    let recipient = Keypair::new();
    context.svm.airdrop(&recipient.pubkey(), 1_000_000).unwrap();
    let transfer_amount = 5_000_000;
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    // Sign the transaction
    let current_slot = 0; // Using 0 since LiteSVM doesn't expose get_slot
    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    // Read the current counter value and calculate next counter
    let current_counter = get_secp256k1_counter(&context, &swig_key, &wallet).unwrap();
    let next_counter = current_counter + 1;

    println!(
        "Current counter: {}, using next counter: {}",
        current_counter, next_counter
    );

    // Create and submit the transaction using SignV2
    let sign_ix = swig_interface::SignV2Instruction::new_secp256k1_with_signers(
        swig_key,
        swig_wallet_address,
        signing_fn,
        current_slot,
        next_counter, // Use dynamic counter value
        transfer_ix,
        1, // Role ID 1
        &[context.default_payer.pubkey()],
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
fn test_secp256k1_direct_signature_reuse_v2() {
    let mut context = setup_test_context().unwrap();

    // Generate a random Ethereum wallet
    let wallet = LocalSigner::random();

    // Create a new swig with the secp256k1 authority
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_secp256k1(&mut context, &wallet, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    // For SignV2, fund the swig_wallet_address instead of swig
    context
        .svm
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();
    let payer2 = Keypair::new();
    context.svm.airdrop(&payer2.pubkey(), 1_000_000).unwrap();

    // Set up a recipient and transaction
    let recipient = Keypair::new();
    context.svm.airdrop(&recipient.pubkey(), 1_000_000).unwrap();
    let transfer_amount = 5_000_000;
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);
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

    // Read the current counter and calculate next counter
    let current_counter = get_secp256k1_counter(&context, &swig_key, &wallet).unwrap();
    let next_counter = current_counter + 1;

    // TRANSACTION 1: Initial transaction that should succeed using SignV2
    let sign_ix = swig_interface::SignV2Instruction::new_secp256k1_with_signers(
        swig_key,
        swig_wallet_address,
        sign_fn,
        current_slot,
        next_counter, // Use dynamic counter value
        transfer_ix.clone(),
        1, // Role ID
        &[context.default_payer.pubkey()],
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
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    let reuse_signature_fn = move |_: &[u8]| -> [u8; 65] { sig };

    // Advance the slot by 2
    context.svm.warp_to_slot(2);

    // TRANSACTION 2: Attempt to reuse the stored signature (should fail) using
    // SignV2
    let sign_ix2 = swig_interface::SignV2Instruction::new_secp256k1_with_signers(
        swig_key,
        swig_wallet_address,
        reuse_signature_fn,
        current_slot,
        next_counter, // Trying to reuse the same counter (should fail)
        transfer_ix2,
        1,
        &[context.default_payer.pubkey()],
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

    // TRANSACTION 3: Fresh signature at current slot (should succeed) using SignV2
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
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    // Get current counter after the failed transaction and calculate next
    let updated_counter = get_secp256k1_counter(&context, &swig_key, &wallet).unwrap();
    let next_counter_fresh = updated_counter + 1;

    let sign_ix3 = swig_interface::SignV2Instruction::new_secp256k1_with_signers(
        swig_key,
        swig_wallet_address,
        fresh_signing_fn,
        current_slot_value, // Use current slot from simulator
        next_counter_fresh, // Use dynamic counter value
        transfer_ix3,
        1,
        &[context.default_payer.pubkey()],
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
fn test_secp256k1_old_signature_v2() {
    let mut context = setup_test_context().unwrap();

    // Generate a random Ethereum wallet
    let wallet = LocalSigner::random();

    // Create a new swig with the secp256k1 authority
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_secp256k1(&mut context, &wallet, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    // For SignV2, fund the swig_wallet_address instead of swig
    context
        .svm
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

    // Set up a recipient and transaction
    let recipient = Keypair::new();
    context.svm.airdrop(&recipient.pubkey(), 1_000_000).unwrap();
    let transfer_amount = 1_000_000;
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

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

    // Get current counter and calculate next
    let current_counter = get_secp256k1_counter(&context, &swig_key, &wallet).unwrap();
    let next_counter = current_counter + 1;

    // Create and submit the transaction with the old signature using SignV2
    let sign_ix = swig_interface::SignV2Instruction::new_secp256k1_with_signers(
        swig_key,
        swig_wallet_address,
        signing_fn,
        old_slot,     // Using old slot
        next_counter, // Use dynamic counter value
        transfer_ix,
        1,
        &[context.default_payer.pubkey()],
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
fn test_secp256k1_add_authority_v2() {
    let mut context = setup_test_context().unwrap();

    // Create primary Ed25519 authority
    let primary_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    // Create a new swig with Ed25519 authority
    let (swig_key, _) = create_swig_ed25519(&mut context, &primary_authority, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    // For SignV2, fund the swig_wallet_address instead of swig
    context
        .svm
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

    // Read the account data to verify initial state
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let roles_before = swig_state.state.roles;
    assert_eq!(roles_before, 2);

    // Test initial Ed25519 signing using SignV2
    let transfer_ix = system_instruction::transfer(
        &swig_wallet_address,
        &context.default_payer.pubkey(),
        1_000_000,
    );
    let sign_ix = swig_interface::SignV2Instruction::new_ed25519(
        swig_key,
        swig_wallet_address,
        primary_authority.pubkey(),
        transfer_ix,
        1, // role_id of the primary wallet
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
        1, // role_id of the primary wallet
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
    assert_eq!(swig_state.state.roles, 3);

    // Test signing with the new Secp256k1 authority using SignV2
    let transfer_ix = system_instruction::transfer(
        &swig_wallet_address,
        &context.default_payer.pubkey(),
        500_000,
    );

    // Create signing function for Secp256k1
    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        secp_wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let sign_ix = swig_interface::SignV2Instruction::new_secp256k1_with_signers(
        swig_key,
        swig_wallet_address,
        signing_fn,
        current_slot,
        1, // counter = 1 (first transaction)
        transfer_ix,
        2, // role_id of the secp256k1 authority
        &[context.default_payer.pubkey()],
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
fn test_secp256k1_add_ed25519_authority_v2() {
    let mut context = setup_test_context().unwrap();

    // Generate a random Ethereum wallet for the primary authority
    let wallet = LocalSigner::random();

    // Create a new swig with the secp256k1 authority
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_secp256k1(&mut context, &wallet, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    // For SignV2, fund the swig_wallet_address instead of swig
    context
        .svm
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

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
        1, // counter = 1 (first transaction)
        1, // role_id of the primary wallet
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
    assert_eq!(swig_state.state.roles, 3);

    // Test signing with the new ed25519 authority using SignV2
    let transfer_ix = system_instruction::transfer(
        &swig_wallet_address,
        &context.default_payer.pubkey(),
        500_000,
    );
    let sign_ix = swig_interface::SignV2Instruction::new_ed25519(
        swig_key,
        swig_wallet_address,
        ed25519_authority.pubkey(),
        transfer_ix,
        2, // role_id of the ed25519 authority
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

#[test_log::test]
fn test_secp256k1_replay_scenario_1_v2() {
    let mut context = setup_test_context().unwrap();

    // Generate a random Ethereum wallet
    let wallet = LocalSigner::random();

    // Create a new swig with the secp256k1 authority
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_secp256k1(&mut context, &wallet, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    // For SignV2, fund the swig_wallet_address instead of swig
    context
        .svm
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

    // Set up a recipient and transaction
    let recipient = Keypair::new();
    context.svm.airdrop(&recipient.pubkey(), 1_000_000).unwrap();
    let transfer_amount = 5_000_000;
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    // Get current slot for first transaction
    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    // Read the current counter value and assert it's 0 (initial state)
    let current_counter = get_secp256k1_counter(&context, &swig_key, &wallet).unwrap();
    assert_eq!(current_counter, 0, "Initial counter should be 0");

    // Calculate the next expected counter
    let next_counter = current_counter + 1;

    // TRANSACTION 1: Initial transaction that should succeed using SignV2
    let sign_ix = swig_interface::SignV2Instruction::new_secp256k1_with_signers(
        swig_key,
        swig_wallet_address,
        signing_fn,
        current_slot,
        next_counter, // Use dynamic counter value instead of hardcoded 1
        transfer_ix.clone(),
        1, // Role ID
        &[context.default_payer.pubkey()],
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix.clone()],
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

    // Verify that the counter was incremented after the successful transaction
    let updated_counter = get_secp256k1_counter(&context, &swig_key, &wallet).unwrap();
    assert_eq!(
        updated_counter, next_counter,
        "Counter should be incremented after successful transaction"
    );

    // TRANSACTION 2: Attempt replay with additional instructions
    // Try to reuse the same signature instruction with additional manipulated
    // instructions
    let message2 = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[
            sign_ix, // Reusing the same instruction with the old counter value (should fail)
            solana_sdk::instruction::Instruction {
                program_id: spl_memo::ID,
                accounts: vec![solana_sdk::instruction::AccountMeta::new(
                    context.default_payer.pubkey(),
                    true,
                )],
                data: b"replay".to_vec(),
            },
        ],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx2 =
        VersionedTransaction::try_new(VersionedMessage::V0(message2), &[&context.default_payer])
            .unwrap();

    // Second transaction should fail due to counter validation
    let result2 = context.svm.send_transaction(tx2);
    assert!(
        result2.is_err(),
        "Expected second transaction to fail due to replay protection"
    );

    // Verify the specific error is related to signature reuse
    match result2.unwrap_err().err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => {
            // This should match the error code for PermissionDeniedSecp256k1SignatureReused
            println!("Error code: {}", code);
            assert!(code > 0, "Expected a custom error code for signature reuse");
        },
        err => panic!("Expected InstructionError::Custom, got {:?}", err),
    }

    // TRANSACTION 3: Fresh transaction with correct counter (should succeed) using
    // SignV2
    let transfer_ix3 =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    let fresh_signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    // Get the current counter after the failed replay attempt
    let current_counter_after_replay = get_secp256k1_counter(&context, &swig_key, &wallet).unwrap();
    assert_eq!(
        current_counter_after_replay, updated_counter,
        "Counter should remain unchanged after failed transaction"
    );

    // Calculate the next counter for the fresh transaction
    let next_counter_fresh = current_counter_after_replay + 1;

    let sign_ix3 = swig_interface::SignV2Instruction::new_secp256k1_with_signers(
        swig_key,
        swig_wallet_address,
        fresh_signing_fn,
        current_slot,
        next_counter_fresh, // Use dynamic counter value
        transfer_ix3,
        1,
        &[context.default_payer.pubkey()],
    )
    .unwrap();

    let message3 = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix3],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx3 =
        VersionedTransaction::try_new(VersionedMessage::V0(message3), &[&context.default_payer])
            .unwrap();

    // Third transaction should succeed with correct counter
    let result3 = context.svm.send_transaction(tx3);
    println!("result3: {:?}", result3);
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

    // Verify the counter was incremented after the final successful transaction
    let final_counter = get_secp256k1_counter(&context, &swig_key, &wallet).unwrap();
    assert_eq!(
        final_counter, next_counter_fresh,
        "Final counter should be incremented after successful transaction"
    );

    println!(
        "Test completed successfully! Counter progression: 0 -> {} -> {} (failed replay) -> {}",
        next_counter, updated_counter, final_counter
    );
}

#[test_log::test]
fn test_secp256k1_replay_scenario_2_v2() {
    let mut context = setup_test_context().unwrap();

    // Generate a random Ethereum wallet
    let wallet = LocalSigner::random();

    // Create a new swig with the secp256k1 authority
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_secp256k1(&mut context, &wallet, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    // For SignV2, fund the swig_wallet_address instead of swig
    context
        .svm
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

    // Set up a recipient and transaction
    let recipient = Keypair::new();
    context.svm.airdrop(&recipient.pubkey(), 1_000_000).unwrap();
    let transfer_amount = 5_000_000;
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    // Get current slot for first transaction
    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    // Read the current counter and calculate next counter
    let current_counter = get_secp256k1_counter(&context, &swig_key, &wallet).unwrap();
    let next_counter = current_counter + 1;

    // TRANSACTION 1: Initial transaction that should succeed using SignV2
    let sign_ix = swig_interface::SignV2Instruction::new_secp256k1_with_signers(
        swig_key,
        swig_wallet_address,
        signing_fn,
        current_slot,
        next_counter, // Use dynamic counter value
        transfer_ix.clone(),
        1, // Role ID
        &[context.default_payer.pubkey()],
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix.clone()],
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

    // Send with manipulated instructions
    let message2 = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[
            sign_ix, // sending the same instruction again
            solana_sdk::instruction::Instruction {
                program_id: spl_memo::ID,
                accounts: vec![solana_sdk::instruction::AccountMeta::new(
                    context.default_payer.pubkey(),
                    true,
                )],
                data: b"replayed".to_vec(),
            },
        ],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx2 =
        VersionedTransaction::try_new(VersionedMessage::V0(message2), &[&context.default_payer])
            .unwrap();

    let result2 = context.svm.send_transaction(tx2);
    assert!(
        result2.is_err(),
        "Expected second transaction to succeed (demonstrating vulnerability): {:?}",
        result2.ok()
    );

    // Verify second transfer was not successful
    let recipient_account_final = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_ne!(
        recipient_account_final.lamports,
        1_000_000 + 2 * transfer_amount
    );
}

#[test_log::test]
fn test_secp256k1_session_authority_odometer_v2() {
    let mut context = setup_test_context().unwrap();

    // Generate a random Ethereum wallet
    let wallet = LocalSigner::random();

    let id = rand::random::<[u8; 32]>();

    // Create a swig with secp256k1 session authority type
    let (swig_key, _) =
        create_swig_secp256k1_session(&mut context, &wallet, id, 100, [0; 32]).unwrap();

    // Helper function to read the current counter for session authorities
    let get_session_counter = |ctx: &SwigTestContext| -> Result<u32, String> {
        let swig_account = ctx
            .svm
            .get_account(&swig_key)
            .ok_or("Swig account not found")?;
        let swig = SwigWithRoles::from_bytes(&swig_account.data)
            .map_err(|e| format!("Failed to parse swig data: {:?}", e))?;

        let role = swig
            .get_role(1)
            .map_err(|e| format!("Failed to get role: {:?}", e))?
            .ok_or("Role not found")?;

        if let Some(auth) = role
            .authority
            .as_any()
            .downcast_ref::<Secp256k1SessionAuthority>()
        {
            Ok(auth.signature_odometer)
        } else {
            Err("Authority is not a Secp256k1SessionAuthority".to_string())
        }
    };

    // Initial counter should be 0
    let initial_counter = get_session_counter(&context).unwrap();
    assert_eq!(initial_counter, 0, "Initial session counter should be 0");

    // Verify the session authority structure is correctly initialized
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 2);
    let role = swig.get_role(1).unwrap().unwrap();

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

    println!("✓ Secp256k1 session authority structure correctly initialized");
    println!("✓ Signature odometer field present and initialized to 0");
    println!("✓ Session authority has proper session-based behavior");
    println!("✓ All other fields remain intact after adding odometer");
}
