#![cfg(not(feature = "program_scope_test"))]
// This feature flag ensures these tests are only run when the
// "program_scope_test" feature is not enabled. This allows us to isolate
// and run only program_scope tests or only the regular tests.

mod common;
use common::*;
use solana_sdk::{
    clock::Clock,
    instruction::InstructionError,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use solana_system_interface::instruction as system_instruction;
use swig_interface::{AuthorityConfig, ClientAction};
use swig_state::{
    action::all::All,
    authority::{
        secp256r1::{
            Secp256r1Authority, Secp256r1SessionAuthority, COMPRESSED_PUBKEY_SERIALIZED_SIZE,
            MESSAGE_DATA_OFFSET, MESSAGE_DATA_SIZE, PUBKEY_DATA_OFFSET, SIGNATURE_OFFSETS_START,
        },
        AuthorityType,
    },
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
};

/// Helper to generate a real secp256r1 key pair for testing
fn create_test_secp256r1_keypair() -> (openssl::ec::EcKey<openssl::pkey::Private>, [u8; 33]) {
    use openssl::{
        bn::BigNumContext,
        ec::{EcGroup, EcKey, PointConversionForm},
        nid::Nid,
    };

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let signing_key = EcKey::generate(&group).unwrap();

    let mut ctx = BigNumContext::new().unwrap();
    let pubkey_bytes = signing_key
        .public_key()
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap();

    let pubkey_array: [u8; 33] = pubkey_bytes.try_into().unwrap();
    (signing_key, pubkey_array)
}

/// Helper function to create a secp256r1 authority with a test public key
fn create_test_secp256r1_authority() -> [u8; 33] {
    let (_, pubkey) = create_test_secp256r1_keypair();
    pubkey
}

/// Helper function to get the current signature counter for a secp256r1
/// authority
fn get_secp256r1_counter(
    context: &SwigTestContext,
    swig_key: &solana_sdk::pubkey::Pubkey,
    public_key: &[u8; 33],
) -> Result<u32, String> {
    // Get the swig account data
    let swig_account = context
        .svm
        .get_account(swig_key)
        .ok_or("Swig account not found")?;
    let swig = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| format!("Failed to parse swig data: {:?}", e))?;

    // Look up the role ID for this authority
    let role_id = swig
        .lookup_role_id(public_key)
        .map_err(|e| format!("Failed to lookup role: {:?}", e))?
        .ok_or("Authority not found in swig account")?;

    // Get the role
    let role = swig
        .get_role(role_id)
        .map_err(|e| format!("Failed to get role: {:?}", e))?
        .ok_or("Role not found")?;

    // The authority should be a Secp256r1Authority
    if matches!(role.authority.authority_type(), AuthorityType::Secp256r1) {
        // Get the authority from the any() interface
        let secp_authority = role
            .authority
            .as_any()
            .downcast_ref::<Secp256r1Authority>()
            .ok_or("Failed to downcast to Secp256r1Authority")?;

        Ok(secp_authority.signature_odometer)
    } else {
        Err("Authority is not a Secp256r1Authority".to_string())
    }
}

#[test_log::test]
fn test_secp256r1_basic_signing_v2() {
    let mut context = setup_test_context().unwrap();

    // Create a real secp256r1 key pair for testing
    let (signing_key, public_key) = create_test_secp256r1_keypair();

    // Create a new swig with the secp256r1 authority
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_secp256r1(&mut context, &public_key, id).unwrap();
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

    // Get current slot and counter
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let current_counter = get_secp256r1_counter(&context, &swig_key, &public_key).unwrap();
    let next_counter = current_counter + 1;

    println!(
        "Current counter: {}, using next counter: {}",
        current_counter, next_counter
    );

    // Create authority function that signs the message hash
    let mut authority_fn = |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        let signature =
            sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap();
        signature
    };

    // Create the secp256r1 signing instructions using SignV2 (returns
    // Vec<Instruction>)
    let instructions = swig_interface::SignV2Instruction::new_secp256r1(
        swig_key,
        swig_wallet_address,
        authority_fn,
        current_slot,
        next_counter,
        transfer_ix.clone(),
        0, // Role ID 0
        &public_key,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &instructions, // Use the returned instructions directly
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&context.default_payer])
            .unwrap();

    // Send the transaction - should now succeed with real cryptography
    let result = context.svm.send_transaction(tx);

    println!("Transaction result: {:?}", result);

    // Verify the transaction succeeded
    assert!(
        result.is_ok(),
        "Transaction should succeed with real secp256r1 signature: {:?}",
        result.err()
    );

    // Verify the counter was incremented
    let new_counter = get_secp256r1_counter(&context, &swig_key, &public_key).unwrap();
    assert_eq!(
        new_counter, next_counter,
        "Counter should be incremented after successful transaction"
    );

    // Verify the transfer actually happened
    let recipient_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    assert_eq!(
        recipient_balance,
        1_000_000 + transfer_amount,
        "Recipient should receive the transferred amount"
    );

    println!("✓ Secp256r1 signing test passed with real cryptography");
}

#[test_log::test]
fn test_secp256r1_counter_increment_v2() {
    let mut context = setup_test_context().unwrap();

    // Create a real secp256r1 key pair for testing
    let (_, public_key) = create_test_secp256r1_keypair();

    // Create a new swig with the secp256r1 authority
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_secp256r1(&mut context, &public_key, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    // For SignV2, fund the swig_wallet_address instead of swig
    context
        .svm
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

    // Verify initial counter is 0
    let initial_counter = get_secp256r1_counter(&context, &swig_key, &public_key).unwrap();
    assert_eq!(initial_counter, 0, "Initial counter should be 0");

    println!("✓ Initial counter verified as 0");
    println!("✓ Secp256r1 authority structure works correctly");
}

#[test_log::test]
fn test_secp256r1_replay_protection_v2() {
    let mut context = setup_test_context().unwrap();

    // Create a real secp256r1 key pair for testing
    let (signing_key, public_key) = create_test_secp256r1_keypair();

    // Create a new swig with the secp256r1 authority
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_secp256r1(&mut context, &public_key, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    // For SignV2, fund the swig_wallet_address instead of swig
    context
        .svm
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

    // Set up transfer instruction
    let recipient = Keypair::new();
    context.svm.airdrop(&recipient.pubkey(), 1_000_000).unwrap();
    let transfer_amount = 1_000_000;
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    // First transaction with counter 1
    let counter1 = 1;

    // Create authority function that signs the message hash
    let mut authority_fn1 = |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        let signature =
            sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap();
        signature
    };

    let instructions1 = swig_interface::SignV2Instruction::new_secp256r1(
        swig_key,
        swig_wallet_address,
        authority_fn1,
        current_slot,
        counter1,
        transfer_ix.clone(),
        0,
        &public_key,
    )
    .unwrap();

    // Execute first transaction
    let message1 = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &instructions1,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx1 =
        VersionedTransaction::try_new(VersionedMessage::V0(message1), &[&context.default_payer])
            .unwrap();
    let result1 = context.svm.send_transaction(tx1);

    assert!(
        result1.is_ok(),
        "First transaction should succeed: {:?}",
        result1.err()
    );
    println!("✓ First transaction with counter 1 succeeded");

    // Try second transaction with same counter (should fail due to replay
    // protection)
    let mut authority_fn2 = |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        let signature =
            sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap();
        signature
    };

    let instructions2 = swig_interface::SignV2Instruction::new_secp256r1(
        swig_key,
        swig_wallet_address,
        authority_fn2,
        current_slot,
        counter1, // Same counter - should trigger replay protection
        transfer_ix.clone(),
        0,
        &public_key,
    )
    .unwrap();

    let message2 = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &instructions2,
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
        "Second transaction with same counter should fail due to replay protection"
    );
    println!("✓ Second transaction with same counter failed (replay protection working)");

    // Verify counter is now 1
    let current_counter = get_secp256r1_counter(&context, &swig_key, &public_key).unwrap();
    assert_eq!(
        current_counter, 1,
        "Counter should be 1 after first transaction"
    );

    println!("✓ Replay protection test passed - counter-based protection is working");
}

#[test_log::test]
fn test_secp256r1_add_authority_v2() {
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

    // Create a real secp256r1 public key to add as second authority
    let (_, secp256r1_pubkey) = create_test_secp256r1_keypair();

    // Create instruction to add the Secp256r1 authority
    let add_authority_ix = swig_interface::AddAuthorityInstruction::new_with_ed25519_authority(
        swig_key,
        context.default_payer.pubkey(),
        primary_authority.pubkey(),
        0, // role_id of the primary wallet
        AuthorityConfig {
            authority_type: AuthorityType::Secp256r1,
            authority: &secp256r1_pubkey,
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
        "Failed to add Secp256r1 authority: {:?}",
        result.err()
    );

    // Verify the authority was added
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_state.state.roles, 2);

    println!("✓ Successfully added Secp256r1 authority");
    println!("✓ Authority count increased to 2");
}

#[test_log::test]
fn test_secp256r1_session_authority_v2() {
    let mut context = setup_test_context().unwrap();

    // Create a real secp256r1 public key for session authority
    let (_, public_key) = create_test_secp256r1_keypair();

    // Create session authority parameters
    let session_key = rand::random::<[u8; 32]>();
    let max_session_length = 1000; // 1000 slots

    let create_params = swig_state::authority::secp256r1::CreateSecp256r1SessionAuthority::new(
        public_key,
        session_key,
        max_session_length,
    );

    // Verify the structure works
    assert_eq!(create_params.public_key, public_key);
    assert_eq!(create_params.session_key, session_key);
    assert_eq!(create_params.max_session_length, max_session_length);

    println!("✓ Secp256r1 session authority structure works correctly");
    println!(
        "✓ Session parameters: max_length = {} slots",
        max_session_length
    );
}

#[test_log::test]
fn test_secp256r1_session_authority_odometer_v2() {
    let mut context = setup_test_context().unwrap();

    // Create a real secp256r1 key pair for testing
    let (_, public_key) = create_test_secp256r1_keypair();

    let id = rand::random::<[u8; 32]>();

    // Create a swig with secp256r1 session authority type using the helper function
    let (swig_key, _) =
        create_swig_secp256r1_session(&mut context, &public_key, id, 100, [0; 32]).unwrap();

    // Helper function to read the current counter for session authorities
    let get_session_counter = |ctx: &SwigTestContext| -> Result<u32, String> {
        let swig_account = ctx
            .svm
            .get_account(&swig_key)
            .ok_or("Swig account not found")?;
        let swig = SwigWithRoles::from_bytes(&swig_account.data)
            .map_err(|e| format!("Failed to parse swig data: {:?}", e))?;

        let role = swig
            .get_role(0)
            .map_err(|e| format!("Failed to get role: {:?}", e))?
            .ok_or("Role not found")?;

        if let Some(auth) = role
            .authority
            .as_any()
            .downcast_ref::<Secp256r1SessionAuthority>()
        {
            Ok(auth.signature_odometer)
        } else {
            Err("Authority is not a Secp256r1SessionAuthority".to_string())
        }
    };

    // Initial counter should be 0
    let initial_counter = get_session_counter(&context).unwrap();
    assert_eq!(initial_counter, 0, "Initial session counter should be 0");

    // Verify the session authority structure is correctly initialized
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 1);
    let role = swig.get_role(0).unwrap().unwrap();

    assert_eq!(
        role.authority.authority_type(),
        AuthorityType::Secp256r1Session
    );
    assert!(role.authority.session_based());

    let auth: &Secp256r1SessionAuthority = role.authority.as_any().downcast_ref().unwrap();
    assert_eq!(auth.max_session_age, 100);
    assert_eq!(auth.public_key, public_key);
    assert_eq!(auth.current_session_expiration, 0);
    assert_eq!(auth.session_key, [0; 32]);
    assert_eq!(auth.signature_odometer, 0, "Initial odometer should be 0");

    println!("✓ Secp256r1 session authority structure correctly initialized");
    println!("✓ Signature odometer field present and initialized to 0");
    println!("✓ Session authority has proper session-based behavior");
}

/// Helper function to create a swig account with secp256r1 authority for
/// testing
fn create_swig_secp256r1(
    context: &mut SwigTestContext,
    public_key: &[u8; 33],
    id: [u8; 32],
) -> Result<(solana_sdk::pubkey::Pubkey, u8), Box<dyn std::error::Error>> {
    let payer_pubkey = context.default_payer.pubkey();
    let (swig_address, swig_bump) = solana_sdk::pubkey::Pubkey::find_program_address(
        &swig_account_seeds(&id),
        &common::program_id(),
    );

    let (swig_wallet_address, wallet_address_bump) =
        solana_sdk::pubkey::Pubkey::find_program_address(
            &swig_wallet_address_seeds(swig_address.as_ref()),
            &common::program_id(),
        );
    let create_ix = swig_interface::CreateInstruction::new(
        swig_address,
        swig_bump,
        payer_pubkey,
        swig_wallet_address,
        wallet_address_bump,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256r1,
            authority: public_key,
        },
        vec![ClientAction::All(All {})],
        id,
    )?;

    let message = v0::Message::try_compile(
        &payer_pubkey,
        &[create_ix],
        &[],
        context.svm.latest_blockhash(),
    )?;

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&context.default_payer])?;

    context.svm.send_transaction(tx).unwrap();

    Ok((swig_address, swig_bump))
}

#[test_log::test]
fn test_secp256r1_add_authority_with_secp256r1_v2() {
    let mut context = setup_test_context().unwrap();

    // Create a real secp256r1 key pair for the primary authority
    let (signing_key, public_key) = create_test_secp256r1_keypair();
    let id = rand::random::<[u8; 32]>();

    // Create a new swig with secp256r1 authority
    let (swig_key, _) = create_swig_secp256r1(&mut context, &public_key, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    // For SignV2, fund the swig_wallet_address instead of swig
    context
        .svm
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

    // Create a second secp256r1 public key to add as a new authority
    let (_, new_public_key) = create_test_secp256r1_keypair();

    // Get current slot and counter for the authority
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let current_counter = get_secp256r1_counter(&context, &swig_key, &public_key).unwrap();
    let next_counter = current_counter + 1;

    // Create authority function that signs the message hash
    let mut authority_fn = |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        let signature =
            sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap();
        signature
    };

    // Create instruction to add the new Secp256r1 authority using SignV2
    let instructions = swig_interface::AddAuthorityInstruction::new_with_secp256r1_authority(
        swig_key,
        context.default_payer.pubkey(),
        authority_fn,
        current_slot,
        next_counter,
        0, // role_id of the primary authority
        &public_key,
        AuthorityConfig {
            authority_type: AuthorityType::Secp256r1,
            authority: &new_public_key,
        },
        vec![ClientAction::All(All {})],
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &instructions,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&context.default_payer])
            .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to add Secp256r1 authority using secp256r1 signature: {:?}",
        result.err()
    );

    // Verify the authority was added
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_state.state.roles, 2);

    // Verify the counter was incremented
    let new_counter = get_secp256r1_counter(&context, &swig_key, &public_key).unwrap();
    assert_eq!(
        new_counter, next_counter,
        "Counter should be incremented after successful transaction"
    );

    println!("✓ Successfully added Secp256r1 authority using secp256r1 signature");
    println!("✓ Authority count increased to 2");
    println!("✓ Counter incremented correctly");
}

#[test_log::test]
fn test_secp256r1_signature_offsets_bypass_allows_unauthorized_transfer_v2() {
    let mut context = setup_test_context().unwrap();

    // Primary wallet authority
    let (_, primary_pubkey) = create_test_secp256r1_keypair();

    eprintln!("Primary pubkey: {:?}", primary_pubkey);

    // Secondary keypair for signing
    let (secondary_key, secondary_pubkey) = create_test_secp256r1_keypair();
    eprintln!("Secondary pubkey: {:?}", secondary_pubkey);

    let test_message = [0x42u8; 32];

    // Register the primary key as the only authority on a funded swig wallet
    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_secp256r1(&mut context, &primary_pubkey, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    // Fund the swig_wallet_address
    context
        .svm
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

    // Set up transfer transaction
    let recipient = Keypair::new();
    context.svm.airdrop(&recipient.pubkey(), 1_000_000).unwrap();
    let transfer_amount = 3_000_000;
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let current_counter = get_secp256r1_counter(&context, &swig_key, &primary_pubkey).unwrap();
    let next_counter = current_counter + 1;

    // Build signing instructions but use a different key inside signing callback
    let mut expected_hash = [0u8; 32];
    let mut expected_hash_recorded = false;
    let mut authority_fn = |message_hash: &[u8]| -> [u8; 64] {
        expected_hash.copy_from_slice(message_hash);
        expected_hash_recorded = true;
        use solana_secp256r1_program::sign_message;
        sign_message(&test_message, &secondary_key.private_key_to_der().unwrap()).unwrap()
    };

    let mut instructions = swig_interface::SignV2Instruction::new_secp256r1(
        swig_key,
        swig_wallet_address,
        &mut authority_fn,
        current_slot,
        next_counter,
        transfer_ix.clone(),
        0,
        &primary_pubkey,
    )
    .unwrap();

    // Instruction 0 is the secp256r1 precompile call.
    let secp_ix = instructions.first_mut().unwrap();

    // Append secondary key and message data at the end of the instruction buffer.
    let secondary_pubkey_offset = u16::try_from(secp_ix.data.len()).unwrap();
    secp_ix.data.extend_from_slice(&secondary_pubkey);

    let message_offset = u16::try_from(secp_ix.data.len()).unwrap();
    secp_ix.data.extend_from_slice(&test_message);

    // Modify the offsets to point to the appended data instead of expected
    // locations.
    let public_key_offset_index = SIGNATURE_OFFSETS_START + 4;
    let message_offset_index = SIGNATURE_OFFSETS_START + 8;
    secp_ix.data[public_key_offset_index..public_key_offset_index + 2]
        .copy_from_slice(&secondary_pubkey_offset.to_le_bytes());
    secp_ix.data[message_offset_index..message_offset_index + 2]
        .copy_from_slice(&message_offset.to_le_bytes());

    // Place expected data at the standard offsets for verification
    secp_ix.data[PUBKEY_DATA_OFFSET..PUBKEY_DATA_OFFSET + COMPRESSED_PUBKEY_SERIALIZED_SIZE]
        .copy_from_slice(&primary_pubkey);
    secp_ix.data[MESSAGE_DATA_OFFSET..MESSAGE_DATA_OFFSET + MESSAGE_DATA_SIZE]
        .copy_from_slice(&expected_hash);

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &instructions,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&context.default_payer])
            .unwrap();

    let result = context.svm.send_transaction(tx);

    eprintln!("Transaction result: {:?}", result);
    assert!(
        result.is_err(),
        "Transaction should fail because offset values are validated"
    );

    // The recipient should NOT have received any funds (transaction was rejected)
    let recipient_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    assert_eq!(
        recipient_balance, 1_000_000,
        "Recipient should NOT have received funds since transaction was rejected"
    );

    // The counter should not have advanced (transaction was rejected)
    let final_counter = get_secp256r1_counter(&context, &swig_key, &primary_pubkey).unwrap();
    assert_eq!(
        final_counter, current_counter,
        "Counter should not have advanced since transaction was rejected"
    );
}
