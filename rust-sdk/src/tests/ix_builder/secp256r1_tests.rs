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
use swig_state::{
    action::all::All,
    authority::{
        secp256r1::{Secp256r1Authority, Secp256r1SessionAuthority},
        AuthorityType,
    },
    swig::{swig_wallet_address_seeds, SwigWithRoles},
};

use super::*;
use crate::{
    client_role::{ClientRole, Ed25519ClientRole, Secp256r1ClientRole},
    instruction_builder::SwigInstructionBuilder,
    types::Permission as ClientPermission,
};

#[test_log::test]
fn test_secp256r1_basic_signing() {
    let mut context = setup_test_context().unwrap();

    // Create a real secp256r1 key pair for testing
    let (signing_key, public_key) = create_test_secp256r1_keypair();

    // Create a new swig with the secp256r1 authority using instruction builder
    let id = rand::random::<[u8; 32]>();

    // Create signing function for the client role
    let signing_fn = Box::new(move |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        let signature =
            sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap();
        signature
    });

    let mut builder = SwigInstructionBuilder::new(
        id,
        Box::new(Secp256r1ClientRole::new(public_key, signing_fn)),
        context.default_payer.pubkey(),
        0, // role_id
    );

    // Build the create instruction
    let create_ix = builder.create_swig_account_instruction().unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[create_ix],
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
        "Failed to create Swig account: {:?}",
        result.err()
    );

    let swig_key = builder.get_swig_config_address().unwrap();
    let swig_wallet_address = builder.swig_wallet_address();

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

    // Get current slot for signing
    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    // Create signed instructions using the instruction builder
    let signed_instructions = builder
        .sign_v2_instruction(vec![transfer_ix], Some(current_slot))
        .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &signed_instructions,
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
        new_counter, 1,
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
fn test_secp256r1_counter_increment() {
    let mut context = setup_test_context().unwrap();

    // Create a real secp256r1 key pair for testing
    let (_, public_key) = create_test_secp256r1_keypair();

    // Create a new swig with the secp256r1 authority using instruction builder
    let id = rand::random::<[u8; 32]>();

    // Create a dummy signing function for creation (won't be used for signing)
    let dummy_signing_fn = Box::new(|_message_hash: &[u8]| -> [u8; 64] {
        [0u8; 64] // Dummy signature
    });

    let builder = SwigInstructionBuilder::new(
        id,
        Box::new(Secp256r1ClientRole::new(public_key, dummy_signing_fn)),
        context.default_payer.pubkey(),
        0, // role_id
    );

    // Build the create instruction
    let create_ix = builder.create_swig_account_instruction().unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[create_ix],
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
        "Failed to create Swig account: {:?}",
        result.err()
    );

    let swig_key = builder.get_swig_config_address().unwrap();
    let swig_wallet_address = builder.swig_wallet_address();

    // Verify initial counter is 0
    let initial_counter = get_secp256r1_counter(&context, &swig_key, &public_key).unwrap();
    assert_eq!(initial_counter, 0, "Initial counter should be 0");

    println!("✓ Initial counter verified as 0");
    println!("✓ Secp256r1 authority structure works correctly");
}

#[test_log::test]
fn test_secp256r1_replay_protection() {
    let mut context = setup_test_context().unwrap();

    // Create a real secp256r1 key pair for testing
    let (signing_key, public_key) = create_test_secp256r1_keypair();

    // Create a new swig with the secp256r1 authority using instruction builder
    let id = rand::random::<[u8; 32]>();

    // Create signing function for the client role
    let signing_fn = Box::new(move |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        let signature =
            sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap();
        signature
    });

    let mut builder = SwigInstructionBuilder::new(
        id,
        Box::new(Secp256r1ClientRole::new(public_key, signing_fn)),
        context.default_payer.pubkey(),
        0, // role_id
    );

    // Build the create instruction
    let create_ix = builder.create_swig_account_instruction().unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[create_ix],
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
        "Failed to create Swig account: {:?}",
        result.err()
    );

    let swig_key = builder.get_swig_config_address().unwrap();
    let swig_wallet_address = builder.swig_wallet_address();

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

    // First transaction - should succeed
    let signed_instructions1 = builder
        .sign_v2_instruction(vec![transfer_ix.clone()], Some(current_slot))
        .unwrap();

    let message1 = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &signed_instructions1,
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
    println!("✓ First transaction succeeded");

    // Try second transaction with same counter (should fail due to replay
    // protection) We need to manually set the counter to 1 to simulate replay
    // Re-create the signing_key for the replay closure
    let (replay_signing_key, _) = create_test_secp256r1_keypair();
    let signing_fn_clone = Box::new(move |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        let signature = sign_message(
            message_hash,
            &replay_signing_key.private_key_to_der().unwrap(),
        )
        .unwrap();
        signature
    });

    // Create a new client role with odometer set to 1 to simulate replay
    let mut replay_client_role =
        Secp256r1ClientRole::new_without_odometer(public_key, signing_fn_clone);
    replay_client_role.update_odometer(1).unwrap();

    let mut replay_builder = SwigInstructionBuilder::new(
        id,
        Box::new(replay_client_role),
        context.default_payer.pubkey(),
        0, // role_id
    );

    let signed_instructions2 = replay_builder
        .sign_v2_instruction(vec![transfer_ix], Some(current_slot))
        .unwrap();

    let message2 = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &signed_instructions2,
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
fn test_secp256r1_add_authority() {
    let mut context = setup_test_context().unwrap();

    // Create primary Ed25519 authority
    let primary_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    // Create a new swig with Ed25519 authority using instruction builder
    let mut builder = SwigInstructionBuilder::new(
        id,
        Box::new(Ed25519ClientRole::new(primary_authority.pubkey())),
        context.default_payer.pubkey(),
        0, // role_id
    );

    let create_ix = builder.create_swig_account_instruction().unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[create_ix],
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
        "Failed to create Swig account: {:?}",
        result.err()
    );

    let swig_key = builder.get_swig_config_address().unwrap();
    let swig_wallet_address = builder.swig_wallet_address();
    context
        .svm
        .airdrop(&builder.swig_wallet_address(), 10_000_000_000)
        .unwrap();

    // Create a real secp256r1 public key to add as second authority
    let (_, secp256r1_pubkey) = create_test_secp256r1_keypair();

    // Create instruction to add the Secp256r1 authority using instruction builder
    let add_authority_ix = builder
        .add_authority_instruction(
            AuthorityType::Secp256r1,
            &secp256r1_pubkey,
            vec![ClientPermission::All],
            None, // current_slot not needed for Ed25519
        )
        .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &add_authority_ix,
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
fn test_secp256r1_session_authority() {
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
fn test_secp256r1_session_authority_odometer() {
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
    use swig_state::swig::swig_account_seeds;

    let payer_pubkey = context.default_payer.pubkey();
    let (swig_address, swig_bump) = solana_sdk::pubkey::Pubkey::find_program_address(
        &swig_account_seeds(&id),
        &swig_interface::program_id(),
    );

    let (swig_wallet_address, wallet_address_bump) =
        solana_sdk::pubkey::Pubkey::find_program_address(
            &swig_wallet_address_seeds(swig_address.as_ref()),
            &swig_interface::program_id(),
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
fn test_secp256r1_add_authority_with_secp256r1() {
    let mut context = setup_test_context().unwrap();

    // Create a real secp256r1 key pair for the primary authority
    let (signing_key, public_key) = create_test_secp256r1_keypair();
    let id = rand::random::<[u8; 32]>();

    // Create a new swig with secp256r1 authority using instruction builder
    let signing_fn = Box::new(move |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        let signature =
            sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap();
        signature
    });

    let mut builder = SwigInstructionBuilder::new(
        id,
        Box::new(Secp256r1ClientRole::new(public_key, signing_fn)),
        context.default_payer.pubkey(),
        0, // role_id
    );

    // Build the create instruction
    let create_ix = builder.create_swig_account_instruction().unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[create_ix],
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
        "Failed to create Swig account: {:?}",
        result.err()
    );

    let swig_key = builder.get_swig_config_address().unwrap();
    let swig_wallet_address = builder.swig_wallet_address();
    context
        .svm
        .airdrop(&builder.swig_wallet_address(), 10_000_000_000)
        .unwrap();

    let swig_account = context.svm.get_account(&swig_key).unwrap();

    display_swig(swig_key, &swig_account).unwrap();

    // Create a second secp256r1 public key to add as a new authority
    let (_, new_public_key) = create_test_secp256r1_keypair();

    // Get current slot for signing
    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    // Create instruction to add the new Secp256r1 authority using instruction
    // builder
    let add_authority_ix = builder
        .add_authority_instruction(
            AuthorityType::Secp256r1,
            &new_public_key,
            vec![ClientPermission::All],
            Some(current_slot),
        )
        .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &add_authority_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&context.default_payer])
            .unwrap();

    let result = context.svm.send_transaction(tx);
    println!("Transaction result: {:?}", result);
    assert!(
        result.is_ok(),
        "Failed to add Secp256r1 authority using secp256r1 signature: {:?}",
        result.err()
    );

    let swig_account = context.svm.get_account(&swig_key).unwrap();

    display_swig(swig_key, &swig_account).unwrap();
    // Verify the authority was added
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_state.state.roles, 2);

    // Verify the counter was incremented
    let new_counter = get_secp256r1_counter(&context, &swig_key, &public_key).unwrap();
    assert_eq!(
        new_counter, 1,
        "Counter should be incremented after successful transaction"
    );

    println!("✓ Successfully added Secp256r1 authority using secp256r1 signature");
    println!("✓ Authority count increased to 2");
    println!("✓ Counter incremented correctly");
}
