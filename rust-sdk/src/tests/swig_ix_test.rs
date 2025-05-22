use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use common::*;
use litesvm::{types::TransactionMetadata, LiteSVM};
use litesvm_token::spl_token;
use solana_program::{pubkey::Pubkey, system_program};
use solana_sdk::{
    account::ReadableAccount,
    clock::Clock,
    message::{v0, VersionedMessage},
    signature::Keypair,
    signer::Signer,
    system_instruction,
    transaction::VersionedTransaction,
};
use swig_interface::{
    program_id, AuthorityConfig, ClientAction, CreateInstruction, CreateSessionInstruction,
    SignInstruction,
};
use swig_state_x::{
    action::{
        all::All, manage_authority::ManageAuthority, program_scope::ProgramScope,
        sol_limit::SolLimit, sol_recurring_limit::SolRecurringLimit,
    },
    authority::{
        ed25519::{CreateEd25519SessionAuthority, ED25519Authority, Ed25519SessionAuthority},
        secp256k1::{
            CreateSecp256k1SessionAuthority, Secp256k1Authority, Secp256k1SessionAuthority,
        },
        AuthorityType,
    },
    role::Role,
    swig::{swig_account_seeds, SwigWithRoles},
    IntoBytes,
};

use super::*;
use crate::{
    error::SwigError, instruction_builder::AuthorityManager, types::Permission, RecurringConfig,
    SwigInstructionBuilder, SwigWallet,
};

#[test_log::test]
fn test_create_swig_account_with_ed25519_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [1u8; 32];
    let authority = Keypair::new();
    let payer = context.default_payer;
    let role_id = 0;

    let builder = SwigInstructionBuilder::new(
        swig_id,
        AuthorityManager::Ed25519(authority.pubkey()),
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

    // Verify the account was created correctly
    let (swig_key, _) = Pubkey::find_program_address(&swig_account_seeds(&swig_id), &program_id());
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let root_role = swig_data.get_role(0).unwrap().unwrap();

    assert_eq!(swig_data.state.id, swig_id);
    assert_eq!(swig_data.state.roles, 1);
}

#[test_log::test]
fn test_create_swig_account_with_secp256k1_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [1u8; 32];

    let wallet = LocalSigner::random();

    let secp_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();

    let payer = &context.default_payer;
    let role_id = 0;

    let builder = SwigInstructionBuilder::new(
        swig_id,
        AuthorityManager::Secp256k1(secp_pubkey, Box::new(|_| [0u8; 65])),
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

    // Verify the account was created correctly
    let (swig_key, _) = Pubkey::find_program_address(&swig_account_seeds(&swig_id), &program_id());
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let root_role = swig_data.get_role(0).unwrap().unwrap();

    assert_eq!(swig_data.state.id, swig_id);
    assert_eq!(swig_data.state.roles, 1);
    assert_eq!(
        root_role.authority.authority_type(),
        AuthorityType::Secp256k1
    );
}

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
        AuthorityManager::Ed25519(authority.pubkey()),
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
        AuthorityManager::Ed25519(authority.pubkey()),
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
fn test_add_authority_with_ed25519_root() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [3u8; 32];
    let authority = Keypair::new();
    let role_id = 0;

    // First create the Swig account
    let (swig_key, _) = create_swig_ed25519(&mut context, &authority, swig_id).unwrap();

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        AuthorityManager::Ed25519(authority.pubkey()),
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
        &[add_auth_ix],
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
fn test_add_authority_and_transfer_with_ed25519_root() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [4u8; 32];
    let authority = Keypair::new();
    let role_id = 0;

    let (swig_key, _) = create_swig_ed25519(&mut context, &authority, swig_id).unwrap();

    context.svm.airdrop(&swig_key, 100_000_000_000).unwrap();

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        AuthorityManager::Ed25519(authority.pubkey()),
        context.default_payer.pubkey(),
        role_id,
    );

    let new_authority = Keypair::new();
    let new_authority_bytes = new_authority.pubkey().to_bytes();
    let permissions = vec![Permission::Sol {
        amount: 1_000_000_000,
        recurring: None,
    }];

    let recipient = Keypair::new();

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
        &[add_auth_ix],
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

    let transfer_ix =
        solana_program::system_instruction::transfer(&swig_key, &recipient.pubkey(), 100000);

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
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);

    assert!(
        result.is_ok(),
        "Failed to execute signed instruction: {:?}",
        result.err()
    );

    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(recipient_account.lamports, 100000);
}

#[test_log::test]
fn test_create_ed25519_session_with_add_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [5u8; 32];
    let authority = Keypair::new();
    let session_key = Keypair::new();

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        AuthorityManager::Ed25519Session(CreateEd25519SessionAuthority::new(
            authority.pubkey().to_bytes(),
            [0; 32],
            100,
        )),
        context.default_payer.pubkey(),
        0,
    );

    let ix = builder.build_swig_account().unwrap();
    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[ix],
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

    let swig_key = builder.get_swig_account().unwrap();

    // start a session
    let session_ix = builder
        .create_session_instruction(session_key.pubkey(), 100, None)
        .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[session_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx_session = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx_session);
    assert!(
        result.is_ok(),
        "Failed to create session: {:?}",
        result.err()
    );
}

#[test_log::test]
fn test_add_authority_and_transfer_with_secp256k1_root() {
    // First create the Swig account
    let mut context = setup_test_context().unwrap();
    let swig_id = [1u8; 32];
    let payer = &context.default_payer;
    let role_id = 0;

    // Create Swig Wallet with Secp256k1 authority
    let wallet = LocalSigner::random();
    let secp_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();

    let mut sig = [0u8; 65];
    let wallet = wallet.clone();
    let signing_fn = move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        AuthorityManager::Secp256k1(secp_pubkey.clone(), Box::new(signing_fn.clone())),
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

    // Add a new authority to the Swig account
    let swig_key = builder.get_swig_account().unwrap();

    let new_authority = LocalSigner::random();
    let new_secp_pubkey = new_authority
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();

    let permissions = vec![Permission::Sol {
        amount: 10_000_000_000,
        recurring: None,
    }];

    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    let add_auth_ix = builder
        .add_authority_instruction(
            AuthorityType::Secp256k1,
            &new_secp_pubkey,
            permissions,
            Some(current_slot),
        )
        .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_auth_ix],
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

    // Transfer 1SOL to the new authority
    let mut sign_fn2 = move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        new_authority.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    let mut builder_with_new_authority = SwigInstructionBuilder::new(
        swig_id,
        AuthorityManager::Secp256k1(new_secp_pubkey, Box::new(sign_fn2)),
        payer.pubkey(),
        1,
    );

    // Fund the Swig account
    context.svm.airdrop(&swig_key, 1_000_000_000).unwrap();

    // Create a transfer instruction to test signing
    let recipient = Keypair::new();
    let transfer_amount = 100_000_000;
    let transfer_ix = solana_program::system_instruction::transfer(
        &swig_key,
        &recipient.pubkey(),
        transfer_amount,
    );
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let sign_ix = builder_with_new_authority
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

    // Verify the transfer was successful
    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(recipient_account.lamports, transfer_amount);
}

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
        AuthorityManager::Ed25519Session(CreateEd25519SessionAuthority::new(
            swig_authority.pubkey().to_bytes(),
            [0; 32],
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

    let swig_pubkey = swig_key;
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_data = swig_account.data;

    let swig_with_roles = SwigWithRoles::from_bytes(&swig_data)
        .map_err(|e| SwigError::InvalidSwigData)
        .unwrap();

    let auth: &Ed25519SessionAuthority = role.authority.as_any().downcast_ref().unwrap();

    // create an ed25519 session authority
    let session_authority = Keypair::new();
    let session_authority_pubkey = session_authority.pubkey().to_bytes();

    let create_session_ix = swig_ix_builder
        .create_session_instruction(session_authority.pubkey(), 100, None)
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
        AuthorityManager::Secp256k1Session(
            CreateSecp256k1SessionAuthority::new(
                secp_pubkey[1..].try_into().unwrap(),
                [0; 32],
                100,
            ),
            Box::new(signing_fn),
        ),
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
        AuthorityType::Secp256k1Session
    );
    assert!(role.authority.session_based());
    let auth: &Secp256k1SessionAuthority = role.authority.as_any().downcast_ref().unwrap();

    assert_eq!(auth.max_session_age, 100);
    // assert_eq!(auth.public_key, secp_pubkey[1..].try_into().unwrap());
    assert_eq!(auth.current_session_expiration, 0);
    assert_eq!(auth.session_key, [0; 32]);

    let swig_pubkey = swig_key;
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_data = swig_account.data;

    let swig_with_roles = SwigWithRoles::from_bytes(&swig_data)
        .map_err(|e| SwigError::InvalidSwigData)
        .unwrap();

    let auth: &Secp256k1SessionAuthority = role.authority.as_any().downcast_ref().unwrap();

    // create an ed25519 session authority
    let session_authority = Keypair::new();
    let session_authority_pubkey = session_authority.pubkey().to_bytes();

    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let create_session_ix = swig_ix_builder
        .create_session_instruction(session_authority.pubkey(), 100, Some(current_slot))
        .unwrap();

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
    let swig_data = swig_account.data;

    let swig_with_roles = SwigWithRoles::from_bytes(&swig_data)
        .map_err(|e| SwigError::InvalidSwigData)
        .unwrap();

    let role = swig_with_roles.get_role(0).unwrap().unwrap();

    let auth: &Secp256k1SessionAuthority = role.authority.as_any().downcast_ref().unwrap();
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

    let wallet = wallet.clone();
    let signing_fn = move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        AuthorityManager::Secp256k1(secp_pubkey, Box::new(signing_fn)),
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

    let wallet = wallet.clone();
    let signing_fn = move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        AuthorityManager::Secp256k1(secp_pubkey, Box::new(signing_fn)),
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
        &[add_auth_ix],
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
        AuthorityManager::Ed25519(authority.pubkey()),
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
        &[add_auth_ix],
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
        &[remove_auth_ix],
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
        AuthorityManager::Ed25519(authority.pubkey()),
        payer.pubkey(),
        role_id,
    );

    let new_authority = Keypair::new();
    let new_payer = Keypair::new();

    builder
        .switch_authority(1, AuthorityManager::Ed25519(new_authority.pubkey()))
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

fn test_token_transfer_with_program_scope() {
    let mut context = setup_test_context().unwrap();

    // Setup payers and recipients
    let swig_authority = Keypair::new();
    let regular_sender = Keypair::new();
    let recipient = Keypair::new();

    // Airdrop to participants
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&regular_sender.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    // Setup token mint
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    // Setup swig account
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let swig_create_result = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_result.is_ok());

    // Setup token accounts
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig,
        &context.default_payer,
    )
    .unwrap();

    let new_authority = Keypair::new();

    let program_scope = Permission::ProgramScope {
        program_id: spl_token::ID,
        target_account: swig_ata,
        numeric_type: 1,
        limit: Some(1_000_000),
        window: Some(0),
        balance_field_start: Some(64),
        balance_field_end: Some(72),
    };

    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    let mut builder = SwigInstructionBuilder::new(
        id,
        AuthorityManager::Ed25519(swig_authority.pubkey()),
        context.default_payer.pubkey(),
        0,
    );

    let add_auth_ix = builder
        .add_authority_instruction(
            AuthorityType::Ed25519,
            &new_authority.pubkey().to_bytes(),
            vec![program_scope],
            Some(current_slot),
        )
        .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_auth_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &new_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to add authority: {:?}",
        result.err()
    );

    println!("Added ProgramScope action for token program");

    let swig_account = context.svm.get_account(&swig).unwrap();

    let regular_sender_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &regular_sender.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    // Mint tokens to both sending accounts
    let initial_token_amount = 1000;
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        initial_token_amount,
    )
    .unwrap();

    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &regular_sender_ata,
        initial_token_amount,
    )
    .unwrap();

    // Test regular token transfer
    let transfer_amount = 100;
    let token_program_id = spl_token::ID;

    let regular_transfer_ix = spl_token::instruction::transfer(
        &token_program_id,
        &regular_sender_ata,
        &recipient_ata,
        &regular_sender.pubkey(),
        &[],
        transfer_amount,
    )
    .unwrap();

    let regular_transfer_message = v0::Message::try_compile(
        &regular_sender.pubkey(),
        &[regular_transfer_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let regular_transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(regular_transfer_message),
        &[regular_sender],
    )
    .unwrap();

    let result = context.svm.send_transaction(regular_transfer_tx);
    assert!(
        result.is_ok(),
        "Regular transfer failed: {:?}",
        result.err()
    );

    // Test swig token transfer
    let swig_transfer_ix = spl_token::instruction::transfer(
        &token_program_id,
        &swig_ata,
        &recipient_ata,
        &swig,
        &[],
        transfer_amount,
    )
    .unwrap();

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        swig_authority.pubkey(),
        swig_authority.pubkey(),
        swig_transfer_ix,
        1, // authority role id
    )
    .unwrap();

    let swig_transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let swig_transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(swig_transfer_message),
        &[swig_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(swig_transfer_tx);
    assert!(result.is_ok(), "Swig transfer failed: {:?}", result.err());
}

/// Helper function to perform token transfers through the swig
fn perform_token_transfer(
    context: &mut SwigTestContext,
    swig: Pubkey,
    swig_authority: &Keypair,
    swig_ata: Pubkey,
    recipient_ata: Pubkey,
    amount: u64,
    expected_success: bool,
) -> Vec<String> {
    // Expire the blockhash to ensure we don't get AlreadyProcessed errors
    context.svm.expire_blockhash();

    // Get the current token balance before the transfer
    let before_token_account = context.svm.get_account(&swig_ata).unwrap();
    let before_balance = if before_token_account.data.len() >= 72 {
        // SPL token accounts have their balance at offset 64-72
        u64::from_le_bytes(before_token_account.data[64..72].try_into().unwrap())
    } else {
        0
    };
    println!("Before transfer, token balance: {}", before_balance);

    let token_program_id = spl_token::ID;

    let transfer_ix = spl_token::instruction::transfer(
        &token_program_id,
        &swig_ata,
        &recipient_ata,
        &swig,
        &[],
        amount,
    )
    .unwrap();

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        swig_authority.pubkey(),
        swig_authority.pubkey(),
        transfer_ix,
        1, // authority role id
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[swig_authority])
            .unwrap();

    let result = context.svm.send_transaction(transfer_tx);

    // Get the current token balance after the transfer
    let after_token_account = context.svm.get_account(&swig_ata).unwrap();
    let after_balance = if after_token_account.data.len() >= 72 {
        // SPL token accounts have their balance at offset 64-72
        u64::from_le_bytes(after_token_account.data[64..72].try_into().unwrap())
    } else {
        0
    };
    println!("After transfer, token balance: {}", after_balance);

    if expected_success {
        assert!(
            result.is_ok(),
            "Expected successful transfer, but got error: {:?}",
            result.err()
        );
        // Verify the token balance actually decreased by the expected amount
        assert_eq!(
            before_balance - after_balance,
            amount,
            "Token balance did not decrease by the expected amount"
        );
        println!("Successfully transferred {} tokens", amount);
        println!(
            "Token balance decreased from {} to {}",
            before_balance, after_balance
        );
        result.unwrap().logs
    } else {
        println!("result: {:?}", result);
        assert!(
            result.is_err(),
            "Expected transfer to fail, but it succeeded"
        );
        // Verify the balance didn't change
        assert_eq!(
            before_balance, after_balance,
            "Token balance should not have changed for a failed transfer"
        );
        println!("Transfer of {} tokens was correctly rejected", amount);
        Vec::new()
    }
}

use solana_sdk::account::Account;

pub fn display_swig(swig_pubkey: Pubkey, swig_account: &Account) -> Result<(), SwigError> {
    let swig_with_roles =
        SwigWithRoles::from_bytes(&swig_account.data).map_err(|e| SwigError::InvalidSwigData)?;

    println!("╔══════════════════════════════════════════════════════════════════");
    println!("║ SWIG WALLET DETAILS");
    println!("╠══════════════════════════════════════════════════════════════════");
    println!("║ Account Address: {}", swig_pubkey);
    println!("║ Total Roles: {}", swig_with_roles.state.role_counter);
    println!(
        "║ Balance: {} SOL",
        swig_account.lamports() as f64 / 1_000_000_000.0
    );

    println!("╠══════════════════════════════════════════════════════════════════");
    println!("║ ROLES & PERMISSIONS");
    println!("╠══════════════════════════════════════════════════════════════════");

    for i in 0..swig_with_roles.state.role_counter {
        let role = swig_with_roles
            .get_role(i)
            .map_err(|e| SwigError::AuthorityNotFound)?;

        if let Some(role) = role {
            println!("║");
            println!("║ Role ID: {}", i);
            println!(
                "║ ├─ Type: {}",
                if role.authority.session_based() {
                    "Session-based Authority"
                } else {
                    "Permanent Authority"
                }
            );
            println!("║ ├─ Authority Type: {:?}", role.authority.authority_type());
            println!(
                "║ ├─ Authority: {}",
                match role.authority.authority_type() {
                    AuthorityType::Ed25519 | AuthorityType::Ed25519Session => {
                        let authority = role.authority.identity().unwrap();
                        let authority = bs58::encode(authority).into_string();
                        authority
                    },
                    AuthorityType::Secp256k1 | AuthorityType::Secp256k1Session => {
                        let authority = role.authority.identity().unwrap();
                        let authority_hex = hex::encode([&[0x4].as_slice(), authority].concat());
                        // get eth address from public key
                        let mut hasher = solana_sdk::keccak::Hasher::default();
                        hasher.hash(authority_hex.as_bytes());
                        let hash = hasher.result();
                        let address = format!("0x{}", hex::encode(&hash.0[12..32]));
                        address
                    },
                    _ => todo!(),
                }
            );

            println!("║ ├─ Permissions:");

            // Check All permission
            if (Role::get_action::<All>(&role, &[]).map_err(|_| SwigError::AuthorityNotFound)?)
                .is_some()
            {
                println!("║ │  ├─ Full Access (All Permissions)");
            }

            // Check Manage Authority permission
            if (Role::get_action::<ManageAuthority>(&role, &[])
                .map_err(|_| SwigError::AuthorityNotFound)?)
            .is_some()
            {
                println!("║ │  ├─ Manage Authority");
            }

            // Check Sol Limit
            if let Some(action) = Role::get_action::<SolLimit>(&role, &[])
                .map_err(|_| SwigError::AuthorityNotFound)?
            {
                println!(
                    "║ │  ├─ SOL Limit: {} SOL",
                    action.amount as f64 / 1_000_000_000.0
                );
            }

            // Check Sol Recurring Limit
            if let Some(action) = Role::get_action::<SolRecurringLimit>(&role, &[])
                .map_err(|_| SwigError::AuthorityNotFound)?
            {
                println!("║ │  ├─ Recurring SOL Limit:");
                println!(
                    "║ │  │  ├─ Amount: {} SOL",
                    action.recurring_amount as f64 / 1_000_000_000.0
                );
                println!("║ │  │  ├─ Window: {} slots", action.window);
                println!(
                    "║ │  │  ├─ Current Usage: {} SOL",
                    action.current_amount as f64 / 1_000_000_000.0
                );
                println!("║ │  │  └─ Last Reset: Slot {}", action.last_reset);
            }

            // Check Program Scope
            if let Some(action) = Role::get_action::<ProgramScope>(
                &role,
                &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            )
            .map_err(|_| SwigError::AuthorityNotFound)?
            {
                let program_id = Pubkey::from(action.program_id);
                let target_account = Pubkey::from(action.target_account);
                println!("║ │  ├─ Program Scope:");
                println!("║ │  │  ├─ Program ID: {:?}", program_id);
                println!("║ │  │  ├─ Target Account: {:?}", target_account);
                println!("║ │  │  ├─ Numeric Type: {}", action.numeric_type);
                println!("║ │  │  ├─ Window: {}", action.window);
                println!("║ │  │  ├─ Limit: {}", action.limit);
                println!(
                    "║ │  │  ├─ Balance Field Start: {}",
                    action.balance_field_start
                );
                println!("║ │  │  └─ Balance Field End: {}", action.balance_field_end);
            }
            println!("║ │  ");
        }
    }

    println!("╚══════════════════════════════════════════════════════════════════");

    Ok(())
}
