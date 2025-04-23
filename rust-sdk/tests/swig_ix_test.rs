mod common;

use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use common::*;
use litesvm::{types::TransactionMetadata, LiteSVM};
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
use swig_sdk::{AuthorityManager, Permission, SwigError, SwigInstructionBuilder, SwigWallet};
use swig_state_x::{
    action::{
        all::All, manage_authority::ManageAuthority, sol_limit::SolLimit,
        sol_recurring_limit::SolRecurringLimit,
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

#[test_log::test]
fn test_ix_build_and_execute_swig_account() {
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

    // Verify the account was created correctly
    let (swig_key, _) = Pubkey::find_program_address(&swig_account_seeds(&swig_id), &program_id());
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_data.state.id, swig_id);
}

#[test_log::test]
fn test_ix_build_and_execute_swig_account_secp256k1() {
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
    assert_eq!(swig_data.state.id, swig_id);
}

#[test_log::test]
fn test_ix_sign_instruction_execution() {
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
fn test_ix_sign_instruction_execution_secp256k1() {
    // First create the Swig account
    let mut context = setup_test_context().unwrap();
    let swig_id = [1u8; 32];
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

    // Fund the Swig account
    context.svm.airdrop(&swig_key, 1_000_000_000).unwrap();

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
fn test_ix_add_authority_instruction_execution() {
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
fn test_ix_add_authority_instruction_execution_secp256k1() {
    // First create the Swig account
    let mut context = setup_test_context().unwrap();
    let swig_id = [1u8; 32];
    let payer = &context.default_payer;
    let role_id = 0;

    let wallet = LocalSigner::random();

    let secp_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();

    let mut sig = [0u8; 65];
    let wallet = wallet; // Move wallet into a separate binding

    let mut sign_fn = move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        AuthorityManager::Secp256k1(secp_pubkey, Box::new(sign_fn)),
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

    let new_ed_authority = Keypair::new();
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

    // Verify the new authority was added
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_data.state.roles, 2); // Root authority + new authority
}

#[test_log::test]
fn test_ix_add_authority_and_transfer_sol() {
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
fn test_ix_ed25519_session_with_add_authority() {
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
fn test_ix_add_authority_and_transfer_sol_secp256k1() {
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

// #[test_log::test]
// fn test_ix_remove_authority_execution() {
//     let mut context = setup_test_context().unwrap();
//     let swig_id = [4u8; 32];
//     let authority = Keypair::new();
//     let payer = &context.default_payer;
//     let role_id = 0;

//     // First create the Swig account
//     let (swig_key, _) = create_swig_ed25519(&mut context, &authority,
// swig_id).unwrap();

//     // Add a new authority that we'll remove
//     let new_authority = Keypair::new();
//     add_authority_with_ed25519_root(
//         &mut context,
//         &swig_key,
//         &authority,
//         AuthorityConfig {
//             authority_type: AuthorityType::Ed25519,
//             authority: new_authority.pubkey().as_ref(),
//         },
//         vec![ClientAction::All],
//     )
//     .unwrap();

//     let builder = SwigInstructionBuilder::new(
//         swig_id,
//         AuthorityType::Ed25519,
//         authority.pubkey(),
//         payer.pubkey(),
//         role_id,
//     );

//     let remove_auth_ix = builder.remove_authority(1).unwrap(); // Remove
// authority with ID 1

//     let msg = v0::Message::try_compile(
//         &payer.pubkey(),
//         &[remove_auth_ix],
//         &[],
//         context.svm.latest_blockhash(),
//     )
//     .unwrap();

//     let tx =
//         VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer,
// &authority]).unwrap();

//     let result = context.svm.send_transaction(tx);
//     assert!(
//         result.is_ok(),
//         "Failed to remove authority: {:?}",
//         result.err()
//     );

//     // Verify the authority was removed
//     let swig_account = context.svm.get_account(&swig_key).unwrap();
//     let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
//     assert_eq!(swig_data.state.roles, 1); // Only root authority remains
// }

// #[test_log::test]
// fn test_ix_replace_authority_execution() {
//     let mut context = setup_test_context().unwrap();
//     let swig_id = [5u8; 32];
//     let authority = Keypair::new();
//     let payer = &context.default_payer;
//     let role_id = 0;

//     // First create the Swig account
//     let (swig_key, _) = create_swig_ed25519(&mut context, &authority,
// swig_id).unwrap();

//     // Add an authority that we'll replace
//     let old_authority = Keypair::new();
//     add_authority_with_ed25519_root(
//         &mut context,
//         &swig_key,
//         &authority,
//         AuthorityConfig {
//             authority_type: AuthorityType::Ed25519,
//             authority: old_authority.pubkey().as_ref(),
//         },
//         vec![ClientAction::All(All {})],
//     )
//     .unwrap();

//     let builder = SwigInstructionBuilder::new(
//         swig_id,
//         AuthorityType::Ed25519,
//         authority.pubkey(),
//         payer.pubkey(),
//         role_id,
//     );

//     let new_authority = Keypair::new();
//     let new_authority_bytes = new_authority.pubkey().to_bytes();
//     let permissions = vec![Permission::All];

//     let replace_auth_ixs = builder
//         .replace_authority(
//             1, // Replace authority with ID 1
//             AuthorityType::Ed25519,
//             &new_authority_bytes,
//             permissions,
//         )
//         .unwrap();

//     let msg = v0::Message::try_compile(
//         &payer.pubkey(),
//         &replace_auth_ixs,
//         &[],
//         context.svm.latest_blockhash(),
//     )
//     .unwrap();

//     let tx =
//         VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer,
// &authority]).unwrap();

//     let result = context.svm.send_transaction(tx);
//     assert!(
//         result.is_ok(),
//         "Failed to replace authority: {:?}",
//         result.err()
//     );

//     // Verify the authority was replaced
//     let swig_account = context.svm.get_account(&swig_key).unwrap();
//     let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
//     assert_eq!(swig_data.state.roles, 2); // Root authority + new authority
// }

#[test_log::test]
fn test_ix_ed25519_session() {
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
fn test_ix_secp256k1_session() {
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
    //assert_eq!(auth.public_key, secp_pubkey[1..].try_into().unwrap());
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
