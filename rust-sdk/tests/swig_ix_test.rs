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
use swig_sdk::{AuthorityManager, Permission, SwigError, SwigInstructionBuilder};
use swig_state_x::{
    action::{
        all::All, manage_authority::ManageAuthority, sol_limit::SolLimit,
        sol_recurring_limit::SolRecurringLimit,
    },
    authority::{
        ed25519::{CreateEd25519SessionAuthority, ED25519Authority, Ed25519SessionAuthority},
        secp256k1::{CreateSecp256k1SessionAuthority, Secp256k1Authority},
        AuthorityType,
    },
    role::Role,
    swig::{swig_account_seeds, SwigWithRoles},
    IntoBytes,
};

#[test_log::test]
fn test_build_and_execute_swig_account() {
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
fn test_build_and_execute_swig_account_secp256k1() {
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
fn test_sign_instruction_execution() {
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

    // Print all the accounts
    println!("Swig key: {:?}", swig_key);
    println!("Recipient key: {:?}", recipient.pubkey());
    println!("Authority key: {:?}", authority.pubkey());
    println!("Payer key: {:?}", context.default_payer.pubkey());

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
fn test_sign_instruction_execution_secp256k1() {
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
        let tsig = wallet
            .sign_hash_sync(&hash)
            .map_err(|_| SwigError::InvalidSecp256k1)
            .unwrap()
            .as_bytes();
        let mut sig = [0u8; 65];
        sig.copy_from_slice(&tsig);
        sig
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

    // Print all the accounts
    println!("Swig key: {:?}", swig_key);
    println!("Recipient key: {:?}", recipient.pubkey());
    println!("Payer key: {:?}", context.default_payer.pubkey());

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
fn test_add_authority_instruction_execution() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [3u8; 32];
    let authority = Keypair::new();
    let role_id = 0;

    // First create the Swig account
    let (swig_key, _) = create_swig_ed25519(&mut context, &authority, swig_id).unwrap();

    println!("swig key {:?}", swig_key);
    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        AuthorityManager::Ed25519(authority.pubkey()),
        context.default_payer.pubkey(),
        role_id,
    );
    println!("Swig account from builder {:?}", builder.get_swig_account());

    let new_authority = Keypair::new();
    println!("new authority {:?}", new_authority.pubkey());
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
fn test_add_authority_instruction_execution_secp256k1() {
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
    println!("new authority {:?}", new_authority.address());
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
fn test_add_authority_and_transfer_sol() {
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
fn test_add_authority_and_transfer_sol_secp256k1() {
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
    let wallet = wallet; // Move wallet into a separate binding

    let mut sign_fn = move |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        let tsig = wallet
            .sign_hash_sync(&hash)
            .map_err(|_| SwigError::InvalidSecp256k1)
            .unwrap()
            .as_bytes();
        let mut sig = [0u8; 65];
        sig.copy_from_slice(&tsig);
        sig
    };

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        AuthorityManager::Secp256k1(secp_pubkey.clone(), Box::new(sign_fn.clone())),
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
    println!("current slot {:?}", current_slot);
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
// fn test_remove_authority_execution() {
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
// fn test_replace_authority_execution() {
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
    println!("auth: {:?}", auth);

    // create an ed25519 session authority
    println!("creating session authority");
    let session_authority = Keypair::new();
    let session_authority_pubkey = session_authority.pubkey().to_bytes();

    let create_session_ix = swig_ix_builder
        .create_session_instruction(session_authority.pubkey(), 100)
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
    println!("auth: {:?}", auth);
}

#[test_log::test]
fn test_create_session() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = [0; 32];

    // Create a swig with ed25519session authority type
    let (swig_key, res) =
        create_swig_ed25519_session(&mut context, &swig_authority, id, 100, [0; 32]).unwrap();

    println!("res: {:?}", res.logs);
    // Airdrop funds to the swig account so it can transfer SOL
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

pub fn create_swig_ed25519_session(
    context: &mut SwigTestContext,
    authority: &Keypair,
    id: [u8; 32],
    session_max_length: u64,
    initial_session_key: [u8; 32],
) -> anyhow::Result<(Pubkey, TransactionMetadata)> {
    let payer_pubkey = context.default_payer.pubkey();
    let (swig, bump) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());

    let authority_pubkey = authority.pubkey().to_bytes();
    let authority_data = CreateEd25519SessionAuthority::new(
        authority_pubkey,
        initial_session_key,
        session_max_length,
    );
    let authority_data_bytes = authority_data
        .into_bytes()
        .map_err(|e| anyhow::anyhow!("Failed to serialize authority data {:?}", e))?;
    let initial_authority = AuthorityConfig {
        authority_type: AuthorityType::Ed25519Session,
        authority: authority_data_bytes,
    };

    let swig_ix_builder = SwigInstructionBuilder::new(
        id,
        AuthorityManager::Ed25519Session(CreateEd25519SessionAuthority::new(
            authority_pubkey,
            initial_session_key,
            session_max_length,
        )),
        context.default_payer.pubkey(),
        0,
    );

    let create_ix = swig_ix_builder.build_swig_account()?;

    let msg = v0::Message::try_compile(
        &payer_pubkey,
        &[create_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[context.default_payer.insecure_clone()],
    )
    .unwrap();
    let bench = context
        .svm
        .send_transaction(tx)
        .map_err(|e| anyhow::anyhow!("Failed to send transaction {:?}", e))?;
    Ok((swig, bench))
}
