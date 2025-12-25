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
use swig_state::{
    authority::AuthorityType,
    swig::{swig_account_seeds, SwigWithRoles},
};

use super::*;
use crate::{
    client_role::{Ed25519ClientRole, Secp256k1ClientRole},
    types::{Permission, RecurringConfig},
};

#[test_log::test]
fn test_add_sol_destination_limit_with_ed25519() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [1u8; 32];
    let authority = Keypair::new();
    let payer = &context.default_payer;
    let role_id = 1;

    let builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
        payer.pubkey(),
        role_id,
    );

    // Create Swig account
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

    // Add a new authority with SOL destination limit
    let new_authority = Keypair::new();
    let destination = Keypair::new().pubkey();
    let limit_amount = 500_000; // 0.0005 SOL

    let permissions = vec![Permission::SolDestination {
        destination,
        amount: limit_amount,
        recurring: None,
    }];

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
        payer.pubkey(),
        role_id,
    );

    let add_authority_ix = builder
        .add_authority_instruction(
            AuthorityType::Ed25519,
            &new_authority.pubkey().to_bytes(),
            permissions,
            None,
        )
        .unwrap();

    let msg = v0::Message::try_compile(
        &payer.pubkey(),
        &add_authority_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer, &authority]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to add authority: {:?}",
        result.err()
    );
}

#[test_log::test]
fn test_add_sol_recurring_destination_limit_with_ed25519() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [2u8; 32];
    let authority = Keypair::new();
    let payer = &context.default_payer;
    let role_id = 1;

    let builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
        payer.pubkey(),
        role_id,
    );

    // Create Swig account
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

    // Add a new authority with SOL recurring destination limit
    let new_authority = Keypair::new();
    let destination = Keypair::new().pubkey();
    let limit_amount = 500_000; // 0.0005 SOL
    let window = 1000; // 1000 slots

    let permissions = vec![Permission::SolDestination {
        destination,
        amount: limit_amount,
        recurring: Some(RecurringConfig::new(window)),
    }];

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
        payer.pubkey(),
        role_id,
    );

    let add_authority_ix = builder
        .add_authority_instruction(
            AuthorityType::Ed25519,
            &new_authority.pubkey().to_bytes(),
            permissions,
            None,
        )
        .unwrap();

    let msg = v0::Message::try_compile(
        &payer.pubkey(),
        &add_authority_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer, &authority]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to add authority: {:?}",
        result.err()
    );
}

#[test_log::test]
fn test_add_token_destination_limit_with_ed25519() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [3u8; 32];
    let authority = Keypair::new();
    let payer = &context.default_payer;
    let role_id = 1;

    let builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
        payer.pubkey(),
        role_id,
    );

    // Create Swig account
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

    // Add a new authority with token destination limit
    let new_authority = Keypair::new();
    let token_mint = Keypair::new().pubkey();
    let destination = Keypair::new().pubkey();
    let limit_amount = 1000; // 1000 tokens

    let permissions = vec![Permission::TokenDestination {
        mint: token_mint,
        destination,
        amount: limit_amount,
        recurring: None,
    }];

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
        payer.pubkey(),
        role_id,
    );

    let add_authority_ix = builder
        .add_authority_instruction(
            AuthorityType::Ed25519,
            &new_authority.pubkey().to_bytes(),
            permissions,
            None,
        )
        .unwrap();

    let msg = v0::Message::try_compile(
        &payer.pubkey(),
        &add_authority_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer, &authority]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to add authority: {:?}",
        result.err()
    );
}

#[test_log::test]
fn test_add_token_recurring_destination_limit_with_ed25519() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [4u8; 32];
    let authority = Keypair::new();
    let payer = &context.default_payer;
    let role_id = 1;

    let builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
        payer.pubkey(),
        role_id,
    );

    // Create Swig account
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

    // Add a new authority with token recurring destination limit
    let new_authority = Keypair::new();
    let token_mint = Keypair::new().pubkey();
    let destination = Keypair::new().pubkey();
    let limit_amount = 1000; // 1000 tokens
    let window = 1000; // 1000 slots

    let permissions = vec![Permission::TokenDestination {
        mint: token_mint,
        destination,
        amount: limit_amount,
        recurring: Some(RecurringConfig::new(window)),
    }];

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
        payer.pubkey(),
        role_id,
    );

    let add_authority_ix = builder
        .add_authority_instruction(
            AuthorityType::Ed25519,
            &new_authority.pubkey().to_bytes(),
            permissions,
            None,
        )
        .unwrap();

    let msg = v0::Message::try_compile(
        &payer.pubkey(),
        &add_authority_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer, &authority]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to add authority: {:?}",
        result.err()
    );
}

#[test_log::test]
fn test_add_sol_destination_limit_with_secp256k1() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [5u8; 32];
    let payer = &context.default_payer;
    let role_id = 1;

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

    // Create Swig account
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

    // Add a new authority with SOL destination limit
    let new_wallet = LocalSigner::random();
    let new_secp_pubkey = new_wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();
    let destination = Keypair::new().pubkey();
    let limit_amount = 500_000; // 0.0005 SOL

    let permissions = vec![Permission::SolDestination {
        destination,
        amount: limit_amount,
        recurring: None,
    }];

    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    let add_authority_ix = builder
        .add_authority_instruction(
            AuthorityType::Secp256k1,
            &new_secp_pubkey,
            permissions,
            Some(current_slot),
        )
        .unwrap();

    let msg = v0::Message::try_compile(
        &payer.pubkey(),
        &add_authority_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to add authority: {:?}",
        result.err()
    );
}

#[test_log::test]
fn test_multiple_destination_limits() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [6u8; 32];
    let authority = Keypair::new();
    let payer = &context.default_payer;
    let role_id = 1;

    let builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
        payer.pubkey(),
        role_id,
    );

    // Create Swig account
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

    // Add a new authority with multiple destination limits
    let new_authority = Keypair::new();
    let destination1 = Keypair::new().pubkey();
    let destination2 = Keypair::new().pubkey();
    let token_mint = Keypair::new().pubkey();
    let token_destination = Keypair::new().pubkey();

    let permissions = vec![
        Permission::SolDestination {
            destination: destination1,
            amount: 500_000,
            recurring: None,
        },
        Permission::SolDestination {
            destination: destination2,
            amount: 1_000_000,
            recurring: Some(RecurringConfig::new(1000)),
        },
        Permission::TokenDestination {
            mint: token_mint,
            destination: token_destination,
            amount: 1000,
            recurring: None,
        },
    ];

    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(authority.pubkey())),
        payer.pubkey(),
        role_id,
    );

    let add_authority_ix = builder
        .add_authority_instruction(
            AuthorityType::Ed25519,
            &new_authority.pubkey().to_bytes(),
            permissions,
            None,
        )
        .unwrap();

    let msg = v0::Message::try_compile(
        &payer.pubkey(),
        &add_authority_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer, &authority]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to add authority: {:?}",
        result.err()
    );
}
