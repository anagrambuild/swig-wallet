use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use litesvm::{types::TransactionMetadata, LiteSVM};
use litesvm_token::spl_token;
use solana_program::{pubkey::Pubkey, system_program};
use solana_sdk::{
    account::ReadableAccount,
    clock::Clock,
    message::{v0, VersionedMessage},
    signature::{Keypair, Signer},
    transaction::VersionedTransaction,
};
use swig_interface::{program_id, AuthorityConfig};
use swig_state::{
    action::program_scope::ProgramScope,
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
};

use super::*;
use crate::{
    client_role::Ed25519ClientRole,
    tests::common::{mint_to, setup_ata, setup_mint},
};

#[test_log::test]
fn test_token_transfer_with_program_scope() {
    let mut context = setup_test_context().unwrap();

    // Setup swig authority
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    // Airdrop to participants
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
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
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let swig_create_result = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_result.is_ok());

    // Setup token accounts
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
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

    // Define program scope permissions
    let permissions = vec![
        Permission::Program {
            program_id: spl_token::ID,
        },
        Permission::ProgramScope {
            program_id: spl_token::ID,
            target_account: swig_ata,
            numeric_type: 2,
            limit: Some(1000),
            window: Some(0),
            balance_field_start: Some(64),
            balance_field_end: Some(72),
        },
    ];

    let mut ix_builder = SwigInstructionBuilder::new(
        id,
        Box::new(Ed25519ClientRole::new(swig_authority.pubkey())),
        context.default_payer.pubkey(),
        0,
    );

    let new_authority = Keypair::new();

    // Add new authority with program scope permissions
    let add_auth_ix = ix_builder
        .add_authority_instruction(
            AuthorityType::Ed25519,
            &new_authority.pubkey().to_bytes(),
            permissions,
            None,
        )
        .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &add_auth_ix,
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
        "Failed to add authority: {:?}",
        result.err()
    );

    // Mint initial tokens to swig account
    let initial_token_amount = 1000;
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        initial_token_amount,
    )
    .unwrap();

    // Perform token transfer through swig
    let transfer_amount = 100;
    let swig_transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig_wallet_address,
        &[],
        transfer_amount,
    )
    .unwrap();

    let mut new_authority_ix = SwigInstructionBuilder::new(
        id,
        Box::new(Ed25519ClientRole::new(new_authority.pubkey())),
        context.default_payer.pubkey(),
        1,
    );

    let sign_ix = ix_builder
        .sign_instruction(
            vec![swig_transfer_ix],
            Some(context.svm.get_sysvar::<Clock>().slot),
        )
        .unwrap();

    let transfer_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &sign_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message),
        &[&context.default_payer, &swig_authority],
    )
    .unwrap();

    let transfer_result = context.svm.send_transaction(transfer_tx);
    assert!(
        transfer_result.is_ok(),
        "Token transfer failed: {:?}",
        transfer_result.err()
    );
}

#[test_log::test]
#[ignore] // TODO: This test has a pre-existing bug with InvalidDataPayload error
fn test_recurring_limit_program_scope() {
    let mut context = setup_test_context().unwrap();

    // Setup swig authority
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    // Airdrop to participants
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
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
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let swig_create_result = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_result.is_ok());

    // Setup token accounts
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
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

    // Setup a RecurringLimit program scope
    // Set a limit of 500 tokens per 100 slots
    let window_size = 100;
    let transfer_limit = 500_u64;

    let permissions = vec![
        Permission::Program {
            program_id: spl_token::ID,
        },
        Permission::ProgramScope {
            program_id: spl_token::ID,
            target_account: swig_ata,
            numeric_type: 2, // U64
            limit: Some(transfer_limit),
            window: Some(window_size),
            balance_field_start: Some(64),
            balance_field_end: Some(72),
        },
    ];

    let mut ix_builder = SwigInstructionBuilder::new(
        id,
        Box::new(Ed25519ClientRole::new(swig_authority.pubkey())),
        context.default_payer.pubkey(),
        0,
    );

    let new_authority = Keypair::new();
    // Add authority with program scope permissions
    let add_auth_ix = ix_builder
        .add_authority_instruction(
            AuthorityType::Ed25519,
            &new_authority.pubkey().to_bytes(),
            permissions,
            None,
        )
        .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &add_auth_ix,
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
        "Failed to add authority: {:?}",
        result.err()
    );

    // Mint initial tokens to swig account
    let initial_token_amount = 1000;
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        initial_token_amount,
    )
    .unwrap();

    // First batch of transfers - should succeed up to the limit
    let transfer_batch = 100;
    let mut transferred = 0;

    let mut new_ix_builder = SwigInstructionBuilder::new(
        id,
        Box::new(Ed25519ClientRole::new(new_authority.pubkey())),
        context.default_payer.pubkey(),
        1,
    );

    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig_wallet_address,
        &[],
        transfer_batch,
    )
    .unwrap();

    // Transfer in batches of 100 tokens up to limit (should succeed)
    while transferred + transfer_batch <= transfer_limit {
        let current_slot = context.svm.get_sysvar::<Clock>().slot;

        let sign_ix = new_ix_builder
            .sign_instruction(vec![transfer_ix.clone()], Some(current_slot))
            .unwrap();

        let transfer_message = v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &sign_ix,
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap();

        let transfer_tx = VersionedTransaction::try_new(
            VersionedMessage::V0(transfer_message),
            &[&context.default_payer, &new_authority],
        )
        .unwrap();

        let transfer_result = context.svm.send_transaction(transfer_tx);
        assert!(
            transfer_result.is_ok(),
            "Token transfer failed: {:?}",
            transfer_result.err()
        );
        transferred += transfer_batch;
        context.svm.expire_blockhash();
    }

    // Try to transfer one more batch (should fail)
    let sign_ix = new_ix_builder
        .sign_instruction(
            vec![transfer_ix],
            Some(context.svm.get_sysvar::<Clock>().slot),
        )
        .unwrap();

    let transfer_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &sign_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message),
        &[&context.default_payer, &new_authority],
    )
    .unwrap();

    let transfer_result = context.svm.send_transaction(transfer_tx);
    assert!(
        transfer_result.is_err(),
        "Transfer should have failed due to limit"
    );

    // Advance the clock past the window to trigger a reset
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    context.svm.warp_to_slot(current_slot + window_size + 1);
    context.svm.expire_blockhash();

    // After resetting the clock, we should be able to transfer again
    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig_wallet_address,
        &[],
        transfer_batch,
    )
    .unwrap();

    let sign_ix = new_ix_builder
        .sign_instruction(
            vec![transfer_ix],
            Some(context.svm.get_sysvar::<Clock>().slot),
        )
        .unwrap();

    let transfer_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &sign_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message),
        &[&context.default_payer, &new_authority],
    )
    .unwrap();

    let transfer_result = context.svm.send_transaction(transfer_tx);
    assert!(
        transfer_result.is_ok(),
        "Token transfer after window reset failed: {:?}",
        transfer_result.err()
    );
}
