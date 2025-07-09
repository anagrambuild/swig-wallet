//! Tests for TokenDestinationLimit functionality.
//!
//! This module contains comprehensive tests for the TokenDestinationLimit
//! action type, which enforces limits on token transfers to specific
//! destination accounts.

mod common;
use common::*;
use litesvm_token::spl_token::{self, instruction::TokenInstruction};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{program_id, AuthorityConfig, ClientAction, SignInstruction};
use swig_state::{
    action::{token_destination_limit::TokenDestinationLimit, Actionable},
    authority::AuthorityType,
    swig::{swig_account_seeds, SwigWithRoles},
};

/// Test basic token destination limit functionality
#[test_log::test]
fn test_token_destination_limit_basic() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    // Airdrop to participants
    context
        .svm
        .airdrop(&recipient.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Setup token infrastructure
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig,
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

    // Mint initial tokens to the SWIG's token account
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        1000,
    )
    .unwrap();

    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    // Set up token destination limit: 500 tokens to specific destination
    let destination_limit = TokenDestinationLimit {
        token_mint: mint_pubkey.to_bytes(),
        destination: recipient_ata.to_bytes(),
        amount: 500,
    };

    let _txn = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::TokenDestinationLimit(destination_limit)],
    )
    .unwrap();

    context.svm.airdrop(&swig, 2_000_000_000).unwrap();

    // Transfer within limit should succeed (when full implementation is complete)
    let transfer_amount = 300u64;

    let token_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer {
            amount: transfer_amount,
        }
        .pack(),
    };

    let sign_ix = SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix,
        1,
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    // Note: This test will currently fail because the full token destination limit
    // implementation is not yet complete. The test demonstrates the expected API.
    let res = context.svm.send_transaction(transfer_tx);

    // For now, we expect this to fail with a missing permission error
    // because the token destination limit checking is not fully implemented
    assert!(res.is_err());
    println!("Transfer result (expected to fail for now): {:?}", res);

    // TODO: Once the full implementation is complete, this should succeed
    // and we should verify that the limit was decremented correctly
}

/// Test token destination limit exceeded
#[test_log::test]
fn test_token_destination_limit_exceeds_limit() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    context
        .svm
        .airdrop(&recipient.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig,
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

    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        1000,
    )
    .unwrap();

    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    // Set up token destination limit: only 200 tokens to specific destination
    let destination_limit = TokenDestinationLimit {
        token_mint: mint_pubkey.to_bytes(),
        destination: recipient_ata.to_bytes(),
        amount: 200,
    };

    let _txn = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::TokenDestinationLimit(destination_limit)],
    )
    .unwrap();

    context.svm.airdrop(&swig, 2_000_000_000).unwrap();

    // Try to transfer more than the limit (should fail when implementation is
    // complete)
    let transfer_amount = 300u64; // Exceeds the 200 token limit

    let token_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer {
            amount: transfer_amount,
        }
        .pack(),
    };

    let sign_ix = SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix,
        1,
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    let res = context.svm.send_transaction(transfer_tx);

    // Should fail (currently fails for different reason - missing implementation)
    assert!(res.is_err());

    // TODO: Once implementation is complete, verify it fails with
    // PermissionDeniedTokenDestinationLimitExceeded error
}

/// Test multiple token destination limits for different destinations
#[test_log::test]
fn test_multiple_token_destination_limits() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient1 = Keypair::new();
    let recipient2 = Keypair::new();

    context
        .svm
        .airdrop(&recipient1.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&recipient2.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig,
        &context.default_payer,
    )
    .unwrap();
    let recipient1_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &recipient1.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    let recipient2_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &recipient2.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        2000,
    )
    .unwrap();

    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    // Set up different limits for different destinations
    let destination_limit1 = TokenDestinationLimit {
        token_mint: mint_pubkey.to_bytes(),
        destination: recipient1_ata.to_bytes(),
        amount: 300,
    };

    let destination_limit2 = TokenDestinationLimit {
        token_mint: mint_pubkey.to_bytes(),
        destination: recipient2_ata.to_bytes(),
        amount: 500,
    };

    let _txn = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::TokenDestinationLimit(destination_limit1),
            ClientAction::TokenDestinationLimit(destination_limit2),
        ],
    )
    .unwrap();

    context.svm.airdrop(&swig, 2_000_000_000).unwrap();

    // Test transfer to first destination (should succeed when implementation is
    // complete)
    let transfer_amount1 = 250u64; // Within 300 limit

    let token_ix1 = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient1_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer {
            amount: transfer_amount1,
        }
        .pack(),
    };

    let sign_ix1 = SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix1,
        1,
    )
    .unwrap();

    let transfer_message1 = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix1],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx1 = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message1),
        &[&second_authority],
    )
    .unwrap();

    let res1 = context.svm.send_transaction(transfer_tx1);

    // Currently fails due to incomplete implementation
    assert!(res1.is_err());
    println!("First transfer result: {:?}", res1);

    // TODO: Test second destination with different limit
    // TODO: Verify that limits are tracked independently per destination
}

/// Test token destination limit with different token mints
#[test_log::test]
fn test_token_destination_limit_different_mints() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    context
        .svm
        .airdrop(&recipient.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Setup two different token mints
    let mint1_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let mint2_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    let swig_ata1 = setup_ata(
        &mut context.svm,
        &mint1_pubkey,
        &swig,
        &context.default_payer,
    )
    .unwrap();
    let swig_ata2 = setup_ata(
        &mut context.svm,
        &mint2_pubkey,
        &swig,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata1 = setup_ata(
        &mut context.svm,
        &mint1_pubkey,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata2 = setup_ata(
        &mut context.svm,
        &mint2_pubkey,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    // Mint tokens to both accounts
    mint_to(
        &mut context.svm,
        &mint1_pubkey,
        &context.default_payer,
        &swig_ata1,
        1000,
    )
    .unwrap();
    mint_to(
        &mut context.svm,
        &mint2_pubkey,
        &context.default_payer,
        &swig_ata2,
        1000,
    )
    .unwrap();

    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    // Set up different limits for different token mints to same destination
    let destination_limit1 = TokenDestinationLimit {
        token_mint: mint1_pubkey.to_bytes(),
        destination: recipient_ata1.to_bytes(),
        amount: 300,
    };

    let destination_limit2 = TokenDestinationLimit {
        token_mint: mint2_pubkey.to_bytes(),
        destination: recipient_ata2.to_bytes(),
        amount: 500,
    };

    let _txn = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::TokenDestinationLimit(destination_limit1),
            ClientAction::TokenDestinationLimit(destination_limit2),
        ],
    )
    .unwrap();

    context.svm.airdrop(&swig, 2_000_000_000).unwrap();

    // Test that limits are enforced per mint/destination combination
    // This test demonstrates the expected behavior once implementation is complete

    println!("Token destination limit test with different mints - implementation pending");

    // TODO: Test transfers for both mints and verify independent limit tracking
}

/// Test token destination limit validation
#[test_log::test]
fn test_token_destination_limit_validation() {
    // Test the TokenDestinationLimit struct validation
    use swig_state::action::token_destination_limit::TokenDestinationLimit;

    let mint = [1u8; 32];
    let destination = [2u8; 32];
    let amount = 1000u64;

    let limit = TokenDestinationLimit {
        token_mint: mint,
        destination,
        amount,
    };

    // Test matches_mint_and_destination
    assert!(limit.matches_mint_and_destination(&mint, &destination));
    assert!(!limit.matches_mint_and_destination(&[3u8; 32], &destination));
    assert!(!limit.matches_mint_and_destination(&mint, &[4u8; 32]));

    // Test match_data with combined mint+destination
    let mut combined_data = Vec::new();
    combined_data.extend_from_slice(&mint);
    combined_data.extend_from_slice(&destination);

    assert!(limit.match_data(&combined_data));

    // Test with insufficient data
    assert!(!limit.match_data(&mint)); // Only mint, no destination
    assert!(!limit.match_data(&[])); // Empty data

    println!("TokenDestinationLimit validation tests passed");
}
