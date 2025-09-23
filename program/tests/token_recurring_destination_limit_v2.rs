#![cfg(not(feature = "program_scope_test"))]
//! Tests for TokenRecurringDestinationLimit functionality with SignV2.
//!
//! This module contains comprehensive tests for the
//! TokenRecurringDestinationLimit action type, including basic functionality,
//! time window resets, edge cases, and integration with other limit types using
//! SignV2 instructions.

mod common;
use common::*;
use litesvm_token::spl_token::{self, instruction::TokenInstruction};
use rand;
use solana_sdk::{
    instruction::InstructionError,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
};
use swig::actions::sign_v2::SignV2Args;
use swig_interface::{AuthorityConfig, ClientAction, SignV2Instruction};
use swig_state::{
    action::{
        program_all::ProgramAll, token_recurring_destination_limit::TokenRecurringDestinationLimit,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
};
use test_log;

/// Test basic token recurring destination limit functionality with SignV2
#[test_log::test]
fn test_token_recurring_destination_limit_basic_v2() {
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
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    // Setup token infrastructure
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
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

    let recurring_amount = 500u64; // 500 tokens per window
    let window = 100u64; // 100 slots
    let recurring_destination_limit = TokenRecurringDestinationLimit {
        token_mint: mint_pubkey.to_bytes(),
        destination: recipient_ata.to_bytes(),
        recurring_amount,
        window,
        last_reset: 0,
        current_amount: recurring_amount,
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
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenRecurringDestinationLimit(recurring_destination_limit),
        ],
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_wallet_address, 2_000_000_000)
        .unwrap();
    context.svm.warp_to_slot(100);

    let recipient_initial_balance: u64 = u64::from_le_bytes(
        context
            .svm
            .get_account(&recipient_ata)
            .unwrap()
            .data
            .get(64..72)
            .unwrap()
            .try_into()
            .unwrap(),
    );

    // Test transfer within limit
    let transfer_amount = 300u64; // Within 500 token limit

    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig_wallet_address,
        &[],
        transfer_amount,
    )
    .unwrap();

    let sign_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        second_authority.pubkey(),
        transfer_ix,
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

    let res = context.svm.send_transaction(transfer_tx).unwrap();

    // Verify transfer succeeded
    let recipient_final_balance = u64::from_le_bytes(
        context
            .svm
            .get_account(&recipient_ata)
            .unwrap()
            .data
            .get(64..72)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        recipient_final_balance,
        recipient_initial_balance + transfer_amount
    );

    // Verify limit was decremented
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();

    let combined_key = [mint_pubkey.to_bytes(), recipient_ata.to_bytes()].concat();
    let dest_limit = role
        .get_action::<TokenRecurringDestinationLimit>(&combined_key)
        .unwrap()
        .unwrap();
    assert_eq!(
        dest_limit.current_amount,
        recurring_amount - transfer_amount
    );

    // wrap and verify limit is reset
    context.svm.warp_to_slot(1000);

    let transfer_amount2 = 1u64;

    let transfer_ix2 = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig_wallet_address,
        &[],
        transfer_amount2,
    )
    .unwrap();

    let sign_ix2 = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        second_authority.pubkey(),
        transfer_ix2,
        1,
    )
    .unwrap();

    let transfer_message2 = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx2 = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message2),
        &[&second_authority],
    )
    .unwrap();

    let res2 = context.svm.send_transaction(transfer_tx2).unwrap();

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();

    let dest_limit = role
        .get_action::<TokenRecurringDestinationLimit>(&combined_key)
        .unwrap()
        .unwrap();
    assert_eq!(
        dest_limit.current_amount,
        recurring_amount - transfer_amount2
    );
}

/// Test token recurring destination limit exceeding the current limit with
/// SignV2
#[test_log::test]
fn test_token_recurring_destination_limit_exceeds_limit_v2() {
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
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
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

    let recurring_amount = 300u64; // 300 tokens per window
    let window = 100u64; // 100 slots
    let recurring_destination_limit = TokenRecurringDestinationLimit {
        token_mint: mint_pubkey.to_bytes(),
        destination: recipient_ata.to_bytes(),
        recurring_amount,
        window,
        last_reset: 0,
        current_amount: recurring_amount,
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
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenRecurringDestinationLimit(recurring_destination_limit),
        ],
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_wallet_address, 2_000_000_000)
        .unwrap();
    context.svm.warp_to_slot(100);

    // Try to transfer more than the limit
    let transfer_amount = 500u64; // Exceeds the 300 token limit

    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig_wallet_address,
        &[],
        transfer_amount,
    )
    .unwrap();

    let sign_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        second_authority.pubkey(),
        transfer_ix,
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

    // Should fail due to insufficient destination limit
    assert!(res.is_err());
    if let Err(e) = res {
        // Should get the specific destination limit exceeded error (3032)
        assert!(matches!(
            e.err,
            TransactionError::InstructionError(_, InstructionError::Custom(3032))
        ));
    }
}

/// Test token recurring destination limit time window reset with SignV2
#[test_log::test]
fn test_token_recurring_destination_limit_time_reset_v2() {
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
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
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

    let recurring_amount = 400u64; // 400 tokens per window
    let window = 50u64; // 50 slots
    let recurring_destination_limit = TokenRecurringDestinationLimit {
        token_mint: mint_pubkey.to_bytes(),
        destination: recipient_ata.to_bytes(),
        recurring_amount,
        window,
        last_reset: 0,
        current_amount: recurring_amount,
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
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenRecurringDestinationLimit(recurring_destination_limit),
        ],
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_wallet_address, 2_000_000_000)
        .unwrap();
    context.svm.warp_to_slot(100);

    // First transfer - use most of the limit
    let transfer_amount1 = 350u64; // 350 tokens

    let transfer_ix1 = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig_wallet_address,
        &[],
        transfer_amount1,
    )
    .unwrap();

    let sign_ix1 = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        second_authority.pubkey(),
        transfer_ix1,
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

    let res1 = context.svm.send_transaction(transfer_tx1).unwrap();

    // Verify limit was decremented
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();
    let combined_key = [mint_pubkey.to_bytes(), recipient_ata.to_bytes()].concat();
    let dest_limit = role
        .get_action::<TokenRecurringDestinationLimit>(&combined_key)
        .unwrap()
        .unwrap();
    assert_eq!(
        dest_limit.current_amount,
        recurring_amount - transfer_amount1
    );

    // Wait for time window to expire
    context.svm.warp_to_slot(200); // Move past the window

    // Second transfer - should reset the limit and allow full amount again
    let transfer_amount2 = 300u64; // 300 tokens - should work after reset

    let transfer_ix2 = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig_wallet_address,
        &[],
        transfer_amount2,
    )
    .unwrap();

    let sign_ix2 = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        second_authority.pubkey(),
        transfer_ix2,
        1,
    )
    .unwrap();

    let transfer_message2 = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx2 = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message2),
        &[&second_authority],
    )
    .unwrap();

    let res2 = context.svm.send_transaction(transfer_tx2).unwrap();

    // Verify limit was reset and then decremented
    let swig_account_final = context.svm.get_account(&swig).unwrap();
    let swig_state_final = SwigWithRoles::from_bytes(&swig_account_final.data).unwrap();
    let role_final = swig_state_final.get_role(1).unwrap().unwrap();
    let dest_limit_final = role_final
        .get_action::<TokenRecurringDestinationLimit>(&combined_key)
        .unwrap()
        .unwrap();
    assert_eq!(
        dest_limit_final.current_amount,
        recurring_amount - transfer_amount2
    );
    assert_eq!(dest_limit_final.last_reset, 200); // Should be updated to
                                                  // current slot
}

/// Test multiple recurring destination limits for different recipients with
/// SignV2
#[test_log::test]
fn test_multiple_token_recurring_destination_limits_v2() {
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
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
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

    let recurring_amount1 = 300u64; // 300 tokens per window for recipient1
    let recurring_amount2 = 500u64; // 500 tokens per window for recipient2
    let window = 100u64; // 100 slots

    let recurring_destination_limit1 = TokenRecurringDestinationLimit {
        token_mint: mint_pubkey.to_bytes(),
        destination: recipient1_ata.to_bytes(),
        recurring_amount: recurring_amount1,
        window,
        last_reset: 0,
        current_amount: recurring_amount1,
    };

    let recurring_destination_limit2 = TokenRecurringDestinationLimit {
        token_mint: mint_pubkey.to_bytes(),
        destination: recipient2_ata.to_bytes(),
        recurring_amount: recurring_amount2,
        window,
        last_reset: 0,
        current_amount: recurring_amount2,
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
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenRecurringDestinationLimit(recurring_destination_limit1),
            ClientAction::TokenRecurringDestinationLimit(recurring_destination_limit2),
        ],
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_wallet_address, 2_000_000_000)
        .unwrap();
    context.svm.warp_to_slot(100);

    // Test transfer to recipient1 within limit
    let transfer_amount1 = 200u64; // 200 tokens - within recipient1's limit

    let transfer_ix1 = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient1_ata,
        &swig_wallet_address,
        &[],
        transfer_amount1,
    )
    .unwrap();

    let sign_ix1 = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        second_authority.pubkey(),
        transfer_ix1,
        1,
    )
    .unwrap();

    // Test transfer to recipient2 within limit
    let transfer_amount2 = 400u64; // 400 tokens - within recipient2's limit

    let transfer_ix2 = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient2_ata,
        &swig_wallet_address,
        &[],
        transfer_amount2,
    )
    .unwrap();

    let sign_ix2 = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        second_authority.pubkey(),
        transfer_ix2,
        1,
    )
    .unwrap();

    // Combine both transfers in a single transaction
    let combined_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix1, sign_ix2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let combined_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(combined_message), &[&second_authority])
            .unwrap();

    let res = context.svm.send_transaction(combined_tx).unwrap();

    // Verify both limits were decremented correctly
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();

    let combined_key1 = [mint_pubkey.to_bytes(), recipient1_ata.to_bytes()].concat();
    let combined_key2 = [mint_pubkey.to_bytes(), recipient2_ata.to_bytes()].concat();

    let dest_limit1 = role
        .get_action::<TokenRecurringDestinationLimit>(&combined_key1)
        .unwrap()
        .unwrap();
    assert_eq!(
        dest_limit1.current_amount,
        recurring_amount1 - transfer_amount1
    );

    let dest_limit2 = role
        .get_action::<TokenRecurringDestinationLimit>(&combined_key2)
        .unwrap()
        .unwrap();
    assert_eq!(
        dest_limit2.current_amount,
        recurring_amount2 - transfer_amount2
    );
}

/// Test recurring destination limit that doesn't reset because transfer exceeds
/// fresh limit with SignV2
#[test_log::test]
fn test_token_recurring_destination_limit_no_reset_when_exceeds_fresh_v2() {
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
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
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

    let recurring_amount = 300u64; // 300 tokens per window
    let window = 50u64; // 50 slots
    let recurring_destination_limit = TokenRecurringDestinationLimit {
        token_mint: mint_pubkey.to_bytes(),
        destination: recipient_ata.to_bytes(),
        recurring_amount,
        window,
        last_reset: 0,
        current_amount: 100u64, // Only 100 tokens remaining
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
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenRecurringDestinationLimit(recurring_destination_limit),
        ],
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_wallet_address, 2_000_000_000)
        .unwrap();
    context.svm.warp_to_slot(100); // Move past the window

    // Try to transfer more than the fresh limit would allow
    let transfer_amount = 400u64; // 400 tokens - exceeds even fresh limit (300 tokens)

    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig_wallet_address,
        &[],
        transfer_amount,
    )
    .unwrap();

    let sign_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        second_authority.pubkey(),
        transfer_ix,
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

    // Should fail because transfer exceeds even the fresh limit
    assert!(res.is_err());
    if let Err(e) = res {
        // Should get the specific destination limit exceeded error (3032)
        assert!(matches!(
            e.err,
            TransactionError::InstructionError(_, InstructionError::Custom(3032))
        ));
    }

    // Verify limit was NOT reset (should still have the old current_amount)
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();
    let combined_key = [mint_pubkey.to_bytes(), recipient_ata.to_bytes()].concat();
    let dest_limit = role
        .get_action::<TokenRecurringDestinationLimit>(&combined_key)
        .unwrap()
        .unwrap();
    assert_eq!(dest_limit.current_amount, 100u64); // Should remain unchanged
    assert_eq!(dest_limit.last_reset, 0); // Should not be updated
}

/// Test token recurring destination limit with different token mints with
/// SignV2
#[test_log::test]
fn test_token_recurring_destination_limit_different_mints_v2() {
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
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    // Setup two different token mints
    let mint1_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let mint2_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    let swig_ata1 = setup_ata(
        &mut context.svm,
        &mint1_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    let swig_ata2 = setup_ata(
        &mut context.svm,
        &mint2_pubkey,
        &swig_wallet_address,
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
    let recurring_amount1 = 300u64; // 300 tokens per window for mint1
    let recurring_amount2 = 500u64; // 500 tokens per window for mint2
    let window = 100u64; // 100 slots

    let recurring_destination_limit1 = TokenRecurringDestinationLimit {
        token_mint: mint1_pubkey.to_bytes(),
        destination: recipient_ata1.to_bytes(),
        recurring_amount: recurring_amount1,
        window,
        last_reset: 0,
        current_amount: recurring_amount1,
    };

    let recurring_destination_limit2 = TokenRecurringDestinationLimit {
        token_mint: mint2_pubkey.to_bytes(),
        destination: recipient_ata2.to_bytes(),
        recurring_amount: recurring_amount2,
        window,
        last_reset: 0,
        current_amount: recurring_amount2,
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
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenRecurringDestinationLimit(recurring_destination_limit1),
            ClientAction::TokenRecurringDestinationLimit(recurring_destination_limit2),
        ],
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_wallet_address, 2_000_000_000)
        .unwrap();
    context.svm.warp_to_slot(100);

    // Test that limits are enforced per mint/destination combination
    let transfer_amount1 = 250u64; // Within 300 limit for mint1

    let transfer_ix1 = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata1,
        &recipient_ata1,
        &swig_wallet_address,
        &[],
        transfer_amount1,
    )
    .unwrap();

    let sign_ix1 = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        second_authority.pubkey(),
        transfer_ix1,
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

    let res1 = context.svm.send_transaction(transfer_tx1).unwrap();

    let transfer_amount2 = 200u64; // Within 500 limit for mint2

    let transfer_ix2 = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata2,
        &recipient_ata2,
        &swig_wallet_address,
        &[],
        transfer_amount2,
    )
    .unwrap();

    let sign_ix2 = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        second_authority.pubkey(),
        transfer_ix2,
        1,
    )
    .unwrap();

    let transfer_message2 = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx2 = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message2),
        &[&second_authority],
    )
    .unwrap();

    let res2 = context.svm.send_transaction(transfer_tx2).unwrap();

    // Verify both limits were decremented correctly
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();

    let combined_key1 = [mint1_pubkey.to_bytes(), recipient_ata1.to_bytes()].concat();
    let combined_key2 = [mint2_pubkey.to_bytes(), recipient_ata2.to_bytes()].concat();

    let dest_limit1 = role
        .get_action::<TokenRecurringDestinationLimit>(&combined_key1)
        .unwrap()
        .unwrap();
    let dest_limit2 = role
        .get_action::<TokenRecurringDestinationLimit>(&combined_key2)
        .unwrap()
        .unwrap();

    assert_eq!(
        dest_limit1.current_amount,
        recurring_amount1 - transfer_amount1
    );
    assert_eq!(
        dest_limit2.current_amount,
        recurring_amount2 - transfer_amount2
    );
}

/// Test token recurring destination limit validation with SignV2
#[test_log::test]
fn test_token_recurring_destination_limit_validation_v2() {
    // Test the TokenRecurringDestinationLimit struct validation
    use swig_state::action::token_recurring_destination_limit::TokenRecurringDestinationLimit;

    let mint = [1u8; 32];
    let destination = [2u8; 32];
    let recurring_amount = 1000u64;
    let window = 100u64;
    let last_reset = 0u64;
    let current_amount = 800u64;

    let limit = TokenRecurringDestinationLimit {
        token_mint: mint,
        destination,
        recurring_amount,
        window,
        last_reset,
        current_amount,
    };

    // Test matches_destination with combined mint+destination
    let mut combined_data = Vec::new();
    combined_data.extend_from_slice(&mint);
    combined_data.extend_from_slice(&destination);

    assert!(limit.matches_destination(&combined_data.try_into().unwrap()));

    // Test with different mint
    let mut different_mint_data = Vec::new();
    different_mint_data.extend_from_slice(&[3u8; 32]);
    different_mint_data.extend_from_slice(&destination);

    assert!(!limit.matches_destination(&different_mint_data.try_into().unwrap()));

    // Test with different destination
    let mut different_dest_data = Vec::new();
    different_dest_data.extend_from_slice(&mint);
    different_dest_data.extend_from_slice(&[4u8; 32]);

    assert!(!limit.matches_destination(&different_dest_data.try_into().unwrap()));
}
