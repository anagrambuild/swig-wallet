#![cfg(not(feature = "program_scope_test"))]
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
    action::{
        program_all::ProgramAll, sol_destination_limit::SolDestinationLimit,
        token_destination_limit::TokenDestinationLimit, Actionable,
    },
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
    convert_swig_to_v1(&mut context, &swig);

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
    let destination_limit_amount = destination_limit.amount;

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
            ClientAction::TokenDestinationLimit(destination_limit),
        ],
    )
    .unwrap();

    context.svm.airdrop(&swig, 2_000_000_000).unwrap();

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

    // Transfer within limit should succeed (when full implementation is complete)
    let transfer_amount = 300u64;

    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig,
        &[],
        transfer_amount,
    )
    .unwrap();

    let sign_ix = SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        transfer_ix,
        2,
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

    assert!(res.is_ok());

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

    // Verify destination limit was decremented
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(2).unwrap().unwrap();

    let combined_key = [mint_pubkey.to_bytes(), recipient_ata.to_bytes()].concat();
    let dest_limit = role
        .get_action::<TokenDestinationLimit>(&combined_key)
        .unwrap()
        .unwrap();
    assert_eq!(
        dest_limit.amount,
        destination_limit_amount - transfer_amount
    );
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
    convert_swig_to_v1(&mut context, &swig);

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
        vec![
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenDestinationLimit(destination_limit),
        ],
    )
    .unwrap();

    context.svm.airdrop(&swig, 2_000_000_000).unwrap();

    // Try to transfer more than the limit (should fail when implementation is
    // complete)
    let transfer_amount = 300u64; // Exceeds the 200 token limit

    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient_ata,
        &swig,
        &[],
        transfer_amount,
    )
    .unwrap();

    let sign_ix = SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        transfer_ix,
        2,
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

    // assert that the error code is 3030
    // res: Err(FailedTransactionMetadata { err: InstructionError(0, Custom(3030)),
    // meta: TransactionMetadata { signature:
    // 4mXmuEdc4HQZVuhWtcESGxZtTm4i15bTnDeyaZUH6QgYEf8aA6ms1MtgFs29powLaVutuNBVgaZEhry6Yzk1uEVb,
    // logs: ["Program swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB invoke [1]",
    // "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]", "Program
    // log: Instruction: Transfer", "Program
    // TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 4644 of 196170 compute
    // units", "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success",
    // "Program log: here in this swig!", "Program log: here in swig token
    // account!", "Program log: here in process_token_destinations", "Program log:
    // here in source account", "Program log: combined_key: [119, 79, 123, 130, 4,
    // 117, 249, 16, 187, 174, 119, 154, 215, 23, 44, 213, 148, 54, 170, 108, 185,
    // 24, 51, 115, 103, 26, 168, 230, 41, 213, 59, 214, 187, 3, 138, 147, 56, 162,
    // 40, 215, 40, 205, 240, 127, 110, 143, 127, 117, 234, 107, 231, 59, 67, 250,
    // 227, 232, 24, 83, 41, 77, 111, 25, 55, 184]", "Program log: here in
    // TokenRecurringDestinationLimit", "Program log: TokenDestinationLimit diff:
    // 300", "Program swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB consumed 24973 of
    // 200000 compute units", "Program swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB
    // failed: custom program error: 0xbd6"], inner_instructions: [[InnerInstruction
    // { instruction: CompiledInstruction { program_id_index: 4, accounts: [1, 2,
    // 3], data: [3, 44, 1, 0, 0, 0, 0, 0, 0] }, stack_height: 2 }]],
    // compute_units_consumed: 24973, return_data: TransactionReturnData {
    // program_id: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, data: [] } } })
    assert_eq!(
        res.unwrap_err().err,
        solana_sdk::transaction::TransactionError::InstructionError(
            0,
            solana_sdk::instruction::InstructionError::Custom(3031)
        ),
        "Expected error code 3030"
    );
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
    convert_swig_to_v1(&mut context, &swig);

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

    let recipient1_initial_balance = u64::from_le_bytes(
        context
            .svm
            .get_account(&recipient1_ata)
            .unwrap()
            .data
            .get(64..72)
            .unwrap()
            .try_into()
            .unwrap(),
    );

    let recipient2_initial_balance = u64::from_le_bytes(
        context
            .svm
            .get_account(&recipient2_ata)
            .unwrap()
            .data
            .get(64..72)
            .unwrap()
            .try_into()
            .unwrap(),
    );

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
            ClientAction::TokenDestinationLimit(destination_limit1),
            ClientAction::TokenDestinationLimit(destination_limit2),
        ],
    )
    .unwrap();

    context.svm.airdrop(&swig, 2_000_000_000).unwrap();

    let transfer_amount1 = 250u64; // Within 300 limit

    let token_ix1 = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient1_ata,
        &swig,
        &[],
        transfer_amount1,
    )
    .unwrap();

    let sign_ix1 = SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix1,
        2,
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

    assert!(res1.is_ok());

    let recipient1_final_balance = u64::from_le_bytes(
        context
            .svm
            .get_account(&recipient1_ata)
            .unwrap()
            .data
            .get(64..72)
            .unwrap()
            .try_into()
            .unwrap(),
    );

    assert_eq!(
        recipient1_final_balance,
        recipient1_initial_balance + transfer_amount1
    );

    let transfer_amount2 = 200u64; // Within 500 limit

    let token_ix2 = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata,
        &recipient2_ata,
        &swig,
        &[],
        transfer_amount2,
    )
    .unwrap();

    let sign_ix2 = SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix2,
        2,
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

    let res2 = context.svm.send_transaction(transfer_tx2);

    assert!(res2.is_ok());

    let recipient2_final_balance = u64::from_le_bytes(
        context
            .svm
            .get_account(&recipient2_ata)
            .unwrap()
            .data
            .get(64..72)
            .unwrap()
            .try_into()
            .unwrap(),
    );

    assert_eq!(
        recipient2_final_balance,
        recipient2_initial_balance + transfer_amount2
    );

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(2).unwrap().unwrap();

    let combined_key1 = [mint_pubkey.to_bytes(), recipient1_ata.to_bytes()].concat();
    let combined_key2 = [mint_pubkey.to_bytes(), recipient2_ata.to_bytes()].concat();

    let dest_limit1 = role
        .get_action::<TokenDestinationLimit>(&combined_key1)
        .unwrap()
        .unwrap();
    let dest_limit2 = role
        .get_action::<TokenDestinationLimit>(&combined_key2)
        .unwrap()
        .unwrap();

    assert_eq!(dest_limit1.amount, 300 - transfer_amount1);
    assert_eq!(dest_limit2.amount, 500 - transfer_amount2);
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

    let recipient1_initial_balance = u64::from_le_bytes(
        context
            .svm
            .get_account(&recipient_ata1)
            .unwrap()
            .data
            .get(64..72)
            .unwrap()
            .try_into()
            .unwrap(),
    );

    let recipient2_initial_balance = u64::from_le_bytes(
        context
            .svm
            .get_account(&recipient_ata2)
            .unwrap()
            .data
            .get(64..72)
            .unwrap()
            .try_into()
            .unwrap(),
    );

    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    convert_swig_to_v1(&mut context, &swig);

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
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::TokenDestinationLimit(destination_limit1),
            ClientAction::TokenDestinationLimit(destination_limit2),
        ],
    )
    .unwrap();

    context.svm.airdrop(&swig, 2_000_000_000).unwrap();

    // Test that limits are enforced per mint/destination combination
    // This test demonstrates the expected behavior once implementation is complete

    let transfer_amount1 = 250u64; // Within 300 limit

    let token_ix1 = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata1,
        &recipient_ata1,
        &swig,
        &[],
        transfer_amount1,
    )
    .unwrap();

    let sign_ix1 = SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix1,
        2,
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

    assert!(res1.is_ok());

    let transfer_amount2 = 200u64; // Within 500 limit

    let token_ix2 = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata2,
        &recipient_ata2,
        &swig,
        &[],
        transfer_amount2,
    )
    .unwrap();

    let sign_ix2 = SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix2,
        2,
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

    let res2 = context.svm.send_transaction(transfer_tx2);

    assert!(res2.is_ok());

    let recipient1_final_balance = u64::from_le_bytes(
        context
            .svm
            .get_account(&recipient_ata1)
            .unwrap()
            .data
            .get(64..72)
            .unwrap()
            .try_into()
            .unwrap(),
    );

    assert_eq!(
        recipient1_final_balance,
        recipient1_initial_balance + transfer_amount1
    );

    let recipient2_final_balance = u64::from_le_bytes(
        context
            .svm
            .get_account(&recipient_ata2)
            .unwrap()
            .data
            .get(64..72)
            .unwrap()
            .try_into()
            .unwrap(),
    );

    assert_eq!(
        recipient2_final_balance,
        recipient2_initial_balance + transfer_amount2
    );

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(2).unwrap().unwrap();

    let combined_key1 = [mint1_pubkey.to_bytes(), recipient_ata1.to_bytes()].concat();
    let combined_key2 = [mint2_pubkey.to_bytes(), recipient_ata2.to_bytes()].concat();

    let dest_limit1 = role
        .get_action::<TokenDestinationLimit>(&combined_key1)
        .unwrap()
        .unwrap();
    let dest_limit2 = role
        .get_action::<TokenDestinationLimit>(&combined_key2)
        .unwrap()
        .unwrap();

    assert_eq!(dest_limit1.amount, 300 - transfer_amount1);
    assert_eq!(dest_limit2.amount, 500 - transfer_amount2);
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
