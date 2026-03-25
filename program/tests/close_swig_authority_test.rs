#![cfg(not(feature = "program_scope_test"))]
//! Tests for CloseSwigAuthority permission on close instructions.
//!
//! These tests verify that the CloseSwigAuthority permission correctly grants
//! or denies access to close_token_account and close_swig instructions,
//! including various permission combinations.

mod common;

use common::*;
use litesvm_token::spl_token;

use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{
    AuthorityConfig, ClientAction, CloseSwigV1Instruction, CloseTokenAccountV1Instruction,
};
use swig_state::{
    action::{
        all::All, all_but_manage_authority::AllButManageAuthority,
        close_swig_authority::CloseSwigAuthority, manage_authority::ManageAuthority,
        program_all::ProgramAll, sol_limit::SolLimit,
    },
    authority::AuthorityType,
    swig::swig_wallet_address_seeds,
};

// =============================================================================
// CloseTokenAccount permission tests
// =============================================================================

/// CloseSwigAuthority alone should allow closing token accounts
#[test_log::test]
fn test_close_token_account_with_close_swig_authority() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let close_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    // Create swig wallet with root authority
    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    // Add authority with CloseSwigAuthority permission
    context
        .svm
        .airdrop(&close_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: close_authority.pubkey().as_ref(),
        },
        vec![ClientAction::CloseSwigAuthority(CloseSwigAuthority)],
    )
    .unwrap();

    // Create a token ATA
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_token_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    let destination = Keypair::new();
    context.svm.airdrop(&destination.pubkey(), 0).unwrap();
    let token_account_rent = context.svm.get_account(&swig_token_ata).unwrap().lamports;

    // Close token account with CloseSwigAuthority - should succeed
    let close_ix = CloseTokenAccountV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        close_authority.pubkey(),
        destination.pubkey(),
        spl_token::ID,
        vec![swig_token_ata],
        1, // role_id for close_authority
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &close_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Transaction should succeed with CloseSwigAuthority: {:?}",
        result.err()
    );

    // Verify token account is closed
    let token_account = context.svm.get_account(&swig_token_ata);
    let is_closed = token_account.is_none() || token_account.as_ref().unwrap().lamports == 0;
    assert!(is_closed, "Token account should be closed");

    // Verify destination received rent
    let destination_balance = context
        .svm
        .get_account(&destination.pubkey())
        .map(|a| a.lamports)
        .unwrap_or(0);
    assert_eq!(destination_balance, token_account_rent);
}

/// CloseSwigAuthority + ManageAuthority together should allow closing token accounts
#[test_log::test]
fn test_close_token_account_with_close_and_manage_authority() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let combined_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    context
        .svm
        .airdrop(&combined_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: combined_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::CloseSwigAuthority(CloseSwigAuthority),
            ClientAction::ManageAuthority(ManageAuthority),
        ],
    )
    .unwrap();

    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_token_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    let destination = Keypair::new();
    context.svm.airdrop(&destination.pubkey(), 0).unwrap();
    let token_account_rent = context.svm.get_account(&swig_token_ata).unwrap().lamports;

    let close_ix = CloseTokenAccountV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        combined_authority.pubkey(),
        destination.pubkey(),
        spl_token::ID,
        vec![swig_token_ata],
        1,
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &combined_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Transaction should succeed with CloseSwigAuthority + ManageAuthority: {:?}",
        result.err()
    );

    let token_account = context.svm.get_account(&swig_token_ata);
    let is_closed = token_account.is_none() || token_account.as_ref().unwrap().lamports == 0;
    assert!(is_closed, "Token account should be closed");

    let destination_balance = context
        .svm
        .get_account(&destination.pubkey())
        .map(|a| a.lamports)
        .unwrap_or(0);
    assert_eq!(destination_balance, token_account_rent);
}

/// All + ManageAuthority + CloseSwigAuthority together should allow closing token accounts
#[test_log::test]
fn test_close_token_account_with_all_manage_and_close_authority() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let super_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    context
        .svm
        .airdrop(&super_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: super_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::All(All),
            ClientAction::ManageAuthority(ManageAuthority),
            ClientAction::CloseSwigAuthority(CloseSwigAuthority),
        ],
    )
    .unwrap();

    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_token_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    let destination = Keypair::new();
    context.svm.airdrop(&destination.pubkey(), 0).unwrap();
    let token_account_rent = context.svm.get_account(&swig_token_ata).unwrap().lamports;

    let close_ix = CloseTokenAccountV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        super_authority.pubkey(),
        destination.pubkey(),
        spl_token::ID,
        vec![swig_token_ata],
        1,
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &super_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Transaction should succeed with All + ManageAuthority + CloseSwigAuthority: {:?}",
        result.err()
    );

    let token_account = context.svm.get_account(&swig_token_ata);
    let is_closed = token_account.is_none() || token_account.as_ref().unwrap().lamports == 0;
    assert!(is_closed, "Token account should be closed");

    let destination_balance = context
        .svm
        .get_account(&destination.pubkey())
        .map(|a| a.lamports)
        .unwrap_or(0);
    assert_eq!(destination_balance, token_account_rent);
}

/// AllButManageAuthority should NOT allow closing token accounts
#[test_log::test]
fn test_close_token_account_denied_with_all_but_manage_authority() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let limited_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    context
        .svm
        .airdrop(&limited_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: limited_authority.pubkey().as_ref(),
        },
        vec![ClientAction::AllButManageAuthority(AllButManageAuthority)],
    )
    .unwrap();

    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_token_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    let destination = Keypair::new();

    let close_ix = CloseTokenAccountV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        limited_authority.pubkey(),
        destination.pubkey(),
        spl_token::ID,
        vec![swig_token_ata],
        1,
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &limited_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "Transaction should fail with AllButManageAuthority (no close permission)"
    );
}

/// ProgramAll should NOT allow closing token accounts
#[test_log::test]
fn test_close_token_account_denied_with_program_all() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let limited_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    context
        .svm
        .airdrop(&limited_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: limited_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ProgramAll(ProgramAll)],
    )
    .unwrap();

    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_token_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    let destination = Keypair::new();

    let close_ix = CloseTokenAccountV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        limited_authority.pubkey(),
        destination.pubkey(),
        spl_token::ID,
        vec![swig_token_ata],
        1,
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &limited_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "Transaction should fail with ProgramAll (no close permission)"
    );
}

// =============================================================================
// CloseSwig permission tests
// =============================================================================

/// CloseSwigAuthority alone should allow closing swig account
#[test_log::test]
fn test_close_swig_with_close_swig_authority() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let close_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    // Add authority with CloseSwigAuthority permission
    context
        .svm
        .airdrop(&close_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: close_authority.pubkey().as_ref(),
        },
        vec![ClientAction::CloseSwigAuthority(CloseSwigAuthority)],
    )
    .unwrap();

    let swig_lamports = context.svm.get_account(&swig_pubkey).unwrap().lamports
        - context.svm.minimum_balance_for_rent_exemption(1);
    let wallet_lamports = context
        .svm
        .get_account(&swig_wallet_address)
        .map(|a| a.lamports)
        .unwrap_or(0);
    let total_lamports = swig_lamports + wallet_lamports;

    let destination = Keypair::new();

    // Close swig with CloseSwigAuthority - should succeed
    let close_ix = CloseSwigV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        close_authority.pubkey(),
        destination.pubkey(),
        1, // role_id for close_authority
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &close_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Transaction should succeed with CloseSwigAuthority: {:?}",
        result.err()
    );

    // Verify swig account is marked as closed with discriminator 255
    let swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    assert_eq!(swig_account.data[0], 255);
    assert_eq!(swig_account.data.len(), 1);
    assert_eq!(
        swig_account.lamports,
        context.svm.minimum_balance_for_rent_exemption(1)
    );

    // Verify destination received lamports
    let destination_balance = context
        .svm
        .get_account(&destination.pubkey())
        .map(|a| a.lamports)
        .unwrap_or(0);
    assert_eq!(destination_balance, total_lamports);
}

/// CloseSwigAuthority + ManageAuthority together should allow closing swig
#[test_log::test]
fn test_close_swig_with_close_and_manage_authority() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let combined_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    context
        .svm
        .airdrop(&combined_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: combined_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::CloseSwigAuthority(CloseSwigAuthority),
            ClientAction::ManageAuthority(ManageAuthority),
        ],
    )
    .unwrap();

    let swig_lamports = context.svm.get_account(&swig_pubkey).unwrap().lamports
        - context.svm.minimum_balance_for_rent_exemption(1);
    let wallet_lamports = context
        .svm
        .get_account(&swig_wallet_address)
        .map(|a| a.lamports)
        .unwrap_or(0);
    let total_lamports = swig_lamports + wallet_lamports;

    let destination = Keypair::new();

    let close_ix = CloseSwigV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        combined_authority.pubkey(),
        destination.pubkey(),
        1,
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &combined_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Transaction should succeed with CloseSwigAuthority + ManageAuthority: {:?}",
        result.err()
    );

    let swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    assert_eq!(swig_account.data[0], 255);
    assert_eq!(swig_account.data.len(), 1);

    let destination_balance = context
        .svm
        .get_account(&destination.pubkey())
        .map(|a| a.lamports)
        .unwrap_or(0);
    assert_eq!(destination_balance, total_lamports);
}

/// All + ManageAuthority + CloseSwigAuthority together should allow closing swig
#[test_log::test]
fn test_close_swig_with_all_manage_and_close_authority() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let super_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    context
        .svm
        .airdrop(&super_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: super_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::All(All),
            ClientAction::ManageAuthority(ManageAuthority),
            ClientAction::CloseSwigAuthority(CloseSwigAuthority),
        ],
    )
    .unwrap();

    let swig_lamports = context.svm.get_account(&swig_pubkey).unwrap().lamports
        - context.svm.minimum_balance_for_rent_exemption(1);
    let wallet_lamports = context
        .svm
        .get_account(&swig_wallet_address)
        .map(|a| a.lamports)
        .unwrap_or(0);
    let total_lamports = swig_lamports + wallet_lamports;

    let destination = Keypair::new();

    let close_ix = CloseSwigV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        super_authority.pubkey(),
        destination.pubkey(),
        1,
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &super_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Transaction should succeed with All + ManageAuthority + CloseSwigAuthority: {:?}",
        result.err()
    );

    let swig_account = context.svm.get_account(&swig_pubkey).unwrap();
    assert_eq!(swig_account.data[0], 255);
    assert_eq!(swig_account.data.len(), 1);

    let destination_balance = context
        .svm
        .get_account(&destination.pubkey())
        .map(|a| a.lamports)
        .unwrap_or(0);
    assert_eq!(destination_balance, total_lamports);
}

/// SolLimit only should NOT allow closing swig
#[test_log::test]
fn test_close_swig_denied_with_sol_limit() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let limited_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    context
        .svm
        .airdrop(&limited_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: limited_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit {
            amount: 1_000_000_000,
        })],
    )
    .unwrap();

    let destination = Keypair::new();

    let close_ix = CloseSwigV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        limited_authority.pubkey(),
        destination.pubkey(),
        1,
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &limited_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "Transaction should fail with SolLimit (no close permission)"
    );
}

/// AllButManageAuthority should NOT allow closing swig
#[test_log::test]
fn test_close_swig_denied_with_all_but_manage_authority() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let limited_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    context
        .svm
        .airdrop(&limited_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: limited_authority.pubkey().as_ref(),
        },
        vec![ClientAction::AllButManageAuthority(AllButManageAuthority)],
    )
    .unwrap();

    let destination = Keypair::new();

    let close_ix = CloseSwigV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        limited_authority.pubkey(),
        destination.pubkey(),
        1,
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &limited_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "Transaction should fail with AllButManageAuthority (no close permission)"
    );
}

/// ProgramAll should NOT allow closing swig
#[test_log::test]
fn test_close_swig_denied_with_program_all() {
    let mut context = setup_test_context().unwrap();
    let authority = Keypair::new();
    let limited_authority = Keypair::new();
    let id = rand::random::<[u8; 32]>();

    let (swig_pubkey, _) = create_swig_ed25519(&mut context, &authority, id).unwrap();

    let (swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(&swig_pubkey.to_bytes()),
        &program_id(),
    );

    context
        .svm
        .airdrop(&limited_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_pubkey,
        &authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: limited_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ProgramAll(ProgramAll)],
    )
    .unwrap();

    let destination = Keypair::new();

    let close_ix = CloseSwigV1Instruction::new_with_ed25519_authority(
        swig_pubkey,
        swig_wallet_address,
        limited_authority.pubkey(),
        destination.pubkey(),
        1,
    )
    .unwrap();

    let message = VersionedMessage::V0(
        v0::Message::try_compile(
            &context.default_payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(400_000),
                close_ix,
            ],
            &[],
            context.svm.latest_blockhash(),
        )
        .unwrap(),
    );

    let tx = VersionedTransaction::try_new(message, &[&context.default_payer, &limited_authority])
        .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "Transaction should fail with ProgramAll (no close permission)"
    );
}
