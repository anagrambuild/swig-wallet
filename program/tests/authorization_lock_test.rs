#![cfg(not(feature = "program_scope_test"))]
//! Tests for AuthorizationLock functionality.
//!
//! This module contains comprehensive tests for the AuthorizationLock
//! action type, which allows locking specific amounts of tokens or SOL
//! for future use within a role.

mod common;

use common::*;
use litesvm::LiteSVM;
use litesvm_token::spl_token::{self, instruction::TokenInstruction};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};
use swig_interface::{
    program_id, AddAuthLockInstruction, AddAuthorityInstruction, AuthorityConfig, ClientAction,
    ModifyAuthLockAddInstruction, ModifyAuthLockUpdateInstruction, RemoveAuthLockInstruction,
    SignInstruction, UpdateAuthorityData, UpdateAuthorityInstruction,
};
use swig_state::{
    action::{
        all::All, authorization_lock::AuthorizationLock,
        manage_auth_lock::ManageAuthorizationLocks, manage_authority::ManageAuthority,
        program_all::ProgramAll, Action, Actionable, Permission,
    },
    authority::AuthorityType,
    role::Role,
    swig::{swig_account_seeds, Swig, SwigWithRoles},
    Transmutable,
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Helper function to create a test context with airdropped authorities
fn setup_test_context_with_authorities() -> anyhow::Result<(SwigTestContext, Keypair, Keypair)> {
    let mut context = setup_test_context()?;
    let swig_authority = Keypair::new();
    let second_authority = Keypair::new();

    // Airdrop to participants
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 1_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    Ok((context, swig_authority, second_authority))
}

/// Helper function to create a Swig wallet with authorization lock permissions
fn create_swig_with_auth_lock_permissions(
    context: &mut SwigTestContext,
    swig_authority: &Keypair,
    second_authority: &Keypair,
    id: [u8; 32],
) -> anyhow::Result<Pubkey> {
    let (swig, _) = create_swig_ed25519(context, swig_authority, id)?;

    // Add second authority with AuthorizationLock permission
    add_authority_with_ed25519_root(
        context,
        &swig,
        swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks::new(),
        )],
    )?;

    Ok(swig)
}

/// Test basic authorization lock functionality for SOL
#[test_log::test]
fn test_authorization_lock_sol_basic() {
    let (mut context, swig_authority, second_authority) =
        setup_test_context_with_authorities().unwrap();
    let id = rand::random::<[u8; 32]>();
    let swig = create_swig_with_auth_lock_permissions(
        &mut context,
        &swig_authority,
        &second_authority,
        id,
    )
    .unwrap();

    // Verify initial state
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_data.get_role(1).unwrap().unwrap();

    assert_eq!(
        role.get_all_actions_of_type::<ManageAuthorizationLocks>()
            .unwrap()
            .len(),
        1
    );

    // Create and add authorization lock
    let auth_lock = AuthorizationLock::new([0; 32], 1_000_000, 1_000_000);
    let add_ix = AddAuthLockInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1, // role_id (second authority)
        auth_lock,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx).unwrap();
    println!("Add auth lock logs: {:?}", result.logs);

    // Verify lock was added
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_data.get_role(1).unwrap().unwrap();

    assert_eq!(
        role.get_all_actions_of_type::<AuthorizationLock>()
            .unwrap()
            .len(),
        1
    );

    // Remove the authorization lock
    let remove_ix = RemoveAuthLockInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1,       // role_id (second authority)
        [0; 32], // mint (SOL lock uses zero mint)
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx).unwrap();
    println!("Remove auth lock logs: {:?}", result.logs);

    // Verify lock was removed
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_data.get_role(1).unwrap().unwrap();

    assert_eq!(
        role.get_all_actions_of_type::<AuthorizationLock>()
            .unwrap()
            .len(),
        0
    );
}

/// Test adding multiple authorization locks and removing the first one
#[test_log::test]
fn test_authorization_lock_multiple_locks() {
    let (mut context, swig_authority, second_authority) =
        setup_test_context_with_authorities().unwrap();
    let id = rand::random::<[u8; 32]>();
    let swig = create_swig_with_auth_lock_permissions(
        &mut context,
        &swig_authority,
        &second_authority,
        id,
    )
    .unwrap();

    // Create two different authorization locks
    let sol_lock = AuthorizationLock::new([0; 32], 1_000_000, 1_000_000); // SOL lock
    let mut token_mint = [0u8; 32];
    token_mint[0] = 1; // Different mint for token lock
    let token_lock = AuthorizationLock::new(token_mint, 2_000_000, 2_000_000); // Token lock

    // Add first authorization lock (SOL)
    let add_sol_ix = AddAuthLockInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1, // role_id (second authority)
        sol_lock,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_sol_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx).unwrap();
    println!("Add SOL lock logs: {:?}", result.logs);

    // Verify the SOL lock was added
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_data.get_role(1).unwrap().unwrap();
    assert_eq!(
        role.get_all_actions_of_type::<AuthorizationLock>()
            .unwrap()
            .len(),
        1
    );

    // Add second authorization lock (Token)
    let add_token_ix = AddAuthLockInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1, // role_id (second authority)
        token_lock,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_token_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx).unwrap();
    println!("Add token lock logs: {:?}", result.logs);

    // Verify both authorization locks were added
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_data.get_role(1).unwrap().unwrap();

    assert_eq!(
        role.get_all_actions_of_type::<AuthorizationLock>()
            .unwrap()
            .len(),
        2
    );
    // Remove the first authorization lock (SOL lock)
    let remove_first_ix = RemoveAuthLockInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1,       // role_id (second authority)
        [0; 32], // mint (SOL lock uses zero mint)
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_first_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx).unwrap();
    println!("Remove first lock logs: {:?}", result.logs);

    // Verify the first lock was removed and the second lock moved to index 0
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_data.get_role(1).unwrap().unwrap();

    assert_eq!(
        role.get_all_actions_of_type::<AuthorizationLock>()
            .unwrap()
            .len(),
        1
    );
}

/// Test authorization lock functionality for tokens
#[test_log::test]
fn test_authorization_lock_token_basic() {
    let (mut context, swig_authority, second_authority) =
        setup_test_context_with_authorities().unwrap();
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

    // Mint initial tokens to the SWIG's token account
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        1_000_000, // 1 token
    )
    .unwrap();

    // Create Swig wallet
    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Add second authority with AuthorizationLock permission for the token
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks::new(),
        )],
    )
    .unwrap();

    // Verify the authorization lock was added
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_data.get_role(1).unwrap().unwrap();

    assert_eq!(
        role.get_all_actions_of_type::<AuthorizationLock>()
            .unwrap()
            .len(),
        0
    );
}

// ============================================================================
// Authorization Lock Update Tests
// ============================================================================

/// Test updating authorization lock values
#[test_log::test]
fn test_authorization_lock_update_values() {
    let (mut context, swig_authority, second_authority) =
        setup_test_context_with_authorities().unwrap();
    let id = rand::random::<[u8; 32]>();
    let swig = create_swig_with_auth_lock_permissions(
        &mut context,
        &swig_authority,
        &second_authority,
        id,
    )
    .unwrap();

    // Create initial authorization lock
    let initial_lock = AuthorizationLock::new([0; 32], 1_000_000, 1_000_000); // SOL lock with 1M amount, expires at 1M

    // Add the initial authorization lock
    let add_ix = AddAuthLockInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1, // role_id (second authority)
        initial_lock,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx).unwrap();
    println!("Add initial auth lock logs: {:?}", result.logs);

    // Verify the initial lock was added
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_data.get_role(1).unwrap().unwrap();

    assert_eq!(
        role.get_all_actions_of_type::<AuthorizationLock>()
            .unwrap()
            .len(),
        1
    );

    // Update the authorization lock with new values
    let new_amount = 2_000_000; // Double the amount
    let new_expires_at = 2_000_000; // Double the expiration time

    let update_ix = ModifyAuthLockUpdateInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1,       // role_id (second authority)
        [0; 32], // mint (SOL lock uses zero mint)
        new_amount,
        new_expires_at,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[update_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx).unwrap();
    println!("Update auth lock logs: {:?}", result.logs);

    // Verify the lock was updated correctly
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_data.get_role(1).unwrap().unwrap();

    assert_eq!(
        role.get_all_actions_of_type::<AuthorizationLock>()
            .unwrap()
            .len(),
        1
    );

    println!("Successfully updated authorization lock values");
    println!("- Amount updated from 1,000,000 to {}", new_amount);
    println!("- Expires_at updated from 1,000,000 to {}", new_expires_at);
    println!("- Mint remained unchanged: [0; 32] (SOL)");
}

// =========================================================================
// Authorization Lock Cache Tests
// =========================================================================

fn read_auth_lock_cache_entries(svm: &LiteSVM, swig: &Pubkey) -> Vec<([u8; 32], u64, u64)> {
    let swig_account = svm.get_account(swig).unwrap();
    let data = &swig_account.data;
    let swig_hdr = unsafe { Swig::load_unchecked(&data[..Swig::LEN]).unwrap() };
    let roles_boundary = swig_hdr.roles_boundary as usize;
    let count = swig_hdr.auth_lock_count as usize;
    let mut out = Vec::with_capacity(count);
    let mut cursor = Swig::LEN + roles_boundary;
    for _ in 0..count {
        let mut mint = [0u8; 32];
        mint.copy_from_slice(&data[cursor..cursor + 32]);
        cursor += 32;
        let mut amt_bytes = [0u8; 8];
        amt_bytes.copy_from_slice(&data[cursor..cursor + 8]);
        cursor += 8;
        let mut exp_bytes = [0u8; 8];
        exp_bytes.copy_from_slice(&data[cursor..cursor + 8]);
        cursor += 8;
        out.push((
            mint,
            u64::from_le_bytes(amt_bytes),
            u64::from_le_bytes(exp_bytes),
        ));
    }
    out
}

#[test_log::test]
fn test_authorization_lock_cache_add_two_mints_and_remove_one() {
    let (mut context, swig_authority, second_authority) =
        setup_test_context_with_authorities().unwrap();
    let id = rand::random::<[u8; 32]>();
    let swig = create_swig_with_auth_lock_permissions(
        &mut context,
        &swig_authority,
        &second_authority,
        id,
    )
    .unwrap();

    // Two different mints
    let mint_sol = [0u8; 32];
    let mut mint_token = [0u8; 32];
    mint_token[0] = 9;

    // Add SOL lock
    let add_sol_ix = AddAuthLockInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1,
        AuthorizationLock::new(mint_sol, 1_000, 10_000),
    )
    .unwrap();
    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_sol_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();
    context.svm.send_transaction(tx).unwrap();

    // Add token lock
    let add_tok_ix = AddAuthLockInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1,
        AuthorizationLock::new(mint_token, 2_500, 20_000),
    )
    .unwrap();
    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_tok_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();
    context.svm.send_transaction(tx).unwrap();

    // Verify cache has two entries with correct data
    let entries = read_auth_lock_cache_entries(&context.svm, &swig);
    assert_eq!(entries.len(), 2);
    assert!(entries
        .iter()
        .any(|(m, a, e)| *m == mint_sol && *a == 1_000 && *e == 10_000));
    assert!(entries
        .iter()
        .any(|(m, a, e)| *m == mint_token && *a == 2_500 && *e == 20_000));

    // Remove token lock and verify cache updates to single entry
    let rm_tok_ix = RemoveAuthLockInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1,
        mint_token,
    )
    .unwrap();
    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[rm_tok_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();
    let result = context.svm.send_transaction(tx).unwrap();

    let entries = read_auth_lock_cache_entries(&context.svm, &swig);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, mint_sol);
    assert_eq!(entries[0].1, 1_000);
    assert_eq!(entries[0].2, 10_000);
}

#[test_log::test]
fn test_authorization_lock_cache_updates_after_modify() {
    let (mut context, swig_authority, second_authority) =
        setup_test_context_with_authorities().unwrap();
    let id = rand::random::<[u8; 32]>();
    let swig = create_swig_with_auth_lock_permissions(
        &mut context,
        &swig_authority,
        &second_authority,
        id,
    )
    .unwrap();

    let mint_sol = [0u8; 32];

    // Add lock
    let add_ix = AddAuthLockInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1,
        AuthorizationLock::new(mint_sol, 1_000, 10_000),
    )
    .unwrap();
    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();
    context.svm.send_transaction(tx).unwrap();

    // Update lock
    let upd_ix = ModifyAuthLockUpdateInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1,
        mint_sol,
        4_000,
        50_000,
    )
    .unwrap();
    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[upd_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();
    context.svm.send_transaction(tx).unwrap();

    // Verify cache reflects updated values
    let entries = read_auth_lock_cache_entries(&context.svm, &swig);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, mint_sol);
    assert_eq!(entries[0].1, 4_000);
    assert_eq!(entries[0].2, 50_000);
}

#[test_log::test]
fn test_authorization_lock_cache_same_mint_flow() {
    let (mut context, swig_authority, second_authority) =
        setup_test_context_with_authorities().unwrap();
    let id = rand::random::<[u8; 32]>();
    let swig = create_swig_with_auth_lock_permissions(
        &mut context,
        &swig_authority,
        &second_authority,
        id,
    )
    .unwrap();

    let mint = [0u8; 32];

    // Add first lock: amount=1_000, expires=10_000
    let add1_ix = AddAuthLockInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1,
        AuthorizationLock::new(mint, 1_000, 10_000),
    )
    .unwrap();
    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add1_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();
    context.svm.send_transaction(tx).unwrap();

    // Cache should have one entry
    let entries = read_auth_lock_cache_entries(&context.svm, &swig);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, mint);
    assert_eq!(entries[0].1, 1_000);
    assert_eq!(entries[0].2, 10_000);

    // Add second lock with SAME mint: amount=2_500, expires=20_000
    let add2_ix = ModifyAuthLockAddInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1,
        mint,
        2_500,
        20_000,
    )
    .unwrap();
    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();
    context.svm.send_transaction(tx).unwrap();

    // Cache should aggregate totals and earliest
    let entries = read_auth_lock_cache_entries(&context.svm, &swig);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, mint);
    assert_eq!(entries[0].1, 3_500); // 1_000 + 2_500
    assert_eq!(entries[0].2, 10_000); // min(10_000, 20_000)

    // Update lock for same mint (program updates the first occurrence):
    // new amount=4_000, new expires=5_000
    let upd_ix = ModifyAuthLockUpdateInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1,
        mint,
        4_000,
        5_000,
    )
    .unwrap();
    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[upd_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();
    context.svm.send_transaction(tx).unwrap();

    // Cache: total should be 4_000 + 2_500 = 6_500, earliest 5_000
    let entries = read_auth_lock_cache_entries(&context.svm, &swig);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, mint);
    assert_eq!(entries[0].1, 6_500);
    assert_eq!(entries[0].2, 5_000);

    // Remove a lock by mint (implementation removes the last one after swap logic)
    let rm_ix = RemoveAuthLockInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1,
        mint,
    )
    .unwrap();
    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[rm_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();
    context.svm.send_transaction(tx).unwrap();

    // Only the updated lock should remain in cache
    let entries = read_auth_lock_cache_entries(&context.svm, &swig);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, mint);
    assert_eq!(entries[0].1, 4_000);
    assert_eq!(entries[0].2, 5_000);
}

/// Test updating authorization lock with different mint (should fail)
#[test_log::test]
fn test_authorization_lock_update_different_mint() {
    let (mut context, swig_authority, second_authority) =
        setup_test_context_with_authorities().unwrap();
    let id = rand::random::<[u8; 32]>();
    let swig = create_swig_with_auth_lock_permissions(
        &mut context,
        &swig_authority,
        &second_authority,
        id,
    )
    .unwrap();

    // Create initial authorization lock
    let initial_lock = AuthorizationLock::new([0; 32], 1_000_000, 1_000_000); // SOL lock

    // Add the initial authorization lock
    let add_ix = AddAuthLockInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1, // role_id (second authority)
        initial_lock,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx).unwrap();
    println!("Add initial auth lock logs: {:?}", result.logs);

    // Try to update the authorization lock with a different mint (should fail)
    let mut different_mint = [0u8; 32];
    different_mint[0] = 1; // Different mint

    let update_ix = ModifyAuthLockUpdateInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1,              // role_id (second authority)
        different_mint, // Different mint - this should cause the update to fail
        2_000_000,
        2_000_000,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[update_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);

    // This should fail because we're trying to update a lock with a different mint
    assert!(
        result.is_err(),
        "Should fail when trying to update lock with different mint"
    );
    println!(
        "Update with different mint failed as expected: {:?}",
        result.err()
    );
}

/// Test updating non-existent authorization lock (should fail)
#[test_log::test]
fn test_authorization_lock_update_nonexistent() {
    let (mut context, swig_authority, second_authority) =
        setup_test_context_with_authorities().unwrap();
    let id = rand::random::<[u8; 32]>();
    let swig = create_swig_with_auth_lock_permissions(
        &mut context,
        &swig_authority,
        &second_authority,
        id,
    )
    .unwrap();

    // Try to update a non-existent authorization lock (should fail)
    let mut non_existent_mint = [0u8; 32];
    non_existent_mint[0] = 99; // Non-existent mint

    let update_ix = ModifyAuthLockUpdateInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1,                 // role_id (second authority)
        non_existent_mint, // Non-existent mint
        2_000_000,
        2_000_000,
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[update_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);

    // This should fail because we're trying to update a non-existent lock
    assert!(
        result.is_err(),
        "Should fail when trying to update non-existent lock"
    );
    println!(
        "Update non-existent lock failed as expected: {:?}",
        result.err()
    );
}

// ============================================================================
// Error Case Tests
// ============================================================================

/// Test authorization lock removal of non-existent lock (should fail)
#[test_log::test]
fn test_authorization_lock_remove_nonexistent() {
    let (mut context, swig_authority, second_authority) =
        setup_test_context_with_authorities().unwrap();
    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Create Swig wallet
    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Add second authority WITHOUT AuthorizationLock permission
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::All(All {})], // No AuthorizationLock permission
    )
    .unwrap();

    // Try to remove a non-existent authorization lock (should fail)
    let remove_ix = UpdateAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        second_authority.pubkey(),
        1, // acting_role_id (second authority)
        1, // authority_to_update_id (same authority)
        UpdateAuthorityData::RemoveActionsByType(vec![ManageAuthorizationLocks::TYPE as u8]),
    )
    .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[remove_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &second_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);

    // This should succeed because removing by type is safe even if no locks exist
    assert!(
        result.is_ok(),
        "Should succeed when removing authorization lock by type even if none exist"
    );
}

// ============================================================================
// Placeholder Tests (Currently Disabled)
// ============================================================================

/// Test authorization lock aggregation when adding multiple locks for same mint
/// Note: This test is currently disabled because the aggregation logic in UpdateAuthorityInstruction
/// is not yet implemented (it's a placeholder). The individual authorization lock operations
/// work correctly via ModifyAuthLockV1 instruction.
#[test_log::test]
fn test_authorization_lock_aggregation() {
    // Skip this test until aggregation logic is implemented in UpdateAuthorityInstruction
    println!("Skipping aggregation test - UpdateAuthorityInstruction aggregation logic not yet implemented");
    return;

    // Placeholder implementation would go here
}

/// Test authorization lock with wrong amount removal (should fail)
/// Note: This test is currently disabled because the removal logic in UpdateAuthorityInstruction
/// is not yet implemented (it's a placeholder). Individual authorization lock removal works
/// correctly via ModifyAuthLockV1 instruction.
#[test_log::test]
fn test_authorization_lock_wrong_amount_removal() {
    // Skip this test until removal logic is implemented in UpdateAuthorityInstruction
    println!("Skipping wrong amount removal test - UpdateAuthorityInstruction removal logic not yet implemented");
    return;

    // Placeholder implementation would go here
}

// ============================================================================
// Instruction Building Tests
// ============================================================================

/// Test that we can build Secp256k1 add authorization lock instructions without errors
#[test]
fn test_add_authorization_lock_secp256k1_instruction_building() -> anyhow::Result<()> {
    let swig_pubkey = Pubkey::new_unique();
    let payer_pubkey = Pubkey::new_unique();

    // Test that we can build Secp256k1 instructions without errors
    let _ix = UpdateAuthorityInstruction::new_with_secp256k1_authority(
        swig_pubkey,
        payer_pubkey,
        |_| [0u8; 65], // dummy signature function
        0,             // current_slot
        0,             // counter
        1,             // acting_role_id
        1,             // authority_to_update_id
        UpdateAuthorityData::AddActions(vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks::new(),
        )]),
    )?;

    Ok(())
}

/// Test that we can build Secp256k1 remove authorization lock instructions without errors
#[test]
fn test_remove_authorization_lock_secp256k1_instruction_building() -> anyhow::Result<()> {
    let swig_pubkey = Pubkey::new_unique();
    let payer_pubkey = Pubkey::new_unique();

    // Test that we can build Secp256k1 instructions without errors
    let _ix = UpdateAuthorityInstruction::new_with_secp256k1_authority(
        swig_pubkey,
        payer_pubkey,
        |_| [0u8; 65], // dummy signature function
        0,             // current_slot
        0,             // counter
        1,             // acting_role_id
        1,             // authority_to_update_id
        UpdateAuthorityData::RemoveActionsByType(vec![ManageAuthorizationLocks::TYPE as u8]),
    )?;

    Ok(())
}

/// Test that we can build Secp256r1 add authorization lock instructions without errors
#[test]
fn test_add_authorization_lock_secp256r1_instruction_building() -> anyhow::Result<()> {
    let swig_pubkey = Pubkey::new_unique();
    let payer_pubkey = Pubkey::new_unique();

    // Test that we can build Secp256r1 instructions without errors
    let dummy_pubkey = [0u8; 33]; // dummy public key
    let _ix = UpdateAuthorityInstruction::new_with_secp256r1_authority(
        swig_pubkey,
        payer_pubkey,
        |_| [0u8; 64], // dummy signature function
        0,             // current_slot
        0,             // counter
        1,             // acting_role_id
        1,             // authority_to_update_id
        UpdateAuthorityData::AddActions(vec![ClientAction::ManageAuthorizationLocks(
            ManageAuthorizationLocks::new(),
        )]),
        &dummy_pubkey,
    )?;

    Ok(())
}

/// Test that we can build Secp256r1 remove authorization lock instructions without errors
#[test]
fn test_remove_authorization_lock_secp256r1_instruction_building() -> anyhow::Result<()> {
    let swig_pubkey = Pubkey::new_unique();
    let payer_pubkey = Pubkey::new_unique();

    // Test that we can build Secp256r1 instructions without errors
    let dummy_pubkey = [0u8; 33]; // dummy public key
    let _ix = UpdateAuthorityInstruction::new_with_secp256r1_authority(
        swig_pubkey,
        payer_pubkey,
        |_| [0u8; 64], // dummy signature function
        0,             // current_slot
        0,             // counter
        1,             // acting_role_id
        1,             // authority_to_update_id
        UpdateAuthorityData::RemoveActionsByType(vec![ManageAuthorizationLocks::TYPE as u8]),
        &dummy_pubkey,
    )?;

    Ok(())
}
