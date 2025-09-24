//! Tests for AllButManageAuthority permission type
//!
//! This permission should allow all operations in sign_v1 (SOL transfers, token
//! transfers, CPI calls) but prohibit authority management operations
//! (add/remove/update authorities) and sub-account operations.

#![cfg(not(feature = "program_scope_test"))]

mod common;
use common::*;
use litesvm_token::spl_token::{self, instruction::TokenInstruction};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction, InstructionError},
    message::{v0, VersionedMessage},
    native_token::LAMPORTS_PER_SOL,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction,
    sysvar::clock::Clock,
    transaction::{TransactionError, VersionedTransaction},
};
use swig::actions::sign_v1::SignV1Args;
use swig_interface::{
    compact_instructions, AuthorityConfig, ClientAction, CreateSubAccountInstruction,
    RemoveAuthorityInstruction, SubAccountSignInstruction, ToggleSubAccountInstruction,
    UpdateAuthorityData, UpdateAuthorityInstruction, WithdrawFromSubAccountInstruction,
};
use swig_state::{
    action::{
        all::All, all_but_manage_authority::AllButManageAuthority,
        manage_authority::ManageAuthority, program::Program, sol_limit::SolLimit,
        sol_recurring_limit::SolRecurringLimit, sub_account::SubAccount, token_limit::TokenLimit,
        token_recurring_limit::TokenRecurringLimit, Action, Permission,
    },
    authority::AuthorityType,
    swig::{sub_account_seeds, swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
    Transmutable,
};

#[test_log::test]
fn test_all_but_manage_authority_can_transfer_sol() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add authority with AllButManageAuthority permission
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::AllButManageAuthority(
            AllButManageAuthority {},
        )],
    )
    .unwrap();

    let swig_lamports_balance = context.svm.get_account(&swig).unwrap().lamports;
    let initial_swig_balance = 10_000_000_000;
    context.svm.airdrop(&swig, initial_swig_balance).unwrap();
    assert!(swig_create_txn.is_ok());

    let amount = 5_000_000_000; // 5 SOL
    let ixd = system_instruction::transfer(&swig, &recipient.pubkey(), amount);
    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        ixd,
        1, // AllButManageAuthority role
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
    assert!(
        res.is_ok(),
        "AllButManageAuthority should be able to transfer SOL"
    );

    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    let swig_account_after = context.svm.get_account(&swig).unwrap();
    assert_eq!(recipient_account.lamports, 10_000_000_000 + amount);

    assert_eq!(
        swig_account_after.lamports,
        swig_lamports_balance + initial_swig_balance - amount
    );

    let swig_state = SwigWithRoles::from_bytes(&swig_account_after.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();
    assert!(role
        .get_action::<AllButManageAuthority>(&[])
        .unwrap()
        .is_some());
}

#[test_log::test]
fn test_all_but_manage_authority_can_transfer_tokens() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    context.svm.warp_to_slot(10);

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

    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        1000,
    )
    .unwrap();

    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add authority with AllButManageAuthority permission
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::AllButManageAuthority(
            AllButManageAuthority {},
        )],
    )
    .unwrap();

    context.svm.airdrop(&swig, 10_000_000_000).unwrap();
    let token_amount = 500;

    context.svm.warp_to_slot(100);
    let token_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer {
            amount: token_amount,
        }
        .pack(),
    };

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix,
        1, // AllButManageAuthority role
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
    assert!(
        res.is_ok(),
        "AllButManageAuthority should be able to transfer tokens"
    );

    let recipient_token_account = context.svm.get_account(&recipient_ata).unwrap();
    let token_account = spl_token::state::Account::unpack(&recipient_token_account.data).unwrap();
    assert_eq!(token_account.amount, token_amount);

    let swig_token_account = context.svm.get_account(&swig_ata).unwrap();
    let swig_token_balance = spl_token::state::Account::unpack(&swig_token_account.data).unwrap();
    assert_eq!(swig_token_balance.amount, 1000 - token_amount);
}

#[test_log::test]
fn test_all_but_manage_authority_can_do_cpi_calls() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
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

    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_ata,
        1000,
    )
    .unwrap();

    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add authority with AllButManageAuthority permission
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::AllButManageAuthority(
            AllButManageAuthority {},
        )],
    )
    .unwrap();

    context.svm.airdrop(&swig, 10_000_000_000).unwrap();
    let sol_amount = 50;
    let token_amount = 500;

    context.svm.warp_to_slot(100);

    // Create multiple instructions to test CPI capabilities
    let sol_ix = system_instruction::transfer(&swig, &recipient.pubkey(), sol_amount);
    let token_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig, false),
        ],
        data: TokenInstruction::Transfer {
            amount: token_amount,
        }
        .pack(),
    };

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        token_ix,
        1, // AllButManageAuthority role
    )
    .unwrap();

    let sign_ix2 = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        sol_ix,
        1, // AllButManageAuthority role
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix, sign_ix2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    let res = context.svm.send_transaction(transfer_tx);
    assert!(
        res.is_ok(),
        "AllButManageAuthority should be able to perform
multiple CPI calls"
    );

    // Verify both SOL and token transfers succeeded
    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(recipient_account.lamports, 10_000_000_000 + sol_amount);

    let recipient_token_account = context.svm.get_account(&recipient_ata).unwrap();
    let token_account = spl_token::state::Account::unpack(&recipient_token_account.data).unwrap();
    assert_eq!(token_account.amount, token_amount);
}

#[test_log::test]
fn test_all_but_manage_authority_cannot_add_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new(); // Root authority
    let restricted_authority = Keypair::new(); // Authority with AllButManageAuthority
    let new_authority = Keypair::new(); // Authority we try to add (should fail)

    // Airdrop to all authorities
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&restricted_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&new_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Create the swig with root authority
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    // Add an authority with AllButManageAuthority permission
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: restricted_authority.pubkey().as_ref(),
        },
        vec![ClientAction::AllButManageAuthority(
            AllButManageAuthority {},
        )],
    )
    .unwrap();

    // Verify we have two authorities (root + restricted)
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_state.state.roles, 2);

    // Get the restricted authority's role ID
    let restricted_role_id = swig_state
        .lookup_role_id(restricted_authority.pubkey().as_ref())
        .unwrap()
        .expect("Restricted authority should exist");

    // Now attempt to add a new authority using the restricted authority
    // This should FAIL because AllButManageAuthority excludes authority management
    let add_authority_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &restricted_authority, // Using restricted authority instead of root
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: new_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 1000 })],
    );

    // The operation should fail with PermissionDeniedToManageAuthority error
    assert!(
        add_authority_result.is_err(),
        "AllButManageAuthority should NOT be able to add new authorities"
    );

    // Verify it's the specific permission error we expect (error code 3010 = 0xbc2)
    let error_msg = format!("{:?}", add_authority_result.unwrap_err());
    assert!(
        error_msg.contains("3010") || error_msg.contains("PermissionDeniedToManageAuthority"),
        "Expected PermissionDeniedToManageAuthority error, got: {}",
        error_msg
    );

    // Verify that the swig still has only 2 authorities (no new authority was
    // added)
    let swig_account_after = context.svm.get_account(&swig).unwrap();
    let swig_state_after = SwigWithRoles::from_bytes(&swig_account_after.data).unwrap();
    assert_eq!(swig_state_after.state.roles, 2);

    // Verify the new authority does not exist
    let new_authority_lookup = swig_state_after
        .lookup_role_id(new_authority.pubkey().as_ref())
        .unwrap();
    assert!(
        new_authority_lookup.is_none(),
        "New authority should not have been added"
    );

    // Verify the restricted authority still exists and has the correct permissions
    let restricted_role = swig_state_after
        .get_role(restricted_role_id)
        .unwrap()
        .unwrap();
    assert!(restricted_role
        .get_action::<AllButManageAuthority>(&[])
        .unwrap()
        .is_some());

    println!("SUCCESS: AllButManageAuthority correctly prevents adding new authorities");
}

#[test_log::test]
fn test_all_but_manage_authority_cannot_remove_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new(); // Root authority
    let restricted_authority = Keypair::new(); // Authority with AllButManageAuthority
    let target_authority = Keypair::new(); // Authority to be removed

    // Airdrop to all authorities
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&restricted_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&target_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Create the swig with root authority
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    // Add an authority with AllButManageAuthority permission
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: restricted_authority.pubkey().as_ref(),
        },
        vec![ClientAction::AllButManageAuthority(
            AllButManageAuthority {},
        )],
    )
    .unwrap();

    // Add a target authority that we'll try to remove
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: target_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 1000 })],
    )
    .unwrap();

    // Verify we have three authorities (root + restricted + target)
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_state.state.roles, 3);

    // Get the role IDs
    let restricted_role_id = swig_state
        .lookup_role_id(restricted_authority.pubkey().as_ref())
        .unwrap()
        .expect("Restricted authority should exist");
    let target_role_id = swig_state
        .lookup_role_id(target_authority.pubkey().as_ref())
        .unwrap()
        .expect("Target authority should exist");

    // Now attempt to remove the target authority using the restricted authority
    // This should FAIL because AllButManageAuthority excludes authority management
    let remove_ix = RemoveAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        restricted_authority.pubkey(),
        restricted_role_id, // Acting role ID (restricted authority)
        target_role_id,     // Authority to remove (target authority)
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
        &[&context.default_payer, &restricted_authority],
    )
    .unwrap();

    let remove_authority_result = context.svm.send_transaction(tx);

    // The operation should fail with PermissionDeniedToManageAuthority error
    assert!(
        remove_authority_result.is_err(),
        "AllButManageAuthority should NOT be able to remove authorities"
    );

    // Verify it's the specific permission error we expect (error code 3010 = 0xbc2)
    let error_msg = format!("{:?}", remove_authority_result.unwrap_err());
    assert!(
        error_msg.contains("3010") || error_msg.contains("PermissionDeniedToManageAuthority"),
        "Expected PermissionDeniedToManageAuthority error, got: {}",
        error_msg
    );

    // Verify that the swig still has 3 authorities (no authority was removed)
    let swig_account_after = context.svm.get_account(&swig).unwrap();
    let swig_state_after = SwigWithRoles::from_bytes(&swig_account_after.data).unwrap();
    assert_eq!(swig_state_after.state.roles, 3);

    // Verify the target authority still exists
    let target_role_still_exists = swig_state_after.get_role(target_role_id).unwrap();
    assert!(
        target_role_still_exists.is_some(),
        "Target authority should still exist"
    );

    // Verify the restricted authority still has AllButManageAuthority permission
    let restricted_role = swig_state_after
        .get_role(restricted_role_id)
        .unwrap()
        .unwrap();
    assert!(restricted_role
        .get_action::<AllButManageAuthority>(&[])
        .unwrap()
        .is_some());

    println!("SUCCESS: AllButManageAuthority correctly prevents removing authorities");
}

#[test_log::test]
fn test_all_but_manage_authority_cannot_create_sub_account() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new(); // Root authority
    let restricted_authority = Keypair::new(); // Authority with AllButManageAuthority

    // Airdrop to authorities
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&restricted_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Create the swig with root authority
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    // Add an authority with AllButManageAuthority permission
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: restricted_authority.pubkey().as_ref(),
        },
        vec![ClientAction::AllButManageAuthority(
            AllButManageAuthority {},
        )],
    )
    .unwrap();

    // Verify we have two authorities (root + restricted)
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_state.state.roles, 2);

    // Get the restricted authority's role ID
    let restricted_role_id = swig_state
        .lookup_role_id(restricted_authority.pubkey().as_ref())
        .unwrap()
        .expect("Restricted authority should exist");

    // Derive the sub-account address that would be created
    let role_id_bytes = restricted_role_id.to_le_bytes();
    let (sub_account, sub_account_bump) =
        Pubkey::find_program_address(&sub_account_seeds(&id, &role_id_bytes), &program_id());

    // Now attempt to create a sub-account using the restricted authority
    // This should FAIL because AllButManageAuthority should not allow sub-account
    // operations
    let create_sub_account_ix = CreateSubAccountInstruction::new_with_ed25519_authority(
        swig,
        restricted_authority.pubkey(),
        restricted_authority.pubkey(),
        sub_account,
        restricted_role_id,
        sub_account_bump,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &restricted_authority.pubkey(),
        &[create_sub_account_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&restricted_authority])
        .unwrap();

    let create_sub_account_result = context.svm.send_transaction(tx);

    // The operation should fail - AllButManageAuthority should not allow
    // sub-account creation
    assert!(
        create_sub_account_result.is_err(),
        "AllButManageAuthority should NOT be able to create sub-accounts"
    );

    // Verify it's a permission-related error (error code 36 = 0x24)
    let error_msg = format!("{:?}", create_sub_account_result.unwrap_err());
    assert!(
        error_msg.contains("36")
            || error_msg.contains("PermissionDenied")
            || error_msg.contains("0x24"),
        "Expected permission error, got: {}",
        error_msg
    );

    // Verify no sub-account was created
    let sub_account_result = context.svm.get_account(&sub_account);
    assert!(
        sub_account_result.is_none(),
        "Sub-account should not have been created"
    );

    // Verify the restricted authority still has AllButManageAuthority permission
    let swig_account_after = context.svm.get_account(&swig).unwrap();
    let swig_state_after = SwigWithRoles::from_bytes(&swig_account_after.data).unwrap();
    let restricted_role = swig_state_after
        .get_role(restricted_role_id)
        .unwrap()
        .unwrap();
    assert!(restricted_role
        .get_action::<AllButManageAuthority>(&[])
        .unwrap()
        .is_some());

    println!("SUCCESS: AllButManageAuthority correctly prevents creating sub-accounts");
}

#[test_log::test]
fn test_all_but_manage_authority_cannot_withdraw_from_sub_account() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new(); // Root authority
    let restricted_authority = Keypair::new(); // Authority with AllButManageAuthority
    let sub_account_authority = Keypair::new(); // Authority to create sub-account

    // Airdrop to all authorities
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&restricted_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&sub_account_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Create the swig with root authority
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    // Add an authority with AllButManageAuthority permission
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: restricted_authority.pubkey().as_ref(),
        },
        vec![ClientAction::AllButManageAuthority(
            AllButManageAuthority {},
        )],
    )
    .unwrap();

    // Add a sub-account authority with proper SubAccount permission
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: sub_account_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccount(SubAccount::new_for_creation())],
    )
    .unwrap();

    // Verify we have three authorities (root + restricted + sub-account)
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_state.state.roles, 3);

    // Get the role IDs
    let restricted_role_id = swig_state
        .lookup_role_id(restricted_authority.pubkey().as_ref())
        .unwrap()
        .expect("Restricted authority should exist");
    let sub_account_role_id = swig_state
        .lookup_role_id(sub_account_authority.pubkey().as_ref())
        .unwrap()
        .expect("Sub-account authority should exist");

    // Create a sub-account using the proper sub-account authority
    let sub_account = create_sub_account(
        &mut context,
        &swig,
        &sub_account_authority,
        sub_account_role_id,
        id,
    )
    .unwrap();

    // Fund the sub-account with some SOL
    let initial_balance = 5_000_000_000;
    context.svm.airdrop(&sub_account, initial_balance).unwrap();

    // Get initial balances
    let swig_initial_balance = context.svm.get_account(&swig).unwrap().lamports;
    let sub_account_initial_balance = context.svm.get_account(&sub_account).unwrap().lamports;

    // Now attempt to withdraw SOL from the sub-account using the restricted
    // authority This should FAIL because AllButManageAuthority should not allow
    // sub-account operations

    // Derive the swig wallet address
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let withdraw_amount = 1_000_000_000;
    let withdraw_ix = WithdrawFromSubAccountInstruction::new_with_ed25519_authority(
        swig,
        restricted_authority.pubkey(),
        restricted_authority.pubkey(),
        sub_account,
        swig_wallet_address,
        restricted_role_id,
        withdraw_amount,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &restricted_authority.pubkey(),
        &[withdraw_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&restricted_authority])
        .unwrap();

    let withdraw_result = context.svm.send_transaction(tx);

    // The operation should fail - AllButManageAuthority should not allow
    // sub-account withdrawals
    assert!(
        withdraw_result.is_err(),
        "AllButManageAuthority should NOT be able to withdraw from sub-accounts"
    );

    // Verify it's a permission-related error
    let error_msg = format!("{:?}", withdraw_result.unwrap_err());
    assert!(
        error_msg.contains("PermissionDenied") || error_msg.contains("Custom"),
        "Expected permission error, got: {}",
        error_msg
    );

    // Verify the balances were NOT changed (no withdrawal occurred)
    let swig_after_balance = context.svm.get_account(&swig).unwrap().lamports;
    let sub_account_after_balance = context.svm.get_account(&sub_account).unwrap().lamports;

    assert_eq!(
        swig_after_balance, swig_initial_balance,
        "Swig account balance should not have changed"
    );
    assert_eq!(
        sub_account_after_balance, sub_account_initial_balance,
        "Sub-account balance should not have changed"
    );

    // Verify the sub-account still exists and is intact
    let sub_account_data = context.svm.get_account(&sub_account).unwrap();
    assert_eq!(sub_account_data.owner, solana_sdk::system_program::ID);

    // Verify the restricted authority still has AllButManageAuthority permission
    let swig_account_after = context.svm.get_account(&swig).unwrap();
    let swig_state_after = SwigWithRoles::from_bytes(&swig_account_after.data).unwrap();
    let restricted_role = swig_state_after
        .get_role(restricted_role_id)
        .unwrap()
        .unwrap();
    assert!(restricted_role
        .get_action::<AllButManageAuthority>(&[])
        .unwrap()
        .is_some());

    println!("SUCCESS: AllButManageAuthority correctly prevents withdrawing from sub-accounts");
}

#[test_log::test]
fn test_all_but_manage_authority_cannot_sign_with_sub_account() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new(); // Root authority
    let restricted_authority = Keypair::new(); // Authority with AllButManageAuthority
    let sub_account_authority = Keypair::new(); // Authority to create and use sub-account
    let recipient = Keypair::new();

    // Airdrop to all authorities and recipient
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&restricted_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&sub_account_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context.svm.airdrop(&recipient.pubkey(), 1_000_000).unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Create the swig with root authority
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    // Add an authority with AllButManageAuthority permission
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: restricted_authority.pubkey().as_ref(),
        },
        vec![ClientAction::AllButManageAuthority(
            AllButManageAuthority {},
        )],
    )
    .unwrap();

    // Add a sub-account authority with proper SubAccount permission
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: sub_account_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccount(SubAccount::new_for_creation())],
    )
    .unwrap();

    // Verify we have three authorities (root + restricted + sub-account)
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_state.state.roles, 3);

    // Get the role IDs
    let restricted_role_id = swig_state
        .lookup_role_id(restricted_authority.pubkey().as_ref())
        .unwrap()
        .expect("Restricted authority should exist");
    let sub_account_role_id = swig_state
        .lookup_role_id(sub_account_authority.pubkey().as_ref())
        .unwrap()
        .expect("Sub-account authority should exist");

    // Create a sub-account using the proper sub-account authority
    let sub_account = create_sub_account(
        &mut context,
        &swig,
        &sub_account_authority,
        sub_account_role_id,
        id,
    )
    .unwrap();

    // Fund the sub-account with some SOL
    let initial_balance = 5_000_000_000;
    context.svm.airdrop(&sub_account, initial_balance).unwrap();

    let initial_balance = context.svm.get_account(&sub_account).unwrap().lamports;

    // Create a transfer instruction that would be executed by the sub-account
    let transfer_amount = 1_000_000;
    let transfer_ix =
        system_instruction::transfer(&sub_account, &recipient.pubkey(), transfer_amount);

    // Now attempt to sign with the sub-account using the restricted authority
    // (AllButManageAuthority) This should FAIL because AllButManageAuthority
    // should not allow sub-account operations
    let sign_result = sub_account_sign(
        &mut context,
        &swig,
        &sub_account,
        &restricted_authority, // Using restricted authority instead of sub_account_authority
        restricted_role_id,    // Using restricted role ID
        vec![transfer_ix],
    );

    // The operation should fail - AllButManageAuthority should not allow
    // sub-account signing
    assert!(
        sign_result.is_err(),
        "AllButManageAuthority should NOT be able to sign with sub-accounts"
    );

    // Verify it's a permission-related error
    let error_msg = format!("{:?}", sign_result.unwrap_err());
    assert!(
        error_msg.contains("PermissionDenied")
            || error_msg.contains("Custom")
            || error_msg.contains("3006"),
        "Expected permission error, got: {}",
        error_msg
    );

    // Verify the funds were NOT transferred (transaction failed)
    let recipient_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    assert_eq!(
        recipient_balance, 1_000_000,
        "Recipient's balance should not have changed"
    );

    // Verify the restricted authority still has AllButManageAuthority permission
    let swig_account_after = context.svm.get_account(&swig).unwrap();
    let swig_state_after = SwigWithRoles::from_bytes(&swig_account_after.data).unwrap();
    let restricted_role = swig_state_after
        .get_role(restricted_role_id)
        .unwrap()
        .unwrap();
    assert!(restricted_role
        .get_action::<AllButManageAuthority>(&[])
        .unwrap()
        .is_some());

    println!("SUCCESS: AllButManageAuthority correctly prevents signing with sub-accounts");
}

#[test_log::test]
fn test_all_but_manage_authority_cannot_toggle_sub_account() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new(); // Root authority
    let restricted_authority = Keypair::new(); // Authority with AllButManageAuthority
    let sub_account_authority = Keypair::new(); // Authority to create sub-account

    // Airdrop to all authorities
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&restricted_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&sub_account_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Create the swig with root authority
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    // Add an authority with AllButManageAuthority permission
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: restricted_authority.pubkey().as_ref(),
        },
        vec![ClientAction::AllButManageAuthority(
            AllButManageAuthority {},
        )],
    )
    .unwrap();

    // Add a sub-account authority with proper SubAccount permission
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: sub_account_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccount(SubAccount::new_for_creation())],
    )
    .unwrap();

    // Verify we have three authorities (root + restricted + sub-account)
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_state.state.roles, 3);

    // Get the role IDs
    let restricted_role_id = swig_state
        .lookup_role_id(restricted_authority.pubkey().as_ref())
        .unwrap()
        .expect("Restricted authority should exist");
    let sub_account_role_id = swig_state
        .lookup_role_id(sub_account_authority.pubkey().as_ref())
        .unwrap()
        .expect("Sub-account authority should exist");

    // Create a sub-account using the proper sub-account authority
    let sub_account = create_sub_account(
        &mut context,
        &swig,
        &sub_account_authority,
        sub_account_role_id,
        id,
    )
    .unwrap();

    // Verify the sub-account is initially enabled by checking the SubAccount action
    let swig_account_data = context.svm.get_account(&swig).unwrap();
    let swig_with_roles = SwigWithRoles::from_bytes(&swig_account_data.data).unwrap();
    let role = swig_with_roles
        .get_role(sub_account_role_id)
        .unwrap()
        .unwrap();

    // Find the SubAccount action and verify it's enabled
    let mut cursor = 0;
    let mut found_enabled_action = false;

    for _i in 0..role.position.num_actions() {
        let action_header =
            unsafe { Action::load_unchecked(&role.actions[cursor..cursor + Action::LEN]) }.unwrap();
        cursor += Action::LEN;

        if action_header.permission().unwrap() == Permission::SubAccount {
            let action_data = &role.actions[cursor..cursor + action_header.length() as usize];
            let sub_account_action = unsafe { SubAccount::load_unchecked(action_data) }.unwrap();

            if sub_account_action.sub_account == sub_account.to_bytes() {
                assert!(
                    sub_account_action.enabled,
                    "Sub-account should be initially enabled"
                );
                found_enabled_action = true;
                break;
            }
        }

        cursor += action_header.length() as usize;
    }

    assert!(found_enabled_action, "SubAccount action not found");

    // Now attempt to toggle (disable) the sub-account using the restricted
    // authority This should FAIL because AllButManageAuthority should not allow
    // sub-account management operations
    let toggle_ix = ToggleSubAccountInstruction::new_with_ed25519_authority(
        swig,
        restricted_authority.pubkey(),
        restricted_authority.pubkey(),
        sub_account,
        restricted_role_id,
        None,
        false, // disable
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &restricted_authority.pubkey(),
        &[toggle_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&restricted_authority])
        .unwrap();

    let toggle_result = context.svm.send_transaction(tx);

    // The operation should fail - AllButManageAuthority should not allow
    // sub-account toggling
    assert!(
        toggle_result.is_err(),
        "AllButManageAuthority should NOT be able to toggle sub-accounts"
    );

    // Verify it's a permission-related error
    let error_msg = format!("{:?}", toggle_result.unwrap_err());
    assert!(
        error_msg.contains("PermissionDenied") || error_msg.contains("Custom"),
        "Expected permission error, got: {}",
        error_msg
    );

    // Verify the sub-account is still enabled (no change occurred)
    let swig_account_data_after = context.svm.get_account(&swig).unwrap();
    let swig_with_roles_after = SwigWithRoles::from_bytes(&swig_account_data_after.data).unwrap();
    let role_after = swig_with_roles_after
        .get_role(sub_account_role_id)
        .unwrap()
        .unwrap();

    // Find the SubAccount action and verify it's still enabled
    let mut cursor = 0;
    let mut found_enabled_action = false;

    for _i in 0..role_after.position.num_actions() {
        let action_header =
            unsafe { Action::load_unchecked(&role_after.actions[cursor..cursor + Action::LEN]) }
                .unwrap();
        cursor += Action::LEN;

        if action_header.permission().unwrap() == Permission::SubAccount {
            let action_data = &role_after.actions[cursor..cursor + action_header.length() as usize];
            let sub_account_action = unsafe { SubAccount::load_unchecked(action_data) }.unwrap();

            if sub_account_action.sub_account == sub_account.to_bytes() {
                assert!(
                    sub_account_action.enabled,
                    "Sub-account should still be enabled"
                );
                found_enabled_action = true;
                break;
            }
        }

        cursor += action_header.length() as usize;
    }

    assert!(found_enabled_action, "SubAccount action not found");

    // Verify the restricted authority still has AllButManageAuthority permission
    let swig_account_after = context.svm.get_account(&swig).unwrap();
    let swig_state_after = SwigWithRoles::from_bytes(&swig_account_after.data).unwrap();
    let restricted_role = swig_state_after
        .get_role(restricted_role_id)
        .unwrap()
        .unwrap();
    assert!(restricted_role
        .get_action::<AllButManageAuthority>(&[])
        .unwrap()
        .is_some());

    println!("SUCCESS: AllButManageAuthority correctly prevents toggling sub-accounts");
}

#[test_log::test]
fn test_all_but_manage_authority_cannot_update_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new(); // Root authority
    let restricted_authority = Keypair::new(); // Authority with AllButManageAuthority
    let target_authority = Keypair::new(); // Authority to be updated

    // Airdrop to all authorities
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&restricted_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&target_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;

    // Create the swig with root authority
    let swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_txn.is_ok());

    // Add an authority with AllButManageAuthority permission
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: restricted_authority.pubkey().as_ref(),
        },
        vec![ClientAction::AllButManageAuthority(
            AllButManageAuthority {},
        )],
    )
    .unwrap();

    // Add a target authority that we'll try to update
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: target_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(SolLimit { amount: 1000 })],
    )
    .unwrap();

    // Verify we have three authorities (root + restricted + target)
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig_state.state.roles, 3);

    // Get the role IDs
    let restricted_role_id = swig_state
        .lookup_role_id(restricted_authority.pubkey().as_ref())
        .unwrap()
        .expect("Restricted authority should exist");
    let target_role_id = swig_state
        .lookup_role_id(target_authority.pubkey().as_ref())
        .unwrap()
        .expect("Target authority should exist");

    // Store initial state of target authority for later verification
    let target_role_initial = swig_state.get_role(target_role_id).unwrap().unwrap();
    let initial_actions_count = target_role_initial.get_all_actions().unwrap().len();

    // Now attempt to update the target authority using the restricted authority
    // This should FAIL because AllButManageAuthority excludes authority management
    let new_actions = vec![
        ClientAction::SolLimit(SolLimit { amount: 2000 }), // Different limit
        ClientAction::AllButManageAuthority(AllButManageAuthority {}), // Add new action
    ];

    let update_ix = UpdateAuthorityInstruction::new_with_ed25519_authority(
        swig,
        context.default_payer.pubkey(),
        restricted_authority.pubkey(),
        restricted_role_id, // Acting role ID (restricted authority)
        target_role_id,     // Authority to update (target authority)
        UpdateAuthorityData::ReplaceAll(new_actions),
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
        &[&context.default_payer, &restricted_authority],
    )
    .unwrap();

    let update_result = context.svm.send_transaction(tx);

    // The operation should fail with PermissionDeniedToManageAuthority error
    assert!(
        update_result.is_err(),
        "AllButManageAuthority should NOT be able to update authorities"
    );

    // Verify it's the specific permission error we expect (error code 3010 = 0xbc2)
    let error_msg = format!("{:?}", update_result.unwrap_err());
    assert!(
        error_msg.contains("3010") || error_msg.contains("PermissionDeniedToManageAuthority"),
        "Expected PermissionDeniedToManageAuthority error, got: {}",
        error_msg
    );

    // Verify that the swig still has 3 authorities (no changes)
    let swig_account_after = context.svm.get_account(&swig).unwrap();
    let swig_state_after = SwigWithRoles::from_bytes(&swig_account_after.data).unwrap();
    assert_eq!(swig_state_after.state.roles, 3);

    // Verify the target authority was not modified
    let target_role_after = swig_state_after.get_role(target_role_id).unwrap().unwrap();
    let final_actions_count = target_role_after.get_all_actions().unwrap().len();

    // The action count should remain the same (no update occurred)
    assert_eq!(
        initial_actions_count, final_actions_count,
        "Target authority actions should not have changed"
    );

    // Verify the target authority still has the original SolLimit action
    assert!(target_role_after
        .get_action::<SolLimit>(&[])
        .unwrap()
        .is_some());

    // Verify it does NOT have the new AllButManageAuthority action (update failed)
    assert!(target_role_after
        .get_action::<AllButManageAuthority>(&[])
        .unwrap()
        .is_none());

    // Verify the restricted authority still has AllButManageAuthority permission
    let restricted_role = swig_state_after
        .get_role(restricted_role_id)
        .unwrap()
        .unwrap();
    assert!(restricted_role
        .get_action::<AllButManageAuthority>(&[])
        .unwrap()
        .is_some());

    println!("SUCCESS: AllButManageAuthority correctly prevents updating authorities");
}
