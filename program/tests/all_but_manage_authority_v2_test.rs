//! Tests for AllButManageAuthority permission type
//!
//! This permission should allow all operations in sign_v2 (SOL transfers, token
//! transfers, CPI calls) but prohibit authority management operations
//! (add/remove/update authorities) and sub-account operations.
//!
//! SignV2 VERSION: This is the SignV2 version of
//! all_but_manage_authority_test.rs The tests use SignV2Instruction and
//! swig_wallet_address PDA for transactions.

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
    sysvar::clock::Clock,
    transaction::{TransactionError, VersionedTransaction},
};
use solana_system_interface::instruction as system_instruction;
use swig_interface::{
    AuthorityConfig, ClientAction, CreateSubAccountInstruction, RemoveAuthorityInstruction,
    SignV2Instruction, SubAccountSignInstruction, ToggleSubAccountInstruction, UpdateAuthorityData,
    UpdateAuthorityInstruction, WithdrawFromSubAccountInstruction,
};
use swig_state::{
    action::{
        all::All, all_but_manage_authority::AllButManageAuthority,
        manage_authority::ManageAuthority, program::Program, sol_limit::SolLimit,
        sol_recurring_limit::SolRecurringLimit, sub_account::SubAccount, token_limit::TokenLimit,
        token_recurring_limit::TokenRecurringLimit,
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

    // For SignV2, derive swig_wallet_address and fund it for transfers
    let (swig_wallet_address, wallet_address_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());
    let initial_swig_wallet_balance = 10_000_000_000;
    context
        .svm
        .airdrop(&swig_wallet_address, initial_swig_wallet_balance)
        .unwrap();

    let amount = 5_000_000_000; // 5 SOL
    let ixd = system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), amount);

    // Create SignV2 instruction using the interface
    let sign_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
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

    // Capture initial balances right before the transaction
    let initial_recipient_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    let initial_swig_wallet_address_balance = context
        .svm
        .get_account(&swig_wallet_address)
        .unwrap()
        .lamports;

    let res = context.svm.send_transaction(transfer_tx);
    let res_clone = res.clone();
    println!("{:?}", res_clone.unwrap().pretty_logs());
    assert!(
        res.is_ok(),
        "AllButManageAuthority should be able to transfer SOL"
    );

    let final_recipient_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    let final_swig_wallet_address_balance = context
        .svm
        .get_account(&swig_wallet_address)
        .unwrap()
        .lamports;

    assert_eq!(
        final_recipient_balance,
        initial_recipient_balance + amount,
        "Recipient should have received the transfer amount"
    );

    assert_eq!(
        final_swig_wallet_address_balance,
        initial_swig_wallet_address_balance - amount,
        "Swig wallet address should have the transfer amount deducted"
    );

    let swig_account_after = context.svm.get_account(&swig).unwrap();
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

    // For SignV2, derive swig_wallet_address for token operations
    let (swig_wallet_address, wallet_address_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    // Setup token infrastructure - use swig_wallet_address as token authority
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address, // Use swig_wallet_address as token account owner
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

    context
        .svm
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();
    let token_amount = 500;

    context.svm.warp_to_slot(100);
    let token_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig_wallet_address, false), // Use swig_wallet_address as authority
        ],
        data: TokenInstruction::Transfer {
            amount: token_amount,
        }
        .pack(),
    };

    // Create SignV2 instruction for token transfer using the interface
    let sign_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
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

    // For SignV2, derive swig_wallet_address for operations
    let (swig_wallet_address, wallet_address_bump) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    // Setup token infrastructure - use swig_wallet_address as token authority
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address, // Use swig_wallet_address as token account owner
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

    context
        .svm
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();
    let sol_amount = 50;
    let token_amount = 500;

    context.svm.warp_to_slot(100);

    // Create multiple instructions to test CPI capabilities - both use
    // swig_wallet_address
    let sol_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), sol_amount);
    let token_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig_wallet_address, false), // Use swig_wallet_address as authority
        ],
        data: TokenInstruction::Transfer {
            amount: token_amount,
        }
        .pack(),
    };

    // Create SignV2 instruction for token transfer using the interface
    let sign_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        token_ix,
        1, // AllButManageAuthority role
    )
    .unwrap();

    // Create SignV2 instruction for SOL transfer using the interface
    let sign_ix2 = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
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

    // Capture initial balances right before the transaction
    let initial_recipient_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;

    let res = context.svm.send_transaction(transfer_tx);
    assert!(
        res.is_ok(),
        "AllButManageAuthority should be able to perform multiple CPI calls"
    );

    // Verify both SOL and token transfers succeeded
    let final_recipient_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    assert_eq!(
        final_recipient_balance,
        initial_recipient_balance + sol_amount,
        "Recipient should have received the SOL transfer amount"
    );

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
