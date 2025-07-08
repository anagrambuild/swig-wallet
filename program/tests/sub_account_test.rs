#![cfg(not(feature = "program_scope_test"))]
// This feature flag ensures these tests are only run when the
// "program_scope_test" feature is not enabled. This allows us to isolate
// and run only program_scope tests or only the regular tests.
mod common;

use common::*;
use litesvm_token::spl_token;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
    system_instruction,
    transaction::VersionedTransaction,
};
use swig_interface::{
    AuthorityConfig, ClientAction, CreateSubAccountInstruction, SignInstruction,
    SubAccountSignInstruction, ToggleSubAccountInstruction, WithdrawFromSubAccountInstruction,
};
use swig_state::{
    action::{
        all::All,
        manage_authority::ManageAuthority,
        sol_limit::SolLimit,
        sub_account::{self, SubAccount},
    },
    authority::AuthorityType,
    swig::{sub_account_seeds, swig_account_seeds, SwigSubAccount, SwigWithRoles},
    IntoBytes, Transmutable, TransmutableMut,
};

// Helper function to set up a test with a root authority and a sub-account
// authority
fn setup_test_with_sub_account_authority(
    context: &mut SwigTestContext,
) -> anyhow::Result<(Pubkey, Keypair, Keypair, [u8; 32])> {
    let root_authority = Keypair::new();
    let sub_account_authority = Keypair::new();

    // Airdrop to both authorities
    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&sub_account_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig account with the root authority
    let (swig_key, _) = create_swig_ed25519(context, &root_authority, id)?;

    // Add the sub-account authority with SubAccount permission
    add_authority_with_ed25519_root(
        context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: sub_account_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccount(SubAccount {
            sub_account: [0; 32],
        })],
    )?;

    Ok((swig_key, root_authority, sub_account_authority, id))
}

fn setup_test_with_sub_account_authority_fail_with_invalid_layout(
    context: &mut SwigTestContext,
) -> anyhow::Result<()> {
    let root_authority = Keypair::new();
    let sub_account_authority = Keypair::new();

    // Airdrop to both authorities
    context
        .svm
        .airdrop(&root_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&sub_account_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();

    // Create a swig account with the root authority
    let (swig_key, _) = create_swig_ed25519(context, &root_authority, id)?;

    // Add the sub-account authority with SubAccount permission
    let res = add_authority_with_ed25519_root(
        context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: sub_account_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SubAccount(SubAccount {
            sub_account: [1; 32],
        })],
    );

    assert!(res.is_err());
    println!("res: {:?}", res);
    Ok(())
}

// Test creating a sub-account with the proper permissions
#[test_log::test]
fn test_create_sub_account() {
    let mut context = setup_test_context().unwrap();

    // Set up the test environment
    let (swig_key, _, sub_account_authority, id) =
        setup_test_with_sub_account_authority(&mut context).unwrap();

    // Create the sub-account with the sub-account authority
    let role_id = 1; // The sub-account authority has role_id 1
    let sub_account =
        create_sub_account(&mut context, &swig_key, &sub_account_authority, role_id, id).unwrap();

    // Verify the sub-account was created
    let sub_account_data = context.svm.get_account(&sub_account).unwrap();
    assert_eq!(sub_account_data.owner, program_id());

    // Verify the sub-account has the expected data structure
    let sub_account_state =
        unsafe { SwigSubAccount::load_unchecked(&sub_account_data.data).unwrap() };

    assert_eq!(sub_account_state.swig_id, id);
    assert_eq!(sub_account_state.role_id, role_id);
    assert!(sub_account_state.enabled);
}

// Test the withdrawal from a sub-account back to the main swig account
#[test_log::test]
fn test_withdraw_sol_from_sub_account() {
    let mut context = setup_test_context().unwrap();

    // Set up the test environment
    let (swig_key, root_authority, sub_account_authority, id) =
        setup_test_with_sub_account_authority(&mut context).unwrap();

    // Create the sub-account with the sub-account authority
    let role_id = 1; // The sub-account authority has role_id 1
    let root_role_id = 0;
    let sub_account =
        create_sub_account(&mut context, &swig_key, &sub_account_authority, role_id, id).unwrap();

    // Fund the sub-account with some SOL
    let initial_balance = 5_000_000_000;
    context.svm.airdrop(&sub_account, initial_balance).unwrap();

    // Get the initial balances
    let swig_initial_balance = context.svm.get_account(&swig_key).unwrap().lamports;
    let sub_account_initial_balance = context.svm.get_account(&sub_account).unwrap().lamports;

    // Withdraw some SOL from the sub-account using the sub-account authority
    let withdraw_amount = 1_000_000_000;
    let withdraw_result = withdraw_from_sub_account(
        &mut context,
        &swig_key,
        &sub_account,
        &root_authority,
        root_role_id,
        withdraw_amount,
    )
    .unwrap();

    // Verify the balances were updated correctly
    let swig_after_balance = context.svm.get_account(&swig_key).unwrap().lamports;
    let sub_account_after_balance = context.svm.get_account(&sub_account).unwrap().lamports;

    assert_eq!(
        swig_after_balance,
        swig_initial_balance + withdraw_amount,
        "Swig account balance didn't increase by the correct amount"
    );
    assert_eq!(
        sub_account_after_balance,
        sub_account_initial_balance - withdraw_amount,
        "Sub-account balance didn't decrease by the correct amount"
    );
}

// Test signing transactions with a sub-account
#[test_log::test]
fn test_sub_account_sign() {
    let mut context = setup_test_context().unwrap();
    let recipient = Keypair::new();

    // Set up the test environment
    let (swig_key, root_authority, sub_account_authority, id) =
        setup_test_with_sub_account_authority(&mut context).unwrap();

    context.svm.airdrop(&recipient.pubkey(), 1_000_000).unwrap();

    // Create the sub-account with the sub-account authority
    let role_id = 1; // The sub-account authority has role_id 1
    let sub_account =
        create_sub_account(&mut context, &swig_key, &sub_account_authority, role_id, id).unwrap();

    // Fund the sub-account with some SOL
    let initial_balance = 5_000_000_000;
    context.svm.airdrop(&sub_account, initial_balance).unwrap();

    // Create a transfer instruction that will be executed by the sub-account
    let transfer_amount = 1_000_000;
    let transfer_ix =
        system_instruction::transfer(&sub_account, &recipient.pubkey(), transfer_amount);

    // Sign and execute with the sub-account using the sub-account authority
    let sign_result = sub_account_sign(
        &mut context,
        &swig_key,
        &sub_account,
        &sub_account_authority,
        role_id,
        vec![transfer_ix],
    )
    .unwrap();

    // Verify the funds were transferred
    let recipient_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    assert_eq!(
        recipient_balance,
        1_000_000 + transfer_amount,
        "Recipient's balance didn't increase by the correct amount"
    );
}

// Test toggling a sub-account on and off
#[test_log::test]
fn test_toggle_sub_account() {
    let mut context = setup_test_context().unwrap();
    let recipient = Keypair::new();
    context.svm.warp_to_slot(1);
    // Set up the test environment
    let (swig_key, root_authority, sub_account_authority, id) =
        setup_test_with_sub_account_authority(&mut context).unwrap();

    context.svm.airdrop(&recipient.pubkey(), 1_000_000).unwrap();

    // Create the sub-account with the sub-account authority
    let role_id = 1; // The sub-account authority has role_id 1
    let root_role_id = 0;
    let sub_account =
        create_sub_account(&mut context, &swig_key, &sub_account_authority, role_id, id).unwrap();

    // Fund the sub-account with some SOL
    let initial_balance = 5_000_000_000;
    context.svm.airdrop(&sub_account, initial_balance).unwrap();

    // Disable the sub-account using the root authority
    let disable_result = toggle_sub_account(
        &mut context,
        &swig_key,
        &sub_account,
        &root_authority,
        root_role_id,
        false, // disabled
    )
    .unwrap();

    // Verify the sub-account is disabled
    let sub_account_data = context.svm.get_account(&sub_account).unwrap();
    let sub_account_state =
        unsafe { SwigSubAccount::load_unchecked(&sub_account_data.data).unwrap() };
    assert!(!sub_account_state.enabled, "Sub-account should be disabled");

    // Try to use the disabled sub-account - this should fail
    let transfer_amount = 1_000_000;
    let transfer_ix =
        system_instruction::transfer(&sub_account, &recipient.pubkey(), transfer_amount);

    let sign_result = sub_account_sign(
        &mut context,
        &swig_key,
        &sub_account,
        &sub_account_authority,
        role_id,
        vec![transfer_ix],
    );

    assert!(
        sign_result.is_err(),
        "Transaction should fail with disabled sub-account"
    );
    // warp ahead 10 slots
    context.svm.warp_to_slot(10);
    // Re-enable the sub-account using the sub-account authority
    let enable_result = toggle_sub_account(
        &mut context,
        &swig_key,
        &sub_account,
        &root_authority,
        root_role_id,
        true, // enabled
    )
    .unwrap();

    // Verify the sub-account is enabled
    let sub_account_data = context.svm.get_account(&sub_account).unwrap();
    let sub_account_state =
        unsafe { SwigSubAccount::load_unchecked(&sub_account_data.data).unwrap() };
    assert!(sub_account_state.enabled, "Sub-account should be enabled");
    context.svm.warp_to_slot(1000);
    context.svm.expire_blockhash();
    // Now the transaction should succeed with the enabled sub-account
    let transfer_amount = 1_000_000;
    let transfer_ix =
        system_instruction::transfer(&sub_account, &recipient.pubkey(), transfer_amount);

    let sign_result = sub_account_sign(
        &mut context,
        &swig_key,
        &sub_account,
        &sub_account_authority,
        role_id,
        vec![transfer_ix],
    )
    .unwrap();

    // Verify the funds were transferred
    let recipient_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    assert_eq!(
        recipient_balance,
        1_000_000 + transfer_amount,
        "Recipient's balance didn't increase by the correct amount"
    );
}

// Test that a non-root authority without proper permissions cannot disable a
// sub-account
#[test_log::test]
fn test_non_root_authority_cannot_disable_sub_account() {
    let mut context = setup_test_context().unwrap();

    // Set up the test environment
    let (swig_key, root_authority, sub_account_authority, id) =
        setup_test_with_sub_account_authority(&mut context).unwrap();

    // Create a new authority with some permissions but NOT the ManageAuthority
    // permission
    let unauthorized_authority = Keypair::new();
    context
        .svm
        .airdrop(&unauthorized_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add the unauthorized authority with insufficient permissions (not including
    // ManageAuthority or All)
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: unauthorized_authority.pubkey().as_ref(),
        },
        // Give it some permission but not SubAccount or ManageAuthority
        vec![ClientAction::SolLimit(SolLimit { amount: 1000 })],
    )
    .unwrap();

    // Create the sub-account with the sub-account authority
    let role_id = 1;
    let sub_account =
        create_sub_account(&mut context, &swig_key, &sub_account_authority, role_id, id).unwrap();

    // Fund the sub-account with some SOL
    let initial_balance = 5_000_000_000;
    context.svm.airdrop(&sub_account, initial_balance).unwrap();

    // Attempt to disable the sub-account using the unauthorized authority - this
    // should fail
    let disable_result = toggle_sub_account(
        &mut context,
        &swig_key,
        &sub_account,
        &unauthorized_authority,
        2,     // The authority exists but lacks permissions
        false, // disabled
    );

    assert!(
        disable_result.is_err(),
        "Authority without proper permissions should not be able to disable the sub-account"
    );

    // Verify the sub-account is still enabled
    let sub_account_data = context.svm.get_account(&sub_account).unwrap();
    let sub_account_state =
        unsafe { SwigSubAccount::load_unchecked(&sub_account_data.data).unwrap() };
    assert!(
        sub_account_state.enabled,
        "Sub-account should still be enabled"
    );
}

// Test that a non-root authority without proper permissions cannot withdraw
// from a sub-account
#[test_log::test]
fn test_non_root_authority_cannot_withdraw_from_sub_account() {
    let mut context = setup_test_context().unwrap();

    // Set up the test environment
    let (swig_key, root_authority, sub_account_authority, id) =
        setup_test_with_sub_account_authority(&mut context).unwrap();

    // Create a new authority with some permissions but NOT the withdrawal
    // permission
    let unauthorized_authority = Keypair::new();
    context
        .svm
        .airdrop(&unauthorized_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add the unauthorized authority with insufficient permissions
    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &root_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: unauthorized_authority.pubkey().as_ref(),
        },
        // Give it some permission but not SubAccount or All
        vec![ClientAction::SolLimit(SolLimit { amount: 1000 })],
    )
    .unwrap();

    // Create the sub-account with the sub-account authority
    let role_id = 1;
    let sub_account =
        create_sub_account(&mut context, &swig_key, &sub_account_authority, role_id, id).unwrap();

    // Fund the sub-account with some SOL
    let initial_balance = 5_000_000_000;
    context.svm.airdrop(&sub_account, initial_balance).unwrap();

    // Attempt to withdraw from the sub-account using the unauthorized authority -
    // this should fail
    let withdraw_amount = 1_000_000_000;
    let withdraw_result = withdraw_from_sub_account(
        &mut context,
        &swig_key,
        &sub_account,
        &unauthorized_authority,
        2, // The authority exists but lacks permissions
        withdraw_amount,
    );

    assert!(
        withdraw_result.is_err(),
        "Authority without proper permissions should not be able to withdraw from the sub-account"
    );

    // Verify the balances were not changed
    let sub_account_data = context.svm.get_account(&sub_account).unwrap();
    let sub_account_state =
        unsafe { SwigSubAccount::load_unchecked(&sub_account_data.data).unwrap() };
    assert_eq!(sub_account_state.enabled, true);
    let sub_account_balance = sub_account_data.lamports - sub_account_state.reserved_lamports;
    assert_eq!(
        sub_account_balance, initial_balance,
        "Sub-account balance should not have changed"
    );
}

#[test_log::test]
fn test_withdraw_token_from_sub_account() {
    let mut context = setup_test_context().unwrap();
    let (swig_key, root_authority, sub_account_authority, authority_id) =
        setup_test_with_sub_account_authority(&mut context).unwrap();
    let role_id = 1;
    let sub_account = create_sub_account(
        &mut context,
        &swig_key,
        &sub_account_authority,
        role_id,
        authority_id,
    )
    .unwrap();
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_key,
        &context.default_payer,
    )
    .unwrap();

    let sub_account_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &sub_account,
        &context.default_payer,
    )
    .unwrap();
    let initial_token_amount = 1000;
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &sub_account_ata,
        initial_token_amount,
    )
    .unwrap();
    let withdraw_result = withdraw_token_from_sub_account(
        &mut context,
        &swig_key,
        &sub_account,
        &root_authority,
        &sub_account_ata,
        &swig_ata,
        &spl_token::id(),
        0,
        initial_token_amount,
    )
    .unwrap();

    let sub_account_ata_after_balance = context.svm.get_account(&sub_account_ata).unwrap();
    let swig_ata_after_balance = context.svm.get_account(&swig_ata).unwrap();
    let sub_account_token_account =
        spl_token::state::Account::unpack(&sub_account_ata_after_balance.data).unwrap();
    let swig_token_account =
        spl_token::state::Account::unpack(&swig_ata_after_balance.data).unwrap();
    assert_eq!(sub_account_token_account.amount, 0);
    assert_eq!(swig_token_account.amount, initial_token_amount);
}
