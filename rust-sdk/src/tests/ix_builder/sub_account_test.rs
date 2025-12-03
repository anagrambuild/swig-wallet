use alloy_primitives::B256;
use alloy_signer::SignerSync;
use alloy_signer_local::LocalSigner;
use litesvm_token::spl_token;
use solana_sdk::{
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::VersionedTransaction,
};
use solana_system_interface::instruction as system_instruction;
use swig_interface::program_id;
use swig_state::{
    authority::AuthorityType,
    swig::{sub_account_seeds, swig_account_seeds, SwigWithRoles},
};

use super::*;
use crate::{client_role::Ed25519ClientRole, tests::common::*};

#[test_log::test]
fn test_sub_account_functionality() {
    let mut context = setup_test_context().unwrap();
    let swig_id = [3u8; 32];
    let root_authority = Keypair::new();
    let sub_account_authority = Keypair::new();
    let role_id = 0;

    println!("Root authority: {:?}", root_authority.pubkey());
    println!(
        "Sub-account authority: {:?}",
        sub_account_authority.pubkey()
    );

    // Fund the root authority with some SOL
    context
        .svm
        .airdrop(&root_authority.pubkey(), 1_000_000)
        .unwrap();

    // First create the Swig account with root authority
    let (swig_key, swig_wallet_address, _) =
        create_swig_ed25519(&mut context, &root_authority, swig_id).unwrap();

    // Create instruction builder with root authority
    let mut builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(root_authority.pubkey())),
        context.default_payer.pubkey(),
        role_id,
    );

    // Add a new authority to the Swig account with SubAccount permission
    let ix = builder
        .add_authority_instruction(
            AuthorityType::Ed25519,
            &sub_account_authority.pubkey().to_bytes(),
            vec![Permission::SubAccount {
                sub_account: [0; 32],
            }],
            None,
        )
        .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &root_authority],
    )
    .unwrap();

    context.svm.send_transaction(tx).unwrap();

    // Create a sub-account using the sub-account authority
    let sub_account_role_id = 1; // The sub-account authority has role_id 1
    let mut sub_account_builder = SwigInstructionBuilder::new(
        swig_id,
        Box::new(Ed25519ClientRole::new(sub_account_authority.pubkey())),
        context.default_payer.pubkey(),
        sub_account_role_id,
    );

    let create_sub_account_ix = sub_account_builder.create_sub_account(None).unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &create_sub_account_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &sub_account_authority],
    )
    .unwrap();

    context.svm.send_transaction(tx).unwrap();

    // Get the sub-account address
    let role_id_bytes = sub_account_role_id.to_le_bytes();
    let (sub_account, _) =
        Pubkey::find_program_address(&sub_account_seeds(&swig_id, &role_id_bytes), &program_id());

    // Fund the sub-account with some SOL for testing
    context.svm.airdrop(&sub_account, 5_000_000_000).unwrap();

    // Create a test recipient for transfer
    let recipient = Keypair::new();
    context.svm.airdrop(&recipient.pubkey(), 1_000_000).unwrap();

    // Get initial balances
    let initial_sub_account_balance = context.svm.get_account(&sub_account).unwrap().lamports;
    let initial_recipient_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    println!(
        "Initial sub-account balance: {}",
        initial_sub_account_balance
    );
    println!("Initial recipient balance: {}", initial_recipient_balance);

    // Create a transfer instruction to be executed by the sub-account
    let transfer_amount = 1_000_000;
    let transfer_ix = system_instruction::transfer(
        &sub_account,
        &recipient.pubkey(),
        1_000_000, // 0.001 SOL
    );

    // Sign and execute the transfer using the sub-account authority
    let sub_account_sign_ix = sub_account_builder
        .sign_instruction_with_sub_account(vec![transfer_ix], None)
        .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &sub_account_sign_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &sub_account_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to execute sub-account transfer: {:?}",
        result.err()
    );

    // Verify the transfer was successful
    let final_sub_account_balance = context.svm.get_account(&sub_account).unwrap().lamports;
    let final_recipient_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    println!("Final sub-account balance: {}", final_sub_account_balance);
    println!("Final recipient balance: {}", final_recipient_balance);

    assert_eq!(
        final_recipient_balance,
        initial_recipient_balance + transfer_amount,
        "Recipient balance did not increase by the correct amount"
    );
    assert_eq!(
        final_sub_account_balance,
        initial_sub_account_balance - transfer_amount,
        "Sub-account balance did not decrease by the correct amount"
    );

    println!("Testing withdraw");

    // Get balances before withdraw
    let pre_withdraw_sub_account_balance = context.svm.get_account(&sub_account).unwrap().lamports;
    let pre_withdraw_swig_balance = context
        .svm
        .get_account(&swig_wallet_address)
        .unwrap()
        .lamports;
    println!(
        "Pre-withdraw sub-account balance: {}",
        pre_withdraw_sub_account_balance
    );
    println!(
        "Pre-withdraw swig account balance: {}",
        pre_withdraw_swig_balance
    );

    let withdraw_amount = 1_000_000;
    let withdraw_ix = builder
        .withdraw_from_sub_account(sub_account, withdraw_amount, None)
        .unwrap();
    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &withdraw_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &root_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to withdraw from sub-account: {:?}",
        result.err()
    );

    // Verify the withdraw was successful
    let post_withdraw_sub_account_balance = context.svm.get_account(&sub_account).unwrap().lamports;
    let post_withdraw_swig_balance = context
        .svm
        .get_account(&swig_wallet_address)
        .unwrap()
        .lamports;
    println!(
        "Post-withdraw sub-account balance: {}",
        post_withdraw_sub_account_balance
    );
    println!(
        "Post-withdraw swig account balance: {}",
        post_withdraw_swig_balance
    );

    assert_eq!(
        post_withdraw_sub_account_balance,
        pre_withdraw_sub_account_balance - withdraw_amount,
        "Sub-account balance did not decrease by the correct withdraw amount"
    );
    assert_eq!(
        post_withdraw_swig_balance,
        pre_withdraw_swig_balance + withdraw_amount,
        "Swig account balance did not increase by the correct withdraw amount"
    );

    println!("root authroity:: {:?}", root_authority.pubkey().to_bytes());
    println!(
        "default payer:: {:?}",
        context.default_payer.pubkey().to_bytes()
    );
    display_swig(swig_key, &context.svm.get_account(&swig_key).unwrap()).unwrap();

    // Test toggling the sub-account (disable/enable)
    // Must be performed by the sub-account authority (role_id = 1),
    // because authenticate uses the authority associated with the provided role_id.
    let toggle_ix = sub_account_builder
        .toggle_sub_account(
            sub_account,
            sub_account_role_id,
            sub_account_role_id,
            false,
            None,
        )
        .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &toggle_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &sub_account_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to toggle sub-account: {:?}",
        result.err()
    );

    // Verify the sub-account is disabled by attempting another transfer (should
    // fail)
    let transfer_ix =
        system_instruction::transfer(&sub_account, &recipient.pubkey(), transfer_amount);
    let sub_account_sign_ix = sub_account_builder
        .sign_instruction_with_sub_account(vec![transfer_ix], None)
        .unwrap();

    let msg = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &sub_account_sign_ix,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(msg),
        &[&context.default_payer, &sub_account_authority],
    )
    .unwrap();

    // This should fail because the sub-account is disabled
    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "Transaction should fail with disabled sub-account"
    );

    display_swig(swig_key, &context.svm.get_account(&swig_key).unwrap()).unwrap();
}
