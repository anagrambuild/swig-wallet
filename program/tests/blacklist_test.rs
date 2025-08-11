#![cfg(not(feature = "program_scope_test"))]

mod common;

use common::*;
use litesvm_token::spl_token;
use solana_sdk::{
    instruction::Instruction,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction,
    transaction::VersionedTransaction,
};
use swig_interface::{AddAuthorityInstruction, AuthorityConfig, ClientAction, SignInstruction};
use swig_state::{
    action::{
        blacklist::Blacklist, program::Program, program_all::ProgramAll, sol_limit::SolLimit,
        Actionable,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, SwigWithRoles},
    IntoBytes, Transmutable,
};

#[test_log::test]
fn test_blacklist_program_prevents_cpi() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    let amount = 1_000_000_000;
    context
        .svm
        .airdrop(&swig_authority.pubkey(), amount)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let secondary_authority = Keypair::new();
    context
        .svm
        .airdrop(&secondary_authority.pubkey(), amount)
        .unwrap();

    // Create a blacklist action for a specific program
    let system_program = solana_sdk::system_program::ID;
    let blacklist_action = Blacklist::new_program(system_program.to_bytes());

    let bench = add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::Blacklist(blacklist_action),
            ClientAction::SolLimit(SolLimit { amount: amount / 2 }),
        ],
    )
    .unwrap();

    // Verify the blacklist action was added
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    assert_eq!(swig.state.roles, 2);

    let role_id = swig
        .lookup_role_id(secondary_authority.pubkey().as_ref())
        .unwrap()
        .unwrap();

    let role = swig.get_role(role_id).unwrap().unwrap();
    assert_eq!(role.position.num_actions(), 3);

    // Test that the blacklisted program cannot be used in CPI
    let recipient = Keypair::new();
    context.svm.airdrop(&recipient.pubkey(), amount).unwrap();

    // Create an instruction that would call the blacklisted program
    let transfer_ix = system_instruction::transfer(&swig_key, &recipient.pubkey(), amount / 4);

    // This should fail because the program is blacklisted
    let sign_ix = SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix,
        role_id,
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message),
        &[&secondary_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(transfer_tx);

    println!("result: {:?}", result);
    // The transaction should fail due to blacklist
    assert!(result.is_err());

    // Check if the return error is 3029 (PermissionDeniedBlacklisted)
    let error = result.unwrap_err();
    assert_eq!(
        error.err,
        solana_sdk::transaction::TransactionError::InstructionError(
            0,
            solana_sdk::instruction::InstructionError::Custom(3029)
        )
    );
}

#[test_log::test]
fn test_blacklist_wallet_prevents_transaction() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    let amount = 1_000_000_000;
    context
        .svm
        .airdrop(&swig_authority.pubkey(), amount)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let secondary_authority = Keypair::new();
    context
        .svm
        .airdrop(&secondary_authority.pubkey(), amount)
        .unwrap();

    // Create a blacklist action for a specific wallet address
    let blacklisted_wallet = Keypair::new().pubkey();
    let blacklist_action = Blacklist::new_wallet(blacklisted_wallet.to_bytes());

    let bench = add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::Blacklist(blacklist_action),
            ClientAction::SolLimit(SolLimit { amount: amount / 2 }),
        ],
    )
    .unwrap();

    // Verify the blacklist action was added
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();

    let role_id = swig
        .lookup_role_id(secondary_authority.pubkey().as_ref())
        .unwrap()
        .unwrap();

    // Test that the blacklisted wallet cannot receive transactions
    let transfer_ix = system_instruction::transfer(&swig_key, &blacklisted_wallet, amount / 4);

    // This should fail because the destination wallet is blacklisted
    let sign_ix = SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix,
        role_id,
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message),
        &[&secondary_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(transfer_tx);

    // The transaction should fail due to blacklist
    assert!(result.is_err());

    // Check if the return error is 3029 (PermissionDeniedBlacklisted)
    let error = result.unwrap_err();
    assert_eq!(
        error.err,
        solana_sdk::transaction::TransactionError::InstructionError(
            0,
            solana_sdk::instruction::InstructionError::Custom(3029)
        )
    );
}

#[test_log::test]
fn test_blacklist_with_program_permission() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    let amount = 1_000_000_000;
    context
        .svm
        .airdrop(&swig_authority.pubkey(), amount)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let secondary_authority = Keypair::new();
    context
        .svm
        .airdrop(&secondary_authority.pubkey(), amount)
        .unwrap();

    // Create a blacklist action for the system program
    let blacklisted_program = solana_sdk::system_program::ID;
    let blacklist_action = Blacklist::new_program(blacklisted_program.to_bytes());

    // Also add a program permission for the same program
    let program_action = Program {
        program_id: blacklisted_program.to_bytes(),
    };

    let bench = add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::Blacklist(blacklist_action),
            ClientAction::Program(program_action),
            ClientAction::SolLimit(SolLimit { amount: amount / 2 }),
        ],
    )
    .unwrap();

    // Verify the actions were added
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();

    let role_id = swig
        .lookup_role_id(secondary_authority.pubkey().as_ref())
        .unwrap()
        .unwrap();

    let role = swig.get_role(role_id).unwrap().unwrap();
    assert_eq!(role.position.num_actions(), 3);

    // Test that the blacklist takes precedence over program permission
    let recipient = Keypair::new();
    context.svm.airdrop(&recipient.pubkey(), amount).unwrap();

    let transfer_ix = system_instruction::transfer(&swig_key, &recipient.pubkey(), amount / 4);

    // This should still fail because blacklist takes precedence
    let sign_ix = SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix,
        role_id,
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message),
        &[&secondary_authority],
    )
    .unwrap();

    let result = context.svm.send_transaction(transfer_tx);

    // The transaction should fail due to blacklist
    assert!(result.is_err());

    // Check if the return error is 3029 (PermissionDeniedBlacklisted)
    let error = result.unwrap_err();
    assert_eq!(
        error.err,
        solana_sdk::transaction::TransactionError::InstructionError(
            0,
            solana_sdk::instruction::InstructionError::Custom(3029)
        )
    );
}

#[test_log::test]
fn test_multiple_blacklist_entries() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();

    let amount = 1_000_000_000;
    context
        .svm
        .airdrop(&swig_authority.pubkey(), amount)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let secondary_authority = Keypair::new();
    context
        .svm
        .airdrop(&secondary_authority.pubkey(), amount)
        .unwrap();

    // Create multiple blacklist actions
    let blacklisted_program1 = solana_sdk::system_program::ID;
    let blacklisted_program2 = spl_token::id();
    let blacklisted_wallet = Keypair::new().pubkey();

    let blacklist_action1 = Blacklist::new_program(blacklisted_program1.to_bytes());
    let blacklist_action2 = Blacklist::new_program(blacklisted_program2.to_bytes());
    let blacklist_action3 = Blacklist::new_wallet(blacklisted_wallet.to_bytes());

    let bench = add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::Blacklist(blacklist_action1),
            ClientAction::Blacklist(blacklist_action2),
            ClientAction::Blacklist(blacklist_action3),
            ClientAction::SolLimit(SolLimit { amount: amount / 2 }),
        ],
    )
    .unwrap();

    // Verify all blacklist actions were added
    let swig_account = context.svm.get_account(&swig_key).unwrap();
    let swig = SwigWithRoles::from_bytes(&swig_account.data).unwrap();

    let role_id = swig
        .lookup_role_id(secondary_authority.pubkey().as_ref())
        .unwrap()
        .unwrap();

    let role = swig.get_role(role_id).unwrap().unwrap();
    assert_eq!(role.position.num_actions(), 4);

    // Test that all blacklisted entities are blocked
    let recipient = Keypair::new();
    context.svm.airdrop(&recipient.pubkey(), amount).unwrap();

    // Test blacklisted program 1
    let transfer_ix1 = system_instruction::transfer(&swig_key, &recipient.pubkey(), amount / 4);

    let sign_ix1 = SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix1,
        role_id,
    )
    .unwrap();

    let transfer_message1 = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[sign_ix1],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx1 = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message1),
        &[&secondary_authority],
    )
    .unwrap();

    let result1 = context.svm.send_transaction(transfer_tx1);
    assert!(result1.is_err());

    // Check if the return error is 3029 (PermissionDeniedBlacklisted)
    let error1 = result1.unwrap_err();
    assert_eq!(
        error1.err,
        solana_sdk::transaction::TransactionError::InstructionError(
            0,
            solana_sdk::instruction::InstructionError::Custom(3029)
        )
    );

    // Test blacklisted wallet
    let transfer_ix2 = system_instruction::transfer(&swig_key, &blacklisted_wallet, amount / 4);

    let sign_ix2 = SignInstruction::new_ed25519(
        swig_key,
        secondary_authority.pubkey(),
        secondary_authority.pubkey(),
        transfer_ix2,
        role_id,
    )
    .unwrap();

    let transfer_message2 = v0::Message::try_compile(
        &secondary_authority.pubkey(),
        &[sign_ix2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx2 = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message2),
        &[&secondary_authority],
    )
    .unwrap();

    let result2 = context.svm.send_transaction(transfer_tx2);
    assert!(result2.is_err());

    // Check if the return error is 3029 (PermissionDeniedBlacklisted)
    let error2 = result2.unwrap_err();
    assert_eq!(
        error2.err,
        solana_sdk::transaction::TransactionError::InstructionError(
            0,
            solana_sdk::instruction::InstructionError::Custom(3029)
        )
    );
}
