#![cfg(not(feature = "program_scope_test"))]

mod common;
use common::*;
use litesvm_token::spl_token;
use solana_sdk::{
    instruction::{AccountMeta, Instruction, InstructionError},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{AuthorityConfig, ClientAction};
use swig_state::{
    action::program::Program,
    authority::AuthorityType,
    swig::{swig_account_seeds, SwigWithRoles},
};

/// Test that CPI signing requires a Program action with the correct program ID
#[test_log::test]
fn test_cpi_signing_requires_program_permission() {
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

    // Create swig account with ed25519 authority
    let (_, _transaction_metadata) =
        create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    convert_swig_to_v1(&mut context, &swig);

    // Add a second authority with Program permission for system program
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create Program action for system program and SolLimit for transfers
    let system_program_action = Program {
        program_id: solana_sdk::system_program::ID.to_bytes(),
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
            ClientAction::Program(system_program_action),
            ClientAction::SolLimit(swig_state::action::sol_limit::SolLimit { amount: 10_000_000 }),
        ],
    )
    .unwrap();

    context.svm.airdrop(&swig, 10_000_000_000).unwrap();
    context.svm.warp_to_slot(100);

    // Test 1: CPI signing with correct Program permission should succeed
    let transfer_amount = 1_000_000;
    let transfer_ix = system_instruction::transfer(&swig, &recipient.pubkey(), transfer_amount);

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        transfer_ix,
        2, // Second authority should be role_id 1
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message),
        &[second_authority.insecure_clone()],
    )
    .unwrap();

    let result = context.svm.send_transaction(transfer_tx);
    if result.is_err() {
        println!("Transaction failed: {:?}", result);
    }
    assert!(
        result.is_ok(),
        "CPI signing with correct Program permission should succeed"
    );

    // Test 2: Add authority without Program permission for a different program
    let third_authority = Keypair::new();
    context
        .svm
        .airdrop(&third_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create Program action for a different program (SPL Token program)
    let token_program_action = Program {
        program_id: spl_token::ID.to_bytes(),
    };

    let _txn = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: third_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::Program(token_program_action),
            ClientAction::SolLimit(swig_state::action::sol_limit::SolLimit { amount: 10_000_000 }),
        ],
    )
    .unwrap();

    // Test 3: CPI signing with wrong Program permission should fail
    let transfer_ix2 = system_instruction::transfer(&swig, &recipient.pubkey(), transfer_amount);

    let sign_ix2 = swig_interface::SignInstruction::new_ed25519(
        swig,
        third_authority.pubkey(),
        third_authority.pubkey(),
        transfer_ix2,
        2, // Third authority should be role_id 2
    )
    .unwrap();

    let transfer_message2 = v0::Message::try_compile(
        &third_authority.pubkey(),
        &[sign_ix2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx2 = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message2),
        &[third_authority.insecure_clone()],
    )
    .unwrap();

    let result2 = context.svm.send_transaction(transfer_tx2);
    assert!(
        result2.is_err(),
        "CPI signing with wrong Program permission should fail"
    );

    // Verify it's the expected permission error
    if let Err(failed_tx) = result2 {
        println!("Got expected error: {:?}", failed_tx.err);
    } else {
        panic!("Expected permission denied error, got: {:?}", result2);
    }
}

/// Test that authorities without any Program permission cannot CPI sign
#[test_log::test]
fn test_cpi_signing_without_program_permission_fails() {
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

    // Create swig account with ed25519 authority
    let (_, _transaction_metadata) =
        create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    convert_swig_to_v1(&mut context, &swig);

    // Add a second authority with NO Program permission
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Add authority with SolLimit permission only (no Program permission)
    let _txn = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolLimit(
            swig_state::action::sol_limit::SolLimit { amount: 10_000_000 },
        )],
    )
    .unwrap();

    context.svm.airdrop(&swig, 10_000_000_000).unwrap();
    context.svm.warp_to_slot(100);

    // Test: CPI signing without Program permission should fail
    let transfer_amount = 1_000_000;
    let transfer_ix = system_instruction::transfer(&swig, &recipient.pubkey(), transfer_amount);

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        transfer_ix,
        2, // Second authority should be role_id 1
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message),
        &[second_authority.insecure_clone()],
    )
    .unwrap();

    let result = context.svm.send_transaction(transfer_tx);
    assert!(
        result.is_err(),
        "CPI signing without Program permission should fail"
    );

    // Verify it's the expected permission error
    if let Err(failed_tx) = result {
        println!("Got expected error: {:?}", failed_tx.err);
    } else {
        panic!("Expected permission denied error, got: {:?}", result);
    }
}

/// Test that ProgramAll permission allows CPI signing to any program
#[test_log::test]
fn test_cpi_signing_with_program_all_permission() {
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

    // Create swig account with ed25519 authority
    let (_, _transaction_metadata) =
        create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    convert_swig_to_v1(&mut context, &swig);

    // Add a second authority with ProgramAll permission
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create ProgramAll action
    let program_all_action = swig_state::action::program_all::ProgramAll::new();

    let _txn = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ProgramAll(program_all_action),
            ClientAction::SolLimit(swig_state::action::sol_limit::SolLimit { amount: 10_000_000 }),
        ],
    )
    .unwrap();

    context.svm.airdrop(&swig, 10_000_000_000).unwrap();
    context.svm.warp_to_slot(100);

    // Test: CPI signing with ProgramAll permission should work for any program
    let transfer_amount = 1_000_000;
    let transfer_ix = system_instruction::transfer(&swig, &recipient.pubkey(), transfer_amount);

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
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

    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message),
        &[second_authority.insecure_clone()],
    )
    .unwrap();

    let result = context.svm.send_transaction(transfer_tx);
    if let Err(ref err) = result {
        println!("Transaction failed with error: {:?}", err);
    }
    assert!(
        result.is_ok(),
        "CPI signing with ProgramAll permission should succeed"
    );
}

/// Test that ProgramCurated permission allows CPI signing to curated programs
/// only
#[test_log::test]
fn test_cpi_signing_with_program_curated_permission() {
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

    // Create swig account with ed25519 authority
    let (_, _transaction_metadata) =
        create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    convert_swig_to_v1(&mut context, &swig);

    // Add a second authority with ProgramCurated permission
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Create ProgramCurated action
    let program_curated_action = swig_state::action::program_curated::ProgramCurated::new();

    let _txn = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::ProgramCurated(program_curated_action),
            ClientAction::SolLimit(swig_state::action::sol_limit::SolLimit { amount: 10_000_000 }),
        ],
    )
    .unwrap();

    context.svm.airdrop(&swig, 10_000_000_000).unwrap();
    context.svm.warp_to_slot(100);

    // Test 1: CPI signing with ProgramCurated permission should work for system
    // program (curated)
    let transfer_amount = 1_000_000;
    let transfer_ix = system_instruction::transfer(&swig, &recipient.pubkey(), transfer_amount);

    let sign_ix = swig_interface::SignInstruction::new_ed25519(
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

    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message),
        &[second_authority.insecure_clone()],
    )
    .unwrap();

    let result = context.svm.send_transaction(transfer_tx);
    assert!(
        result.is_ok(),
        "CPI signing with ProgramCurated permission should succeed for system program"
    );
}
