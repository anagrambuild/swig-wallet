#![cfg(not(feature = "program_scope_test"))]

//! Tests for SOL recurring destination limit functionality with SignV2.
//!
//! This module contains comprehensive tests for the
//! SolRecurringDestinationLimit action using SignV2 instruction type, including
//! basic functionality, time window resets, edge cases, and integration with
//! other limit types.

mod common;
use common::*;
use rand;
use solana_sdk::{
    instruction::InstructionError,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{AuthorityConfig, ClientAction, SignV2Instruction};
use swig_state::{
    action::{
        program_all::ProgramAll, sol_recurring_destination_limit::SolRecurringDestinationLimit,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
};
use test_log;

/// Test basic SOL recurring destination limit functionality with SignV2
#[test_log::test]
fn test_sol_recurring_destination_limit_basic_v2() {
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

    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let recurring_amount = 500_000_000u64; // 0.5 SOL per window
    let window = 100u64; // 100 slots
    let recurring_destination_limit = SolRecurringDestinationLimit {
        destination: recipient.pubkey().to_bytes(),
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
            ClientAction::SolRecurringDestinationLimit(recurring_destination_limit),
        ],
    )
    .unwrap();

    // Fund the SWIG wallet address (not the swig account itself)
    context
        .svm
        .airdrop(&swig_wallet_address, 2_000_000_000)
        .unwrap();
    context.svm.warp_to_slot(100);

    // Test transfer within limit
    let transfer_amount = 300_000_000u64; // 0.3 SOL - within limit

    let inner_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);
    let sol_transfer_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        second_authority.pubkey(),
        inner_ix,
        1, // role_id
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sol_transfer_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    let res = context.svm.send_transaction(transfer_tx).unwrap();
    println!("Transfer logs: {}", res.pretty_logs());

    // Verify limit was decremented
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();
    let dest_limit = role
        .get_action::<SolRecurringDestinationLimit>(&recipient.pubkey().to_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(
        dest_limit.current_amount,
        recurring_amount - transfer_amount
    );
}

/// Test SOL recurring destination limit exceeding the current limit with SignV2
#[test_log::test]
fn test_sol_recurring_destination_limit_exceeds_limit_v2() {
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

    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let recurring_amount = 300_000_000u64; // 0.3 SOL per window
    let window = 100u64; // 100 slots
    let recurring_destination_limit = SolRecurringDestinationLimit {
        destination: recipient.pubkey().to_bytes(),
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
            ClientAction::SolRecurringDestinationLimit(recurring_destination_limit),
        ],
    )
    .unwrap();

    // Fund the SWIG wallet address (not the swig account itself)
    context
        .svm
        .airdrop(&swig_wallet_address, 2_000_000_000)
        .unwrap();
    context.svm.warp_to_slot(100);

    // Try to transfer more than the limit
    let transfer_amount = 500_000_000u64; // 0.5 SOL - exceeds limit

    let inner_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);
    let sol_transfer_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        second_authority.pubkey(),
        inner_ix,
        1, // role_id
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sol_transfer_ix],
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
        println!("Expected error: {:?}", e);
        // Should get the specific destination limit exceeded error (3030)
        assert!(matches!(
            e.err,
            TransactionError::InstructionError(_, InstructionError::Custom(3030))
        ));
    }
}

/// Test SOL recurring destination limit time window reset with SignV2
#[test_log::test]
fn test_sol_recurring_destination_limit_time_reset_v2() {
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

    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let recurring_amount = 400_000_000u64; // 0.4 SOL per window
    let window = 50u64; // 50 slots
    let recurring_destination_limit = SolRecurringDestinationLimit {
        destination: recipient.pubkey().to_bytes(),
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
            ClientAction::SolRecurringDestinationLimit(recurring_destination_limit),
        ],
    )
    .unwrap();

    // Fund the SWIG wallet address (not the swig account itself)
    context
        .svm
        .airdrop(&swig_wallet_address, 2_000_000_000)
        .unwrap();
    context.svm.warp_to_slot(100);

    // First transfer - use most of the limit
    let transfer_amount1 = 350_000_000u64; // 0.35 SOL

    let inner_ix1 =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount1);
    let sol_transfer_ix1 = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        second_authority.pubkey(),
        inner_ix1,
        1, // role_id
    )
    .unwrap();

    let transfer_message1 = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sol_transfer_ix1],
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
    println!("First transfer logs: {}", res1.pretty_logs());

    // Verify limit was decremented
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();
    let dest_limit = role
        .get_action::<SolRecurringDestinationLimit>(&recipient.pubkey().to_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(
        dest_limit.current_amount,
        recurring_amount - transfer_amount1
    );

    // Wait for time window to expire
    context.svm.warp_to_slot(200); // Move past the window

    // Second transfer - should reset the limit and allow full amount again
    let transfer_amount2 = 300_000_000u64; // 0.3 SOL - should work after reset

    let inner_ix2 =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount2);
    let sol_transfer_ix2 = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        second_authority.pubkey(),
        inner_ix2,
        1, // role_id
    )
    .unwrap();

    let transfer_message2 = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sol_transfer_ix2],
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
    println!("Second transfer after reset logs: {}", res2.pretty_logs());

    // Verify limit was reset and then decremented
    let swig_account_final = context.svm.get_account(&swig).unwrap();
    let swig_state_final = SwigWithRoles::from_bytes(&swig_account_final.data).unwrap();
    let role_final = swig_state_final.get_role(1).unwrap().unwrap();
    let dest_limit_final = role_final
        .get_action::<SolRecurringDestinationLimit>(&recipient.pubkey().to_bytes())
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
fn test_multiple_sol_recurring_destination_limits_v2() {
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

    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let recurring_amount1 = 300_000_000u64; // 0.3 SOL per window for recipient1
    let recurring_amount2 = 500_000_000u64; // 0.5 SOL per window for recipient2
    let window = 100u64; // 100 slots

    let recurring_destination_limit1 = SolRecurringDestinationLimit {
        destination: recipient1.pubkey().to_bytes(),
        recurring_amount: recurring_amount1,
        window,
        last_reset: 0,
        current_amount: recurring_amount1,
    };

    let recurring_destination_limit2 = SolRecurringDestinationLimit {
        destination: recipient2.pubkey().to_bytes(),
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
            ClientAction::SolRecurringDestinationLimit(recurring_destination_limit1),
            ClientAction::SolRecurringDestinationLimit(recurring_destination_limit2),
        ],
    )
    .unwrap();

    // Fund the SWIG wallet address (not the swig account itself)
    context
        .svm
        .airdrop(&swig_wallet_address, 2_000_000_000)
        .unwrap();
    context.svm.warp_to_slot(100);

    // Test transfer to recipient1 within limit
    let transfer_amount1 = 200_000_000u64; // 0.2 SOL - within recipient1's limit

    let inner_ix1 =
        system_instruction::transfer(&swig_wallet_address, &recipient1.pubkey(), transfer_amount1);
    let sol_transfer_ix1 = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        second_authority.pubkey(),
        inner_ix1,
        1, // role_id
    )
    .unwrap();

    // Test transfer to recipient2 within limit
    let transfer_amount2 = 400_000_000u64; // 0.4 SOL - within recipient2's limit

    let inner_ix2 =
        system_instruction::transfer(&swig_wallet_address, &recipient2.pubkey(), transfer_amount2);
    let sol_transfer_ix2 = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        second_authority.pubkey(),
        inner_ix2,
        1, // role_id
    )
    .unwrap();

    // Combine both transfers in a single transaction
    let combined_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sol_transfer_ix1, sol_transfer_ix2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let combined_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(combined_message), &[&second_authority])
            .unwrap();

    let res = context.svm.send_transaction(combined_tx).unwrap();
    println!("Combined transfers logs: {}", res.pretty_logs());

    // Verify both limits were decremented correctly
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();

    let dest_limit1 = role
        .get_action::<SolRecurringDestinationLimit>(&recipient1.pubkey().to_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(
        dest_limit1.current_amount,
        recurring_amount1 - transfer_amount1
    );

    let dest_limit2 = role
        .get_action::<SolRecurringDestinationLimit>(&recipient2.pubkey().to_bytes())
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
fn test_sol_recurring_destination_limit_no_reset_when_exceeds_fresh_v2() {
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

    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let recurring_amount = 300_000_000u64; // 0.3 SOL per window
    let window = 50u64; // 50 slots
    let recurring_destination_limit = SolRecurringDestinationLimit {
        destination: recipient.pubkey().to_bytes(),
        recurring_amount,
        window,
        last_reset: 0,
        current_amount: 100_000_000u64, // Only 0.1 SOL remaining
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
            ClientAction::SolRecurringDestinationLimit(recurring_destination_limit),
        ],
    )
    .unwrap();

    // Fund the SWIG wallet address (not the swig account itself)
    context
        .svm
        .airdrop(&swig_wallet_address, 2_000_000_000)
        .unwrap();
    context.svm.warp_to_slot(100); // Move past the window

    // Try to transfer more than the fresh limit would allow
    let transfer_amount = 400_000_000u64; // 0.4 SOL - exceeds even fresh limit (0.3 SOL)

    let inner_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);
    let sol_transfer_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        second_authority.pubkey(),
        inner_ix,
        1, // role_id
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sol_transfer_ix],
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
        println!("Expected error (exceeds fresh limit): {:?}", e);
        // Should get the specific destination limit exceeded error (3030)
        assert!(matches!(
            e.err,
            TransactionError::InstructionError(_, InstructionError::Custom(3030))
        ));
    }

    // Verify limit was NOT reset (should still have the old current_amount)
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();
    let dest_limit = role
        .get_action::<SolRecurringDestinationLimit>(&recipient.pubkey().to_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(dest_limit.current_amount, 100_000_000u64); // Should remain unchanged
    assert_eq!(dest_limit.last_reset, 0); // Should not be updated
}
