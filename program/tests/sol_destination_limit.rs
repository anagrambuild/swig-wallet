#![cfg(not(feature = "program_scope_test"))]

mod common;
use common::*;
use solana_sdk::{
    instruction::InstructionError,
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    system_instruction,
    transaction::{TransactionError, VersionedTransaction},
};
use swig_interface::{AuthorityConfig, ClientAction, SignInstruction};
use swig_state::{
    action::{
        program_all::ProgramAll, sol_destination_limit::SolDestinationLimit, sol_limit::SolLimit,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, SwigWithRoles},
};

/// Test basic SOL destination limit functionality
#[test_log::test]
fn test_sol_destination_limit_basic() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    // Setup accounts with initial balances
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

    // Create SWIG wallet
    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Add authority with destination-specific limit
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let destination_limit_amount = 500_000_000u64; // 0.5 SOL
    let destination_limit = SolDestinationLimit {
        destination: recipient.pubkey().to_bytes(),
        amount: destination_limit_amount,
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
            ClientAction::SolDestinationLimit(destination_limit),
        ],
    )
    .unwrap();

    // Fund the SWIG wallet
    context.svm.airdrop(&swig, 2_000_000_000).unwrap();
    context.svm.warp_to_slot(100);

    // Test transfer within limit
    let transfer_amount = 300_000_000u64; // 0.3 SOL - within limit
    let recipient_initial_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;

    let inner_ix = system_instruction::transfer(&swig, &recipient.pubkey(), transfer_amount);
    let sol_transfer_ix = SignInstruction::new_ed25519(
        swig,
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

    // Verify transfer succeeded
    let recipient_final_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    assert_eq!(
        recipient_final_balance,
        recipient_initial_balance + transfer_amount
    );

    // Verify destination limit was decremented
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();
    let dest_limit = role
        .get_action::<SolDestinationLimit>(&recipient.pubkey().to_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(
        dest_limit.amount,
        destination_limit_amount - transfer_amount
    );
}

/// Test edge case: General SOL limit hit before destination limit
#[test_log::test]
fn test_general_sol_limit_hit_before_destination_limit() {
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

    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    // Set general limit LOWER than destination limit
    let general_limit_amount = 300_000_000u64; // 0.3 SOL general limit (lower)
    let destination_limit_amount = 800_000_000u64; // 0.8 SOL destination limit (higher)

    let destination_limit = SolDestinationLimit {
        destination: recipient.pubkey().to_bytes(),
        amount: destination_limit_amount,
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
            ClientAction::SolLimit(SolLimit {
                amount: general_limit_amount,
            }),
            ClientAction::SolDestinationLimit(destination_limit),
        ],
    )
    .unwrap();

    context.svm.airdrop(&swig, 2_000_000_000).unwrap();
    context.svm.warp_to_slot(100);

    // Try to transfer amount that exceeds general limit but is within destination
    // limit
    let transfer_amount = 500_000_000u64; // 0.5 SOL - exceeds general limit (0.3) but within destination limit (0.8)

    let inner_ix = system_instruction::transfer(&swig, &recipient.pubkey(), transfer_amount);
    let sol_transfer_ix = SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        inner_ix,
        1,
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

    // Should fail due to general SOL limit being exceeded
    assert!(res.is_err());
    if let Err(e) = res {
        println!("Expected error (general limit exceeded): {:?}", e);
        // Should get insufficient balance error from general SOL limit
        assert!(matches!(
            e.err,
            TransactionError::InstructionError(_, InstructionError::Custom(_))
        ));
    }
}

/// Test edge case: Destination limit hit before general SOL limit
#[test_log::test]
fn test_destination_limit_hit_before_general_sol_limit() {
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

    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    // Set destination limit LOWER than general limit
    let general_limit_amount = 800_000_000u64; // 0.8 SOL general limit (higher)
    let destination_limit_amount = 300_000_000u64; // 0.3 SOL destination limit (lower)

    let destination_limit = SolDestinationLimit {
        destination: recipient.pubkey().to_bytes(),
        amount: destination_limit_amount,
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
            ClientAction::SolLimit(SolLimit {
                amount: general_limit_amount,
            }),
            ClientAction::SolDestinationLimit(destination_limit),
        ],
    )
    .unwrap();

    context.svm.airdrop(&swig, 2_000_000_000).unwrap();
    context.svm.warp_to_slot(100);

    // Try to transfer amount that exceeds destination limit but is within general
    // limit
    let transfer_amount = 500_000_000u64; // 0.5 SOL - exceeds destination limit (0.3) but within general limit (0.8)

    let inner_ix = system_instruction::transfer(&swig, &recipient.pubkey(), transfer_amount);
    let sol_transfer_ix = SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        inner_ix,
        1,
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

    // Should fail due to destination limit being exceeded
    assert!(res.is_err());
    if let Err(e) = res {
        println!("Expected error (destination limit exceeded): {:?}", e);
        // Should get the new specific destination limit exceeded error
        assert!(matches!(
            e.err,
            TransactionError::InstructionError(_, InstructionError::Custom(_))
        ));
    }
}

/// Test multiple destinations with different limits
#[test_log::test]
fn test_multiple_destination_limits() {
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

    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let destination_limit1_amount = 300_000_000u64; // 0.3 SOL for recipient1
    let destination_limit2_amount = 500_000_000u64; // 0.5 SOL for recipient2

    let destination_limit1 = SolDestinationLimit {
        destination: recipient1.pubkey().to_bytes(),
        amount: destination_limit1_amount,
    };

    let destination_limit2 = SolDestinationLimit {
        destination: recipient2.pubkey().to_bytes(),
        amount: destination_limit2_amount,
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
            ClientAction::SolDestinationLimit(destination_limit1),
            ClientAction::SolDestinationLimit(destination_limit2),
        ],
    )
    .unwrap();

    context.svm.airdrop(&swig, 2_000_000_000).unwrap();
    context.svm.warp_to_slot(100);

    // Test transfer to recipient1 within limit
    let transfer_amount1 = 200_000_000u64; // 0.2 SOL - within recipient1's limit

    let inner_ix1 = system_instruction::transfer(&swig, &recipient1.pubkey(), transfer_amount1);
    let sol_transfer_ix1 = SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        inner_ix1,
        1,
    )
    .unwrap();

    // Test transfer to recipient2 within limit (in the same transaction)
    let transfer_amount2 = 400_000_000u64; // 0.4 SOL - within recipient2's limit

    let inner_ix2 = system_instruction::transfer(&swig, &recipient2.pubkey(), transfer_amount2);
    let sol_transfer_ix2 = SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        inner_ix2,
        1,
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
    let swig_account_final = context.svm.get_account(&swig).unwrap();
    let swig_state_final = SwigWithRoles::from_bytes(&swig_account_final.data).unwrap();
    let role_final = swig_state_final.get_role(1).unwrap().unwrap();

    let dest_limit1 = role_final
        .get_action::<SolDestinationLimit>(&recipient1.pubkey().to_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(
        dest_limit1.amount,
        destination_limit1_amount - transfer_amount1
    );

    let dest_limit2 = role_final
        .get_action::<SolDestinationLimit>(&recipient2.pubkey().to_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(
        dest_limit2.amount,
        destination_limit2_amount - transfer_amount2
    );
}
/// Test SOL destination limit exceeding the limit
#[test_log::test]
fn test_sol_destination_limit_exceeds_limit() {
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

    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let destination_limit_amount = 300_000_000u64; // 0.3 SOL
    let destination_limit = SolDestinationLimit {
        destination: recipient.pubkey().to_bytes(),
        amount: destination_limit_amount,
    };

    let _txn = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::SolDestinationLimit(destination_limit)],
    )
    .unwrap();

    context.svm.airdrop(&swig, 2_000_000_000).unwrap();
    context.svm.warp_to_slot(100);

    // Try to transfer more than the limit
    let transfer_amount = 500_000_000u64; // 0.5 SOL - exceeds limit

    let inner_ix = system_instruction::transfer(&swig, &recipient.pubkey(), transfer_amount);
    let sol_transfer_ix = SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        inner_ix,
        1,
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
        // Check for the specific error related to insufficient balance/permission
        assert!(matches!(
            e.err,
            TransactionError::InstructionError(_, InstructionError::Custom(_))
        ));
    }
}

/// Test SOL destination limit combined with general SOL limit
#[test_log::test]
fn test_sol_destination_limit_with_general_limit() {
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

    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 1_000_000_000)
        .unwrap();

    let general_limit_amount = 800_000_000u64; // 0.8 SOL general limit
    let destination_limit_amount = 500_000_000u64; // 0.5 SOL destination limit

    let destination_limit = SolDestinationLimit {
        destination: recipient.pubkey().to_bytes(),
        amount: destination_limit_amount,
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
            ClientAction::SolLimit(SolLimit {
                amount: general_limit_amount,
            }),
            ClientAction::SolDestinationLimit(destination_limit),
        ],
    )
    .unwrap();

    context.svm.airdrop(&swig, 2_000_000_000).unwrap();
    context.svm.warp_to_slot(100);

    // Test transfer within both limits
    let transfer_amount = 400_000_000u64; // 0.4 SOL - within both limits

    let inner_ix = system_instruction::transfer(&swig, &recipient.pubkey(), transfer_amount);
    let sol_transfer_ix = SignInstruction::new_ed25519(
        swig,
        second_authority.pubkey(),
        second_authority.pubkey(),
        inner_ix,
        1,
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
    println!("Combined limits transfer logs: {}", res.pretty_logs());

    // Verify both limits were decremented
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role = swig_state.get_role(1).unwrap().unwrap();

    let general_limit = role.get_action::<SolLimit>(&[]).unwrap().unwrap();
    assert_eq!(general_limit.amount, general_limit_amount - transfer_amount);

    let dest_limit = role
        .get_action::<SolDestinationLimit>(&recipient.pubkey().to_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(
        dest_limit.amount,
        destination_limit_amount - transfer_amount
    );
}
