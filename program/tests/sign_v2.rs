#![cfg(not(feature = "program_scope_test"))]
// This feature flag ensures these tests are only run when the
// "program_scope_test" feature is not enabled. This allows us to isolate
// and run only program_scope tests or only the regular tests.

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
    sysvar::{clock::Clock, rent::Rent},
    transaction::{TransactionError, VersionedTransaction},
};
use solana_system_interface::instruction as system_instruction;
use swig_interface::{AuthorityConfig, ClientAction, SignInstruction, SignV2Instruction};
use swig_state::{
    action::{
        all::All, program::Program, program_all::ProgramAll, sol_limit::SolLimit,
        sol_recurring_limit::SolRecurringLimit, token_limit::TokenLimit,
        token_recurring_limit::TokenRecurringLimit,
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds, SwigWithRoles},
};

#[test_log::test]
fn test_sign_v2_transfer_sol() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    // Setup accounts
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 20_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    // Create the swig account (this now also creates the empty swig_wallet_address
    // PDA)
    let (_, _transaction_metadata) =
        create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Transfer additional funds to the swig_wallet_address PDA
    // The PDA is already created as system-owned by the create_v1 function
    let transfer_to_wallet_ix = system_instruction::transfer(
        &swig_authority.pubkey(),
        &swig_wallet_address,
        1_000_000_000,
    );

    let transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[transfer_to_wallet_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&swig_authority])
            .unwrap();

    context.svm.send_transaction(transfer_tx).unwrap();

    // Create a simple transfer instruction from swig_wallet_address
    let transfer_amount = 100_000_000; // 0.1 SOL
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    // Create SignV2 instruction with the swig_wallet_address
    let sign_v2_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        swig_authority.pubkey(),
        transfer_ix,
        0, // role_id 0 for root authority
    )
    .unwrap();

    // Build and execute transaction
    let transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&swig_authority])
            .unwrap();

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

    // Execute the transaction
    let result = context.svm.send_transaction(transfer_tx);

    if result.is_err() {
        println!("Transaction failed: {:?}", result.err());
        assert!(false, "SignV2 transaction should succeed");
    } else {
        let txn = result.unwrap();
        println!(
            "SignV2 Transfer successful - CU consumed: {:?}",
            txn.compute_units_consumed
        );
        println!("Logs: {}", txn.pretty_logs());
    }

    // Verify the transfer was successful
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
        initial_recipient_balance + transfer_amount,
        "Recipient should have received the transfer amount"
    );

    assert_eq!(
        final_swig_wallet_address_balance,
        initial_swig_wallet_address_balance - transfer_amount,
        "Swig wallet address account should have the transfer amount deducted"
    );

    println!(
        "✅ SignV2 test passed: Successfully transferred {} lamports",
        transfer_amount
    );
}

#[test_log::test]
fn test_sign_v2_transfer_sol_with_additional_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    // Setup accounts
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 20_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    // Create swig account and fund wallet address
    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let transfer_to_wallet_ix = system_instruction::transfer(
        &swig_authority.pubkey(),
        &swig_wallet_address,
        1_000_000_000,
    );
    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &swig_authority.pubkey(),
                &[transfer_to_wallet_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&swig_authority],
    )
    .unwrap();
    context.svm.send_transaction(transfer_tx).unwrap();

    // Add second authority with SOL limit
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();
    let amount = 100000;

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::SolLimit(SolLimit { amount: amount / 2 }),
            ClientAction::Program(Program {
                program_id: solana_sdk_ids::system_program::ID.to_bytes(),
            }),
        ],
    )
    .unwrap();

    // Test transfer with second authority
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), amount / 2);
    let sign_v2_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        transfer_ix,
        1, // second authority role_id
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    let initial_recipient_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    let result = context.svm.send_transaction(transfer_tx);

    assert!(
        result.is_ok(),
        "SignV2 transaction with additional authority should succeed"
    );

    // Verify transfer succeeded
    let final_recipient_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    assert_eq!(
        final_recipient_balance,
        initial_recipient_balance + amount / 2
    );

    // Verify sol limit was decremented
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_state = SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role1 = swig_state.get_role(1).unwrap().unwrap();
    let action = role1.get_action::<SolLimit>(&[]).unwrap().unwrap();
    assert_eq!(action.amount, 0);
}

#[test_log::test]
fn test_sign_v2_transfer_sol_all_with_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 20_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    // Create swig account and fund wallet address
    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let transfer_to_wallet_ix = system_instruction::transfer(
        &swig_authority.pubkey(),
        &swig_wallet_address,
        10_000_000_000,
    );
    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &swig_authority.pubkey(),
                &[transfer_to_wallet_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&swig_authority],
    )
    .unwrap();
    context.svm.send_transaction(transfer_tx).unwrap();

    // Add second authority with All permission
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::All(All {})],
    )
    .unwrap();

    // Test large transfer with All permission
    let amount = 5_000_000_000; // 5 SOL
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), amount);
    let sign_v2_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        transfer_ix,
        1, // second authority role_id
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    let initial_recipient_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    let result = context.svm.send_transaction(transfer_tx);

    assert!(
        result.is_ok(),
        "SignV2 transaction with All authority should succeed"
    );

    // Verify transfer succeeded
    let final_recipient_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    assert_eq!(final_recipient_balance, initial_recipient_balance + amount);
}

#[test_log::test]
fn test_sign_v2_fail_transfer_sol_with_insufficient_limit() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 20_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    // Create swig account and fund wallet address
    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let transfer_to_wallet_ix = system_instruction::transfer(
        &swig_authority.pubkey(),
        &swig_wallet_address,
        10_000_000_000,
    );
    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &swig_authority.pubkey(),
                &[transfer_to_wallet_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&swig_authority],
    )
    .unwrap();
    context.svm.send_transaction(transfer_tx).unwrap();

    // Add second authority with small SOL limit
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::SolLimit(SolLimit { amount: 1000 }),
            ClientAction::Program(Program {
                program_id: solana_sdk_ids::system_program::ID.to_bytes(),
            }),
        ],
    )
    .unwrap();

    // Attempt transfer exceeding limit
    let amount = 1001; // Exceeds the 1000 limit
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), amount);
    let sign_v2_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        transfer_ix,
        1, // second authority role_id
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    let result = context.svm.send_transaction(transfer_tx);

    assert!(
        result.is_err(),
        "SignV2 transaction exceeding limit should fail"
    );
    assert_eq!(
        result.unwrap_err().err,
        TransactionError::InstructionError(0, InstructionError::Custom(3011))
    );
}

#[test_log::test]
fn test_sign_v2_fail_not_correct_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 20_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    // Create swig account and fund wallet address
    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let transfer_to_wallet_ix = system_instruction::transfer(
        &swig_authority.pubkey(),
        &swig_wallet_address,
        10_000_000_000,
    );
    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &swig_authority.pubkey(),
                &[transfer_to_wallet_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&swig_authority],
    )
    .unwrap();
    context.svm.send_transaction(transfer_tx).unwrap();

    // Add legitimate second authority
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![ClientAction::All(All {})],
    )
    .unwrap();

    // Try to use fake authority
    let fake_authority = Keypair::new();
    context
        .svm
        .airdrop(&fake_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let amount = 1001;
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), amount);
    let sign_v2_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        fake_authority.pubkey(),
        transfer_ix,
        1, // trying to use role_id 1 but with wrong authority
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &fake_authority.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&fake_authority])
            .unwrap();

    let result = context.svm.send_transaction(transfer_tx);

    assert!(
        result.is_err(),
        "SignV2 transaction with wrong authority should fail"
    );
    assert_eq!(
        result.unwrap_err().err,
        TransactionError::InstructionError(0, InstructionError::Custom(3005))
    );
}

#[test_log::test]
fn test_sign_v2_transfer_sol_with_recurring_limit() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 20_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    // Create swig account and fund wallet address
    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let transfer_to_wallet_ix = system_instruction::transfer(
        &swig_authority.pubkey(),
        &swig_wallet_address,
        10_000_000_000,
    );
    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &swig_authority.pubkey(),
                &[transfer_to_wallet_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&swig_authority],
    )
    .unwrap();
    context.svm.send_transaction(transfer_tx).unwrap();

    // Add second authority with recurring limit
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::SolRecurringLimit(SolRecurringLimit {
                recurring_amount: 500,
                window: 100,
                last_reset: 0,
                current_amount: 500,
            }),
            ClientAction::Program(Program {
                program_id: solana_sdk_ids::system_program::ID.to_bytes(),
            }),
        ],
    )
    .unwrap();

    // First transfer within limit should succeed
    let amount = 500;
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), amount);
    let sign_v2_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        transfer_ix,
        1,
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    let result = context.svm.send_transaction(transfer_tx);
    assert!(result.is_ok(), "First transfer within limit should succeed");

    // Second transfer exceeding limit should fail
    let amount2 = 500;
    let transfer_ix2 =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), amount2);
    let sign_v2_ix2 = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        transfer_ix2,
        1,
    )
    .unwrap();

    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + 10);
    context.svm.expire_blockhash();

    let transfer_message2 = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_v2_ix2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx2 = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message2),
        &[&second_authority],
    )
    .unwrap();

    let result2 = context.svm.send_transaction(transfer_tx2);
    assert!(
        result2.is_err(),
        "Second transfer exceeding limit should fail"
    );

    // Warp time forward past the window
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    context.svm.warp_to_slot(current_slot + 110);
    context.svm.expire_blockhash();

    // Third transfer should succeed after window reset
    let amount3 = 500;
    let transfer_ix3 =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), amount3);
    let sign_v2_ix3 = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        transfer_ix3,
        1,
    )
    .unwrap();

    let transfer_message3 = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_v2_ix3],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx3 = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message3),
        &[&second_authority],
    )
    .unwrap();

    let result3 = context.svm.send_transaction(transfer_tx3);
    assert!(
        result3.is_ok(),
        "Third transfer after window reset should succeed"
    );

    // Verify final balances
    let recipient_account = context.svm.get_account(&recipient.pubkey()).unwrap();
    assert_eq!(
        recipient_account.lamports,
        10_000_000_000 + amount + amount3
    );
}

#[test_log::test]
fn test_sign_v2_transfer_token_with_recurring_limit() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 20_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    // Setup token infrastructure
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_wallet_address_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
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

    // Mint initial tokens to the swig_wallet_address token account
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_wallet_address_ata,
        1000,
    )
    .unwrap();

    // Create swig account and fund wallet address
    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let transfer_to_wallet_ix = system_instruction::transfer(
        &swig_authority.pubkey(),
        &swig_wallet_address,
        1_000_000_000,
    );
    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &swig_authority.pubkey(),
                &[transfer_to_wallet_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&swig_authority],
    )
    .unwrap();
    context.svm.send_transaction(transfer_tx).unwrap();

    // Add second authority with token recurring limit
    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::TokenRecurringLimit(TokenRecurringLimit {
                token_mint: mint_pubkey.to_bytes().try_into().unwrap(),
                window: 100,
                limit: 500,
                current: 500,
                last_reset: 0,
            }),
            ClientAction::Program(Program {
                program_id: spl_token::id().to_bytes(),
            }),
        ],
    )
    .unwrap();

    // First token transfer within limit should succeed
    let amount = 300;
    let token_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_wallet_address_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig_wallet_address, false),
        ],
        data: TokenInstruction::Transfer { amount }.pack(),
    };

    let sign_v2_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        token_ix,
        1,
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&second_authority])
            .unwrap();

    let result = context.svm.send_transaction(transfer_tx);
    assert!(
        result.is_ok(),
        "First token transfer within limit should succeed"
    );

    // Second token transfer exceeding limit should fail
    let amount2 = 300; // This would exceed the 500 token limit
    let token_ix2 = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_wallet_address_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig_wallet_address, false),
        ],
        data: TokenInstruction::Transfer { amount: amount2 }.pack(),
    };

    let sign_v2_ix2 = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        token_ix2,
        1,
    )
    .unwrap();

    context
        .svm
        .warp_to_slot(context.svm.get_sysvar::<Clock>().slot + 10);
    context.svm.expire_blockhash();

    let transfer_message2 = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_v2_ix2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx2 = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message2),
        &[&second_authority],
    )
    .unwrap();

    let result2 = context.svm.send_transaction(transfer_tx2);
    assert!(
        result2.is_err(),
        "Second token transfer exceeding limit should fail"
    );

    // Warp time forward past the window
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    context.svm.warp_to_slot(current_slot + 110);
    context.svm.expire_blockhash();

    // Third token transfer should succeed after window reset
    let amount3 = 300;
    let token_ix3 = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_wallet_address_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig_wallet_address, false),
        ],
        data: TokenInstruction::Transfer { amount: amount3 }.pack(),
    };

    let sign_v2_ix3 = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        second_authority.pubkey(),
        token_ix3,
        1,
    )
    .unwrap();

    let transfer_message3 = v0::Message::try_compile(
        &second_authority.pubkey(),
        &[sign_v2_ix3],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx3 = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message3),
        &[&second_authority],
    )
    .unwrap();

    let result3 = context.svm.send_transaction(transfer_tx3);
    assert!(
        result3.is_ok(),
        "Third token transfer after window reset should succeed"
    );

    // Verify final token balances
    let recipient_token_account = context.svm.get_account(&recipient_ata).unwrap();
    let recipient_token_balance =
        spl_token::state::Account::unpack(&recipient_token_account.data).unwrap();
    assert_eq!(recipient_token_balance.amount, amount + amount3);

    let swig_token_account = context.svm.get_account(&swig_wallet_address_ata).unwrap();
    let swig_token_balance = spl_token::state::Account::unpack(&swig_token_account.data).unwrap();
    assert_eq!(swig_token_balance.amount, 1000 - amount - amount3);
}

#[test_log::test]
fn test_sign_v2_transfer_between_swig_accounts() {
    let mut context = setup_test_context().unwrap();

    // Create first Swig account (sender)
    let sender_authority = Keypair::new();
    context
        .svm
        .airdrop(&sender_authority.pubkey(), 10_000_000_000)
        .unwrap();
    let sender_id = rand::random::<[u8; 32]>();
    let sender_swig =
        Pubkey::find_program_address(&swig_account_seeds(&sender_id), &program_id()).0;
    let (sender_swig_wallet_address, _) = Pubkey::find_program_address(
        &swig_wallet_address_seeds(sender_swig.as_ref()),
        &program_id(),
    );

    // Create second Swig account (recipient)
    let recipient_authority = Keypair::new();
    context
        .svm
        .airdrop(&recipient_authority.pubkey(), 10_000_000_000)
        .unwrap();
    let recipient_id = rand::random::<[u8; 32]>();
    let recipient_swig =
        Pubkey::find_program_address(&swig_account_seeds(&recipient_id), &program_id()).0;

    // Create both Swig accounts
    let sender_create_result = create_swig_ed25519(&mut context, &sender_authority, sender_id);
    assert!(
        sender_create_result.is_ok(),
        "Failed to create sender Swig account"
    );

    let recipient_create_result =
        create_swig_ed25519(&mut context, &recipient_authority, recipient_id);
    assert!(
        recipient_create_result.is_ok(),
        "Failed to create recipient Swig account"
    );

    // Fund the sender's wallet address
    let transfer_to_wallet_ix = system_instruction::transfer(
        &sender_authority.pubkey(),
        &sender_swig_wallet_address,
        5_000_000_000,
    );
    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &sender_authority.pubkey(),
                &[transfer_to_wallet_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&sender_authority],
    )
    .unwrap();
    context.svm.send_transaction(transfer_tx).unwrap();

    // Create transfer instruction from sender wallet address to recipient swig
    let transfer_amount = 1_000_000_000; // 1 SOL
    let transfer_ix = system_instruction::transfer(
        &sender_swig_wallet_address,
        &recipient_swig,
        transfer_amount,
    );

    // Sign the transfer with sender authority using SignV2
    let sign_v2_ix = SignV2Instruction::new_ed25519(
        sender_swig,
        sender_swig_wallet_address,
        sender_authority.pubkey(),
        transfer_ix,
        0, // root authority role
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &sender_authority.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&sender_authority])
            .unwrap();

    let result = context.svm.send_transaction(transfer_tx);
    assert!(
        result.is_ok(),
        "Transfer between Swig accounts failed: {:?}",
        result.err()
    );

    // Verify the transfer was successful
    let sender_wallet_address_account = context
        .svm
        .get_account(&sender_swig_wallet_address)
        .unwrap();
    let recipient_swig_account = context.svm.get_account(&recipient_swig).unwrap();

    // Get initial recipient balance (should include the rent-exempt amount plus
    // transfer)
    let recipient_initial_balance = {
        let rent = context.svm.get_sysvar::<Rent>();
        rent.minimum_balance(recipient_swig_account.data.len())
    };

    assert_eq!(
        recipient_swig_account.lamports,
        recipient_initial_balance + transfer_amount,
        "Recipient Swig account did not receive the correct amount"
    );

    println!(
        "✅ Successfully transferred {} lamports from Swig wallet address {} to Swig {}",
        transfer_amount, sender_swig_wallet_address, recipient_swig
    );
}

#[test_log::test]
fn test_sign_v2_transfer_with_different_payer_and_authority() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let different_payer = Keypair::new(); // This is the key difference - payer != authority
    let recipient = Keypair::new();

    // Setup accounts - fund both authority and payer
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 20_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&different_payer.pubkey(), 20_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    // Create the swig account using the authority
    let (_, _transaction_metadata) =
        create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Transfer additional funds to the swig_wallet_address PDA using the different
    // payer
    let transfer_to_wallet_ix = system_instruction::transfer(
        &different_payer.pubkey(),
        &swig_wallet_address,
        1_000_000_000,
    );

    let transfer_message = v0::Message::try_compile(
        &different_payer.pubkey(),
        &[transfer_to_wallet_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&different_payer])
            .unwrap();

    context.svm.send_transaction(transfer_tx).unwrap();

    // Create a simple transfer instruction from swig_wallet_address
    let transfer_amount = 100_000_000; // 0.1 SOL
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    // Create SignV2 instruction signed by the swig authority
    let sign_v2_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        swig_authority.pubkey(),
        transfer_ix,
        0, // role_id 0 for root authority
    )
    .unwrap();

    // Build and execute transaction - payer signs but authority is different
    let transfer_message = v0::Message::try_compile(
        &different_payer.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message),
        &[&different_payer, &swig_authority],
    )
    .unwrap();

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

    // Execute the transaction
    let result = context.svm.send_transaction(transfer_tx);

    if result.is_err() {
        println!("Transaction failed: {:?}", result.err());
        assert!(
            false,
            "SignV2 transaction with different payer and authority should succeed"
        );
    } else {
        let txn = result.unwrap();
        println!(
            "SignV2 Transfer with different payer/authority successful - CU consumed: {:?}",
            txn.compute_units_consumed
        );
        println!("Logs: {}", txn.pretty_logs());
    }

    // Verify the transfer was successful
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
        initial_recipient_balance + transfer_amount,
        "Recipient should have received the transfer amount"
    );

    assert_eq!(
        final_swig_wallet_address_balance,
        initial_swig_wallet_address_balance - transfer_amount,
        "Swig wallet address account should have the transfer amount deducted"
    );

    println!(
        "✅ SignV2 test passed: Successfully transferred {} lamports with different payer ({}) \
         and authority ({})",
        transfer_amount,
        different_payer.pubkey().to_string()[..8].to_string(),
        swig_authority.pubkey().to_string()[..8].to_string()
    );
}

#[test_log::test]
fn test_sign_v2_secp256k1_transfer() {
    let mut context = setup_test_context().unwrap();

    // Import required dependencies for secp256k1
    use alloy_primitives::B256;
    use alloy_signer::SignerSync;
    use alloy_signer_local::{LocalSigner, PrivateKeySigner};

    // Generate a random Ethereum wallet for secp256k1 authority
    let secp_wallet = LocalSigner::random();
    let recipient = Keypair::new();

    // Setup accounts
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    // Create the swig account with secp256k1 authority
    let (_, _transaction_metadata) = create_swig_secp256k1(&mut context, &secp_wallet, id).unwrap();

    // Fund the swig_wallet_address PDA
    context
        .svm
        .airdrop(&swig_wallet_address, 1_000_000_000)
        .unwrap();

    // Create a simple transfer instruction from swig_wallet_address
    let transfer_amount = 100_000_000; // 0.1 SOL
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    // Create signing function for secp256k1
    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        secp_wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    // Create SignV2 instruction with secp256k1
    let sign_v2_ix = SignV2Instruction::new_secp256k1(
        swig,
        swig_wallet_address,
        signing_fn,
        current_slot,
        1, // counter = 1 (first secp256k1 transaction)
        transfer_ix,
        0, // role_id 0 for root authority
    )
    .unwrap();

    // Build and execute transaction
    let transfer_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message),
        &[&context.default_payer],
    )
    .unwrap();

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

    // Execute the transaction
    let result = context.svm.send_transaction(transfer_tx);

    if result.is_err() {
        println!("Transaction failed: {:?}", result.err());
        assert!(false, "SignV2 secp256k1 transaction should succeed");
    } else {
        let txn = result.unwrap();
        println!(
            "SignV2 secp256k1 Transfer successful - CU consumed: {:?}",
            txn.compute_units_consumed
        );
        println!("Logs: {}", txn.pretty_logs());
    }

    // Verify the transfer was successful
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
        initial_recipient_balance + transfer_amount,
        "Recipient should have received the transfer amount"
    );

    assert_eq!(
        final_swig_wallet_address_balance,
        initial_swig_wallet_address_balance - transfer_amount,
        "Swig wallet address account should have the transfer amount deducted"
    );

    println!(
        "✅ SignV2 secp256k1 test passed: Successfully transferred {} lamports using secp256k1 \
         authority",
        transfer_amount
    );
}

/// Helper to generate a real secp256r1 key pair for testing
fn create_test_secp256r1_keypair() -> (openssl::ec::EcKey<openssl::pkey::Private>, [u8; 33]) {
    use openssl::{
        bn::BigNumContext,
        ec::{EcGroup, EcKey, PointConversionForm},
        nid::Nid,
    };

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let signing_key = EcKey::generate(&group).unwrap();

    let mut ctx = BigNumContext::new().unwrap();
    let pubkey_bytes = signing_key
        .public_key()
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap();

    let pubkey_array: [u8; 33] = pubkey_bytes.try_into().unwrap();
    (signing_key, pubkey_array)
}

/// Helper function to get the current signature counter for a secp256r1
/// authority
fn get_secp256r1_counter(
    context: &SwigTestContext,
    swig_key: &solana_sdk::pubkey::Pubkey,
    public_key: &[u8; 33],
) -> Result<u32, String> {
    // Get the swig account data
    let swig_account = context
        .svm
        .get_account(swig_key)
        .ok_or("Swig account not found")?;
    let swig = SwigWithRoles::from_bytes(&swig_account.data)
        .map_err(|e| format!("Failed to parse swig data: {:?}", e))?;

    // Look up the role ID for this authority
    let role_id = swig
        .lookup_role_id(public_key)
        .map_err(|e| format!("Failed to lookup role: {:?}", e))?
        .ok_or("Authority not found in swig account")?;

    // Get the role
    let role = swig
        .get_role(role_id)
        .map_err(|e| format!("Failed to get role: {:?}", e))?
        .ok_or("Role not found")?;

    // The authority should be a Secp256r1Authority
    if matches!(role.authority.authority_type(), AuthorityType::Secp256r1) {
        // Get the authority from the any() interface
        use swig_state::authority::secp256r1::Secp256r1Authority;
        let secp_authority = role
            .authority
            .as_any()
            .downcast_ref::<Secp256r1Authority>()
            .ok_or("Failed to downcast to Secp256r1Authority")?;

        Ok(secp_authority.signature_odometer)
    } else {
        Err("Authority is not a Secp256r1Authority".to_string())
    }
}

#[test_log::test]
fn test_sign_v2_combined_sol_and_token_transfer() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    // Setup accounts
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 20_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    // Setup token infrastructure - only create swig ATA, recipient ATA will be
    // created in transaction
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_wallet_address_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    // Calculate recipient ATA address but don't create it yet
    // Use the standard associated token account derivation
    use solana_sdk::pubkey::Pubkey;
    const ASSOCIATED_TOKEN_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
    let associated_token_program_id = ASSOCIATED_TOKEN_PROGRAM_ID.parse::<Pubkey>().unwrap();
    let recipient_ata = Pubkey::find_program_address(
        &[
            &recipient.pubkey().to_bytes(),
            &spl_token::id().to_bytes(),
            &mint_pubkey.to_bytes(),
        ],
        &associated_token_program_id,
    )
    .0;

    // Mint initial tokens to the swig_wallet_address token account
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_wallet_address_ata,
        1000,
    )
    .unwrap();

    // Create the swig account with All permission to allow all operations
    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Fund the swig_wallet_address with SOL
    let transfer_to_wallet_ix = system_instruction::transfer(
        &swig_authority.pubkey(),
        &swig_wallet_address,
        2_000_000_000,
    );
    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &swig_authority.pubkey(),
                &[transfer_to_wallet_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&swig_authority],
    )
    .unwrap();
    context.svm.send_transaction(transfer_tx).unwrap();

    // Create instructions for ATA creation, SOL transfer, and token transfer
    let sol_amount = 500_000_000; // 0.5 SOL
    let token_amount = 250; // 250 tokens

    // 1. Create ATA instruction for recipient
    // Manually create the ATA creation instruction since
    // spl_associated_token_account isn't available
    let create_ata_ix = Instruction {
        program_id: associated_token_program_id,
        accounts: vec![
            AccountMeta::new(swig_wallet_address, true), /* payer (swig wallet pays for ATA
                                                          * creation) */
            AccountMeta::new(recipient_ata, false), // associated token account
            AccountMeta::new_readonly(recipient.pubkey(), false), // owner
            AccountMeta::new_readonly(mint_pubkey, false), // mint
            AccountMeta::new_readonly(solana_sdk_ids::system_program::ID, false), // system program
            AccountMeta::new_readonly(spl_token::id(), false), // token program
        ],
        data: vec![], // create_associated_token_account has no instruction data
    };

    // 2. SOL transfer instruction
    let sol_transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), sol_amount);

    // 3. Token transfer instruction
    let token_transfer_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_wallet_address_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig_wallet_address, false),
        ],
        data: TokenInstruction::Transfer {
            amount: token_amount,
        }
        .pack(),
    };

    // Create three separate SignV2 instructions
    let create_ata_sign_v2_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        swig_authority.pubkey(),
        create_ata_ix,
        0, // role_id 0 for root authority (has All permission)
    )
    .unwrap();

    let sol_sign_v2_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        swig_authority.pubkey(),
        sol_transfer_ix,
        0, // role_id 0 for root authority (has All permission)
    )
    .unwrap();

    let token_sign_v2_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        swig_authority.pubkey(),
        token_transfer_ix,
        0, // role_id 0 for root authority (has All permission)
    )
    .unwrap();

    // Build and execute transaction with all three SignV2 instructions
    let transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[create_ata_sign_v2_ix, sol_sign_v2_ix, token_sign_v2_ix], /* All three SignV2
                                                                     * instructions in one
                                                                     * transaction */
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&swig_authority])
            .unwrap();

    // Capture initial balances
    let initial_recipient_sol_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    let initial_swig_wallet_sol_balance = context
        .svm
        .get_account(&swig_wallet_address)
        .unwrap()
        .lamports;
    let initial_swig_token_balance = {
        let account = context.svm.get_account(&swig_wallet_address_ata).unwrap();
        spl_token::state::Account::unpack(&account.data)
            .unwrap()
            .amount
    };

    // Verify recipient ATA doesn't exist yet
    assert!(
        context.svm.get_account(&recipient_ata).is_none(),
        "Recipient ATA should not exist yet"
    );

    // Execute the transaction
    let result = context.svm.send_transaction(transfer_tx);

    if result.is_err() {
        println!("Transaction failed: {:?}", result.err());
        assert!(
            false,
            "Combined ATA creation, SOL and token transfer should succeed"
        );
    } else {
        let txn = result.unwrap();
        println!(
            "Combined SignV2 Transfer successful - CU consumed: {:?}",
            txn.compute_units_consumed
        );
        println!("Logs: {}", txn.pretty_logs());
    }

    // Verify SOL transfer was successful
    let final_recipient_sol_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    let final_swig_wallet_sol_balance = context
        .svm
        .get_account(&swig_wallet_address)
        .unwrap()
        .lamports;

    assert_eq!(
        final_recipient_sol_balance,
        initial_recipient_sol_balance + sol_amount,
        "Recipient should have received the SOL transfer amount"
    );

    // Note: SOL balance will also include the cost of ATA creation
    assert!(
        final_swig_wallet_sol_balance < initial_swig_wallet_sol_balance - sol_amount,
        "Swig wallet address should have the SOL transfer amount plus ATA creation cost deducted"
    );

    // Verify ATA was created and token transfer was successful
    let recipient_ata_account = context.svm.get_account(&recipient_ata).unwrap();
    let recipient_token_balance =
        spl_token::state::Account::unpack(&recipient_ata_account.data).unwrap();
    assert_eq!(
        recipient_token_balance.amount, token_amount,
        "Recipient should have received the token transfer amount"
    );
    assert_eq!(
        recipient_token_balance.owner,
        recipient.pubkey(),
        "ATA should be owned by recipient"
    );
    assert_eq!(
        recipient_token_balance.mint, mint_pubkey,
        "ATA should be for the correct mint"
    );

    let final_swig_token_balance = {
        let account = context.svm.get_account(&swig_wallet_address_ata).unwrap();
        spl_token::state::Account::unpack(&account.data)
            .unwrap()
            .amount
    };

    assert_eq!(
        final_swig_token_balance,
        initial_swig_token_balance - token_amount,
        "Swig wallet should have the token transfer amount deducted"
    );

    println!(
        "✅ Combined SignV2 test passed: Successfully created ATA, transferred {} lamports and {} \
         tokens in one transaction using three SignV2 instructions",
        sol_amount, token_amount
    );
}

#[test_log::test]
fn test_sign_v2_fail_using_another_swig_wallet_address() {
    let mut context = setup_test_context().unwrap();

    // Create first swig wallet
    let swig1_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig1_authority.pubkey(), 10_000_000_000)
        .unwrap();
    let swig1_id = rand::random::<[u8; 32]>();
    let swig1 = Pubkey::find_program_address(&swig_account_seeds(&swig1_id), &program_id()).0;
    let (swig1_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig1.as_ref()), &program_id());

    // Create second swig wallet
    let swig2_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig2_authority.pubkey(), 10_000_000_000)
        .unwrap();
    let swig2_id = rand::random::<[u8; 32]>();
    let swig2 = Pubkey::find_program_address(&swig_account_seeds(&swig2_id), &program_id()).0;
    let (swig2_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig2.as_ref()), &program_id());

    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 1_000_000_000)
        .unwrap();

    // Create both swig accounts
    let (_, _) = create_swig_ed25519(&mut context, &swig1_authority, swig1_id).unwrap();
    let (_, _) = create_swig_ed25519(&mut context, &swig2_authority, swig2_id).unwrap();

    // Fund both swig wallet addresses
    let fund_swig1_ix = system_instruction::transfer(
        &swig1_authority.pubkey(),
        &swig1_wallet_address,
        5_000_000_000,
    );
    let fund_swig2_ix = system_instruction::transfer(
        &swig2_authority.pubkey(),
        &swig2_wallet_address,
        5_000_000_000,
    );

    // Fund swig1 wallet address
    let fund_tx1 = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &swig1_authority.pubkey(),
                &[fund_swig1_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&swig1_authority],
    )
    .unwrap();
    context.svm.send_transaction(fund_tx1).unwrap();

    // Fund swig2 wallet address
    let fund_tx2 = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &swig2_authority.pubkey(),
                &[fund_swig2_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&swig2_authority],
    )
    .unwrap();
    context.svm.send_transaction(fund_tx2).unwrap();

    // Verify both wallet addresses are funded
    let swig1_wallet_balance = context
        .svm
        .get_account(&swig1_wallet_address)
        .unwrap()
        .lamports;
    let swig2_wallet_balance = context
        .svm
        .get_account(&swig2_wallet_address)
        .unwrap()
        .lamports;
    assert!(
        swig1_wallet_balance >= 5_000_000_000,
        "Swig1 wallet should be funded"
    );
    assert!(
        swig2_wallet_balance >= 5_000_000_000,
        "Swig2 wallet should be funded"
    );

    // Attempt: swig1 tries to transfer from swig2's wallet address
    // This should fail because swig1 doesn't own swig2's wallet address PDA
    let malicious_transfer_amount = 1_000_000_000; // 1 SOL
    let malicious_transfer_ix = system_instruction::transfer(
        &swig2_wallet_address,
        &recipient.pubkey(),
        malicious_transfer_amount,
    );

    let malicious_sign_v2_ix = SignV2Instruction::new_ed25519(
        swig1,                // swig1 account
        swig2_wallet_address, // swig1's authority
        swig1_authority.pubkey(),
        malicious_transfer_ix,
        0, // role_id 0 for root authority
    )
    .unwrap();

    let malicious_message = v0::Message::try_compile(
        &swig1_authority.pubkey(),
        &[malicious_sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let malicious_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(malicious_message), &[&swig1_authority])
            .unwrap();

    let initial_recipient_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    let initial_swig2_wallet_balance = context
        .svm
        .get_account(&swig2_wallet_address)
        .unwrap()
        .lamports;

    // This transaction should fail
    let result = context.svm.send_transaction(malicious_tx);

    assert!(
        result.is_err(),
        "Transaction should fail when trying to use another swig's wallet address"
    );

    // Verify no funds were transferred
    let final_recipient_balance = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    let final_swig2_wallet_balance = context
        .svm
        .get_account(&swig2_wallet_address)
        .unwrap()
        .lamports;

    assert_eq!(
        final_recipient_balance, initial_recipient_balance,
        "Recipient balance should not have changed"
    );

    assert_eq!(
        final_swig2_wallet_balance, initial_swig2_wallet_balance,
        "Swig2 wallet balance should not have changed"
    );

    println!("✅ Security test passed: Swig1 cannot use Swig2's wallet address for transfers");

    // Verify that legitimate transfers still work
    // swig1 should be able to transfer from its own wallet address
    let legitimate_transfer_ix = system_instruction::transfer(
        &swig1_wallet_address,
        &recipient.pubkey(),
        malicious_transfer_amount,
    );

    let legitimate_sign_v2_ix = SignV2Instruction::new_ed25519(
        swig1,
        swig1_wallet_address,
        swig1_authority.pubkey(),
        legitimate_transfer_ix,
        0,
    )
    .unwrap();

    let legitimate_message = v0::Message::try_compile(
        &swig1_authority.pubkey(),
        &[legitimate_sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let legitimate_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(legitimate_message),
        &[&swig1_authority],
    )
    .unwrap();

    let legitimate_result = context.svm.send_transaction(legitimate_tx);
    assert!(
        legitimate_result.is_ok(),
        "Legitimate transfer from own wallet address should succeed"
    );

    // Verify the legitimate transfer worked
    let final_recipient_balance_after_legitimate = context
        .svm
        .get_account(&recipient.pubkey())
        .unwrap()
        .lamports;
    assert_eq!(
        final_recipient_balance_after_legitimate,
        initial_recipient_balance + malicious_transfer_amount,
        "Legitimate transfer should have succeeded"
    );

    println!("✅ Verified: Legitimate transfers from own wallet address still work");
}

#[test_log::test]
fn test_sign_v2_secp256r1_transfer() {
    let mut context = setup_test_context().unwrap();

    // Create a real secp256r1 key pair for testing
    let (signing_key, public_key) = create_test_secp256r1_keypair();
    let recipient = Keypair::new();

    // Setup accounts
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    // Create the swig account with secp256r1 authority
    let (_, _transaction_metadata) = create_swig_secp256r1(&mut context, &public_key, id).unwrap();

    // Fund the swig_wallet_address PDA
    context
        .svm
        .airdrop(&swig_wallet_address, 1_000_000_000)
        .unwrap();

    // Create a simple transfer instruction from swig_wallet_address
    let transfer_amount = 100_000_000; // 0.1 SOL
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    // Get current slot and counter
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    let current_counter = get_secp256r1_counter(&context, &swig, &public_key).unwrap();
    let next_counter = current_counter + 1;

    println!(
        "Current counter: {}, using next counter: {}",
        current_counter, next_counter
    );

    // Create authority function that signs the message hash
    let authority_fn = |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        let signature =
            sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap();
        signature
    };

    // Create SignV2 instruction with secp256r1 (returns Vec<Instruction>)
    let sign_v2_instructions = SignV2Instruction::new_secp256r1(
        swig,
        swig_wallet_address,
        authority_fn,
        current_slot,
        next_counter,
        transfer_ix,
        0, // role_id 0 for root authority
        &public_key,
    )
    .unwrap();

    // Build and execute transaction
    let transfer_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &sign_v2_instructions, // Use the Vec<Instruction> directly
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message),
        &[&context.default_payer],
    )
    .unwrap();

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

    // Execute the transaction
    let result = context.svm.send_transaction(transfer_tx);

    if result.is_err() {
        println!("Transaction failed: {:?}", result.err());
        assert!(false, "SignV2 secp256r1 transaction should succeed");
    } else {
        let txn = result.unwrap();
        println!(
            "SignV2 secp256r1 Transfer successful - CU consumed: {:?}",
            txn.compute_units_consumed
        );
        println!("Logs: {}", txn.pretty_logs());
    }

    // Verify the transfer was successful
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
        initial_recipient_balance + transfer_amount,
        "Recipient should have received the transfer amount"
    );

    assert_eq!(
        final_swig_wallet_address_balance,
        initial_swig_wallet_address_balance - transfer_amount,
        "Swig wallet address account should have the transfer amount deducted"
    );

    // Verify the counter was incremented
    let new_counter = get_secp256r1_counter(&context, &swig, &public_key).unwrap();
    assert_eq!(
        new_counter, next_counter,
        "Counter should be incremented after successful transaction"
    );

    println!(
        "✅ SignV2 secp256r1 test passed: Successfully transferred {} lamports using secp256r1 \
         authority with real cryptography",
        transfer_amount
    );
}

#[test_log::test]
fn test_sign_v1_rejected_by_swig_v2() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 20_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let (_, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let transfer_to_wallet_ix = system_instruction::transfer(
        &swig_authority.pubkey(),
        &swig_wallet_address,
        1_000_000_000,
    );
    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &swig_authority.pubkey(),
                &[transfer_to_wallet_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&swig_authority],
    )
    .unwrap();
    context.svm.send_transaction(transfer_tx).unwrap();

    let transfer_amount = 100_000_000;
    let transfer_ix = system_instruction::transfer(&swig, &recipient.pubkey(), transfer_amount);

    let sign_v1_ix = SignInstruction::new_ed25519(
        swig,
        swig_authority.pubkey(),
        swig_authority.pubkey(),
        transfer_ix,
        0,
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign_v1_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[&swig_authority])
            .unwrap();

    let result = context.svm.send_transaction(transfer_tx);

    assert!(
        result.is_err(),
        "SignV1 instruction should be rejected by Swig v2 account"
    );
    assert_eq!(
        result.unwrap_err().err,
        TransactionError::InstructionError(0, InstructionError::Custom(45))
    );

    println!("✅ Test passed: Swig v2 correctly rejects SignV1 instruction with error code 45");
}

#[test_log::test]
fn test_sign_v2_token_transfer_through_secondary_authority() {
    let mut context = setup_test_context().unwrap();

    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig_key, _) = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig_key.as_ref()), &program_id());

    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let swig_wallet_address_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &recipient.pubkey(),
        &recipient,
    )
    .unwrap();
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_wallet_address_ata,
        1000,
    )
    .unwrap();

    let transfer_to_wallet_ix = system_instruction::transfer(
        &swig_authority.pubkey(),
        &swig_wallet_address,
        1_000_000_000,
    );
    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(
            v0::Message::try_compile(
                &swig_authority.pubkey(),
                &[transfer_to_wallet_ix],
                &[],
                context.svm.latest_blockhash(),
            )
            .unwrap(),
        ),
        &[&swig_authority],
    )
    .unwrap();
    context.svm.send_transaction(transfer_tx).unwrap();

    add_authority_with_ed25519_root(
        &mut context,
        &swig_key,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: recipient.pubkey().as_ref(),
        },
        vec![
            ClientAction::TokenLimit(TokenLimit {
                token_mint: mint_pubkey.to_bytes().try_into().unwrap(),
                current_amount: 600_000_000,
            }),
            ClientAction::ProgramAll(ProgramAll {}),
        ],
    )
    .unwrap();

    let token_transfer_ix = Instruction {
        program_id: spl_token::id(),
        accounts: vec![
            AccountMeta::new(swig_wallet_address_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new(swig_wallet_address, false),
        ],
        data: TokenInstruction::Transfer { amount: 100 }.pack(),
    };

    let sign_v2_ix = SignV2Instruction::new_ed25519(
        swig_key,
        swig_wallet_address,
        recipient.pubkey(),
        token_transfer_ix,
        1,
    )
    .unwrap();

    println!("sign_v2_ix: {:?}", sign_v2_ix.data);

    let message = v0::Message::try_compile(
        &recipient.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&recipient]).unwrap();

    let result = context.svm.send_transaction(tx);
    println!("result: {:?}", result);
    assert!(result.is_ok(), "Transfer below limit should succeed");
    println!(
        "Compute units consumed for below limit transfer: {}",
        result.unwrap().compute_units_consumed
    );
}

#[test_log::test]
fn test_sign_v2_minimum_rent_check() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let different_payer = Keypair::new(); // This is the key difference - payer != authority
    let recipient = Keypair::new();

    // Setup accounts - fund both authority and payer
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 20_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&different_payer.pubkey(), 20_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    // Create the swig account using the authority
    let (_, _transaction_metadata) =
        create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let secondary_authority = Keypair::new();
    context
        .svm
        .airdrop(&secondary_authority.pubkey(), 1_000_000);

    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: AuthorityType::Ed25519,
            authority: secondary_authority.pubkey().to_bytes().as_ref(),
        },
        vec![
            ClientAction::ProgramAll(ProgramAll {}),
            ClientAction::SolLimit(SolLimit {
                amount: 3_000_000_000,
            }),
        ],
    )
    .unwrap();

    context
        .svm
        .airdrop(&swig_wallet_address, 1_000_000_000)
        .unwrap();

    // Failure case - transfer amount is greater than the swig wallet balance and the rent exempt minimum
    let transfer_amount = 1_000_000_000 + 1; // swig wallet balance + 1
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    // Create SignV2 instruction signed by the swig authority
    let sign_v2_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        secondary_authority.pubkey(),
        transfer_ix,
        1, // role_id 0 for root authority
    )
    .unwrap();

    // Build and execute transaction - payer signs but authority is different
    let transfer_message = v0::Message::try_compile(
        &different_payer.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message),
        &[&different_payer, &secondary_authority],
    )
    .unwrap();

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

    // Execute the transaction
    let result = context.svm.send_transaction(transfer_tx);

    assert!(result.is_err(), "Transfer should be rejected");

    // Success case - transfer amount is less than the swig wallet balance and the rent exempt minimum
    let transfer_amount = 1_000_000_000; // swig wallet balance
    let transfer_ix =
        system_instruction::transfer(&swig_wallet_address, &recipient.pubkey(), transfer_amount);

    // Create SignV2 instruction signed by the swig authority
    let sign_v2_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        secondary_authority.pubkey(),
        transfer_ix,
        1, // role_id 0 for root authority
    )
    .unwrap();

    // Build and execute transaction - payer signs but authority is different
    let transfer_message = v0::Message::try_compile(
        &different_payer.pubkey(),
        &[sign_v2_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(transfer_message),
        &[&different_payer, &secondary_authority],
    )
    .unwrap();

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

    // Execute the transaction
    let result = context.svm.send_transaction(transfer_tx);

    assert!(result.is_ok(), "Transfer should succeed");

    // Verify the transfer was successful
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
        initial_recipient_balance + transfer_amount,
        "Recipient should have received the transfer amount"
    );

    assert_eq!(
        final_swig_wallet_address_balance,
        initial_swig_wallet_address_balance - transfer_amount,
        "Swig wallet address account should have the transfer amount deducted"
    );

    println!(
        "✅ SignV2 test passed: Successfully transferred {} lamports with different payer ({}) \
         and authority ({})",
        transfer_amount,
        different_payer.pubkey().to_string()[..8].to_string(),
        swig_authority.pubkey().to_string()[..8].to_string()
    );
}
