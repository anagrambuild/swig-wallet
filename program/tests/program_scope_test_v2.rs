#![cfg(feature = "program_scope_test")]
// This file contains SignV2 tests specifically for the program_scope feature.
// These tests mirror the SignV1 tests in program_scope_test.rs but use the new
// SwigV2 account structure where funds are held in a separate swig_wallet_address
// PDA rather than the swig config account directly.

mod common;
use common::*;
use litesvm_token::spl_token::{self};
use solana_sdk::{
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
use swig::actions::sign_v2::SignV2Args;
use swig_interface::{compact_instructions, AuthorityConfig, ClientAction, SignV2Instruction};
use swig_state::{
    action::{
        program::Program,
        program_scope::{NumericType, ProgramScope, ProgramScopeType},
    },
    authority::AuthorityType,
    swig::{swig_account_seeds, swig_wallet_address_seeds},
    IntoBytes, Transmutable,
};

/// This test compares the baseline performance of:
/// 1. A regular token transfer (outside of swig)
/// 2. A token transfer using swig with ProgramScope via SignV2
///
/// This is the SignV2 equivalent of test_token_transfer_with_program_scope
#[test_log::test]
fn test_token_transfer_with_program_scope_v2() {
    let mut context = setup_test_context().unwrap();

    // Setup payers and recipients
    let swig_authority = Keypair::new();
    let regular_sender = Keypair::new();
    let recipient = Keypair::new();

    // Airdrop to participants
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&regular_sender.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    // Setup token mint
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    // Setup swig account (creates V2 by default - no convert_swig_to_v1 call)
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let swig_create_result = create_swig_ed25519(&mut context, &swig_authority, id);
    assert!(swig_create_result.is_ok());

    // Setup token accounts - for V2, the ATA is created for swig_wallet_address instead of swig
    let swig_wallet_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    let program_scope = ProgramScope {
        program_id: spl_token::ID.to_bytes(),
        target_account: swig_wallet_ata.to_bytes(), // Target the swig wallet's token account
        scope_type: ProgramScopeType::Limit as u64,
        numeric_type: NumericType::U64 as u64,
        current_amount: 0,
        limit: 1000,
        window: 0,               // Not used for Limit type
        last_reset: 0,           // Not used for Limit type
        balance_field_start: 64, // SPL Token balance starts at byte 64
        balance_field_end: 72,   // SPL Token balance ends at byte 72 (u64 is 8 bytes)
    };

    let add_authority_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: swig_state::authority::AuthorityType::Ed25519,
            authority: swig_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::Program(Program {
                program_id: spl_token::ID.to_bytes(),
            }),
            ClientAction::ProgramScope(program_scope),
        ],
    );

    println!("{:?}", add_authority_result);
    assert!(add_authority_result.is_ok());

    println!("Added ProgramScope action for token program (SignV2)");

    let regular_sender_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &regular_sender.pubkey(),
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

    // Mint tokens to both sending accounts
    let initial_token_amount = 1000;
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_wallet_ata,
        initial_token_amount,
    )
    .unwrap();

    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &regular_sender_ata,
        initial_token_amount,
    )
    .unwrap();

    // Measure regular token transfer performance
    let transfer_amount = 100;
    let token_program_id = spl_token::ID;

    let regular_transfer_ix = spl_token::instruction::transfer(
        &token_program_id,
        &regular_sender_ata,
        &recipient_ata,
        &regular_sender.pubkey(),
        &[],
        transfer_amount,
    )
    .unwrap();

    let regular_transfer_message = v0::Message::try_compile(
        &regular_sender.pubkey(),
        &[regular_transfer_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let regular_tx_accounts = regular_transfer_message.account_keys.len();

    let regular_transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(regular_transfer_message),
        &[regular_sender],
    )
    .unwrap();

    let regular_transfer_result = context.svm.send_transaction(regular_transfer_tx).unwrap();
    let regular_transfer_cu = regular_transfer_result.compute_units_consumed;

    println!("Regular token transfer CU: {}", regular_transfer_cu);
    println!("Regular token transfer accounts: {}", regular_tx_accounts);

    // Measure swig token transfer performance using SignV2
    // The key difference: we transfer FROM swig_wallet_address, and use SignV2Instruction
    let swig_transfer_ix = spl_token::instruction::transfer(
        &token_program_id,
        &swig_wallet_ata,
        &recipient_ata,
        &swig_wallet_address, // In V2, the swig_wallet_address is the authority
        &[],
        transfer_amount,
    )
    .unwrap();

    // Use SignV2Instruction instead of SignInstruction
    let sign_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        swig_authority.pubkey(),
        swig_transfer_ix,
        1, // authority role id
    )
    .unwrap();

    let swig_transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let swig_tx_accounts = swig_transfer_message.account_keys.len();

    let swig_transfer_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(swig_transfer_message),
        &[swig_authority],
    )
    .unwrap();

    let swig_transfer_result = context.svm.send_transaction(swig_transfer_tx).unwrap();
    let swig_transfer_cu = swig_transfer_result.compute_units_consumed;
    println!("Swig token transfer CU (SignV2): {}", swig_transfer_cu);
    println!("Swig token transfer accounts: {}", swig_tx_accounts);
    println!("Swig transfer logs: {:?}", swig_transfer_result.logs);

    // Compare results
    let cu_difference = swig_transfer_cu as i64 - regular_transfer_cu as i64;
    let account_difference = swig_tx_accounts as i64 - regular_tx_accounts as i64;

    println!("Performance comparison (SignV2):");
    println!(
        "CU difference (swig - regular): {} CU ({:.2}% overhead)",
        cu_difference,
        (cu_difference as f64 / regular_transfer_cu as f64) * 100.0
    );
    println!(
        "Account difference (swig - regular): {} accounts",
        account_difference
    );
    // SignV2 may have slightly different overhead than SignV1
    // Updated to 5699 to account for authorization lock processing overhead
    assert!(swig_transfer_cu - regular_transfer_cu <= 5699);
}

/// Helper function to perform token transfers through the swig using SignV2
fn perform_token_transfer_v2(
    context: &mut SwigTestContext,
    swig: Pubkey,
    swig_wallet_address: Pubkey,
    swig_authority: &Keypair,
    swig_wallet_ata: Pubkey,
    recipient_ata: Pubkey,
    amount: u64,
    expected_success: bool,
) -> Vec<String> {
    // Expire the blockhash to ensure we don't get AlreadyProcessed errors
    context.svm.expire_blockhash();

    // Get the current token balance before the transfer
    let before_token_account = context.svm.get_account(&swig_wallet_ata).unwrap();
    let before_balance = if before_token_account.data.len() >= 72 {
        // SPL token accounts have their balance at offset 64-72
        u64::from_le_bytes(before_token_account.data[64..72].try_into().unwrap())
    } else {
        0
    };
    println!("Before transfer, token balance: {}", before_balance);

    let token_program_id = spl_token::ID;

    // In V2, the swig_wallet_address is the authority for the token transfer
    let transfer_ix = spl_token::instruction::transfer(
        &token_program_id,
        &swig_wallet_ata,
        &recipient_ata,
        &swig_wallet_address,
        &[],
        amount,
    )
    .unwrap();

    // Use SignV2Instruction
    let sign_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        swig_authority.pubkey(),
        transfer_ix,
        1, // authority role id
    )
    .unwrap();

    let transfer_message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let transfer_tx =
        VersionedTransaction::try_new(VersionedMessage::V0(transfer_message), &[swig_authority])
            .unwrap();

    let result = context.svm.send_transaction(transfer_tx);

    // Get the current token balance after the transfer
    let after_token_account = context.svm.get_account(&swig_wallet_ata).unwrap();
    let after_balance = if after_token_account.data.len() >= 72 {
        // SPL token accounts have their balance at offset 64-72
        u64::from_le_bytes(after_token_account.data[64..72].try_into().unwrap())
    } else {
        0
    };
    println!("After transfer, token balance: {}", after_balance);

    if expected_success {
        assert!(
            result.is_ok(),
            "Expected successful transfer, but got error: {:?}",
            result.err()
        );
        // Verify the token balance actually decreased by the expected amount
        assert_eq!(
            before_balance - after_balance,
            amount,
            "Token balance did not decrease by the expected amount"
        );
        println!("Successfully transferred {} tokens (SignV2)", amount);
        println!(
            "Token balance decreased from {} to {}",
            before_balance, after_balance
        );
        result.unwrap().logs
    } else {
        println!("result: {:?}", result);
        assert!(
            result.is_err(),
            "Expected transfer to fail, but it succeeded"
        );
        // Verify the balance didn't change
        assert_eq!(
            before_balance, after_balance,
            "Token balance should not have changed for a failed transfer"
        );
        println!(
            "Transfer of {} tokens was correctly rejected (SignV2)",
            amount
        );
        Vec::new()
    }
}

/// Helper function to read the current ProgramScope state
fn read_program_scope_state_v2(
    context: &mut SwigTestContext,
    swig: &Pubkey,
    authority: &Keypair,
    target_account: &Pubkey,
) -> Option<u128> {
    context.svm.expire_blockhash();

    // Get the swig account data
    let swig_account = context.svm.get_account(swig).unwrap();
    let swig_data = swig_account.data.clone();

    // Find the roles in the swig account
    const SWIG_LEN: usize = 240;

    if swig_data.len() < SWIG_LEN {
        println!("Swig data too short");
        return None;
    }

    let swig_with_roles = swig_state::swig::SwigWithRoles::from_bytes(&swig_data).ok()?;

    // Find the authority's role
    let role_id = swig_with_roles
        .lookup_role_id(authority.pubkey().as_ref())
        .ok()??;
    let role = swig_with_roles.get_role(role_id).ok()??;

    // Search through actions for ProgramScope targeting our account
    let target_bytes = target_account.to_bytes();
    let mut cursor = 0;

    const ACTION_LEN: usize = 8;

    while cursor < role.actions.len() {
        if cursor + ACTION_LEN > role.actions.len() {
            break;
        }

        let action = unsafe {
            swig_state::action::Action::load_unchecked(&role.actions[cursor..cursor + ACTION_LEN])
        }
        .ok()?;

        cursor += ACTION_LEN;
        let action_len = action.length() as usize;

        if cursor + action_len > role.actions.len() {
            break;
        }

        if action.permission().ok() == Some(swig_state::action::Permission::ProgramScope) {
            let action_data = &role.actions[cursor..cursor + action_len];
            const PROGRAM_SCOPE_LEN: usize = 144; // Fixed: was incorrectly 128

            if action_data.len() == PROGRAM_SCOPE_LEN {
                let program_scope = unsafe {
                    swig_state::action::program_scope::ProgramScope::load_unchecked(action_data)
                }
                .ok()?;

                // Check if this ProgramScope targets our account
                if program_scope.target_account == target_bytes {
                    println!("Found ProgramScope for target account (SignV2)");
                    println!("  Current amount: {}", program_scope.current_amount);
                    println!("  Limit: {}", program_scope.limit);
                    println!("  Last reset: {}", program_scope.last_reset);
                    println!(
                        "  Balance field indices: {}..{}",
                        program_scope.balance_field_start, program_scope.balance_field_end
                    );

                    // If balance indices are set, try to read the balance
                    if program_scope.balance_field_start > 0 && program_scope.balance_field_end > 0
                    {
                        // Get the account data
                        if let Some(account) = context.svm.get_account(target_account) {
                            if account.data.len() >= program_scope.balance_field_end as usize {
                                let balance_data = &account.data[program_scope.balance_field_start
                                    as usize
                                    ..program_scope.balance_field_end as usize];
                                if balance_data.len() == 8 {
                                    // For u64
                                    let balance =
                                        u64::from_le_bytes(balance_data.try_into().unwrap())
                                            as u128;
                                    println!(
                                        "  Current actual balance (from account data): {}",
                                        balance
                                    );
                                }
                            }
                        }
                    }

                    return Some(program_scope.current_amount);
                }
            }
        }

        cursor += action_len;
    }

    println!("Could not find ProgramScope for target account");
    None
}

/// This test verifies the functionality of RecurringLimit ProgramScope using SignV2
/// This is the SignV2 equivalent of test_recurring_limit_program_scope
#[test_log::test]
fn test_recurring_limit_program_scope_v2() {
    let mut context = setup_test_context().unwrap();

    // Setup payers and recipients
    let swig_authority = Keypair::new();
    let recipient = Keypair::new();

    // Airdrop to participants
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();
    context
        .svm
        .airdrop(&recipient.pubkey(), 10_000_000_000)
        .unwrap();

    // Expire the blockhash after airdrops
    context.svm.expire_blockhash();

    // Setup token mint
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    // Expire the blockhash after mint setup
    context.svm.expire_blockhash();

    // Setup swig account (V2 - no convert_swig_to_v1 call)
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    let swig_create_result = create_swig_ed25519(&mut context, &swig_authority, id);
    println!("swig_create_result: {:?}", swig_create_result);
    assert!(swig_create_result.is_ok());

    // Expire the blockhash after swig creation
    context.svm.expire_blockhash();

    // Setup token accounts - for V2, ATA is for swig_wallet_address
    let swig_wallet_ata = setup_ata(
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

    // Expire the blockhash after ATA setup
    context.svm.expire_blockhash();

    // Setup a RecurringLimit program scope
    // Set a limit of 500 tokens per 100 slots
    let window_size = 100;
    let transfer_limit = 500_u64;

    let program_scope = ProgramScope {
        program_id: spl_token::ID.to_bytes(),
        target_account: swig_wallet_ata.to_bytes(),
        scope_type: ProgramScopeType::RecurringLimit as u64,
        numeric_type: NumericType::U64 as u64,
        current_amount: 0,
        limit: transfer_limit as u128,
        window: window_size,
        last_reset: 0,
        balance_field_start: 64,
        balance_field_end: 72,
    };

    let add_authority_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: swig_state::authority::AuthorityType::Ed25519,
            authority: swig_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::Program(Program {
                program_id: spl_token::ID.to_bytes(),
            }),
            ClientAction::ProgramScope(program_scope),
        ],
    );

    assert!(add_authority_result.is_ok());
    println!("Added RecurringLimit ProgramScope action for token program (SignV2)");

    // Expire the blockhash after adding authority
    context.svm.expire_blockhash();

    // Mint tokens to the swig wallet's token account (enough for multiple transfers)
    let initial_token_amount = 2000;
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_wallet_ata,
        initial_token_amount,
    )
    .unwrap();

    // Expire the blockhash after minting tokens
    context.svm.expire_blockhash();

    // First test batch of transfers - should succeed up to the limit
    println!("\n=== PHASE 1: Initial transfers within limit (SignV2) ===");
    let mut transferred = 0;
    let transfer_batch = 100;

    // Check initial program scope state
    let initial_amount =
        read_program_scope_state_v2(&mut context, &swig, &swig_authority, &swig_wallet_ata);
    println!("Initial program scope current_amount: {:?}", initial_amount);

    // Transfer in batches of 100 tokens up to limit (should succeed)
    while transferred + transfer_batch <= transfer_limit {
        perform_token_transfer_v2(
            &mut context,
            swig,
            swig_wallet_address,
            &swig_authority,
            swig_wallet_ata,
            recipient_ata,
            transfer_batch,
            true,
        );
        transferred += transfer_batch;
        println!("Total transferred: {}/{}", transferred, transfer_limit);

        // Check program scope state after each transfer
        let current_amount =
            read_program_scope_state_v2(&mut context, &swig, &swig_authority, &swig_wallet_ata);
        println!(
            "After transfer, program scope current_amount: {:?}",
            current_amount
        );

        // Verify the program scope is tracking correctly
        if let Some(amount) = current_amount {
            assert_eq!(
                amount, transferred as u128,
                "Program scope current_amount should match transferred amount"
            );
        }
    }

    // Try to transfer one more batch (should fail)
    println!("\n=== PHASE 2: Transfer exceeding limit (SignV2) ===");
    perform_token_transfer_v2(
        &mut context,
        swig,
        swig_wallet_address,
        &swig_authority,
        swig_wallet_ata,
        recipient_ata,
        transfer_batch,
        false,
    );

    // Check program scope state after failed transfer
    let current_amount =
        read_program_scope_state_v2(&mut context, &swig, &swig_authority, &swig_wallet_ata);
    println!(
        "After failed transfer, program scope current_amount: {:?}",
        current_amount
    );

    // Verify the program scope is still at the limit
    if let Some(amount) = current_amount {
        assert_eq!(
            amount, transferred as u128,
            "Program scope current_amount should still be at the same value after failed transfer"
        );
    }

    // Get the current slot for reference
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    println!("Current slot: {}", current_slot);

    // Advance the clock past the window to trigger a reset
    let slots_to_advance = window_size + 1;
    println!(
        "\n=== PHASE 3: Advancing {} slots to reset limit (SignV2) ===",
        slots_to_advance
    );
    context.svm.warp_to_slot(current_slot + slots_to_advance);
    let new_slot = context.svm.get_sysvar::<Clock>().slot;
    println!(
        "New slot: {} (advanced by {})",
        new_slot,
        new_slot - current_slot
    );

    // Check program scope state after slot advancement
    let current_amount =
        read_program_scope_state_v2(&mut context, &swig, &swig_authority, &swig_wallet_ata);
    println!(
        "After slot advancement, program scope current_amount: {:?}",
        current_amount
    );

    // After advancing the clock, we should be able to transfer again
    println!("\n=== PHASE 4: Transfers after limit reset (SignV2) ===");
    transferred = 0;

    // Transfer in batches again (should succeed until limit)
    while transferred + transfer_batch <= transfer_limit {
        let logs = perform_token_transfer_v2(
            &mut context,
            swig,
            swig_wallet_address,
            &swig_authority,
            swig_wallet_ata,
            recipient_ata,
            transfer_batch,
            true,
        );
        transferred += transfer_batch;
        println!(
            "Total transferred after reset: {}/{}",
            transferred, transfer_limit
        );

        // Check program scope state after each transfer in second batch
        let current_amount =
            read_program_scope_state_v2(&mut context, &swig, &swig_authority, &swig_wallet_ata);
        println!(
            "After transfer (post-reset), program scope current_amount: {:?}",
            current_amount
        );

        // Verify the program scope is tracking correctly after reset
        if let Some(amount) = current_amount {
            assert_eq!(
                amount, transferred as u128,
                "Program scope current_amount should match transferred amount after reset"
            );
        }

        // Print interesting logs for debugging
        for log in logs {
            if log.contains("program scope run") || log.contains("current_amount") {
                println!("Log: {}", log);
            }
        }
    }

    // Try to transfer one more batch (should fail again)
    println!("\n=== PHASE 5: Transfer exceeding limit after reset (SignV2) ===");
    perform_token_transfer_v2(
        &mut context,
        swig,
        swig_wallet_address,
        &swig_authority,
        swig_wallet_ata,
        recipient_ata,
        transfer_batch,
        false,
    );

    // Advance a few more slots but not enough for a full window
    println!("\n=== PHASE 6: Advancing by half window (SignV2) ===");
    context.svm.warp_to_slot(new_slot + window_size / 2);
    let current_slot = context.svm.get_sysvar::<Clock>().slot;
    println!("Current slot: {}", current_slot);

    // Should still be rejected as we haven't reached a full window
    perform_token_transfer_v2(
        &mut context,
        swig,
        swig_wallet_address,
        &swig_authority,
        swig_wallet_ata,
        recipient_ata,
        transfer_batch,
        false,
    );

    // Finally, advance the remaining slots to complete a window
    println!("\n=== PHASE 7: Completing the window reset (SignV2) ===");
    let curr_slot = context.svm.get_sysvar::<Clock>().slot;
    context.svm.warp_to_slot(curr_slot + window_size / 2 + 1);
    let final_slot = context.svm.get_sysvar::<Clock>().slot;
    println!("Current slot: {}", final_slot);

    // Now should succeed again
    perform_token_transfer_v2(
        &mut context,
        swig,
        swig_wallet_address,
        &swig_authority,
        swig_wallet_ata,
        recipient_ata,
        transfer_batch,
        true,
    );

    println!("RecurringLimit ProgramScope test completed successfully (SignV2)!");
}

/// Test that verifies ProgramScope limit enforcement in CPI scenarios using SignV2
/// This is the SignV2 equivalent of test_program_scope_token_limit_cpi_enforcement
#[test_log::test]
fn test_program_scope_token_limit_cpi_enforcement_v2() {
    use swig_state::IntoBytes;
    let mut context = setup_test_context().unwrap();

    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let id = rand::random::<[u8; 32]>();
    let swig = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id()).0;
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    // Setup token infrastructure
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    // For V2, the ATA is for swig_wallet_address
    let swig_wallet_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    let funding_account = Keypair::new();
    context
        .svm
        .airdrop(&funding_account.pubkey(), 10_000_000_000)
        .unwrap();
    let funding_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &funding_account.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_authority.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    // Mint tokens to funding account
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &funding_ata,
        2000,
    )
    .unwrap();

    // Mint initial tokens to SWIG wallet account
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_wallet_ata,
        1000,
    )
    .unwrap();

    let _swig_create_txn = create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let second_authority = Keypair::new();
    context
        .svm
        .airdrop(&second_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Setup ProgramScope with Limit type for 500 tokens
    let program_scope = ProgramScope {
        program_id: spl_token::ID.to_bytes(),
        target_account: swig_wallet_ata.to_bytes(),
        scope_type: ProgramScopeType::Limit as u64,
        numeric_type: NumericType::U64 as u64,
        current_amount: 0,
        limit: 500,
        window: 0,               // Not used for Limit type
        last_reset: 0,           // Not used for Limit type
        balance_field_start: 64, // SPL Token balance starts at byte 64
        balance_field_end: 72,   // SPL Token balance ends at byte 72 (u64 is 8 bytes)
    };

    // Add authority with ProgramScope limit of 500 tokens
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: swig_state::authority::AuthorityType::Ed25519,
            authority: second_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::Program(Program {
                program_id: spl_token::ID.to_bytes(),
            }),
            ClientAction::ProgramScope(program_scope),
        ],
    )
    .unwrap();

    let transfer_amount: u64 = 1000; // 1000 tokens (exceeds the 500 token limit)

    // Instruction 1: Transfer tokens TO the Swig wallet from funding account
    let fund_swig_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &funding_ata,
        &swig_wallet_ata,
        &funding_account.pubkey(),
        &[],
        transfer_amount,
    )
    .unwrap();

    // Instruction 2: Transfer tokens FROM Swig wallet to recipient
    // In V2, the authority is swig_wallet_address
    let withdraw_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_wallet_ata,
        &recipient_ata,
        &swig_wallet_address,
        &[],
        transfer_amount,
    )
    .unwrap();

    // Build accounts for SignV2 with multiple CPIs
    let initial_accounts = vec![
        AccountMeta::new(swig, false),
        AccountMeta::new(swig_wallet_address, false),
        AccountMeta::new(context.default_payer.pubkey(), true),
        AccountMeta::new(second_authority.pubkey(), true),
        AccountMeta::new(funding_account.pubkey(), true),
        AccountMeta::new(funding_ata, false),
        AccountMeta::new(swig_wallet_ata, false),
        AccountMeta::new(recipient_ata, false),
        AccountMeta::new_readonly(spl_token::ID, false),
    ];

    let (final_accounts, compact_ixs) = swig_interface::compact_instructions(
        swig,
        initial_accounts,
        vec![fund_swig_ix, withdraw_ix],
    );

    let instruction_payload = compact_ixs.into_bytes();

    // Prepare the `sign_v2` instruction manually
    let sign_args = SignV2Args::new(1, instruction_payload.len() as u16); // Role ID 1 for limited_authority
    let mut sign_ix_data = Vec::new();
    sign_ix_data.extend_from_slice(sign_args.into_bytes().unwrap());
    sign_ix_data.extend_from_slice(&instruction_payload);
    sign_ix_data.push(3); // authority account index (second_authority)

    let sign_ix = solana_sdk::instruction::Instruction {
        program_id: swig::ID.into(),
        accounts: final_accounts,
        data: sign_ix_data,
    };

    // Get initial token balances
    let initial_swig_token_account = context.svm.get_account(&swig_wallet_ata).unwrap();
    let initial_swig_token_balance =
        spl_token::state::Account::unpack(&initial_swig_token_account.data).unwrap();

    let initial_recipient_token_account = context.svm.get_account(&recipient_ata).unwrap();
    let initial_recipient_token_balance =
        spl_token::state::Account::unpack(&initial_recipient_token_account.data).unwrap();

    println!(
        "Initial Swig wallet token balance: {} tokens",
        initial_swig_token_balance.amount
    );
    println!(
        "Initial recipient token balance: {} tokens",
        initial_recipient_token_balance.amount
    );
    println!(
        "Testing 500 token ProgramScope limit enforcement with funding+withdrawing {} tokens (SignV2)...",
        transfer_amount
    );

    // Build the transaction
    let test_message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let test_tx = VersionedTransaction::try_new(
        VersionedMessage::V0(test_message),
        &[&context.default_payer, &second_authority, &funding_account], // All required signers
    )
    .unwrap();

    let result = context.svm.send_transaction(test_tx);

    // Always print final balances regardless of transaction outcome
    let final_swig_token_account = context.svm.get_account(&swig_wallet_ata).unwrap();
    let final_swig_token_balance =
        spl_token::state::Account::unpack(&final_swig_token_account.data).unwrap();

    let final_recipient_token_account = context.svm.get_account(&recipient_ata).unwrap();
    let final_recipient_token_balance =
        spl_token::state::Account::unpack(&final_recipient_token_account.data).unwrap();

    println!(
        "Final Swig wallet token balance: {} tokens",
        final_swig_token_balance.amount
    );
    println!(
        "Final recipient token balance: {} tokens",
        final_recipient_token_balance.amount
    );

    // Print transaction result
    if result.is_err() {
        let error = result.as_ref().unwrap_err();
        println!(
            "❌ Transaction failed with error (expected for SignV2): {:?}",
            error.err
        );
        println!("Logs: {:?}", error.meta.logs);
    } else {
        let transaction_result = result.as_ref().unwrap();
        println!(
            "✅ Transaction succeeded: {}",
            transaction_result.pretty_logs()
        );
    }

    // The transaction should fail due to program scope limit enforcement
    assert!(
        result.is_err(),
        "Transaction should fail due to program scope limit enforcement in CPI scenarios (SignV2)"
    );
}

/// Test that verifies balance underflow checking with ProgramScope using SignV2
/// This is the SignV2 equivalent of test_program_scope_balance_underflow_check
#[test_log::test]
fn test_program_scope_balance_underflow_check_v2() {
    let mut context = setup_test_context().unwrap();
    let swig_authority = Keypair::new();
    let external_funding_account = Keypair::new(); // External account that funds the swig wallet

    // Airdrops
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10 * LAMPORTS_PER_SOL)
        .unwrap();
    context
        .svm
        .airdrop(&external_funding_account.pubkey(), 10 * LAMPORTS_PER_SOL)
        .unwrap();

    // Setup token mint
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    // Setup swig account (V2 - no convert_swig_to_v1 call)
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Setup token accounts - for V2, ATA is for swig_wallet_address
    let swig_wallet_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();
    let external_funding_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &external_funding_account.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    // Mint initial tokens to the external funding account
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &external_funding_ata,
        2000,
    )
    .unwrap();

    // Define a ProgramScope with a limit of 1000 tokens
    let program_scope = ProgramScope {
        program_id: spl_token::ID.to_bytes(),
        target_account: swig_wallet_ata.to_bytes(),
        scope_type: ProgramScopeType::Limit as u64,
        numeric_type: NumericType::U64 as u64,
        current_amount: 0,
        limit: 1000,
        window: 0,
        last_reset: 0,
        balance_field_start: 64,
        balance_field_end: 72,
    };

    // Add the authority with the ProgramScope
    add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: swig_state::authority::AuthorityType::Ed25519,
            authority: swig_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::Program(swig_state::action::program::Program {
                program_id: spl_token::ID.to_bytes(),
            }),
            ClientAction::ProgramScope(program_scope),
        ],
    )
    .unwrap();

    // CPI 1: Fund the swig wallet ATA with tokens (deposit from external account)
    let funding_amount = 500;
    let funding_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &external_funding_ata,
        &swig_wallet_ata,
        &external_funding_account.pubkey(),
        &[],
        funding_amount,
    )
    .unwrap();

    // CPI 2: Withdraw tokens from swig wallet ATA (should be properly tracked now)
    // In V2, the authority is swig_wallet_address
    let withdrawal_amount = 100;
    let withdrawal_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_wallet_ata,
        &external_funding_ata,
        &swig_wallet_address, // V2: swig_wallet_address signs for this withdrawal
        &[],
        withdrawal_amount,
    )
    .unwrap();

    // Compact the instructions for SignV2
    let initial_accounts = vec![
        AccountMeta::new(swig, false),
        AccountMeta::new(swig_wallet_address, false),
        AccountMeta::new_readonly(swig_authority.pubkey(), true),
        AccountMeta::new(external_funding_ata, false),
        AccountMeta::new(swig_wallet_ata, false),
        AccountMeta::new_readonly(external_funding_account.pubkey(), true),
        AccountMeta::new_readonly(spl_token::ID, false),
    ];
    let (final_accounts, compact_ixs) =
        compact_instructions(swig, initial_accounts, vec![funding_ix, withdrawal_ix]);
    let instruction_payload = compact_ixs.into_bytes();

    // Prepare the sign_v2 instruction
    let sign_args = SignV2Args::new(1, instruction_payload.len() as u16);
    let mut sign_ix_data = Vec::new();
    sign_ix_data.extend_from_slice(sign_args.into_bytes().unwrap());
    sign_ix_data.extend_from_slice(&instruction_payload);
    sign_ix_data.push(2); // authority index

    let sign_ix = Instruction {
        program_id: swig::ID.into(),
        accounts: final_accounts,
        data: sign_ix_data,
    };

    // Build and send the transaction
    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[
            &context.default_payer,
            &swig_authority,
            &external_funding_account,
        ],
    )
    .unwrap();
    let result = context.svm.send_transaction(tx);

    // This transaction should now succeed because balance tracking is fixed
    assert!(
        result.is_ok(),
        "Transaction should succeed with correct balance tracking (SignV2): {:?}",
        result.err()
    );

    println!("✅ Transaction succeeded with proper balance tracking (SignV2)");
    println!("Result: {:?}", result.unwrap().pretty_logs());
}

/// Test ProgramScope with secp256k1 authority using SignV2
/// This tests that program scope limits work correctly with Ethereum-style signatures
#[test_log::test]
fn test_program_scope_with_secp256k1_authority_v2() {
    use alloy_primitives::B256;
    use alloy_signer::SignerSync;
    use alloy_signer_local::LocalSigner;

    let mut context = setup_test_context().unwrap();

    // Generate a random Ethereum wallet for secp256k1
    let wallet = LocalSigner::random();

    // Get the Ethereum public key (uncompressed, without 0x04 prefix)
    let eth_pubkey = wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();
    let authority_bytes = &eth_pubkey[1..]; // Remove the 0x04 prefix

    // Create swig with secp256k1 authority
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_secp256k1(&mut context, &wallet, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    // Fund the swig wallet
    context
        .svm
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

    // Setup token infrastructure
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    let swig_wallet_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 1_000_000_000)
        .unwrap();

    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    // Mint tokens to swig wallet
    let initial_tokens = 1000;
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_wallet_ata,
        initial_tokens,
    )
    .unwrap();

    // Add a second authority (secp256k1) with ProgramScope
    let second_wallet = LocalSigner::random();
    let second_eth_pubkey = second_wallet
        .credential()
        .verifying_key()
        .to_encoded_point(false)
        .to_bytes();
    let second_authority_bytes: Vec<u8> = second_eth_pubkey[1..].to_vec();

    let program_scope = ProgramScope {
        program_id: spl_token::ID.to_bytes(),
        target_account: swig_wallet_ata.to_bytes(),
        scope_type: ProgramScopeType::Limit as u64,
        numeric_type: NumericType::U64 as u64,
        current_amount: 0,
        limit: 500, // Limit of 500 tokens
        window: 0,
        last_reset: 0,
        balance_field_start: 64,
        balance_field_end: 72,
    };

    // Use secp256k1 root authority to add new authority with ProgramScope
    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    // Get current counter for the root authority
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = swig_state::swig::SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role_id = swig_data.lookup_role_id(authority_bytes).unwrap().unwrap();
    let role = swig_data.get_role(role_id).unwrap().unwrap();
    let current_counter = if let Some(secp_auth) =
        role.authority
            .as_any()
            .downcast_ref::<swig_state::authority::secp256k1::Secp256k1Authority>()
    {
        secp_auth.signature_odometer
    } else {
        0
    };
    let next_counter = current_counter + 1;

    let signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    let add_auth_ix = swig_interface::AddAuthorityInstruction::new_with_secp256k1_authority(
        swig,
        context.default_payer.pubkey(),
        signing_fn,
        current_slot,
        next_counter,
        0, // acting role id (root)
        AuthorityConfig {
            authority_type: swig_state::authority::AuthorityType::Secp256k1,
            authority: &second_authority_bytes,
        },
        vec![
            ClientAction::Program(Program {
                program_id: spl_token::ID.to_bytes(),
            }),
            ClientAction::ProgramScope(program_scope),
        ],
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[add_auth_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&context.default_payer])
            .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to add secp256k1 authority with ProgramScope: {:?}",
        result.err()
    );

    println!("Added secp256k1 authority with ProgramScope (limit: 500 tokens)");

    // Now use the second authority to make transfers
    context.svm.expire_blockhash();

    // Get the counter for the new authority
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = swig_state::swig::SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role_id = swig_data
        .lookup_role_id(&second_authority_bytes)
        .unwrap()
        .unwrap();
    let role = swig_data.get_role(role_id).unwrap().unwrap();
    let second_counter = if let Some(secp_auth) =
        role.authority
            .as_any()
            .downcast_ref::<swig_state::authority::secp256k1::Secp256k1Authority>()
    {
        secp_auth.signature_odometer
    } else {
        0
    };

    // Transfer 100 tokens (within limit)
    let transfer_amount = 100u64;
    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_wallet_ata,
        &recipient_ata,
        &swig_wallet_address,
        &[],
        transfer_amount,
    )
    .unwrap();

    let second_signing_fn = |payload: &[u8]| -> [u8; 65] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let hash = B256::from(hash);
        second_wallet.sign_hash_sync(&hash).unwrap().as_bytes()
    };

    let sign_ix = swig_interface::SignV2Instruction::new_secp256k1_with_signers(
        swig,
        swig_wallet_address,
        second_signing_fn,
        current_slot,
        second_counter + 1,
        transfer_ix,
        role_id,
        &[context.default_payer.pubkey()],
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&context.default_payer])
            .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Transfer with secp256k1 authority should succeed: {:?}",
        result.err()
    );

    println!(
        "✅ Successfully transferred {} tokens using secp256k1 authority with ProgramScope (SignV2)",
        transfer_amount
    );

    // Verify the transfer
    let recipient_account = context.svm.get_account(&recipient_ata).unwrap();
    let token_account =
        litesvm_token::spl_token::state::Account::unpack(&recipient_account.data).unwrap();
    assert_eq!(
        token_account.amount, transfer_amount,
        "Recipient should have received the tokens"
    );
}

/// Test ProgramScope with secp256r1 authority using SignV2
/// This tests that program scope limits work correctly with WebAuthn-style signatures
#[test_log::test]
fn test_program_scope_with_secp256r1_authority_v2() {
    use openssl::{
        bn::BigNumContext,
        ec::{EcGroup, EcKey, PointConversionForm},
        nid::Nid,
    };

    let mut context = setup_test_context().unwrap();

    // Generate a secp256r1 key pair
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let signing_key = EcKey::generate(&group).unwrap();
    let mut bn_ctx = BigNumContext::new().unwrap();
    let pubkey_bytes = signing_key
        .public_key()
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut bn_ctx)
        .unwrap();
    let public_key: [u8; 33] = pubkey_bytes.try_into().unwrap();

    // Create swig with secp256r1 authority
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = create_swig_secp256r1(&mut context, &public_key, id).unwrap();
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    // Fund the swig wallet
    context
        .svm
        .airdrop(&swig_wallet_address, 10_000_000_000)
        .unwrap();

    // Setup token infrastructure
    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    let swig_wallet_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 1_000_000_000)
        .unwrap();

    let recipient_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    // Mint tokens to swig wallet
    let initial_tokens = 1000;
    mint_to(
        &mut context.svm,
        &mint_pubkey,
        &context.default_payer,
        &swig_wallet_ata,
        initial_tokens,
    )
    .unwrap();

    // Generate a second secp256r1 key pair for the new authority
    let second_signing_key = EcKey::generate(&group).unwrap();
    let second_pubkey_bytes = second_signing_key
        .public_key()
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut bn_ctx)
        .unwrap();
    let second_public_key: [u8; 33] = second_pubkey_bytes.try_into().unwrap();

    let program_scope = ProgramScope {
        program_id: spl_token::ID.to_bytes(),
        target_account: swig_wallet_ata.to_bytes(),
        scope_type: ProgramScopeType::Limit as u64,
        numeric_type: NumericType::U64 as u64,
        current_amount: 0,
        limit: 500, // Limit of 500 tokens
        window: 0,
        last_reset: 0,
        balance_field_start: 64,
        balance_field_end: 72,
    };

    // Get current slot and counter for root authority
    let current_slot = context.svm.get_sysvar::<Clock>().slot;

    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = swig_state::swig::SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let role_id = swig_data.lookup_role_id(&public_key).unwrap().unwrap();
    let role = swig_data.get_role(role_id).unwrap().unwrap();
    let current_counter = if let Some(secp_auth) =
        role.authority
            .as_any()
            .downcast_ref::<swig_state::authority::secp256r1::Secp256r1Authority>()
    {
        secp_auth.signature_odometer
    } else {
        0
    };
    let next_counter = current_counter + 1;

    // Use secp256r1 root authority to add new authority with ProgramScope
    let authority_fn = |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        sign_message(message_hash, &signing_key.private_key_to_der().unwrap()).unwrap()
    };

    let add_auth_ixs = swig_interface::AddAuthorityInstruction::new_with_secp256r1_authority(
        swig,
        context.default_payer.pubkey(),
        authority_fn,
        current_slot,
        next_counter,
        0, // acting role id (root)
        &public_key,
        AuthorityConfig {
            authority_type: swig_state::authority::AuthorityType::Secp256r1,
            authority: &second_public_key,
        },
        vec![
            ClientAction::Program(Program {
                program_id: spl_token::ID.to_bytes(),
            }),
            ClientAction::ProgramScope(program_scope),
        ],
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &add_auth_ixs,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&context.default_payer])
            .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to add secp256r1 authority with ProgramScope: {:?}",
        result.err()
    );

    println!("Added secp256r1 authority with ProgramScope (limit: 500 tokens)");

    // Now use the second authority to make transfers
    context.svm.expire_blockhash();

    // Get the counter for the new authority
    let swig_account = context.svm.get_account(&swig).unwrap();
    let swig_data = swig_state::swig::SwigWithRoles::from_bytes(&swig_account.data).unwrap();
    let new_role_id = swig_data
        .lookup_role_id(&second_public_key)
        .unwrap()
        .unwrap();
    let new_role = swig_data.get_role(new_role_id).unwrap().unwrap();
    let second_counter = if let Some(secp_auth) =
        new_role
            .authority
            .as_any()
            .downcast_ref::<swig_state::authority::secp256r1::Secp256r1Authority>()
    {
        secp_auth.signature_odometer
    } else {
        0
    };

    // Transfer 100 tokens (within limit)
    let transfer_amount = 100u64;
    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_wallet_ata,
        &recipient_ata,
        &swig_wallet_address,
        &[],
        transfer_amount,
    )
    .unwrap();

    let second_authority_fn = |message_hash: &[u8]| -> [u8; 64] {
        use solana_secp256r1_program::sign_message;
        sign_message(
            message_hash,
            &second_signing_key.private_key_to_der().unwrap(),
        )
        .unwrap()
    };

    let sign_ixs = swig_interface::SignV2Instruction::new_secp256r1(
        swig,
        swig_wallet_address,
        second_authority_fn,
        current_slot,
        second_counter + 1,
        transfer_ix,
        new_role_id,
        &second_public_key,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &context.default_payer.pubkey(),
        &sign_ixs,
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&context.default_payer])
            .unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Transfer with secp256r1 authority should succeed: {:?}",
        result.err()
    );

    println!(
        "✅ Successfully transferred {} tokens using secp256r1 authority with ProgramScope (SignV2)",
        transfer_amount
    );

    // Verify the transfer
    let recipient_account = context.svm.get_account(&recipient_ata).unwrap();
    let token_account =
        litesvm_token::spl_token::state::Account::unpack(&recipient_account.data).unwrap();
    assert_eq!(
        token_account.amount, transfer_amount,
        "Recipient should have received the tokens"
    );
}

/// Test ProgramScope with multiple target accounts using SignV2
/// This tests that an authority can have multiple ProgramScope actions for different accounts
/// with the same program (e.g., multiple token accounts using the SPL Token program).
#[test_log::test]
fn test_program_scope_multiple_targets_v2() {
    let mut context = setup_test_context().unwrap();

    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    // Setup two different token mints
    let mint1 = setup_mint(&mut context.svm, &context.default_payer).unwrap();
    let mint2 = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    // Create swig
    let id = rand::random::<[u8; 32]>();
    let (swig, _) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    // Setup token accounts for both mints
    let swig_ata1 = setup_ata(
        &mut context.svm,
        &mint1,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    let swig_ata2 = setup_ata(
        &mut context.svm,
        &mint2,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 1_000_000_000)
        .unwrap();

    let recipient_ata1 = setup_ata(
        &mut context.svm,
        &mint1,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    let recipient_ata2 = setup_ata(
        &mut context.svm,
        &mint2,
        &recipient.pubkey(),
        &context.default_payer,
    )
    .unwrap();

    // Mint tokens to both swig ATAs
    mint_to(
        &mut context.svm,
        &mint1,
        &context.default_payer,
        &swig_ata1,
        1000,
    )
    .unwrap();

    mint_to(
        &mut context.svm,
        &mint2,
        &context.default_payer,
        &swig_ata2,
        1000,
    )
    .unwrap();

    // Create ProgramScope for each token account with different limits
    let program_scope1 = ProgramScope {
        program_id: spl_token::ID.to_bytes(),
        target_account: swig_ata1.to_bytes(),
        scope_type: ProgramScopeType::Limit as u64,
        numeric_type: NumericType::U64 as u64,
        current_amount: 0,
        limit: 300, // Limit of 300 tokens for mint1
        window: 0,
        last_reset: 0,
        balance_field_start: 64,
        balance_field_end: 72,
    };

    let program_scope2 = ProgramScope {
        program_id: spl_token::ID.to_bytes(),
        target_account: swig_ata2.to_bytes(),
        scope_type: ProgramScopeType::Limit as u64,
        numeric_type: NumericType::U64 as u64,
        current_amount: 0,
        limit: 500, // Limit of 500 tokens for mint2
        window: 0,
        last_reset: 0,
        balance_field_start: 64,
        balance_field_end: 72,
    };

    // Add authority with both ProgramScope actions
    let add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: swig_state::authority::AuthorityType::Ed25519,
            authority: swig_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::Program(Program {
                program_id: spl_token::ID.to_bytes(),
            }),
            ClientAction::ProgramScope(program_scope1),
            ClientAction::ProgramScope(program_scope2),
        ],
    );
    assert!(
        add_result.is_ok(),
        "Failed to add authority with multiple ProgramScopes: {:?}",
        add_result.err()
    );

    println!("Added authority with two ProgramScopes (mint1: 300 limit, mint2: 500 limit)");

    // Test transfer from mint1 (within limit)
    context.svm.expire_blockhash();

    let transfer1_amount = 200u64;
    let transfer1_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata1,
        &recipient_ata1,
        &swig_wallet_address,
        &[],
        transfer1_amount,
    )
    .unwrap();

    let sign_ix1 = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        swig_authority.pubkey(),
        transfer1_ix,
        1,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign_ix1],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&swig_authority]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Transfer from mint1 should succeed: {:?}",
        result.err()
    );

    println!(
        "✅ Transferred {} tokens from mint1 (limit: 300)",
        transfer1_amount
    );

    // Test transfer from mint2 (within limit)
    context.svm.expire_blockhash();

    let transfer2_amount = 400u64;
    let transfer2_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata2,
        &recipient_ata2,
        &swig_wallet_address,
        &[],
        transfer2_amount,
    )
    .unwrap();

    let sign_ix2 = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        swig_authority.pubkey(),
        transfer2_ix,
        1,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign_ix2],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&swig_authority]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_ok(),
        "Transfer from mint2 should succeed: {:?}",
        result.err()
    );

    println!(
        "✅ Transferred {} tokens from mint2 (limit: 500)",
        transfer2_amount
    );

    // Verify both transfers
    let recipient_account1 = context.svm.get_account(&recipient_ata1).unwrap();
    let token_account1 =
        litesvm_token::spl_token::state::Account::unpack(&recipient_account1.data).unwrap();
    assert_eq!(token_account1.amount, transfer1_amount);

    let recipient_account2 = context.svm.get_account(&recipient_ata2).unwrap();
    let token_account2 =
        litesvm_token::spl_token::state::Account::unpack(&recipient_account2.data).unwrap();
    assert_eq!(token_account2.amount, transfer2_amount);

    // Test exceeding mint1 limit (should fail)
    context.svm.expire_blockhash();

    let over_limit_amount = 200u64; // Would bring total to 400, exceeding 300 limit
    let over_limit_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_ata1,
        &recipient_ata1,
        &swig_wallet_address,
        &[],
        over_limit_amount,
    )
    .unwrap();

    let sign_ix_over = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        swig_authority.pubkey(),
        over_limit_ix,
        1,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign_ix_over],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&swig_authority]).unwrap();

    let result = context.svm.send_transaction(tx);
    assert!(
        result.is_err(),
        "Transfer exceeding mint1 limit should fail"
    );

    println!("✅ Correctly rejected transfer that would exceed mint1 limit");
    println!("✅ Multiple ProgramScope targets test completed successfully (SignV2)!");
}

/// Test ProgramScope with invalid balance field indices using SignV2
/// This tests edge cases where balance field configuration is invalid
#[test_log::test]
fn test_program_scope_invalid_balance_field_indices_v2() {
    let mut context = setup_test_context().unwrap();

    let swig_authority = Keypair::new();
    context
        .svm
        .airdrop(&swig_authority.pubkey(), 10_000_000_000)
        .unwrap();

    let mint_pubkey = setup_mint(&mut context.svm, &context.default_payer).unwrap();

    let id = rand::random::<[u8; 32]>();
    let (swig, _) = Pubkey::find_program_address(&swig_account_seeds(&id), &program_id());
    let (swig_wallet_address, _) =
        Pubkey::find_program_address(&swig_wallet_address_seeds(swig.as_ref()), &program_id());

    create_swig_ed25519(&mut context, &swig_authority, id).unwrap();

    let swig_wallet_ata = setup_ata(
        &mut context.svm,
        &mint_pubkey,
        &swig_wallet_address,
        &context.default_payer,
    )
    .unwrap();

    let recipient = Keypair::new();
    context
        .svm
        .airdrop(&recipient.pubkey(), 1_000_000_000)
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
        &swig_wallet_ata,
        1000,
    )
    .unwrap();

    // Create ProgramScope with invalid balance field indices (end > account data length)
    // SPL Token accounts are typically 165 bytes, so setting end to 200 is invalid
    let invalid_program_scope = ProgramScope {
        program_id: spl_token::ID.to_bytes(),
        target_account: swig_wallet_ata.to_bytes(),
        scope_type: ProgramScopeType::Limit as u64,
        numeric_type: NumericType::U64 as u64,
        current_amount: 0,
        limit: 500,
        window: 0,
        last_reset: 0,
        balance_field_start: 190, // Invalid: beyond typical SPL token account size
        balance_field_end: 200,   // Invalid: beyond typical SPL token account size
    };

    // Add authority with invalid ProgramScope
    let add_result = add_authority_with_ed25519_root(
        &mut context,
        &swig,
        &swig_authority,
        AuthorityConfig {
            authority_type: swig_state::authority::AuthorityType::Ed25519,
            authority: swig_authority.pubkey().as_ref(),
        },
        vec![
            ClientAction::Program(Program {
                program_id: spl_token::ID.to_bytes(),
            }),
            ClientAction::ProgramScope(invalid_program_scope),
        ],
    );

    // The add_authority should succeed (we're just storing the config)
    assert!(
        add_result.is_ok(),
        "Adding authority should succeed even with invalid balance fields"
    );

    println!("Added authority with invalid balance field indices");

    // Now try to use the invalid ProgramScope for a transfer
    context.svm.expire_blockhash();

    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::ID,
        &swig_wallet_ata,
        &recipient_ata,
        &swig_wallet_address,
        &[],
        100,
    )
    .unwrap();

    let sign_ix = SignV2Instruction::new_ed25519(
        swig,
        swig_wallet_address,
        swig_authority.pubkey(),
        transfer_ix,
        1,
    )
    .unwrap();

    let message = v0::Message::try_compile(
        &swig_authority.pubkey(),
        &[sign_ix],
        &[],
        context.svm.latest_blockhash(),
    )
    .unwrap();

    let tx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&swig_authority]).unwrap();

    let result = context.svm.send_transaction(tx);

    // The transaction should fail because the balance field indices are invalid
    assert!(
        result.is_err(),
        "Transfer with invalid balance field indices should fail"
    );

    // Check that the error is related to invalid program scope balance fields
    if let Err(e) = result {
        println!("✅ Correctly failed with error: {:?}", e.err);
    }

    println!("✅ Invalid balance field indices test completed successfully (SignV2)!");
}

// =============================================================================
// TODO: The following tests exist in V1 but are NOT yet covered by SignV2:
// =============================================================================
//
// TODO: sign.rs tests that need SignV2 equivalents:
// - test_sign_transfer_sol_with_additional_authority -> test_sign_v2_transfer_sol_with_additional_authority (EXISTS in sign_v2.rs)
// - test_sign_session_ed25519_sol_transfer -> needs SignV2 session test
// - test_sign_session_ed25519_token_transfer -> needs SignV2 session test
// - test_sign_session_secp256k1_token_transfer -> needs SignV2 session test
// - test_swig_create_and_receive_multi_transfer -> needs SignV2 equivalent
// - test_session_ed25519_does_not_allow_manage_authority -> needs SignV2 equivalent
//
// TODO: sign_secp256k1.rs tests that need SignV2 equivalents:
// - Many tests already have V2 versions in sign_secp256k1_v2.rs
// - Review for any missing coverage
//
// TODO: sign_secp256r1.rs tests that need SignV2 equivalents:
// - Many tests already have V2 versions in sign_secp256r1_v2.rs
// - Review for any missing coverage
// =============================================================================
